"""Discovery work on the Outpost: the handlers drive the shared danbyte_checks
collectors against servers on 127.0.0.1 only (an SSH server answering the
fixed inventory commands with recorded output, a greeting server, a stand-in
nmap printing recorded XML), the target policy refuses link-local before any
connection, secrets are dropped and never printed, and the agent pulls work
only from a core that offers it."""
from __future__ import annotations

import asyncio
import json
import os
import socket
import stat
import threading
from pathlib import Path

import asyncssh
import pytest

from danbyte_checks import inventory
from outpost import discovery

FIX = Path(__file__).resolve().parent / "fixtures"
SECRET = "pw-SECRET-outpost-41c"


def run(coro):
    return asyncio.run(coro)


# ─── a local SSH server that answers the fixed commands ──────────────────────

OUTPUT = {
    inventory.COMMANDS["os_release"]: (FIX / "debian12-os-release.txt").read_bytes(),
    inventory.COMMANDS["dpkg"]: (FIX / "debian12-dpkg.txt").read_bytes(),
}


class _Server(asyncssh.SSHServer):
    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        return username == "inv" and password == SECRET


async def _process(proc):
    out = OUTPUT.get(proc.command)
    if out is None:
        proc.exit(127)
        return
    proc.stdout.write(out)
    proc.exit(0)


async def _with_ssh_server(test):
    key = asyncssh.generate_private_key("ssh-ed25519")
    server = await asyncssh.listen("127.0.0.1", 0, server_host_keys=[key],
                                   server_factory=_Server, process_factory=_process,
                                   encoding=None)
    port = server.sockets[0].getsockname()[1]
    try:
        return await test(port, key.convert_to_public())
    finally:
        server.close()
        await server.wait_closed()


def _known(port, pub):
    return inventory.known_hosts_lines("127.0.0.1", [(
        pub.get_algorithm(), inventory._key_dict(pub)["public_key"], port)]).decode()


def _item(port, known, *, password=SECRET, first_use=False):
    return {"item_id": "i1", "mode": "read", "address": "127.0.0.1", "known_hosts": known,
            "first_use": first_use,
            "logins": [{"transport": "ssh_password", "port": port, "fall_through": False,
                        "credential": {"username": "inv", "password": password}}]}


def test_inventory_reads_a_host_with_the_shared_collector(capsys):
    async def go(port, pub):
        job = {"kind": "inventory", "timeout": 20, "concurrency": 2,
               "items": [_item(port, _known(port, pub))]}
        rows = await discovery.run_inventory(job)
        return job, rows

    job, rows = run(_with_ssh_server(go))
    row = rows[0]
    assert row["item_id"] == "i1"
    assert row["used"] == 0
    back = inventory.result_from_dict(json.loads(json.dumps(row["result"])))
    assert back.status == "ok" and back.manager == "dpkg"
    assert back.os["id"] == "debian"
    assert len(back.packages) == 88
    # The secret went to the host only: dropped from the work, never printed,
    # not in what is posted back.
    assert "credential" not in job["items"][0]["logins"][0]
    out = capsys.readouterr()
    assert SECRET not in out.out + out.err
    assert SECRET not in json.dumps(rows)


def test_a_host_key_not_pinned_is_refused_before_the_password_is_sent():
    async def go(port, pub):
        other = asyncssh.generate_private_key("ssh-ed25519").convert_to_public()
        rows = await discovery.run_inventory({"items": [_item(port, _known(port, other))],
                                              "timeout": 15})
        return rows, inventory._key_dict(pub)

    rows, presented = run(_with_ssh_server(go))
    assert rows[0]["result"]["status"] == "host_key_refused"
    assert rows[0]["observed"]["fingerprint"] == presented["fingerprint"]


def test_first_use_takes_the_presented_key():
    async def go(port, pub):
        rows = await discovery.run_inventory({"items": [_item(port, None, first_use=True)],
                                              "timeout": 15})
        return rows, inventory._key_dict(pub)

    rows, presented = run(_with_ssh_server(go))
    assert rows[0]["result"]["status"] == "ok"
    assert rows[0]["result"]["host_key"]["fingerprint"] == presented["fingerprint"]


def test_a_wrong_password_is_tried_once():
    async def go(port, pub):
        item = _item(port, _known(port, pub), password="nope")
        item["logins"].append({**item["logins"][0], "credential": {"username": "inv",
                                                                     "password": SECRET}})
        return await discovery.run_inventory({"items": [item], "timeout": 15})

    rows = run(_with_ssh_server(go))
    assert rows[0]["result"]["status"] == "auth_failed"
    assert len(rows[0]["attempts"]) == 1  # no second password: no lockouts


def test_the_target_policy_refuses_link_local_without_connecting():
    calls = []

    async def collect(*a, **kw):
        calls.append(a)

    rows = run(discovery.run_inventory(
        {"items": [{**_item(22, None), "address": "169.254.169.254"},
                   {"item_id": "o", "mode": "observe", "address": "fe80::1"}]},
        collect=collect, observe=collect))
    assert rows[0]["result"]["status"] == "blocked"
    assert rows[1]["observed"] is None
    assert calls == []
    scan = run(discovery.run_scan({"items": [{"item_id": "s", "address": "169.254.1.1"},
                                             {"item_id": "t", "address": "not-an-ip"}],
                                   "ports": [22]}))
    assert [r["result"]["status"] for r in scan] == ["blocked", "blocked"]


# ─── service scan against a greeting server ──────────────────────────────────


def _greeting_server(banner: bytes):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(8)
    stop = threading.Event()

    def serve():
        sock.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
            except OSError:
                continue
            with conn:
                try:
                    conn.sendall(banner)
                except OSError:
                    pass

    threading.Thread(target=serve, daemon=True).start()
    return sock, stop


def test_scan_finds_and_names_a_service():
    sock, stop = _greeting_server(b"220 (vsFTPd 3.0.5)\r\n")
    port = sock.getsockname()[1]
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    free = closed.getsockname()[1]
    closed.close()
    try:
        rows = run(discovery.run_scan({
            "kind": "service_scan", "engine": "builtin", "ports": [port, free], "rate": 50,
            "hosts_parallel": 1, "items": [{"item_id": "s1", "address": "127.0.0.1"}]}))
    finally:
        stop.set()
        sock.close()
    r = rows[0]["result"]
    assert rows[0]["item_id"] == "s1"
    assert r["status"] == "ok"
    assert [p["port"] for p in r["open"]] == [port]
    assert r["open"][0]["product"] == "vsftpd"
    assert r["open"][0]["version"] == "3.0.5"


def test_the_recog_data_travels_with_the_agent():
    from danbyte_checks import fingerprints

    assert fingerprints.DATA.is_file()
    hit = fingerprints.match("http.server", "openresty/1.21.4.1")
    assert hit["source"] == "recog"  # not one of the built-in rules
    assert hit["version"] == "1.21.4.1"


# ─── nmap ────────────────────────────────────────────────────────────────────


def _fake_nmap(tmp_path) -> str:
    """A stand-in nmap: answers --version like nmap and prints recorded XML."""
    xml = FIX / "nmap-7.98-localhost.xml"
    script = tmp_path / "nmap"
    script.write_text("#!/bin/sh\n"
                      'if [ "$1" = "--version" ]; then echo "Nmap version 7.98"; exit 0; fi\n'
                      f'exec cat "{xml}"\n')
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return str(script)


@pytest.mark.skipif(discovery.is_root(), reason="nmap is refused as root")
def test_nmap_is_detected_advertised_and_run_with_the_shared_argv(tmp_path):
    path = _fake_nmap(tmp_path)
    caps = discovery.capabilities(path)["discovery"]
    assert caps["kinds"] == ["inventory", "service_scan"]
    assert caps["nmap"] == {"version": "7.98"}
    rows = run(discovery.run_scan({
        "engine": "nmap", "ports": [40605, 55991], "rate": 20, "hosts_parallel": 1,
        "nmap": {"intensity": 2, "timing": 3, "host_timeout": 60},
        "items": [{"item_id": "n1", "address": "127.0.0.1"}]}, nmap_binary=path))
    r = rows[0]["result"]
    assert r["status"] == "ok"
    assert {p["port"] for p in r["open"]} <= {40605, 55991}
    assert all(p["source"] == "nmap" for p in r["open"])


def test_no_nmap_means_none_advertised_and_scans_fail_cleanly(tmp_path, monkeypatch):
    caps = discovery.capabilities(str(tmp_path / "missing"))["discovery"]
    monkeypatch.setattr("shutil.which", lambda *_a, **_k: None)
    caps = discovery.capabilities("")["discovery"]
    assert caps["nmap"] is None and caps["nmap_reason"]
    rows = run(discovery.run_scan({"engine": "nmap", "ports": [22],
                                   "items": [{"item_id": "x", "address": "127.0.0.1"}]}))
    assert rows[0]["result"]["status"] == "failed"
    assert "nmap" in rows[0]["result"]["message"]


def test_nmap_is_refused_as_root(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    path, version, why = discovery.detect_nmap(_fake_nmap(tmp_path))
    assert (path, version) == ("", "")
    assert "root" in why
    assert discovery.capabilities()["discovery"]["nmap"] is None


# ─── the cycle and an older core ─────────────────────────────────────────────


class _Client:
    def __init__(self, jobs):
        self.jobs = list(jobs)
        self.posted: list[list[dict]] = []

    async def fetch_discovery_work(self):
        return {"jobs": [self.jobs.pop(0)] if self.jobs else []}

    async def post_discovery_results(self, rows):
        self.posted.append(list(rows))
        return {"accepted": len(rows), "refused": 0}


def test_cycle_runs_until_empty_and_posts_inventory_one_host_at_a_time(monkeypatch):
    async def fake(job):
        return [{"item_id": i["item_id"], "result": {}} for i in job["items"]]

    monkeypatch.setattr(discovery, "run_inventory", fake)
    client = _Client([{"kind": "inventory", "items": [{"item_id": "a"}, {"item_id": "b"}]},
                      {"kind": "something-new", "items": [{"item_id": "c"}]}])
    assert run(discovery.cycle(client)) == 2
    assert [len(p) for p in client.posted] == [1, 1]  # an unknown kind posts nothing


def test_an_older_core_is_never_asked_for_discovery_work():
    assert not discovery.wanted({}, {"checks": []})
    assert not discovery.wanted({"fast": True}, {"discovery_pending": True})
    assert not discovery.wanted({"discovery": True}, {"checks": []})
    assert discovery.wanted({"discovery": True}, {"discovery_pending": True})


def test_hello_advertises_capabilities_beside_the_old_fields():
    from outpost.client import OutpostClient
    from outpost.config import Config

    sent = {}

    class _Resp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"poll_interval_seconds": 15}

    client = OutpostClient(Config(url="https://core.invalid", token="t"),
                           discovery.capabilities("/nonexistent"))

    async def post(url, json=None):
        sent.update(json)
        return _Resp()

    client._http.post = post
    run(client.hello())
    run(client.aclose())
    assert {"version", "protocol", "hostname", "fast"} <= set(sent)
    assert sent["capabilities"]["discovery"]["kinds"] == ["inventory", "service_scan"]
