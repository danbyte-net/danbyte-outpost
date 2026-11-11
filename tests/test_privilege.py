"""How the agent runs: root detection, what hello and ``once`` say about it,
the ambient capability set nmap starts with, ICMP's group check, and
self-update as a service user."""
from __future__ import annotations

import asyncio
import io
import json
import os
import stat
import sys
from pathlib import Path

import pytest

from outpost import discovery, privilege, updater
from outpost import run as run_mod

FIX = Path(__file__).resolve().parent / "fixtures"


# ─── root detection and what is advertised ───────────────────────────────────


def test_runtime_says_whether_the_agent_runs_as_root(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    assert privilege.runtime() == {"root": True}
    assert discovery.is_root()
    monkeypatch.setattr(os, "geteuid", lambda: 997)
    assert privilege.runtime() == {"root": False}
    assert not discovery.is_root()


def test_the_root_warning_names_the_migration_command():
    text = privilege.root_warning("/opt/danbyte-outpost/danbyte-outpost")
    assert "sudo /opt/danbyte-outpost/danbyte-outpost migrate-service-user" in text


def test_as_root_nmap_is_not_offered_and_the_reason_says_what_to_do(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    caps = discovery.capabilities()["discovery"]
    assert caps["nmap"] is None
    assert "root" in caps["nmap_reason"] and "migrate-service-user" in caps["nmap_reason"]
    assert len(caps["nmap_reason"]) <= 200  # the core keeps 200 characters


def _once(monkeypatch, capsys, euid):
    monkeypatch.setattr(os, "geteuid", lambda: euid)
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({"checks": []})))
    assert run_mod.main(["once"]) == 0
    return capsys.readouterr()


def test_once_reports_runtime_beside_the_results_and_warns_on_stderr(monkeypatch, capsys):
    out = _once(monkeypatch, capsys, 0)
    body = json.loads(out.out)  # stdout stays JSON only
    assert body == {"results": [], "runtime": {"root": True}}
    assert "migrate-service-user" in out.err
    out = _once(monkeypatch, capsys, 1000)
    assert json.loads(out.out)["runtime"] == {"root": False}
    assert out.err == ""


def test_the_poll_loop_advertises_runtime_in_hello(monkeypatch):
    sent = {}

    class _Client:
        def __init__(self, cfg, caps):
            sent["caps"] = caps

        async def hello(self):
            raise KeyboardInterrupt  # stop the loop after hello

        async def aclose(self):
            pass

    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    monkeypatch.setattr("outpost.client.OutpostClient", _Client)
    from outpost.config import Config

    with pytest.raises(KeyboardInterrupt):
        asyncio.run(run_mod._loop(Config(url="https://core.invalid", token="t")))
    assert sent["caps"]["runtime"] == {"root": False}
    assert sent["caps"]["discovery"]["kinds"] == ["inventory", "service_scan"]


# ─── capabilities nmap starts with ───────────────────────────────────────────


def test_the_ambient_mask_is_read_from_proc_status(tmp_path):
    status = tmp_path / "status"
    status.write_text("Name:\tx\nCapInh:\t0000000000000000\nCapAmb:\t0000000000002000\n")
    assert privilege.ambient_capabilities(str(status)) == 0x2000  # CAP_NET_RAW
    status.write_text("Name:\tx\n")
    assert privilege.ambient_capabilities(str(status)) is None


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux prctl")
def test_clearing_the_ambient_set_leaves_it_empty():
    assert privilege.clear_ambient_capabilities() is True
    assert privilege.ambient_capabilities() in (0, None)


@pytest.mark.skipif(discovery.is_root(), reason="nmap is refused as root")
@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads /proc")
def test_nmap_starts_without_a_shell_with_the_shared_argv_and_no_capabilities(tmp_path):
    seen = tmp_path / "seen"
    xml = FIX / "nmap-7.98-localhost.xml"
    script = tmp_path / "nmap"
    # The fake nmap records its own argv and capability sets, then answers.
    script.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "--version" ]; then echo "Nmap version 7.98"; exit 0; fi\n'
        f'printf "%s\\n" "$@" > "{seen}.argv"\n'
        f'grep "^Cap" /proc/self/status > "{seen}.caps"\n'
        f'exec cat "{xml}"\n')
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    privilege.clear_ambient_capabilities()
    rows = asyncio.run(discovery.run_scan({
        "engine": "nmap", "ports": [40605, 55991], "rate": 20, "hosts_parallel": 1,
        "nmap": {"intensity": 2, "timing": 3, "host_timeout": 60},
        "items": [{"item_id": "n1", "address": "127.0.0.1"}]}, nmap_binary=str(script)))
    assert rows[0]["result"]["status"] == "ok"
    argv = (tmp_path / "seen.argv").read_text().split("\n")[:-1]
    from danbyte_checks import nmap

    expected = nmap.build_argv(str(script), ["127.0.0.1"], [40605, 55991], intensity=2,
                               timing=3, max_rate=20, host_timeout=60, max_hostgroup=1)
    assert argv == expected[1:]  # exactly the shared list, passed as-is
    assert "--unprivileged" in argv and "-sT" in argv
    caps = dict(line.split(":\t") for line in
                (tmp_path / "seen.caps").read_text().splitlines())
    for key in ("CapAmb", "CapEff", "CapPrm"):
        assert int(caps[key], 16) == 0, key


# ─── ICMP ────────────────────────────────────────────────────────────────────


def test_ping_group_range_decides_icmp():
    assert privilege.parse_ping_group_range("0\t2147483647\n") == (0, 2147483647)
    assert privilege.parse_ping_group_range("garbage") is None
    assert privilege.icmp_allowed([997], (0, 2147483647)) is True
    assert privilege.icmp_allowed([997], (1, 0)) is False  # the kernel's default: none
    assert privilege.icmp_allowed([0, 997], (0, 0)) is True
    assert privilege.icmp_allowed([997], None) is None


def test_a_range_that_leaves_the_agent_out_is_logged(monkeypatch):
    monkeypatch.setattr(privilege, "ping_range", lambda *_a: (1, 0))
    assert "ping_group_range" in privilege.icmp_warning()
    monkeypatch.setattr(privilege, "ping_range", lambda *_a: (0, 2147483647))
    assert privilege.icmp_warning() == ""


def test_icmp_uses_the_unprivileged_datagram_socket(monkeypatch):
    from danbyte_checks import icmp

    seen = {}

    class _Host:
        is_alive = True
        packets_sent = packets_received = 1
        packet_loss = 0.0
        avg_rtt = min_rtt = max_rtt = 0.1

    async def fake_ping(target, **kwargs):
        seen.update(kwargs)
        return _Host()

    monkeypatch.setattr(icmp, "async_ping", fake_ping)
    out = asyncio.run(icmp.IcmpChecker().run("127.0.0.1", {}, {}, 1000))
    assert out.status == "up"
    assert seen["privileged"] is False


@pytest.mark.skipif(privilege.icmp_allowed(privilege.own_groups(), privilege.ping_range())
                    is not True, reason="ping_group_range does not cover this user")
def test_icmp_reaches_localhost_without_privilege():
    from danbyte_checks import icmp

    out = asyncio.run(icmp.IcmpChecker().run("127.0.0.1", {"count": 1}, {}, 2000))
    assert out.status == "up"


# ─── self-update as the service user ─────────────────────────────────────────


class _Dl:
    def __init__(self):
        self.calls = 0

    async def download_binary(self, version):
        self.calls += 1
        return b"\x7fELF new " + version.encode()


def _frozen(monkeypatch, path):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(updater, "_own_binary_path", lambda: str(path))
    monkeypatch.setattr(updater, "_warned", False)


def test_self_update_without_a_writable_directory_keeps_running(tmp_path, monkeypatch,
                                                                 capsys):
    binary = tmp_path / "danbyte-outpost"
    binary.write_bytes(b"\x7fELF old")
    _frozen(monkeypatch, binary)
    monkeypatch.setattr(updater, "writable", lambda _p: False)
    dl = _Dl()
    assert asyncio.run(updater.self_update(dl, "0.10.1")) is False
    assert asyncio.run(updater.self_update(dl, "0.10.1")) is False
    assert dl.calls == 0
    assert binary.read_bytes() == b"\x7fELF old"
    assert capsys.readouterr().err.count("not writable") == 1  # said once


def test_self_update_replaces_its_binary_and_never_follows_a_planted_link(
        tmp_path, monkeypatch):
    binary = tmp_path / "danbyte-outpost"
    binary.write_bytes(b"\x7fELF old")
    victim = tmp_path / "victim"
    victim.write_text("keep")
    (tmp_path / "danbyte-outpost.new").symlink_to(victim)
    _frozen(monkeypatch, binary)

    class _Exit(Exception):
        pass

    def fake_exit(code):
        raise _Exit(code)

    monkeypatch.setattr(os, "_exit", fake_exit)
    with pytest.raises(_Exit):
        asyncio.run(updater.self_update(_Dl(), "0.10.1"))
    assert binary.read_bytes() == b"\x7fELF new 0.10.1"
    assert stat.S_IMODE(binary.stat().st_mode) == 0o755
    assert victim.read_text() == "keep"
    assert not (tmp_path / "danbyte-outpost.new").exists()
