"""``migrate-service-user`` against a directory that stands in for ``/``:
the checks, the dry run, the rewrite, the health watch and the rollback."""
from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from outpost import run as run_mod
from outpost import service_user as su

OLD_UNIT = """[Unit]
Description=Danbyte Outpost
After=network-online.target
Wants=network-online.target
[Service]
EnvironmentFile=/etc/danbyte-outpost/env
Environment=OUTPOST_NMAP_BINARY=/usr/bin/nmap
ExecStart=/opt/danbyte-outpost/danbyte-outpost run --insecure
Restart=always
RestartSec=10
[Install]
WantedBy=multi-user.target
"""
UNIT = "/etc/systemd/system/danbyte-outpost.service"
BIN = "/opt/danbyte-outpost/danbyte-outpost"
SVC_UID = 64990


class FakeHost(su.Host):
    """A host whose "root" is the test's own uid, with scripted systemd."""

    def __init__(self, root: Path, *, euid=0, active=True, comes_up_as=SVC_UID,
                 user_exists=False):
        super().__init__(str(root), root_uid=os.getuid())
        self._euid = euid
        self.users = {"danbyte-outpost": (SVC_UID, SVC_UID)} if user_exists else {}
        self.state = "active" if active else "inactive"
        self.comes_up_as = comes_up_as
        self.restarts = 0
        self.commands: list[list[str]] = []
        self.chowns: list[tuple[str, int, int]] = []

    def euid(self):
        return self._euid

    def which(self, *candidates):
        return candidates[0]

    def user(self, name):
        return self.users.get(name)

    def chown(self, p, uid, gid):
        self.chowns.append((p, uid, gid))

    def proc_uid(self, pid):
        return self.comes_up_as

    def sleep(self, seconds):
        pass

    def run(self, argv):
        self.commands.append(argv)
        if argv[0].endswith("useradd"):
            self.users[argv[-1]] = (SVC_UID, SVC_UID)
            return 0, ""
        if argv[:2] == ["systemctl", "show"]:
            sub = "running" if self.state == "active" else "dead"
            return 0, (f"ActiveState={self.state}\nSubState={sub}\nMainPID=4242\n"
                       f"NRestarts={self.restarts}\n")
        if argv[:2] == ["systemctl", "restart"]:
            self.state = "active"
        return 0, ""


def _tree(tmp_path: Path, unit: str = OLD_UNIT, ping: str = "0\t2147483647\n",
          binary: bytes = b"\x7fELF fake") -> Path:
    root = tmp_path / "root"
    for d in ("run/systemd/system", "etc/systemd/system", "opt/danbyte-outpost",
              "proc/sys/net/ipv4", "etc/danbyte-outpost"):
        (root / d).mkdir(parents=True, exist_ok=True)
    for d in root.rglob("*"):
        d.chmod(0o755)
    root.chmod(0o755)
    (root / "etc/danbyte-outpost").chmod(0o700)
    (root / UNIT.lstrip("/")).write_text(unit)
    b = root / BIN.lstrip("/")
    b.write_bytes(binary)
    b.chmod(0o755)
    (root / "proc/sys/net/ipv4/ping_group_range").write_text(ping)
    return root


def _main(host, out, **kw):
    kw.setdefault("self_paths", [])
    return su.main(host=host, out=out.append, settle=3, **kw)


def _ran(host, *prefix):
    return [c for c in host.commands if c[:len(prefix)] == list(prefix)]


def test_the_rewrite_keeps_the_unit_and_sets_the_user():
    new = su.rewrite_unit(OLD_UNIT, "danbyte-outpost", "/opt/danbyte-outpost")
    s = su.service_settings(new)
    assert s["User"] == ["danbyte-outpost"] and s["Group"] == ["danbyte-outpost"]
    assert s["ExecStart"] == ["/opt/danbyte-outpost/danbyte-outpost run --insecure"]
    assert s["Environment"] == ["OUTPOST_NMAP_BINARY=/usr/bin/nmap"]
    assert s["EnvironmentFile"] == ["/etc/danbyte-outpost/env"]
    assert s["CapabilityBoundingSet"] == [""] and s["AmbientCapabilities"] == [""]
    assert s["NoNewPrivileges"] == ["yes"]
    assert s["ReadWritePaths"] == ["/opt/danbyte-outpost"]
    assert "[Install]\nWantedBy=multi-user.target" in new
    # Doing it twice gives the same unit; an explicit User=root is replaced.
    assert su.rewrite_unit(new, "danbyte-outpost", "/opt/danbyte-outpost") == new
    rooted = OLD_UNIT.replace("Restart=always", "User=root\nRestart=always")
    assert su.service_settings(su.rewrite_unit(rooted, "x"))["User"] == ["x"]
    with pytest.raises(su.MigrationError):
        su.rewrite_unit("[Unit]\nDescription=x\n", "x")


def test_exec_binary_strips_the_prefixes():
    assert su.exec_binary("-/opt/x/danbyte-outpost run") == "/opt/x/danbyte-outpost"
    assert su.exec_binary("") == ""


def test_dry_run_prints_the_plan_and_changes_nothing(tmp_path):
    root = _tree(tmp_path)
    host = FakeHost(root, euid=1000)  # a dry run needs no root
    out: list[str] = []
    assert _main(host, out, dry_run=True) == 0
    assert any("create the system user danbyte-outpost" in line for line in out)
    assert any("self-update" in line for line in out)
    assert out[-1] == "migrate: dry run, nothing was changed."
    assert (root / UNIT.lstrip("/")).read_text() == OLD_UNIT
    assert host.chowns == [] and not _ran(host, "/usr/sbin/useradd")
    assert not _ran(host, "systemctl", "restart")


def test_without_root_it_refuses_to_change_anything(tmp_path):
    root = _tree(tmp_path)
    host = FakeHost(root, euid=1000)
    out: list[str] = []
    assert _main(host, out) == 1
    assert any("as root" in line for line in out)
    assert (root / UNIT.lstrip("/")).read_text() == OLD_UNIT


def test_it_migrates_a_root_install_and_watches_the_restart(tmp_path):
    root = _tree(tmp_path)
    (root / (BIN + ".new").lstrip("/")).write_bytes(b"half an update")
    host = FakeHost(root)
    out: list[str] = []
    assert _main(host, out) == 0, out
    assert _ran(host, "/usr/sbin/useradd")[0][-1] == "danbyte-outpost"
    assert "--shell" in _ran(host, "/usr/sbin/useradd")[0]
    new = (root / UNIT.lstrip("/")).read_text()
    assert su.service_settings(new)["User"] == ["danbyte-outpost"]
    backup = root / "etc/danbyte-outpost/danbyte-outpost.service.root-backup"
    assert backup.read_text() == OLD_UNIT
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600
    assert host.chowns == [(BIN, SVC_UID, SVC_UID),
                           ("/opt/danbyte-outpost", SVC_UID, SVC_UID)]
    assert not (root / (BIN + ".new").lstrip("/")).exists()
    assert _ran(host, "systemctl", "daemon-reload")
    assert _ran(host, "systemctl", "restart", "danbyte-outpost.service")
    assert any("runs as danbyte-outpost" in line for line in out)
    # Again: nothing to do, nothing run.
    host2 = FakeHost(root, user_exists=True)
    out2: list[str] = []
    assert _main(host2, out2) == 0
    assert "already runs as danbyte-outpost" in out2[-1]
    assert host2.commands == [] and host2.chowns == []


def test_a_service_that_does_not_come_up_as_the_user_is_rolled_back(tmp_path):
    root = _tree(tmp_path)
    host = FakeHost(root, user_exists=True, comes_up_as=0)
    out: list[str] = []
    assert _main(host, out) == 1
    assert (root / UNIT.lstrip("/")).read_text() == OLD_UNIT
    own = os.getuid()
    assert host.chowns[-2:] == [("/opt/danbyte-outpost", own, own), (BIN, own, own)]
    assert len(_ran(host, "systemctl", "restart")) == 2  # the try, and back
    assert any("rolled back" in line for line in out)
    assert any("not 64990" in line for line in out)


def test_a_service_that_keeps_restarting_is_rolled_back(tmp_path):
    root = _tree(tmp_path)
    host = FakeHost(root, user_exists=True)
    real_run = host.run

    def flapping(argv):
        if argv[:2] == ["systemctl", "show"] and _ran(host, "systemctl", "restart"):
            host.restarts += 1
        return real_run(argv)

    host.run = flapping
    out: list[str] = []
    assert _main(host, out) == 1
    assert (root / UNIT.lstrip("/")).read_text() == OLD_UNIT
    assert any("restarted while it was watched" in line for line in out)


def test_a_stopped_service_is_migrated_and_left_stopped(tmp_path):
    root = _tree(tmp_path)
    host = FakeHost(root, active=False, user_exists=True)
    out: list[str] = []
    assert _main(host, out) == 0
    assert not _ran(host, "systemctl", "restart")
    assert any("left stopped" in line for line in out)


def test_root_never_runs_a_program_someone_else_can_change(tmp_path):
    root = _tree(tmp_path)
    me = root / "opt/danbyte-outpost/danbyte-outpost"
    me.chmod(0o777)
    host = FakeHost(root)
    out: list[str] = []
    assert _main(host, out, self_paths=[BIN]) == 1
    assert any("Refusing to run as root" in line for line in out)
    assert (root / UNIT.lstrip("/")).read_text() == OLD_UNIT
    assert host.chowns == [] and not _ran(host, "/usr/sbin/useradd")
    assert not _ran(host, "systemctl", "restart")


def test_root_unsafe_checks_every_directory_above(tmp_path):
    root = _tree(tmp_path)
    host = FakeHost(root)
    assert su.root_unsafe(host, BIN) == ""
    (root / "opt").chmod(0o777)
    assert "opt" in su.root_unsafe(host, BIN)
    (root / "opt").chmod(0o755)
    # A sticky directory of root's (like /tmp) is fine.
    (root / "opt").chmod(0o1777)
    assert su.root_unsafe(host, BIN) == ""
    (root / "opt").chmod(0o755)
    # A link is judged by its directory and by what it points to.
    link = root / "usr/bin/danbyte-outpost"
    link.parent.mkdir(parents=True)
    link.parent.chmod(0o755)
    (root / "usr").chmod(0o755)
    link.symlink_to(root / BIN.lstrip("/"))
    assert su.root_unsafe(host, "/usr/bin/danbyte-outpost") == ""
    (root / BIN.lstrip("/")).chmod(0o777)
    assert "danbyte-outpost" in su.root_unsafe(host, "/usr/bin/danbyte-outpost")


def test_a_ping_range_that_leaves_the_user_out_stops_it(tmp_path):
    root = _tree(tmp_path, ping="0\t0\n")
    host = FakeHost(root)
    out: list[str] = []
    assert _main(host, out) == 1
    assert any("ping_group_range" in line for line in out)
    assert not _ran(host, "/usr/sbin/useradd")
    out = []
    assert _main(FakeHost(root), out, ignore_icmp=True) == 0, out


def test_a_drop_in_that_sets_the_user_stops_it(tmp_path):
    root = _tree(tmp_path)
    d = root / "etc/systemd/system/danbyte-outpost.service.d"
    d.mkdir()
    (d / "override.conf").write_text("[Service]\nUser=root\n")
    out: list[str] = []
    assert _main(FakeHost(root), out) == 1
    assert any("override.conf sets User" in line for line in out)


def test_a_python_package_install_keeps_its_root_owned_files(tmp_path):
    unit = OLD_UNIT.replace("/opt/danbyte-outpost/danbyte-outpost run",
                            "/opt/danbyte-outpost/venv/bin/danbyte-outpost run")
    root = _tree(tmp_path, unit=unit)
    venv = root / "opt/danbyte-outpost/venv/bin"
    venv.mkdir(parents=True)
    py = venv / "python3"
    py.write_bytes(b"\x7fELF python")
    py.chmod(0o755)
    script = venv / "danbyte-outpost"
    script.write_text("#!/opt/danbyte-outpost/venv/bin/python3\nprint()\n")
    script.chmod(0o755)
    host = FakeHost(root, user_exists=True)
    out: list[str] = []
    assert _main(host, out) == 0, out
    assert host.chowns == []
    assert "ReadWritePaths" not in su.service_settings(
        (root / UNIT.lstrip("/")).read_text())
    assert any("Python package" in line for line in out)
    # ... and one the service user could not even start is refused.
    script.chmod(0o700)
    root2 = _tree(tmp_path / "b", unit=unit)
    (root2 / "opt/danbyte-outpost/venv/bin").mkdir(parents=True)
    s2 = root2 / "opt/danbyte-outpost/venv/bin/danbyte-outpost"
    s2.write_text("#!/usr/bin/python3\n")
    s2.chmod(0o700)
    out = []
    assert _main(FakeHost(root2, user_exists=True), out) == 1
    assert any("could not start it" in line for line in out)


def test_no_unit_or_no_systemd_is_explained(tmp_path):
    root = _tree(tmp_path)
    (root / UNIT.lstrip("/")).unlink()
    out: list[str] = []
    assert _main(FakeHost(root), out) == 1
    assert any("Re-run the installer" in line for line in out)
    (root / "run/systemd/system").rmdir()
    out = []
    assert _main(FakeHost(root), out) == 1
    assert any("does not run systemd" in line for line in out)


def test_the_cli_passes_its_flags(monkeypatch):
    seen = {}
    monkeypatch.setattr(su, "main", lambda **kw: seen.update(kw) or 0)
    assert run_mod.main(["migrate-service-user", "--dry-run", "--ignore-icmp"]) == 0
    assert seen["dry_run"] is True and seen["ignore_icmp"] is True
    assert seen["user"] == "danbyte-outpost"
    assert seen["unit"] == "danbyte-outpost.service"
    assert seen["settle"] == su.SETTLE_SECONDS


def test_a_bad_user_name_is_refused(tmp_path):
    out: list[str] = []
    assert _main(FakeHost(_tree(tmp_path)), out, user="root") == 1
    assert _main(FakeHost(_tree(tmp_path / "b")), out, user="Bad;name") == 1


def test_the_reference_unit_carries_the_same_block():
    text = (Path(__file__).resolve().parent.parent / "deploy/danbyte-outpost.service")
    s = su.service_settings(text.read_text())
    assert s["User"] == ["danbyte-outpost"]
    for key, value in su.HARDENING:
        assert s.get(key) == [value], key
