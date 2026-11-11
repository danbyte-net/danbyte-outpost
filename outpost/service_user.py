"""``danbyte-outpost migrate-service-user``: move a root-run Outpost service
to an unprivileged system user.

Installs made before agent 0.10 run the systemd unit as root. A self-update
replaces only the binary, so an Outpost that updated itself still runs as
root. It keeps working that way (and says so); this command, run by an
administrator with sudo, moves it over:

1. Checks everything first and changes nothing when a check fails: root,
   systemd, the unit and its ``ExecStart``, that this program itself is a
   file only root can change (root must never run a file the service user
   can write), drop-ins that would override the user, that the service user
   may open ICMP datagram sockets (``net.ipv4.ping_group_range``) and read
   and run the installed program.
2. Creates the system user (no login shell, no home) when it is missing.
3. Backs up the unit, rewrites only its ``[Service]`` section (``User=``,
   ``Group=``, an empty capability set and hardening; everything else in the
   unit is kept), and for the single-file binary hands its directory to the
   service user so self-update keeps working.
4. Reloads systemd, restarts the service and watches it: running, as the
   service user, not restarting. Anything else is rolled back - the old
   unit, the old ownership - and the service is restarted as before.

``--dry-run`` prints the plan and stops. A second run on a migrated unit
does nothing. The agent itself never runs this: it does not escalate and
never rewrites a root-owned file on its own.
"""
from __future__ import annotations

import os
import pwd
import re
import stat
import subprocess
import sys
import time
from dataclasses import dataclass, field

from . import privilege

UNIT_DIR = "/etc/systemd/system"
DEFAULT_UNIT = "danbyte-outpost.service"
BACKUP_DIR = "/etc/danbyte-outpost"
NOLOGIN = ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false")
#: The gids ``useradd --system`` hands out on common distributions.
SYSTEM_GIDS = (100, 999)
SETTLE_SECONDS = 20
_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,30}$")

#: The [Service] lines a migrated (and a freshly installed) unit carries.
#: The installer served by Danbyte writes the same block.
HARDENING = (
    ("NoNewPrivileges", "yes"),
    ("CapabilityBoundingSet", ""),
    ("AmbientCapabilities", ""),
    ("ProtectSystem", "strict"),
    ("ProtectHome", "read-only"),
    ("PrivateTmp", "yes"),
    ("PrivateDevices", "yes"),
    ("ProtectKernelTunables", "yes"),
    ("ProtectKernelModules", "yes"),
    ("ProtectKernelLogs", "yes"),
    ("ProtectControlGroups", "yes"),
    ("ProtectClock", "yes"),
    ("ProtectHostname", "yes"),
    ("RestrictSUIDSGID", "yes"),
    ("RestrictNamespaces", "yes"),
    ("RestrictRealtime", "yes"),
    ("LockPersonality", "yes"),
    ("RestrictAddressFamilies", "AF_INET AF_INET6 AF_UNIX AF_NETLINK"),
    ("UMask", "0077"),
)
MARK = "# Runs as an unprivileged user (danbyte-outpost migrate-service-user)."
_MANAGED = {k for k, _v in HARDENING} | {"User", "Group", "DynamicUser", "ReadWritePaths"}


class MigrationError(Exception):
    pass


# ─── the unit file ───────────────────────────────────────────────────────────


def service_settings(text: str) -> dict[str, list[str]]:
    """The ``[Service]`` keys of a unit, every value in order."""
    out: dict[str, list[str]] = {}
    section = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        if section == "Service" and "=" in line:
            key, value = line.split("=", 1)
            out.setdefault(key.strip(), []).append(value.strip())
    return out


def exec_binary(exec_start: str) -> str:
    """The program of an ``ExecStart=`` value (its ``-@+!:`` prefixes off)."""
    value = exec_start.strip().lstrip("-@+!:")
    return value.split()[0] if value.split() else ""


def hardening_lines(user: str, writable: str = "") -> list[str]:
    lines = [MARK, f"User={user}", f"Group={user}"]
    if writable:
        # Self-update writes the new binary next to the old one.
        lines.append(f"ReadWritePaths={writable}")
    lines += [f"{k}={v}" for k, v in HARDENING]
    return lines


def rewrite_unit(text: str, user: str, writable: str = "") -> str:
    """``text`` with its [Service] section running as ``user``. Every line
    outside the keys this sets is kept as it was."""
    lines = text.splitlines()
    out: list[str] = []
    section = ""
    seen_service = False

    def close_service():
        while out and not out[-1].strip():
            out.pop()
        out.extend(hardening_lines(user, writable))

    for raw in lines:
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            if section == "Service":
                close_service()
            section = line[1:-1]
            seen_service = seen_service or section == "Service"
            out.append(raw)
            continue
        if section == "Service":
            if line == MARK:
                continue
            if "=" in line and not line.startswith(("#", ";")) \
                    and line.split("=", 1)[0].strip() in _MANAGED:
                continue
        out.append(raw)
    if section == "Service":
        close_service()
    if not seen_service:
        raise MigrationError("The unit has no [Service] section.")
    return "\n".join(out) + "\n"


# ─── the host (injectable for tests) ─────────────────────────────────────────


class Host:
    """Everything the migration does to the machine. ``root`` prefixes every
    path, so tests run it against a directory."""

    def __init__(self, root: str = "/", root_uid: int = 0):
        self.root = root
        #: Who "root" is: 0, or the test's own uid against a directory.
        self.root_uid = root_uid

    def path(self, p: str) -> str:
        return os.path.join(self.root, p.lstrip("/")) if self.root != "/" else p

    def euid(self) -> int:
        return os.geteuid()

    def run(self, argv: list[str]) -> tuple[int, str]:
        try:
            p = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                               text=True, timeout=120, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            return 127, str(exc)
        return p.returncode, (p.stdout or "") + (p.stderr or "")

    def which(self, *candidates: str) -> str:
        for c in candidates:
            if os.access(self.path(c), os.X_OK):
                return c
        return ""

    def user(self, name: str) -> tuple[int, int] | None:
        try:
            pw = pwd.getpwnam(name)
        except KeyError:
            return None
        return pw.pw_uid, pw.pw_gid

    def chown(self, p: str, uid: int, gid: int) -> None:
        os.chown(self.path(p), uid, gid, follow_symlinks=False)

    def proc_uid(self, pid: int) -> int | None:
        try:
            with open(f"/proc/{pid}/status", encoding="ascii", errors="replace") as f:
                for line in f:
                    if line.startswith("Uid:"):
                        return int(line.split()[1])
        except (OSError, ValueError, IndexError):
            return None
        return None

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


# ─── the plan ────────────────────────────────────────────────────────────────


@dataclass
class Plan:
    unit: str
    user: str
    text: str = ""
    binary: str = ""
    #: The binary's directory handed to the service user ("" = left alone).
    selfupdate_dir: str = ""
    user_exists: bool = False
    uid: int = -1
    gid: int = -1
    was_active: bool = False
    already: str = ""
    steps: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _writable_by_others(st, root_uid: int) -> bool:
    # A link cannot be changed in place, only replaced through its directory
    # (checked on its own), and what it points to is checked too.
    if stat.S_ISLNK(st.st_mode):
        return False
    if st.st_uid != root_uid:
        return True
    if not st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return False
    # A sticky directory of root's (/tmp): others cannot replace root's files.
    return not (stat.S_ISDIR(st.st_mode) and st.st_mode & stat.S_ISVTX)


def _chain(host: Host, p: str) -> list[str]:
    """``p`` and every directory above it, inside the host's root."""
    top = os.path.normpath(host.path("/"))
    out: list[str] = []
    while True:
        if top != "/" and (p == top or not p.startswith(top + "/")):
            return out
        out.append(p)
        parent = os.path.dirname(p)
        if parent == p:
            return out
        p = parent


def root_unsafe(host: Host, path: str) -> str:
    """Why root must not run ``path`` ("" when only root can change it, the
    directories above it and, for a link, what it points to)."""
    given = host.path(path)
    for p in dict.fromkeys(_chain(host, given) + _chain(host, os.path.realpath(given))):
        try:
            st = os.lstat(p)
        except OSError:
            return f"{p} cannot be read"
        if _writable_by_others(st, host.root_uid):
            return f"{p} can be changed by a user other than root"
    return ""


def _others_can_run(host: Host, path: str) -> str:
    """Why a non-root user cannot run ``path`` ("" when it can)."""
    p = host.path(path)
    try:
        st = os.stat(p)
    except OSError:
        return f"{path} does not exist"
    if not st.st_mode & stat.S_IXOTH or not st.st_mode & stat.S_IROTH:
        return f"{path} is not readable and executable by other users"
    return _enterable(host, os.path.dirname(path))


def _enterable(host: Host, d: str) -> str:
    """Why other users cannot reach into ``d`` ("" when they can)."""
    while d and d != "/":
        try:
            if not os.stat(host.path(d)).st_mode & stat.S_IXOTH:
                return f"{d} cannot be entered by other users"
        except OSError:
            return f"{d} does not exist"
        d = os.path.dirname(d)
    return ""


def _shebang(host: Host, path: str) -> str:
    try:
        with open(host.path(path), "rb") as f:
            head = f.read(256)
    except OSError:
        return ""
    if not head.startswith(b"#!"):
        return ""
    return head[2:].split(b"\n", 1)[0].decode("utf-8", "replace").strip().split(" ")[0]


def _is_elf(host: Host, path: str) -> bool:
    try:
        with open(host.path(path), "rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def _drop_in_overrides(host: Host, unit: str) -> list[str]:
    d = host.path(f"{UNIT_DIR}/{unit}.d")
    found = []
    try:
        names = sorted(os.listdir(d))
    except OSError:
        return []
    for name in names:
        if not name.endswith(".conf"):
            continue
        try:
            with open(os.path.join(d, name), encoding="utf-8", errors="replace") as f:
                keys = service_settings("[Service]\n" + f.read())
        except OSError:
            continue
        hit = sorted(k for k in keys if k in ("User", "Group", "DynamicUser",
                                              "AmbientCapabilities", "CapabilityBoundingSet"))
        if hit:
            found.append(f"{unit}.d/{name} sets {', '.join(hit)}")
    return found


def _service_props(host: Host, unit: str) -> dict[str, str]:
    rc, out = host.run(["systemctl", "show", unit, "-p", "ActiveState", "-p", "SubState",
                        "-p", "MainPID", "-p", "NRestarts"])
    props = {}
    if rc == 0:
        for line in out.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                props[k.strip()] = v.strip()
    return props


def make_plan(host: Host, *, user: str = privilege.SERVICE_USER, unit: str = DEFAULT_UNIT,
              dry_run: bool = False, ignore_icmp: bool = False,
              self_paths: list[str] | None = None, settle: float = SETTLE_SECONDS) -> Plan:
    """Check everything and say what would change. Changes nothing."""
    plan = Plan(unit=f"{UNIT_DIR}/{unit}", user=user)
    if not _USER_RE.match(user) or user == "root":
        plan.errors.append(f"{user!r} is not a usable service user name.")
        return plan
    if host.euid() != 0 and not dry_run:
        plan.errors.append("Run it as root (sudo), or add --dry-run to only look.")
    if not os.path.isdir(host.path("/run/systemd/system")):
        plan.errors.append("This host does not run systemd; set the service user in "
                           "whatever starts the agent.")
        return plan
    try:
        with open(host.path(plan.unit), encoding="utf-8") as f:
            plan.text = f.read()
    except OSError:
        plan.errors.append(f"No unit at {plan.unit}. Re-run the installer from Danbyte "
                           "for a fresh install.")
        return plan
    settings = service_settings(plan.text)
    current = (settings.get("User") or [""])[-1]
    if (settings.get("DynamicUser") or ["no"])[-1].lower() in ("yes", "true", "1", "on"):
        plan.already = "a dynamic user"
    elif current and current not in ("root", "0"):
        plan.already = current
    if plan.already:
        return plan
    exec_start = (settings.get("ExecStart") or [""])[-1]
    plan.binary = exec_binary(exec_start)
    if not plan.binary.startswith("/"):
        plan.errors.append(f"Cannot read the program from ExecStart={exec_start!r}.")
        return plan

    # Root runs this program: refuse when anyone else could have changed it.
    for p in self_paths if self_paths is not None else _self_paths():
        why = root_unsafe(host, p)
        if why:
            plan.errors.append(f"Refusing to run as root: {why}. Re-run the installer "
                               "from Danbyte instead.")
    for d in _drop_in_overrides(host, unit):
        plan.errors.append(f"A drop-in would override the user: {d}. Remove it first.")

    known = host.user(user)
    if known:
        plan.user_exists, (plan.uid, plan.gid) = True, known
        if plan.uid == 0:
            plan.errors.append(f"The user {user} exists with uid 0.")
    rng = privilege.ping_range(host.path(privilege.PING_GROUP_RANGE))
    gids = [plan.gid] if known else list(SYSTEM_GIDS)
    covered = rng is not None and all(rng[0] <= g <= rng[1] for g in gids)
    if rng is not None and not covered:
        msg = (f"net.ipv4.ping_group_range is {rng[0]} {rng[1]}, which does not cover "
               f"{'gid ' + str(plan.gid) if known else 'the system gids'}: ICMP checks would "
               "report unknown. Widen it, e.g. in /etc/sysctl.d/60-danbyte-outpost.conf: "
               "net.ipv4.ping_group_range = 0 2147483647")
        (plan.notes if ignore_icmp else plan.errors).append(
            msg + ("" if ignore_icmp else " (or pass --ignore-icmp)."))

    # The single-file binary updates itself: its directory goes to the user.
    bindir = os.path.dirname(plan.binary)
    try:
        bst = os.lstat(host.path(plan.binary))
        dst = os.lstat(host.path(bindir))
    except OSError:
        plan.errors.append(f"{plan.binary} does not exist.")
        return plan
    if not stat.S_ISREG(bst.st_mode):
        plan.notes.append(f"{plan.binary} is not a regular file: self-update stays off.")
    elif not _is_elf(host, plan.binary):
        plan.notes.append("Installed from a Python package: update it by re-running the "
                          "installer from Danbyte.")
    elif os.path.basename(bindir) != "danbyte-outpost" or not stat.S_ISDIR(dst.st_mode):
        plan.notes.append(f"{bindir} is not a directory of its own: it stays root's and "
                          "self-update stays off.")
    elif dst.st_uid != host.root_uid or bst.st_uid != host.root_uid:
        plan.errors.append(f"{bindir} is not owned by root; check who changed it.")
    else:
        plan.selfupdate_dir = bindir
    if not plan.selfupdate_dir:
        for p in (plan.binary, _shebang(host, plan.binary)):
            why = p and _others_can_run(host, p)
            if why:
                plan.errors.append(f"The service user could not start it: {why}.")
    else:
        why = _enterable(host, os.path.dirname(bindir))
        if why:
            plan.errors.append(f"The service user could not start it: {why}.")

    props = _service_props(host, unit)
    plan.was_active = props.get("ActiveState") in ("active", "activating", "reloading")
    if not plan.user_exists:
        plan.steps.append(f"create the system user {user} (no login shell, no home)")
    plan.steps.append(f"back up {plan.unit} to {BACKUP_DIR}/")
    plan.steps.append(f"rewrite [Service] in {plan.unit}: User={user}, Group={user}, no "
                      "capabilities, hardening")
    if plan.selfupdate_dir:
        plan.steps.append(f"give {plan.selfupdate_dir} and {plan.binary} to {user} "
                          "(self-update)")
    plan.steps.append("systemctl daemon-reload")
    if plan.was_active:
        plan.steps.append(f"restart {unit}, watch it for {int(settle)} s, roll back if "
                          "it does not stay up as the new user")
    else:
        plan.notes.append(f"{unit} is not running; it is left stopped.")
    return plan


def _self_paths() -> list[str]:
    paths = [privilege.own_executable()]
    if not getattr(sys, "frozen", False):
        paths += [sys.executable, os.path.dirname(os.path.abspath(__file__))]
    return [p for p in paths if p]


# ─── doing it ────────────────────────────────────────────────────────────────


def _write_atomic(path: str, text: str, mode: int = 0o644) -> None:
    tmp = f"{path}.tmp-{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _backup(host: Host, plan: Plan) -> str:
    d = host.path(BACKUP_DIR)
    os.makedirs(d, mode=0o700, exist_ok=True)
    name = os.path.join(d, os.path.basename(plan.unit) + ".root-backup")
    try:
        with open(name, encoding="utf-8") as f:
            if f.read() == plan.text:
                return name
        name = f"{name}.{int(time.time())}"
    except OSError:
        pass
    _write_atomic(name, plan.text, 0o600)
    return name


def healthy(host: Host, unit: str, uid: int, settle: float, out=print) -> tuple[bool, str]:
    """Whether ``unit`` came up and stays up as ``uid`` for ``settle`` s."""
    base = _service_props(host, unit).get("NRestarts", "")
    waited = 0.0
    while True:
        props = _service_props(host, unit)
        if props.get("ActiveState") == "failed":
            return False, "the service failed"
        if waited >= settle:
            break
        host.sleep(1)
        waited += 1
    if props.get("ActiveState") != "active" or props.get("SubState") != "running":
        return False, f"the service is {props.get('ActiveState')}/{props.get('SubState')}"
    if base and props.get("NRestarts") != base:
        return False, "the service restarted while it was watched"
    try:
        pid = int(props.get("MainPID") or 0)
    except ValueError:
        pid = 0
    if pid <= 0:
        return False, "the service has no main process"
    running_as = host.proc_uid(pid)
    if running_as != uid:
        return False, f"the service runs as uid {running_as}, not {uid}"
    return True, ""


def apply(host: Host, plan: Plan, *, settle: float = SETTLE_SECONDS, out=print) -> int:
    """Carry the plan out; roll back what was changed when anything fails."""
    unit = os.path.basename(plan.unit)
    if not plan.user_exists:
        shell = host.which(*NOLOGIN) or "/bin/false"
        useradd = host.which("/usr/sbin/useradd", "/sbin/useradd")
        if not useradd:
            out("migrate: useradd is not installed; create the user yourself and re-run.")
            return 1
        rc, msg = host.run([useradd, "--system", "--user-group", "--no-create-home",
                            "--home-dir", "/nonexistent", "--shell", shell, plan.user])
        known = host.user(plan.user)
        if rc != 0 or not known:
            out(f"migrate: could not create {plan.user}: {msg.strip()[:300]}")
            return 1
        plan.uid, plan.gid = known
        out(f"migrate: created the system user {plan.user} (uid {plan.uid})")
        rng = privilege.ping_range(host.path(privilege.PING_GROUP_RANGE))
        if privilege.icmp_allowed([plan.gid], rng) is False and not any(
                "ping_group_range" in n for n in plan.notes):
            out(f"migrate: gid {plan.gid} is outside net.ipv4.ping_group_range; nothing "
                "else was changed. Widen the range (or pass --ignore-icmp) and re-run.")
            return 1

    unit_path = host.path(plan.unit)
    owners: list[tuple[str, int, int, int]] = []  # path, uid, gid, mode
    written = False
    try:
        backup = _backup(host, plan)
        out(f"migrate: saved the old unit as {backup}")
        _write_atomic(unit_path, rewrite_unit(plan.text, plan.user, plan.selfupdate_dir))
        written = True
        if plan.selfupdate_dir:
            stale = host.path(plan.binary + ".new")
            if os.path.lexists(stale):
                os.unlink(stale)
            for p in (plan.binary, plan.selfupdate_dir):
                st = os.lstat(host.path(p))
                owners.append((p, st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)))
                host.chown(p, plan.uid, plan.gid)
                os.chmod(host.path(p), 0o755)
        rc, msg = host.run(["systemctl", "daemon-reload"])
        if rc != 0:
            raise MigrationError(f"daemon-reload failed: {msg.strip()[:300]}")
        if plan.was_active:
            rc, msg = host.run(["systemctl", "restart", unit])
            if rc != 0:
                raise MigrationError(f"restart failed: {msg.strip()[:300]}")
            out(f"migrate: restarted {unit}; watching it for {int(settle)} s")
            ok, why = healthy(host, unit, plan.uid, settle, out=out)
            if not ok:
                raise MigrationError(why)
    except (OSError, MigrationError) as exc:
        out(f"migrate: {exc}; rolling back")
        _rollback(host, plan, owners, written, out=out)
        out(f"migrate: rolled back. See: journalctl -u {unit} -n 50")
        return 1
    out(f"migrate: {unit} runs as {plan.user}." + (
        "" if plan.was_active else " It was stopped and is left stopped."))
    if plan.selfupdate_dir:
        out(f"migrate: {plan.selfupdate_dir} now belongs to {plan.user}; do not run "
            "the program in it with sudo again (re-run the installer instead).")
    return 0


def _rollback(host: Host, plan: Plan, owners, written: bool, out=print) -> None:
    unit = os.path.basename(plan.unit)
    for p, uid, gid, mode in reversed(owners):
        try:
            host.chown(p, uid, gid)
            os.chmod(host.path(p), mode)
        except OSError as exc:
            out(f"migrate: could not restore {p}: {exc}")
    if written:
        try:
            _write_atomic(host.path(plan.unit), plan.text)
        except OSError as exc:
            out(f"migrate: could not restore {plan.unit}: {exc} (the backup is in "
                f"{BACKUP_DIR})")
    host.run(["systemctl", "daemon-reload"])
    if plan.was_active:
        host.run(["systemctl", "restart", unit])


def main(*, user: str = privilege.SERVICE_USER, unit: str = DEFAULT_UNIT,
         dry_run: bool = False, ignore_icmp: bool = False, settle: float = SETTLE_SECONDS,
         host: Host | None = None, self_paths: list[str] | None = None, out=print) -> int:
    host = host or Host()
    if not unit.endswith(".service"):
        unit += ".service"
    plan = make_plan(host, user=user, unit=unit, dry_run=dry_run, ignore_icmp=ignore_icmp,
                     self_paths=self_paths, settle=settle)
    if plan.already:
        out(f"migrate: {unit} already runs as {plan.already}; nothing to do.")
        return 0
    for n in plan.notes:
        out(f"migrate: note: {n}")
    if plan.errors:
        for e in plan.errors:
            out(f"migrate: {e}")
        out("migrate: nothing was changed.")
        return 1
    out("migrate: plan:")
    for s in plan.steps:
        out(f"  - {s}")
    if dry_run:
        out("migrate: dry run, nothing was changed.")
        return 0
    return apply(host, plan, settle=settle, out=out)
