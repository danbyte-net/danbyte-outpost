"""What the agent runs as, and the little it does about privileges itself.

The agent needs no privilege at all on Linux:

* ICMP uses unprivileged datagram sockets (``icmplib`` with
  ``privileged=False``); the kernel allows them for the groups in
  ``net.ipv4.ping_group_range``. No raw socket and no ``CAP_NET_RAW``.
* It binds no port: every transport dials out (or is driven in over SSH).
* It writes no file but its own binary on a self-update and the temporary
  directory nmap runs in.
* The only program it starts is the nmap an administrator installed, with
  ``--unprivileged -sT``.

So the service runs as a plain system user with an empty capability
bounding set. Root still works (an Outpost that self-updated from a root
install keeps running), but it says so in its log and in hello, and nmap
stays off.

:func:`clear_ambient_capabilities` is defence in depth for a unit someone
gave ``AmbientCapabilities=``: ambient capabilities are inherited across
``execve``, so without it nmap would start with them. Clearing the ambient
set changes nothing for the agent itself (it uses no capability) and only
affects the programs it starts.
"""
from __future__ import annotations

import os
import sys

#: The system user the installer and ``migrate-service-user`` create.
SERVICE_USER = "danbyte-outpost"
PING_GROUP_RANGE = "/proc/sys/net/ipv4/ping_group_range"

# prctl(2)
_PR_CAP_AMBIENT = 47
_PR_CAP_AMBIENT_CLEAR_ALL = 4


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def runtime() -> dict:
    """What hello says about how the agent runs (``capabilities.runtime``)."""
    return {"root": is_root()}


def root_warning(exe: str = "") -> str:
    exe = exe or own_executable() or "danbyte-outpost"
    return (
        "outpost: running as root. nmap stays off and the agent has more access "
        f"than it needs: run `sudo {exe} migrate-service-user` (or re-run the "
        "installer from Danbyte) to move it to an unprivileged service user"
    )


def own_executable() -> str:
    """The file this process runs from: the frozen binary, else the
    ``danbyte-outpost`` entry script (best effort)."""
    if getattr(sys, "frozen", False):
        try:
            return os.readlink("/proc/self/exe")
        except OSError:
            return sys.executable
    return os.path.abspath(sys.argv[0]) if sys.argv and sys.argv[0] else ""


def clear_ambient_capabilities() -> bool:
    """Empty this process's ambient capability set so nothing it starts
    inherits one. True when the set is empty afterwards (or the platform has
    none). Never raises."""
    if not sys.platform.startswith("linux"):
        return True
    try:
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl(_PR_CAP_AMBIENT, _PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)
    except (OSError, AttributeError):
        pass
    # A kernel before 4.3 has no ambient set: EINVAL, and nothing to clear.
    return ambient_capabilities() in (0, None)


def ambient_capabilities(status_path: str = "/proc/self/status") -> int | None:
    """The ``CapAmb`` mask of this process, None when it cannot be read."""
    try:
        with open(status_path, encoding="ascii", errors="replace") as f:
            for line in f:
                if line.startswith("CapAmb:"):
                    return int(line.split(":", 1)[1].strip(), 16)
    except (OSError, ValueError):
        return None
    return None


def parse_ping_group_range(text: str) -> tuple[int, int] | None:
    try:
        lo, hi = (int(x) for x in text.split())
    except ValueError:
        return None
    return lo, hi


def ping_range(path: str = PING_GROUP_RANGE) -> tuple[int, int] | None:
    try:
        with open(path, encoding="ascii") as f:
            return parse_ping_group_range(f.read())
    except OSError:
        return None


def icmp_allowed(gids, rng: tuple[int, int] | None) -> bool | None:
    """Whether a process with these groups may open an ICMP datagram socket
    (the kernel's check). None when the range is unknown."""
    if rng is None:
        return None
    lo, hi = rng
    return any(lo <= g <= hi for g in gids)


def own_groups() -> list[int]:
    try:
        return sorted({os.getegid(), *os.getgroups()})
    except (AttributeError, OSError):
        return []


def icmp_warning() -> str:
    """A log line when this process cannot ping, "" otherwise."""
    rng = ping_range()
    if icmp_allowed(own_groups(), rng) is False:
        return (
            f"outpost: net.ipv4.ping_group_range is {rng[0]} {rng[1]} and does not "
            "cover this agent's groups: ICMP checks and sweeps will report unknown. "
            "Widen it (sysctl net.ipv4.ping_group_range='0 2147483647')"
        )
    return ""
