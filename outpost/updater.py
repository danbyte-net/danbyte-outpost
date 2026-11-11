"""Agent self-update — swap the running binary for the golden release + restart.

Only the single-file binary can self-update (a pip/venv install is left to the
package manager). The core tells the agent, in the ``hello`` response, which
version to move to (``update_to``); this downloads it, atomically replaces the
running executable, and exits so systemd (``Restart=always``) relaunches on the
new binary.

The agent writes only where it may: as the service user that is the binary's
own directory, which the installer (or ``migrate-service-user``) hands to it.
When it cannot write there it says so once and keeps running the version it
has; it never asks for more privilege.
"""
from __future__ import annotations

import os
import sys

_warned = False


def can_self_update() -> bool:
    """True only for the PyInstaller single-file binary."""
    return bool(getattr(sys, "frozen", False))


def _own_binary_path() -> str:
    try:
        return os.readlink("/proc/self/exe")
    except OSError:
        return sys.executable


def writable(path: str) -> bool:
    """Whether this process may replace ``path`` (its directory is writable)."""
    return os.access(os.path.dirname(path) or ".", os.W_OK | os.X_OK)


def _write_new(tmp: str, data: bytes) -> None:
    # A leftover from an interrupted update is replaced; a link someone put
    # there is never followed.
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o755)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o755)


async def self_update(client, version: str) -> bool:
    """Download ``version``'s binary, swap it in, and exit (systemd restarts).
    Returns False if it can't (not a frozen binary, or its directory is not
    writable); otherwise never returns."""
    global _warned
    if not can_self_update():
        print(
            "outpost: update available but this isn't the binary install; "
            "update via your package manager",
            file=sys.stderr,
        )
        return False
    path = _own_binary_path()
    if not writable(path):
        if not _warned:
            print(
                f"outpost: update to {version} available but {os.path.dirname(path)} is "
                "not writable by this agent; re-run the installer from Danbyte",
                file=sys.stderr,
            )
            _warned = True
        return False
    tmp = f"{path}.new"
    data = await client.download_binary(version)
    _write_new(tmp, data)
    # Atomic replace — the running process keeps the old inode until it exits.
    os.replace(tmp, path)
    print(f"outpost: updated to {version}; restarting", flush=True)
    os._exit(0)  # systemd Restart=always relaunches on the new binary
