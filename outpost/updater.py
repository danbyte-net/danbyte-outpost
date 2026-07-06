"""Agent self-update — swap the running binary for the golden release + restart.

Only the single-file binary can self-update (a pip/venv install is left to the
package manager). The core tells the agent, in the ``hello`` response, which
version to move to (``update_to``); this downloads it, atomically replaces the
running executable, and exits so systemd (``Restart=always``) relaunches on the
new binary.
"""
from __future__ import annotations

import os
import sys


def can_self_update() -> bool:
    """True only for the PyInstaller single-file binary."""
    return bool(getattr(sys, "frozen", False))


def _own_binary_path() -> str:
    try:
        return os.readlink("/proc/self/exe")
    except OSError:
        return sys.executable


async def self_update(client, version: str) -> bool:
    """Download ``version``'s binary, swap it in, and exit (systemd restarts).
    Returns False if it can't (not a frozen binary); otherwise never returns."""
    if not can_self_update():
        print(
            "outpost: update available but this isn't the binary install; "
            "update via your package manager",
            file=sys.stderr,
        )
        return False
    path = _own_binary_path()
    tmp = f"{path}.new"
    data = await client.download_binary(version)
    with open(tmp, "wb") as f:
        f.write(data)
    os.chmod(tmp, 0o755)
    # Atomic replace — the running process keeps the old inode until it exits.
    os.replace(tmp, path)
    print(f"outpost: updated to {version}; restarting", flush=True)
    os._exit(0)  # systemd Restart=always relaunches on the new binary
