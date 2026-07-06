"""Subnet discovery on the Outpost — ICMP-sweep a prefix locally.

Runs the **shared** ``danbyte_checks.sweep.sweep_cidr`` (the same sweep the core
uses), off the event loop in a worker thread, and returns the live addresses for
the core to turn into IPs.
"""
from __future__ import annotations

import asyncio

from danbyte_checks.sweep import sweep_cidr


async def sweep_prefix(prefix: dict) -> dict:
    """``prefix`` = {prefix_id, cidr}. Returns {prefix_id, alive:[...]}."""
    alive = await asyncio.to_thread(sweep_cidr, prefix.get("cidr", ""))
    return {"prefix_id": prefix.get("prefix_id"), "alive": alive}
