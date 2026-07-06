"""SNMP discovery on the Outpost — fetch a device's observed state locally.

Runs the **shared** ``danbyte_checks.snmp_facts.fetch_snmp`` (the exact function
the Danbyte core runs in ``poll_device``), so discovery gives identical results
wherever it happens. The fetch is blocking (pysnmp sync), so it's run in a worker
thread to stay off the event loop.
"""
from __future__ import annotations

import asyncio

from danbyte_checks.snmp_facts import fetch_snmp


async def discover_device(device: dict) -> dict:
    """``device`` = {device_id, target, version, params, secret_params,
    timeout_ms}. Returns the observed-state result with ``device_id`` attached,
    ready to POST back."""
    result = await asyncio.to_thread(
        fetch_snmp,
        device.get("target"),
        device.get("version"),
        device.get("params") or {},
        device.get("secret_params") or {},
        int(device.get("timeout_ms") or 2000),
    )
    result["device_id"] = device.get("device_id")
    return result
