"""Run a check locally using the **shared** danbyte-checks engine.

The Outpost runs the *exact same* checker code as the Danbyte core (one package,
``danbyte_checks``), so a check gives identical results wherever it runs — no
drift. Every kind the core supports (ICMP/TCP/UDP/HTTP/SNMP/SSH/Telnet) works
here; the Django-only ``exec`` checker is intentionally not shipped to Outposts.
"""
from __future__ import annotations

from danbyte_checks import CheckOutcome, get_checker


async def run_check(check: dict) -> dict:
    """``check`` = {state_id, kind, target, params, secret_params, timeout_ms}.
    Returns {state_id, status, latency_ms, detail}."""
    out = {"state_id": check.get("state_id")}
    checker = get_checker(check.get("kind"))
    if checker is None:
        out.update(
            status="unknown",
            latency_ms=None,
            detail={"error": f"kind '{check.get('kind')}' not available on this Outpost"},
        )
        return out
    try:
        oc = await checker.run(
            check.get("target"),
            check.get("params") or {},
            check.get("secret_params") or {},
            int(check.get("timeout_ms") or 2000),
        )
    except Exception as e:  # never let one bad check kill the batch
        oc = CheckOutcome.unknown(str(e))
    out.update(status=oc.status, latency_ms=oc.latency_ms, detail=oc.detail or {})
    return out
