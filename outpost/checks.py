"""Run a check locally using the **shared** danbyte-checks engine.

The Outpost runs the *exact same* checker code as the Danbyte core (one package,
``danbyte_checks``), so a check gives identical results wherever it runs — no
drift. Every kind the core supports (ICMP/TCP/UDP/HTTP/SNMP/SSH/Telnet) works
here; the Django-only ``exec`` checker is intentionally not shipped to Outposts.
"""
from __future__ import annotations

import sys

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


async def attach_ptrs(results: list, checks: list, dns: dict) -> list:
    """Fill in each result's ``detail["ptr"]`` when Danbyte asked us to.

    PTR is the one lookup whose right answer depends on where it is asked from.
    An Outpost usually sits where the target does, so it can see the DNS view
    the core server cannot - that is the whole point of resolving here.

    **The core keys on the presence of the field, not its value.** If we looked,
    we must always send ``ptr`` (empty string when the address has no PTR); if
    we did not, we must never send it, or our silence would be read as "this
    address has no name" and wipe names in Danbyte. So every failure path here
    leaves the key off and lets the core resolve centrally.
    """
    if not dns.get("resolve") or not results:
        return results
    from danbyte_checks.reverse_dns import ReverseDNSUnavailable, resolve_ptrs

    targets = [t for t in {c.get("target") for c in checks} if t]
    if not targets:
        return results
    try:
        found = await resolve_ptrs(targets, dns.get("resolvers") or ())
    except ReverseDNSUnavailable as e:
        # Configured resolvers we cannot honour. Never quietly fall back to this
        # machine's resolver - that would answer from the wrong place.
        print(f"outpost: reverse dns skipped ({e})", file=sys.stderr)
        return results
    except Exception as e:  # noqa: BLE001 - DNS must never cost us a result
        print(f"outpost: reverse dns failed ({e})", file=sys.stderr)
        return results

    by_state = {c.get("state_id"): c.get("target") for c in checks}
    for r in results:
        target = by_state.get(r.get("state_id"))
        if target in found:
            detail = r.get("detail") or {}
            detail["ptr"] = found[target] or ""
            r["detail"] = detail
    return results
