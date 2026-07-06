"""Outpost entry point.

Phase 0 skeleton: validates config and prints where it would connect. The poll
loop (hello → work → run checkers → results) lands in Phase 1.
"""
from __future__ import annotations

import argparse
import asyncio
import sys

from . import __version__
from .config import Config, ConfigError, load


def _parse(argv: list[str]) -> tuple[str, dict]:
    """Return (command, overrides). Accepts a friendly one-liner:
    ``danbyte-outpost run --url=… --token=…`` (flags override the environment)."""
    p = argparse.ArgumentParser(prog="danbyte-outpost", add_help=True)
    p.add_argument(
        "command", nargs="?", default="run", choices=["run", "check", "once"]
    )
    p.add_argument("--url")
    p.add_argument("--token")
    p.add_argument("--poll", type=int)
    p.add_argument("--insecure", action="store_true", help="skip TLS verify (lab)")
    ns = p.parse_args(argv)
    overrides: dict = {}
    if ns.url:
        overrides["url"] = ns.url
    if ns.token:
        overrides["token"] = ns.token
    if ns.poll:
        overrides["poll"] = ns.poll
    if ns.insecure:
        overrides["verify_tls"] = False
    return ns.command, overrides


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    cmd, overrides = _parse(argv)

    # `once` is the SSH-transport entry point: Danbyte pipes work JSON on stdin
    # and reads results JSON on stdout — no URL/token needed (Danbyte drove in).
    if cmd == "once":
        return asyncio.run(_once())

    try:
        cfg = load(overrides)
    except ConfigError as e:
        print(f"outpost: {e}", file=sys.stderr)
        return 2

    if cmd == "check":
        return asyncio.run(_check(cfg))
    if cmd == "run":
        try:
            asyncio.run(_loop(cfg))
        except KeyboardInterrupt:
            print("outpost: stopped")
        return 0

    print(f"outpost: unknown command {cmd!r} (try: run, check)", file=sys.stderr)
    return 2


async def _once() -> int:
    """SSH transport: read work JSON from stdin, run the checks, write results
    JSON to stdout. stdout must stay clean (JSON only) — Danbyte parses it."""
    import json

    from .checks import run_check

    raw = sys.stdin.read()
    try:
        work = json.loads(raw or "{}").get("checks", [])
    except json.JSONDecodeError as e:
        print(json.dumps({"results": [], "error": f"bad work json: {e}"}))
        return 1
    results = (
        list(await asyncio.gather(*(run_check(c) for c in work))) if work else []
    )
    print(json.dumps({"results": results}))
    return 0


async def _check(cfg: Config) -> int:
    """One-shot: verify the token + print the assignment, then exit."""
    from .client import OutpostClient

    client = OutpostClient(cfg)
    try:
        info = await client.hello()
        print(f"Danbyte Outpost {__version__} — connected to {cfg.url}")
        print(f"  engine: {info.get('engine', {}).get('name')}")
        print(f"  assigned checks: {info.get('assigned_checks')}")
        print(f"  poll: every {info.get('poll_interval_seconds', cfg.poll_seconds)}s")
        return 0
    except Exception as e:  # noqa: BLE001 — friendly CLI error
        print(f"outpost: could not reach Danbyte — {e}", file=sys.stderr)
        return 1
    finally:
        await client.aclose()


async def _snmp_cycle(client, interval: int) -> int:
    """Pull SNMP discovery targets, fetch each locally, post results back.
    Returns the (possibly updated) interval. Isolated so it can't stall checks."""
    from .snmp import discover_device

    work = await client.fetch_snmp_work()
    devices = work.get("devices", [])
    interval = int(work.get("interval_seconds", interval)) or interval
    if devices:
        results = await asyncio.gather(*(discover_device(d) for d in devices))
        n = await client.post_snmp_results(list(results))
        print(f"outpost: snmp polled {len(devices)}, reported {n}")
    return interval


async def _sweep_cycle(client, interval: int) -> int:
    """Pull discovery prefixes, ICMP-sweep each locally, post live IPs back."""
    from .discover import sweep_prefix

    work = await client.fetch_sweep_work()
    prefixes = work.get("prefixes", [])
    interval = int(work.get("interval_seconds", interval)) or interval
    if prefixes:
        results = await asyncio.gather(*(sweep_prefix(p) for p in prefixes))
        n = await client.post_discovered(list(results))
        print(f"outpost: swept {len(prefixes)} prefix(es), created {n} IP(s)")
    return interval


async def _loop(cfg: Config) -> None:
    """Poll loop: hello, then repeatedly pull work → run checks → post results.
    SNMP discovery runs on its own (slower) cadence alongside the checks."""
    import time

    from .checks import run_check
    from .client import OutpostClient

    client = OutpostClient(cfg)
    poll = cfg.poll_seconds
    snmp_interval = 900
    sweep_interval = 600
    next_snmp = 0.0  # run one discovery pass right after startup
    next_sweep = 0.0
    hello_interval = 300
    next_hello = time.monotonic() + hello_interval
    try:
        try:
            info = await client.hello()
            poll = int(info.get("poll_interval_seconds", poll)) or poll
            print(f"Danbyte Outpost {__version__} online → {cfg.url} (poll {poll}s)")
            await _maybe_update(client, info)  # may replace the binary + exit
        except Exception as e:  # keep going; retry in the loop
            print(f"outpost: hello failed ({e}); retrying", file=sys.stderr)

        while True:
            try:
                work = await client.fetch_work()
                checks = work.get("checks", [])
                if checks:
                    results = await asyncio.gather(
                        *(run_check(c) for c in checks)
                    )
                    n = await client.post_results(list(results))
                    print(f"outpost: ran {len(checks)}, reported {n}")
                # A "Discover now" click → sweep on this cycle, not in 10 min.
                if work.get("sweep_pending"):
                    next_sweep = 0.0
            except Exception as e:  # transient — back off and retry
                print(f"outpost: poll error ({e})", file=sys.stderr)
                await asyncio.sleep(min(poll * 2, 60))
                continue

            if time.monotonic() >= next_snmp:
                try:
                    snmp_interval = await _snmp_cycle(client, snmp_interval)
                except Exception as e:  # SNMP trouble never blocks checks
                    print(f"outpost: snmp error ({e})", file=sys.stderr)
                next_snmp = time.monotonic() + snmp_interval

            if time.monotonic() >= next_sweep:
                try:
                    sweep_interval = await _sweep_cycle(client, sweep_interval)
                except Exception as e:  # sweep trouble never blocks checks
                    print(f"outpost: sweep error ({e})", file=sys.stderr)
                next_sweep = time.monotonic() + sweep_interval

            if time.monotonic() >= next_hello:
                try:
                    info = await client.hello()
                    await _maybe_update(client, info)  # may exit to restart
                except Exception as e:
                    print(f"outpost: hello error ({e})", file=sys.stderr)
                next_hello = time.monotonic() + hello_interval

            await asyncio.sleep(poll)
    finally:
        await client.aclose()


async def _maybe_update(client, info: dict) -> None:
    """If the core asked this (auto-updating) Outpost to move to a new golden
    version, do it — self_update replaces the binary and exits to restart."""
    from .updater import can_self_update, self_update

    target = info.get("update_to")
    if target and can_self_update():
        await self_update(client, target)


if __name__ == "__main__":
    raise SystemExit(main())
