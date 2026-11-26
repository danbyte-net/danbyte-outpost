"""Outpost entry point: ``run`` (the poll loop), ``check``, ``once`` (the SSH
transport), ``migrate-service-user`` (moves a root-run service to an
unprivileged user; run by an administrator with sudo) and ``self-check``
(loads every library the agent uses, so a binary that can't run on this
host says so at once)."""
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
        "command", nargs="?", default="run",
        choices=["run", "check", "once", "migrate-service-user", "self-check"],
    )
    p.add_argument("--url")
    p.add_argument("--token")
    p.add_argument("--poll", type=int)
    p.add_argument("--insecure", action="store_true", help="skip TLS verify (lab)")
    p.add_argument("--nmap", help="absolute path of an nmap discovery may run")
    m = p.add_argument_group("migrate-service-user")
    m.add_argument("--dry-run", action="store_true", help="print the plan, change nothing")
    m.add_argument("--user", default="", help="service user (default danbyte-outpost)")
    m.add_argument("--unit", default="", help="unit (default danbyte-outpost.service)")
    m.add_argument("--ignore-icmp", action="store_true",
                   help="migrate although ping_group_range leaves ICMP off")
    m.add_argument("--settle", type=int, default=0,
                   help="seconds to watch the restarted service (default 20)")
    ns = p.parse_args(argv)
    overrides: dict = {}
    if ns.command == "migrate-service-user":
        return ns.command, {"dry_run": ns.dry_run, "user": ns.user, "unit": ns.unit,
                            "ignore_icmp": ns.ignore_icmp, "settle": ns.settle}
    if ns.url:
        overrides["url"] = ns.url
    if ns.token:
        overrides["token"] = ns.token
    if ns.poll:
        overrides["poll"] = ns.poll
    if ns.insecure:
        overrides["verify_tls"] = False
    if ns.nmap:
        overrides["nmap_binary"] = ns.nmap
    return ns.command, overrides


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    cmd, overrides = _parse(argv)

    # `once` is the SSH-transport entry point: Danbyte pipes work JSON on stdin
    # and reads results JSON on stdout — no URL/token needed (Danbyte drove in).
    if cmd == "once":
        return asyncio.run(_once())
    if cmd == "self-check":
        return _self_check()
    if cmd == "migrate-service-user":
        from . import service_user

        return service_user.main(
            user=overrides["user"] or service_user.privilege.SERVICE_USER,
            unit=overrides["unit"] or service_user.DEFAULT_UNIT,
            dry_run=overrides["dry_run"], ignore_icmp=overrides["ignore_icmp"],
            settle=overrides["settle"] or service_user.SETTLE_SECONDS)

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

    from . import privilege
    from .checks import attach_ptrs, run_check

    privilege.clear_ambient_capabilities()
    if privilege.is_root():
        # stderr: stdout carries the results only.
        print(privilege.root_warning(), file=sys.stderr)
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw or "{}")
    except json.JSONDecodeError as e:
        print(json.dumps({"results": [], "error": f"bad work json: {e}"}))
        return 1
    work = payload.get("checks", [])
    results = (
        list(await asyncio.gather(*(run_check(c) for c in work))) if work else []
    )
    results = await attach_ptrs(results, work, payload.get("dns") or {})
    # runtime: how the agent runs; a core that predates it reads results only.
    print(json.dumps({"results": results, "runtime": privilege.runtime()}))
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

    from . import discovery, privilege
    from .checks import attach_ptrs, run_check
    from .client import OutpostClient
    from .fast import FastRunner

    # Nothing the agent starts (nmap) inherits a capability the unit granted.
    privilege.clear_ambient_capabilities()
    if privilege.is_root():
        print(privilege.root_warning(), file=sys.stderr)
    icmp = privilege.icmp_warning()
    if icmp:
        print(icmp, file=sys.stderr)
    # What hello advertises: discovery kinds, and nmap when one may run here
    # (looked up once at start; a restart picks up a newly installed one),
    # and whether the agent runs as root.
    caps = await asyncio.to_thread(discovery.capabilities, cfg.nmap_binary)
    caps["runtime"] = privilege.runtime()
    client = OutpostClient(cfg, caps)
    discovery_task = None
    poll = cfg.poll_seconds
    snmp_interval = 900
    sweep_interval = 600
    next_snmp = 0.0  # run one discovery pass right after startup
    next_sweep = 0.0
    hello_interval = 300
    next_hello = time.monotonic() + hello_interval
    fast: FastRunner | None = None
    fast_task = None
    try:
        try:
            info = await client.hello()
            poll = int(info.get("poll_interval_seconds", poll)) or poll
            print(f"Danbyte Outpost {__version__} online → {cfg.url} (poll {poll}s)")
            await _maybe_update(client, info)  # may replace the binary + exit
        except Exception as e:  # keep going; retry in the loop
            print(f"outpost: hello failed ({e}); retrying", file=sys.stderr)
            info = {}

        while True:
            # The fast lane runs beside the poll loop, as its own task, once
            # the core has said it has the endpoints. A core too old to say
            # so hands sub-minute checks out on the beat like everything else.
            if fast is None and info.get("fast"):
                fast = FastRunner(client, flush_seconds=poll)
                fast_task = asyncio.create_task(fast.run())
            try:
                work = await client.fetch_work()
                checks = work.get("checks", [])
                if checks:
                    results = list(
                        await asyncio.gather(*(run_check(c) for c in checks))
                    )
                    # Danbyte says per poll whether we resolve PTR, and with
                    # what. Omitted or off → the core resolves centrally.
                    results = await attach_ptrs(
                        results, checks, work.get("dns") or {}
                    )
                    n = await client.post_results(results)
                    print(f"outpost: ran {len(checks)}, reported {n}")
                # A "Discover now" click → sweep on this cycle, not in 10 min.
                if work.get("sweep_pending"):
                    next_sweep = 0.0
                # A device's "Poll now" routed to this Outpost (#128) → run
                # the SNMP cycle on this pass instead of the periodic cadence.
                if work.get("snmp_pending"):
                    next_snmp = 0.0
                # Discovery waits for us (a core with the endpoints says so).
                # It runs beside the loop, one cycle at a time, so a long
                # scan never holds up the checks.
                if discovery.wanted(info, work) and (
                        discovery_task is None or discovery_task.done()):
                    discovery_task = asyncio.create_task(
                        _discovery_cycle(client, cfg.nmap_binary))
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
        if discovery_task is not None and not discovery_task.done():
            discovery_task.cancel()
        if fast is not None:
            fast.stopping = True
            if fast_task is not None:
                # Shutting down anyway: a report that fails now is lost, and
                # that is fine - the core keeps the last status it had.
                await asyncio.wait({fast_task}, timeout=5)
        await client.aclose()


async def _discovery_cycle(client, nmap_binary: str) -> None:
    """Run the discovery work waiting for this Outpost; never raises (the
    core gives up what is not reported, at its deadline)."""
    from .discovery import cycle

    try:
        n = await cycle(client, nmap_binary=nmap_binary)
        if n:
            print(f"outpost: discovery reported {n} host(s)")
    except Exception as e:  # noqa: BLE001 - discovery trouble never stops checks
        print(f"outpost: discovery error ({type(e).__name__})", file=sys.stderr)


async def _maybe_update(client, info: dict) -> None:
    """If the core asked this (auto-updating) Outpost to move to a new golden
    version, do it — self_update replaces the binary and exits to restart."""
    from .updater import can_self_update, self_update

    target = info.get("update_to")
    if target and can_self_update():
        await self_update(client, target)

#: Modules the agent imports only when a job needs them. A binary built
#: against a newer C library than the host's fails on the first of these,
#: in the middle of a job; ``self-check`` imports them all up front.
_LAZY_MODULES = (
    "asyncssh",
    "cryptography.hazmat.bindings._rust",
    "pysnmp.hlapi.v3arch.asyncio",
    "icmplib",
    "danbyte_checks.inventory",
)


def _self_check() -> int:
    import importlib
    import platform

    failed = 0
    libc = " ".join(platform.libc_ver()) or "unknown"
    print(f"danbyte-outpost {__version__}, C library {libc}")
    for name in _LAZY_MODULES:
        try:
            importlib.import_module(name)
        except Exception as exc:  # noqa: BLE001 - every failure is reported
            failed += 1
            print(f"  {name}: FAILED: {exc}")
        else:
            print(f"  {name}: ok")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
