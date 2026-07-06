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


async def _loop(cfg: Config) -> None:
    """Poll loop: hello, then repeatedly pull work → run checks → post results."""
    from .checks import run_check
    from .client import OutpostClient

    client = OutpostClient(cfg)
    poll = cfg.poll_seconds
    try:
        try:
            info = await client.hello()
            poll = int(info.get("poll_interval_seconds", poll)) or poll
            print(f"Danbyte Outpost {__version__} online → {cfg.url} (poll {poll}s)")
        except Exception as e:  # keep going; retry in the loop
            print(f"outpost: hello failed ({e}); retrying", file=sys.stderr)

        while True:
            try:
                checks = await client.fetch_work()
                if checks:
                    results = await asyncio.gather(
                        *(run_check(c) for c in checks)
                    )
                    n = await client.post_results(list(results))
                    print(f"outpost: ran {len(checks)}, reported {n}")
            except Exception as e:  # transient — back off and retry
                print(f"outpost: poll error ({e})", file=sys.stderr)
                await asyncio.sleep(min(poll * 2, 60))
                continue
            await asyncio.sleep(poll)
    finally:
        await client.aclose()


if __name__ == "__main__":
    raise SystemExit(main())
