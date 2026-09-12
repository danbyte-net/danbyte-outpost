"""The Outpost's fast lane - sub-minute checks probed here, folded there.

The core hands this agent its sub-minute set (``/api/outpost/fast-work``)
and the agent owns it continuously: a tick loop probes each check on its
own interval from an in-memory schedule, exactly as the core's own lane
does. What the agent does *not* do is decide status: probes are buffered
and reported to ``/api/outpost/fast-results``, and the core runs the same
rise/fall over them it runs over its own probes - so an Outpost-watched
host behaves precisely like a core-watched one.

Reporting is on the poll interval, or at once when a probe's reachability
differs from the last one reported for that check - a host that just went
quiet is not held back for fifteen seconds while the buffer fills.
"""
from __future__ import annotations

import asyncio
import sys
import time

from danbyte_checks import CheckOutcome, get_checker

TICK_SECONDS = 0.05
_REACHABLE = {"up", "degraded"}


class _Entry:
    __slots__ = ("check", "due", "interval", "last_class", "running")

    def __init__(self, check: dict):
        self.check = check
        self.interval = max(int(check.get("interval_ms") or 1000), 200) / 1000
        self.due = time.monotonic()
        self.running = False
        self.last_class = None  # True reachable / False not, as last reported

    def refresh(self, check: dict) -> None:
        self.check = check
        self.interval = max(int(check.get("interval_ms") or 1000), 200) / 1000


class FastRunner:
    """Owns the fast set; ``run()`` never returns."""

    def __init__(self, client, *, refresh_seconds: int = 15, flush_seconds: int = 15):
        self.client = client
        self.entries: dict[str, _Entry] = {}
        self.buffer: dict[str, list[dict]] = {}
        self.refresh_seconds = refresh_seconds
        self.flush_seconds = flush_seconds
        self.flush_now = False
        self.probes = 0
        self.stopping = False

    async def refresh(self) -> None:
        work = await self.client.fetch_fast_work()
        self.refresh_seconds = int(work.get("refresh_seconds") or self.refresh_seconds)
        self.flush_seconds = int(work.get("flush_seconds") or self.flush_seconds)
        keep = set()
        for check in work.get("checks") or []:
            sid = str(check.get("state_id") or "")
            if not sid:
                continue
            keep.add(sid)
            entry = self.entries.get(sid)
            if entry is None:
                self.entries[sid] = _Entry(check)
            else:
                entry.refresh(check)
        for sid in list(self.entries):
            if sid not in keep:
                del self.entries[sid]
                self.buffer.pop(sid, None)

    async def tick(self) -> None:
        now_m = time.monotonic()
        for e in self.entries.values():
            if e.due <= now_m and not e.running:
                e.running = True
                # From this probe, not from when it answers, so a slow
                # answer does not stretch the cadence.
                e.due = now_m + e.interval
                asyncio.create_task(self._probe(e))

    async def _probe(self, e: _Entry) -> None:
        check = e.check
        at = int(time.time() * 1000)
        checker = get_checker(check.get("kind"))
        if checker is None:
            oc = CheckOutcome.unknown(f"kind '{check.get('kind')}' not available on this Outpost")
        else:
            try:
                oc = await checker.run(
                    check.get("target"),
                    check.get("params") or {},
                    check.get("secret_params") or {},
                    int(check.get("timeout_ms") or 2000),
                )
            except Exception as exc:  # noqa: BLE001 - one bad probe is one sample
                oc = CheckOutcome.unknown(str(exc))
        self.probes += 1
        sid = str(check.get("state_id"))
        sample = {"t": at, "status": oc.status, "latency_ms": oc.latency_ms}
        # Detail only when it says something a status does not (an error, a
        # banner) - a thousand copies of {"packets_sent": 1} is not worth
        # the bytes.
        detail = oc.detail or {}
        if detail.get("error"):
            sample["detail"] = {"error": str(detail["error"])[:300]}
        self.buffer.setdefault(sid, []).append(sample)
        reachable = oc.status in _REACHABLE
        if e.last_class is not None and reachable != e.last_class:
            self.flush_now = True
        e.last_class = reachable
        e.running = False

    async def flush(self) -> int:
        buffer, self.buffer = self.buffer, {}
        self.flush_now = False
        results = [{"state_id": sid, "samples": samples} for sid, samples in buffer.items() if samples]
        if not results:
            return 0
        try:
            return await self.client.post_fast_results(results)
        except Exception as exc:  # noqa: BLE001 - keep the probes, retry next flush
            print(f"outpost: fast report failed ({exc}); buffering", file=sys.stderr)
            for r in results:
                self.buffer.setdefault(r["state_id"], [])[:0] = r["samples"]
            # Never let an outage grow the buffer without bound: keep the
            # newest few minutes per check.
            for samples in self.buffer.values():
                if len(samples) > 600:
                    del samples[:-600]
            return 0

    async def run(self) -> None:
        try:
            await self.refresh()
        except Exception as exc:  # noqa: BLE001
            print(f"outpost: fast-work fetch failed ({exc}); retrying", file=sys.stderr)
        next_refresh = time.monotonic() + self.refresh_seconds
        next_flush = time.monotonic() + self.flush_seconds
        print(f"outpost: fast lane up, {len(self.entries)} check(s)")
        while not self.stopping:
            await self.tick()
            now_m = time.monotonic()
            if self.flush_now or now_m >= next_flush:
                next_flush = now_m + self.flush_seconds
                await self.flush()
            if now_m >= next_refresh:
                next_refresh = now_m + self.refresh_seconds
                try:
                    await self.refresh()
                except Exception as exc:  # noqa: BLE001
                    print(f"outpost: fast-work fetch failed ({exc})", file=sys.stderr)
            await asyncio.sleep(TICK_SECONDS)
        await self.flush()
