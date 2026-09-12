"""The agent's fast lane: probes buffer, flush on the poll or at once when
reachability changes, and a failed report keeps the probes."""
from __future__ import annotations

import asyncio

from outpost.fast import FastRunner


class _Client:
    def __init__(self, checks, *, fail=False):
        self.checks = checks
        self.fail = fail
        self.posted: list[list[dict]] = []

    async def fetch_fast_work(self):
        return {"checks": self.checks, "refresh_seconds": 15, "flush_seconds": 10}

    async def post_fast_results(self, results):
        if self.fail:
            raise RuntimeError("core away")
        self.posted.append(results)
        return sum(len(r["samples"]) for r in results)


class _Checker:
    def __init__(self, statuses):
        self.statuses = list(statuses)

    async def run(self, target, params, secrets, timeout_ms):
        from danbyte_checks import CheckOutcome

        status = self.statuses.pop(0) if self.statuses else "up"
        return CheckOutcome(status, 1.0 if status == "up" else None, {})


def _run(coro):
    return asyncio.run(coro)


def test_probes_buffer_and_flush_on_change(monkeypatch):
    checker = _Checker(["up", "up", "down"])
    monkeypatch.setattr("outpost.fast.get_checker", lambda kind: checker)
    client = _Client([{"state_id": "s1", "kind": "icmp", "target": "10.0.0.1",
                       "interval_ms": 1000, "timeout_ms": 500}])
    runner = FastRunner(client, flush_seconds=10)

    async def go():
        await runner.refresh()
        e = runner.entries["s1"]
        for _ in range(3):
            e.due = 0
            await runner.tick()
            await asyncio.sleep(0)
            await asyncio.sleep(0)
        return runner.flush_now, len(runner.buffer["s1"])

    flush_now, buffered = _run(go())
    assert buffered == 3
    # up → down is a change in reachability: report at once.
    assert flush_now is True
    n = _run(runner.flush())
    assert n == 3
    assert client.posted[0][0]["samples"][2]["status"] == "down"
    assert runner.buffer == {}


def test_a_failed_report_keeps_the_probes(monkeypatch):
    checker = _Checker(["up"])
    monkeypatch.setattr("outpost.fast.get_checker", lambda kind: checker)
    client = _Client([{"state_id": "s1", "kind": "icmp", "target": "10.0.0.1",
                       "interval_ms": 1000}], fail=True)
    runner = FastRunner(client)

    async def go():
        await runner.refresh()
        runner.entries["s1"].due = 0
        await runner.tick()
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        return await runner.flush()

    assert _run(go()) == 0
    assert len(runner.buffer["s1"]) == 1


def test_refresh_drops_checks_the_core_took_away():
    client = _Client([{"state_id": "s1", "kind": "icmp", "target": "10.0.0.1"}])
    runner = FastRunner(client)
    _run(runner.refresh())
    assert "s1" in runner.entries
    client.checks = []
    _run(runner.refresh())
    assert runner.entries == {}
