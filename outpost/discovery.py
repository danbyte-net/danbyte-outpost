"""Discovery work on the Outpost: package inventory and service scans for the
hosts of a site the Danbyte server cannot reach.

Everything that touches a host is the **shared** ``danbyte_checks`` code the
core runs itself - the same fixed command list and parsers
(``inventory.read_with_logins`` / ``collect``), the same connect scan and
fingerprints (``service_scan.scan``), the same nmap argument builder
(``nmap.build_argv``) - so a host gives the same answer wherever it is read.
This module only feeds it the work the core handed out and posts the
results back in the core's wire shape (``result_as_dict``,
``host_result_as_dict``).

What the core decided stays decided: the scope, the exemptions, deny
subnets, maintenance, the credentials and the host keys to pin all come in
the work. The agent adds its own target policy (``danbyte_checks.netguard``,
the one it applies to checks: link-local and metadata addresses are always
refused) before any connection.

Credentials arrive in the work answer over the authenticated channel, are
held in memory for the connection, dropped as soon as the host is done and
never printed or written to disk.

nmap: never installed by the agent. It is used only when the core asks for
it, the agent found one it may run (``OUTPOST_NMAP_BINARY``, else ``nmap``
on PATH) and the agent does not run as root.
"""
from __future__ import annotations

import asyncio
import ipaddress
import math
import os

from danbyte_checks import inventory, netguard, nmap, service_scan

#: The work kinds this agent runs; advertised in hello.
KINDS = ("inventory", "service_scan")
#: The discovery wire contract this agent speaks (additive, like checks).
DISCOVERY_PROTOCOL = 1
TIMEOUT_RANGE = (10, 600)
CONCURRENCY_MAX = 16
HOSTS_PARALLEL_MAX = 16
RATE_RANGE = (1, 2000)
#: nmap: the whole batch may take at most this long.
NMAP_RUN_CEILING = 5 * 3600


def _clamp(value, lo, hi, default):
    try:
        v = type(lo)(value)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, v))


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def detect_nmap(configured: str = "") -> tuple[str, str, str]:
    """``(path, version, why_not)``: the nmap this agent may run, the same
    lookup the core uses (``nmap.locate`` / ``nmap.version``)."""
    if is_root():
        return "", "", "the agent runs as root"
    path = nmap.locate(configured)
    if not path:
        return "", "", "not found"
    version = nmap.version(path)
    if not version:
        return "", "", "does not answer like nmap"
    return path, version, ""


def capabilities(nmap_binary: str = "") -> dict:
    """What hello advertises: the kinds, and nmap with its version or why
    there is none."""
    _path, version, why = detect_nmap(nmap_binary)
    return {"discovery": {"kinds": list(KINDS), "protocol": DISCOVERY_PROTOCOL,
                          "nmap": {"version": version} if version else None,
                          "nmap_reason": why}}


def _ip(address) -> str | None:
    try:
        return str(ipaddress.ip_address(str(address)))
    except ValueError:
        return None


def _forget(item: dict) -> None:
    """Drop the secrets of a work item once its host is done."""
    for login in item.get("logins") or []:
        cred = login.get("credential")
        if isinstance(cred, dict):
            cred.clear()
        login.pop("credential", None)


# ─── package inventory ───────────────────────────────────────────────────────


async def run_inventory(job: dict, *, collect=None, observe=None) -> list[dict]:
    """Read each host of an inventory job. Returns one result row per item:
    ``{item_id, result, observed, used, attempts}`` (an observe item only
    ``{item_id, observed}``)."""
    collect = collect or inventory.collect
    observe = observe or inventory.observe_host_key
    timeout = float(_clamp(job.get("timeout"), *TIMEOUT_RANGE, 60))
    sem = asyncio.Semaphore(_clamp(job.get("concurrency"), 1, CONCURRENCY_MAX, 4))

    async def one(item: dict) -> dict:
        out: dict = {"item_id": item.get("item_id")}
        try:
            async with sem:
                address = _ip(item.get("address"))
                if address is None or netguard.target_blocked(address):
                    why = "Not an IP address." if address is None else \
                        "The Outpost's target policy refuses this address."
                    if item.get("mode") == "observe":
                        out["observed"] = None
                    else:
                        out["result"] = inventory.result_as_dict(
                            inventory.InventoryResult("blocked", why))
                    return out
                if item.get("mode") == "observe":
                    port = _clamp(item.get("port"), 1, 65535, 22)
                    out["observed"] = await observe(address, port=port, timeout=10)
                    return out
                # SSH only: a WinRM login is never sent to an Outpost, and one
                # that came would answer "unsupported" (no WinRM collector).
                logins = [x for x in item.get("logins") or [] if isinstance(x, dict)]
                known = item.get("known_hosts")
                r, observed, used, tried = await inventory.read_with_logins(
                    address, logins,
                    known_hosts=known.encode() if isinstance(known, str) and known else None,
                    first_use=bool(item.get("first_use")), timeout=timeout,
                    collect=collect, observe=observe, collect_winrm=None)
                if r is None:
                    r = inventory.InventoryResult(inventory.FAILED, "No login to try.")
                out.update(result=inventory.result_as_dict(r), observed=observed, used=used,
                           attempts=tried)
                return out
        except Exception as exc:  # noqa: BLE001 - one host never stops the job
            out["result"] = inventory.result_as_dict(inventory.InventoryResult(
                inventory.FAILED, f"The Outpost could not read it: {type(exc).__name__}"))
            return out
        finally:
            _forget(item)

    return list(await asyncio.gather(*(one(i) for i in job.get("items") or [])))


# ─── service scan ────────────────────────────────────────────────────────────


async def run_scan(job: dict, *, nmap_binary: str = "", scan=None) -> list[dict]:
    """Scan the addresses of a service-scan job with the engine it names.
    Returns ``{item_id, result}`` per item, in the job's order."""
    items = [i for i in job.get("items") or [] if isinstance(i, dict)]
    try:
        ports = service_scan.parse_ports(job.get("ports"))
    except ValueError as exc:
        return [_scan_row(i, service_scan.HostResult(str(i.get("address")), "failed",
                                                     f"Not a port list: {exc}"))
                for i in items]
    rate = _clamp(job.get("rate"), *RATE_RANGE, 20)
    hosts_parallel = _clamp(job.get("hosts_parallel"), 1, HOSTS_PARALLEL_MAX, 4)
    rows: dict[int, service_scan.HostResult] = {}
    todo = []
    for n, item in enumerate(items):
        address = _ip(item.get("address"))
        if address is None:
            rows[n] = service_scan.HostResult(str(item.get("address")), "blocked",
                                              "Not an IP address.")
        elif netguard.target_blocked(address):
            rows[n] = service_scan.HostResult(address, "blocked",
                                              "The Outpost's target policy refuses this "
                                              "address.")
        else:
            todo.append((n, address))
    addresses = [a for _n, a in todo]
    if addresses:
        if job.get("engine") == "nmap":
            found = await _nmap(addresses, ports, rate, hosts_parallel, job.get("nmap") or {},
                                nmap_binary)
        else:
            found = await (scan or service_scan.scan)(
                addresses, ports, rate=rate, hosts_parallel=hosts_parallel,
                observe_key=inventory.observe_host_key)
        for (n, _a), r in zip(todo, found, strict=True):
            rows[n] = r
    return [_scan_row(item, rows[n]) for n, item in enumerate(items)]


def _scan_row(item: dict, r) -> dict:
    return {"item_id": item.get("item_id"), "result": service_scan.host_result_as_dict(r)}


async def _nmap(addresses, ports, rate, hosts_parallel, options: dict, nmap_binary: str):
    path, _version, why = detect_nmap(nmap_binary)
    if not path:
        return [service_scan.HostResult(a, "failed", f"nmap: {why}.") for a in addresses]
    host_timeout = _clamp(options.get("host_timeout"), *nmap.HOST_TIMEOUT_RANGE, 300)
    try:
        argv = nmap.build_argv(
            path, addresses, ports, intensity=_clamp(options.get("intensity"),
                                                     *nmap.INTENSITY_RANGE, 2),
            timing=_clamp(options.get("timing"), *nmap.TIMING_RANGE, 3), max_rate=rate,
            host_timeout=host_timeout, max_hostgroup=hosts_parallel)
        batches = math.ceil(len(addresses) / max(1, hosts_parallel))
        raw = await asyncio.to_thread(
            nmap.run, argv, timeout=min(NMAP_RUN_CEILING, 60 + host_timeout * batches))
        return nmap.parse_xml(raw, addresses)
    except nmap.NmapError as exc:
        return [service_scan.HostResult(a, "failed", str(exc)[:300]) for a in addresses]


# ─── the cycle ───────────────────────────────────────────────────────────────

#: Results per post: one host's packages can run to megabytes, scans are small.
POST_CHUNK = {"inventory": 1, "service_scan": 50}


async def run_job(job: dict, *, nmap_binary: str = "") -> list[dict]:
    kind = job.get("kind")
    if kind == "inventory":
        return await run_inventory(job)
    if kind == "service_scan":
        return await run_scan(job, nmap_binary=nmap_binary)
    # A kind this agent does not know: nothing is run and nothing is posted;
    # the core gives the items up at their deadline.
    return []


async def cycle(client, *, nmap_binary: str = "", max_jobs: int = 1000) -> int:
    """Claim and run discovery work until the core has none left for us.
    Returns the number of results posted."""
    posted = 0
    for _ in range(max_jobs):
        work = await client.fetch_discovery_work()
        jobs = work.get("jobs") or []
        if not jobs:
            break
        for job in jobs:
            rows = await run_job(job, nmap_binary=nmap_binary)
            step = POST_CHUNK.get(job.get("kind"), 1)
            for i in range(0, len(rows), step):
                await client.post_discovery_results(rows[i:i + step])
                posted += len(rows[i:i + step])
            rows.clear()
            job.clear()
    return posted


def wanted(hello: dict, work: dict) -> bool:
    """Whether to pull discovery work now: the core said it has the
    endpoints (hello ``discovery``) and that work waits (``discovery_pending``
    on the work answer). An older core says neither."""
    return bool((hello or {}).get("discovery")) and bool((work or {}).get("discovery_pending"))
