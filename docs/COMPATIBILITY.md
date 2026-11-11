# Compatibility — the agent and the core evolve independently

An Outpost and the Danbyte core are **separate deployments on separate upgrade
schedules**. A customer may run Danbyte 2.4 at HQ while a branch office still runs
an Outpost built six months ago. That has to keep working. This document is the
contract that makes it safe.

## The golden rule

> **When you add a feature to the internal monitoring engine, the remote must be
> able to support it — and it must degrade gracefully when the remote is older
> than the core (or newer).**

Concretely: never make the core *depend* on a behaviour only new Outposts have.
New behaviour is opt-in and detected, not assumed.

## The wire protocol (`PROTOCOL_VERSION`)

The agent ↔ core contract is four small JSON messages. `PROTOCOL_VERSION`
(`outpost/__init__.py`) is bumped **only on a breaking change** to these shapes.

| Direction | Endpoint | Body |
|---|---|---|
| Outpost → core | `POST /api/outpost/hello` | `{version, protocol, hostname}` → `{poll_interval_seconds, assigned_checks}` |
| Outpost → core | `GET /api/outpost/work` | → `{checks: [{state_id, kind, target, params, secret_params, timeout_ms}]}` |
| Outpost → core | `POST /api/outpost/results` | `{results: [{state_id, status, latency_ms, detail}]}` |
| core → Outpost (SSH) | `danbyte-outpost once` | stdin `{checks:[…]}` → stdout `{results:[…]}` |
| Outpost → core | `GET /api/outpost/fast-work` (0.8+) | → `{checks: [{…, interval_ms}], refresh_seconds, flush_seconds}` |
| Outpost → core | `POST /api/outpost/fast-results` (0.8+) | `{results: [{state_id, samples: [{t, status, latency_ms, detail?}]}]}` |

The fast-lane pair is additive (protocol 1 unchanged). The agent says
`fast: true` in hello and only starts its lane when the core answers
`fast: true` back; an older core never does, an older agent never asks, and
in both cases sub-minute checks run on the ordinary work loop instead.

### Rules that keep it compatible

1. **Additive only.** New fields on a message are always *optional*. An old peer
   ignores unknown fields (JSON does this for free); a new peer must tolerate a
   missing field with a sensible default. Never rename or repurpose a field —
   add a new one and keep the old working.
2. **Unknown check kind → `unknown`, never a crash.** The agent runs
   `danbyte_checks.get_checker(kind)`; if the kind isn't in its (possibly older)
   engine, `run_check` returns `status="unknown"` with a `detail` explaining the
   kind isn't available on this Outpost. The core ingests that like any result.
   So the core can roll out a new check kind before every remote supports it —
   old remotes simply report `unknown` for it until they're upgraded.
3. **`status` is a closed set** — `up | down | degraded | unknown`. Adding a new
   status *is* a protocol break (bump `PROTOCOL_VERSION`), because the core
   validates against this set.
4. **Bump `PROTOCOL_VERSION`** only when 1–3 can't keep something compatible.
   When you do, the core must branch on the `protocol` an Outpost reports in
   `hello` and keep serving old-protocol Outposts until they upgrade.

## Adding a check kind (the common case)

Because `danbyte_checks` is the single, shared engine, a new kind is *not* a
protocol break — but it must reach the remote:

1. Add the checker to **`danbyte_checks/`** in the **monorepo** (its source of
   truth) — with `validate_params` and tests.
2. `scripts/sync-checks.sh` into this repo, then cut a new **Outpost release**.
3. Upload that release to Danbyte's package store and roll it out per site.
4. Until a given remote is upgraded, that kind returns `unknown` there (rule 2) —
   which is the correct, visible signal, not an outage.

## Reverse DNS (added 0.7.0)

`work` and `hello` may carry `"dns": {"resolve": bool, "resolvers": [str]}`.
When `resolve` is true the agent looks up each target's PTR - through the listed
nameservers, or its own host resolver when the list is empty - and reports the
name in that result's `detail` as `ptr`.

**The core decides on the presence of `ptr`, not its value.** An agent that ran
a lookup must always send the key, using `""` when the address genuinely has no
PTR. An agent that did not look must never send it.

Get that backwards and the core reads silence as "this address has no name",
which clears DNS names across the estate. For the same reason a lookup that was
never *answered* - timeout, refusal, unreachable server - must leave the key
off: `danbyte_checks.reverse_dns.resolve_ptrs` already omits those addresses
from its result rather than returning `None` for them, so following its output
is correct by default.

Additive on both sides, so no `PROTOCOL_VERSION` bump: an older agent ignores
the directive and never sends `ptr`, and the core resolves centrally as before.

## LAG membership on interface rows

Interface rows in an SNMP result may carry `lag_if_index` - the ifIndex of the
aggregate the port belongs to, `""` when it is not a member - and an aggregate
row reports `type_name: "lag"` (derived from being a membership target, not
only from ifType 161). The walker reads IEEE8023-LAG-MIB
`dot3adAggPortAttachedAggID` first and IF-MIB `ifStackTable` as the fallback.

**The core decides on the presence of `lag_if_index`, not its value** - the
same rule as `ptr`. An agent that looked sends the key on every row, blank
included; one that never looked sends no such key, and the core reports no
membership drift for its devices. Additive, no `PROTOCOL_VERSION` bump; the
vendored `danbyte_checks/snmp_facts.py` carries it.

## MAC tables, ARP and LLDP (0.9)

An SNMP result from 0.9 carries what the core needs to keep learned MACs with
history (Danbyte 0.17, #284):

- `fdb` rows keep `mac` and `if_index` and add `vlan`, `fdb_id`, `bridge_port`
  and `status` (learned / mgmt / other, `""` without a status column). Only
  learned entries are sent: the switch's own MACs, group addresses and port 0
  are dropped by the walker.
- `fdb_meta` says how the table was read: `source` (qbridge, bridge,
  bridge-vlan, none), `complete`, `truncated`, `vlan_map`, `port_map`, the
  VLANs read / skipped / failed, the drop counts, `rows`, `elapsed_ms` and
  `error`.
- `arp` rows add `type` (invalid entries are dropped), and `arp_meta`
  (`complete`, `rows`, `error`) says whether the ARP walk ran to its end.
- `neighbors` rows add `local_if_index` and `remote_caps`.

**The core decides on the presence of `fdb_meta`, not its value** - the same
rule as `ptr` and `lag_if_index`. An agent without it is treated as legacy:
no VLAN, the learned-only filter runs on the core, and a read counts as
complete only when the device answered with a non-empty table. The work list
may carry `mac_vlan_contexts`, `mac_max_vlans`, `mac_budget_s` and
`mac_vlan_hint` in `params`; an older agent ignores them. Additive, no
`PROTOCOL_VERSION` bump; the vendored `danbyte_checks/snmp_facts.py` carries it.

## Discovery work (0.10)

A Danbyte discovery profile can run on an Outpost: package inventory over
SSH and service scans (the built-in connect scan, or an nmap the admin
installed). This is the first work that is **negotiated** instead of
degrading to `unknown`:

| Direction | Endpoint | Body |
|---|---|---|
| Outpost → core | `POST /api/outpost/hello` | adds `capabilities: {discovery: {kinds, protocol, nmap: {version} or null, nmap_reason}}`; the answer adds `discovery: true` |
| Outpost → core | `GET /api/outpost/work` | the answer adds `discovery_pending: bool` |
| Outpost → core | `GET /api/outpost/discovery-work` | → `{jobs: [{run_id, kind, …, items: [...]}]}` |
| Outpost → core | `POST /api/outpost/discovery-results` | `{results: [{item_id, result, observed?, used?, attempts?}]}` → `{accepted, refused}` |

- **An older agent** sends no `capabilities`. The core hands it no
  discovery work at all; the run's hosts say the Outpost "cannot run it"
  and which agent version they need. Nothing is attempted from the server
  instead - a different network vantage is a different scan.
- **An older core** answers hello without `discovery` and work without
  `discovery_pending`. This agent then never calls the discovery endpoints.
- **The core decides on `kinds`, not on `version`**: an agent advertises
  only what it can run, and the core never hands out a kind (or nmap) the
  last hello did not name.
- An unknown job `kind` is skipped: nothing runs, nothing is posted, and
  the core gives the items up at their deadline.

The jobs are built by the core: scope, exemptions, deny subnets, maintenance
and the credentials are all decided there. A package inventory item carries
the address, the accepted host keys to pin (`known_hosts`, or `first_use`),
and its logins most secure first with their credentials - delivered the way
SNMP credentials already are (Bearer token, the Outpost's own tenant only,
claimed once, `Cache-Control: no-store`). The agent holds them in memory for
the connection, drops them when the host is done and never prints or writes
them. A service-scan job carries the port list, the rate, the hosts at once
and the engine (`builtin` or `nmap` with its intensity, timing and host
timeout). WinRM is never sent to an Outpost: it reads over SSH only.

Results use the shapes of `danbyte_checks.inventory.result_as_dict` and
`danbyte_checks.service_scan.host_result_as_dict`. The core reads them back
with `result_from_dict` / `host_result_from_dict`, which accept only what
the collectors can produce: the item's own address and ports, capped strings,
packages that pass the parsers' name and version checks, host keys whose
fingerprint the core computes itself. Inventory results are posted one host
per request (a host's package list can run to megabytes), scan results up to
50 per request.

nmap is never installed by the agent and is refused when it runs as root
(units installed before 0.10 do): set `OUTPOST_NMAP_BINARY` (or `--nmap`) and
run the agent as the service user (`migrate-service-user`, below) to offer it.
It is looked up once when the agent starts.

The vendored `danbyte_checks/data/` (the service scan's Recog fingerprints and
their notice) is synced, packaged and frozen into the binary with the code.

## Runtime: root or not (0.10)

`hello` adds `capabilities.runtime: {root: bool}`, and the `once` output adds
`runtime: {root: bool}` beside `results`. The core shows a warning on an
Outpost that runs as root and never blocks anything on it. An older agent
sends neither (the core shows nothing: unknown), an older core ignores both.

From 0.10 the installer runs the agent as the system user `danbyte-outpost`
with no capabilities. An install from before keeps its root unit through a
self-update (only the binary is swapped) and keeps working; an
administrator moves it with `sudo danbyte-outpost migrate-service-user`
(or by re-running the installer). The agent never changes its own unit or
asks for privilege. Self-update needs its binary's directory to be writable
by the agent; when it is not, the agent says so once and keeps its version.

## Capability negotiation

`hello` carries `protocol`, `version` and, from 0.10, `capabilities` for the
discovery work kinds (above). Check kinds are still not negotiated: they keep
relying on graceful `unknown` degradation.
