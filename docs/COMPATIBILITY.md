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

## Capability negotiation (planned)

Today `hello` carries `protocol` + `version`; the core records them and relies on
graceful `unknown` degradation. The planned improvement is for `hello` to also
advertise the agent's **supported check kinds**, so the core simply doesn't hand
a remote work it can't run (turning a silent `unknown` into no-op scheduling).
Until then, the graceful-degradation rules above are the contract.
