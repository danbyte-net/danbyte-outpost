# Danbyte Outpost

The remote monitoring agent for [Danbyte](https://github.com/DenDanskeMine/Danbyte-IPAM).

An Outpost runs **at a site that has no direct path to the Danbyte core** — a
NAT'd branch office, an isolated colo, an airgapped DMZ. It monitors the local
network and reports results back to Danbyte. The core never has to reach in.

- **HTTPS pull** — the Outpost dials *out* to Danbyte (443), pulls its assigned
  checks, runs them locally, and posts results. Works through NAT/firewalls.
- **SSH** — for locked-down sites where only `Danbyte → host:22` is allowed,
  Danbyte dials *in* over SSH and drives the agent (`danbyte-outpost once`).

It ships the **same check engine the core runs** (`danbyte_checks`), so a check
gives identical results wherever it runs — no drift. The `run` loop also performs
**SNMP discovery** (facts / interfaces / LLDP topology / ARP) for the site's
devices on a slower cadence, fetching locally and posting results back.

## Install

The easiest path is the one-liner Danbyte generates when you enroll an Outpost
(**Governance → Monitoring engines**), which installs a version pinned + served
by *your* Danbyte instance (so airgapped hosts never touch GitHub/PyPI):

```bash
curl -fsSL https://<your-danbyte>/api/outpost/install.sh | sudo sh -s -- --token=<TOKEN>
```

Or install from source:

```bash
pip install "git+https://github.com/DenDanskeMine/danbyte-outpost.git"
danbyte-outpost run --url=https://<your-danbyte> --token=<TOKEN>
```

## Usage

```bash
danbyte-outpost run    --url=… --token=…   # the poll loop (HTTPS pull transport)
danbyte-outpost check  --url=… --token=…   # one-shot: verify the token + assignment
danbyte-outpost once                       # SSH transport: work JSON on stdin → results on stdout
```

Config comes from flags or the environment (`OUTPOST_URL`, `OUTPOST_TOKEN`,
`OUTPOST_POLL`). See `deploy/danbyte-outpost.service` for a systemd unit.

## Compatibility

The agent and Danbyte are **versioned independently** — a site does *not* have to
upgrade in lockstep with the core. The wire protocol is additive and a check kind
an old agent doesn't know degrades gracefully to `unknown`. Read
[docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) before changing the protocol or
adding a check kind.

## Developing

This repo is developed alongside the Danbyte monorepo. `danbyte_checks/` here is
**vendored** from the monorepo (its source of truth) — see
[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).
