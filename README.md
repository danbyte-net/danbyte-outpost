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

The installer creates the system user `danbyte-outpost` (no login shell, no
home) and runs the service as that user with no capabilities: ICMP uses
unprivileged datagram sockets, the agent binds no port, and nmap runs with
`--unprivileged`. The binary's directory belongs to that user so the agent
can update itself; root never runs it. See [Service user](#service-user).

The binary runs on x86_64 Linux with glibc 2.35 or newer: Debian 12 and 13,
Ubuntu 22.04 and newer, and other distributions of that age. Each release is
started on those systems before it is published. On anything older, install
from source.

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
sudo danbyte-outpost migrate-service-user  # move a root-run service to the service user
danbyte-outpost self-check                 # load every library: does this binary run here?
```

Config comes from flags or the environment (`OUTPOST_URL`, `OUTPOST_TOKEN`,
`OUTPOST_NMAP_BINARY`,
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

## Sub-minute checks

Since 0.8 the agent runs a **fast lane** beside its poll loop: checks the core
marks with an interval under a minute are probed here from an in-memory
schedule (down to 200 ms for ICMP), buffered, and reported on the poll
interval - or at once when a probe's reachability changes. The core applies
its own rise/fall to them, so status and history are identical to a
core-run check. Needs a Danbyte core with the fast-lane endpoints; against an
older core the agent simply does not start the lane.

## Discovery

Since 0.10 the agent runs Danbyte **discovery** work for its site: package
inventory over SSH and service scans, with the same collectors the core runs
(`danbyte_checks.inventory`, `service_scan`, `nmap`). It advertises what it
can do in hello; the core hands it work only then, and only when a profile
runs on this Outpost. Credentials for inventory come with the work, are kept
in memory for the connection and never written or printed. nmap is optional,
never installed by the agent, and refused when the agent runs as root: set
`OUTPOST_NMAP_BINARY` (or `--nmap=/usr/bin/nmap`) and run the service as the
service user (see below) to offer it. Against an older core nothing changes. See
[docs/COMPATIBILITY.md](docs/COMPATIBILITY.md#discovery-work-010).

## Service user

Since 0.10 a fresh install runs as the system user `danbyte-outpost`. An
Outpost installed earlier runs as root, and a self-update only swaps the
binary, so it keeps running as root after updating to 0.10: everything works
as before except nmap, the log says so at start, and Danbyte shows a
**root** badge on the Outpost. Move it over once, on the host:

```bash
sudo /opt/danbyte-outpost/danbyte-outpost migrate-service-user --dry-run   # the plan
sudo /opt/danbyte-outpost/danbyte-outpost migrate-service-user
```

It checks first and changes nothing when a check fails: the unit and its
program, that the program it runs from can be changed by root alone, drop-ins
that set the user, and that `net.ipv4.ping_group_range` covers the new group
(`--ignore-icmp` to go ahead anyway). Then it creates the user, saves the old
unit as `/etc/danbyte-outpost/danbyte-outpost.service.root-backup`, rewrites
only the `[Service]` section (`User=`, `Group=`, an empty capability set and
hardening; your other lines stay), gives the binary's directory to the user,
restarts the service and watches it for 20 s (`--settle`). If it does not
stay up as the user, the old unit and ownership come back and the service is
restarted as before. A second run does nothing. Re-running the installer from
Danbyte does the same for a whole install.

After the move, do not run the binary in `/opt/danbyte-outpost` with sudo:
the service user can write it. To go back by hand:

```bash
sudo cp /etc/danbyte-outpost/danbyte-outpost.service.root-backup \
        /etc/systemd/system/danbyte-outpost.service
sudo chown root:root /opt/danbyte-outpost /opt/danbyte-outpost/danbyte-outpost
sudo systemctl daemon-reload && sudo systemctl restart danbyte-outpost
```

ICMP needs no capability, but the kernel only opens ICMP datagram sockets for
the groups in `net.ipv4.ping_group_range`. systemd sets it to
`0 2147483647` on most distributions; if yours does not, the agent logs it
and ICMP checks report unknown.

**SSH transport.** Danbyte runs `danbyte-outpost once` as the SSH user you
give the engine. Use an ordinary account: nothing in `once` needs root. A run
as root warns on stderr and reports `runtime.root` beside the results.

**Containers.** There is no official image. If you build one, run the agent
as a non-root user; it needs no `--cap-add`. Docker already sets
`net.ipv4.ping_group_range` to `0 2147483647`; podman does not, so pass
`--sysctl net.ipv4.ping_group_range="0 2147483647"` (rootless podman: a
range inside the mapped gids, such as `0 65535`).
