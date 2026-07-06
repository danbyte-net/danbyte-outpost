# Developing danbyte-outpost

## Where it lives

- **This repo** (`danbyte-outpost`) — the standalone, installable agent. Canonical
  home of `outpost/` (the agent) and a **vendored** copy of `danbyte_checks/`.
- **The monorepo** (`Danbyte-IPAM`) — the Danbyte core, and the **source of truth
  for `danbyte_checks/`**. The core imports it (`monitoring/checkers` re-exports
  it), so the shared checkers must change there first.

In this dev environment both are checked out side by side:

```
/home/crosk/danbyte            # the monorepo (Danbyte core)
/home/crosk/danbyte-outpost    # this repo
```

## The `danbyte_checks` sync

`danbyte_checks/` is duplicated here on purpose (so the agent installs
standalone), but the **monorepo copy is authoritative**. Never hand-edit the
checkers here — edit them in the monorepo, then:

```bash
scripts/sync-checks.sh /home/crosk/danbyte    # copy monorepo danbyte_checks/ -> here
```

The script refuses to run if the files already match (nothing to do) and prints a
diff of what it changed. Commit the sync as its own change so the provenance is
clear.

## Local run

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
danbyte-outpost check --url=https://<danbyte> --token=<TOKEN> --insecure   # dev/self-signed
danbyte-outpost run   --url=https://<danbyte> --token=<TOKEN> --insecure
```

## Building the single-file binary

The binary is **not** produced by a normal commit — it's built from a **tagged
release**, so a host can install the Outpost with no Python at all.

- **Automatic (the normal path):** push a version tag and CI does it.
  ```bash
  git tag v0.2.0 && git push origin v0.2.0
  ```
  `.github/workflows/release.yml` runs `scripts/build-binary.sh` (PyInstaller
  `--onefile`) on Linux and **attaches `danbyte-outpost` to the GitHub release**.
- **Manual (to test locally):** `sh scripts/build-binary.sh` → `dist/danbyte-outpost`.

A binary is OS/arch-specific (the CI one is Linux x86_64); build others on their
own platforms. Then **upload the binary to your Danbyte instance's package
store** (Governance → Monitoring engines → Outpost versions). Danbyte detects a
bare binary and generates an installer that just downloads + `chmod +x`es it
(no venv/pip) — whereas a `.whl`/`.tar.gz` or git release installs into a venv.

So the flow is: **land the change → bump the version → tag → CI builds the binary
→ upload it to the package store → roll it out per site.**

## Before a release

1. Land the check/agent change (in the monorepo first if it touches
   `danbyte_checks`), then `sync-checks.sh`.
2. Read [COMPATIBILITY.md](COMPATIBILITY.md) — did the wire protocol change? If
   so, bump `PROTOCOL_VERSION` and make the core branch on it.
3. Bump `version` in `pyproject.toml` + `outpost/__init__.py`.
4. Build (`python -m build`) and upload the artifact to Danbyte's package store
   (Governance → Monitoring engines → Outpost versions), or push a git tag the
   store can reference.
