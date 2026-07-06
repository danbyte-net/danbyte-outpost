#!/bin/sh
# Build a single-file `danbyte-outpost` binary with PyInstaller — no Python
# needed on the target host. Produces dist/danbyte-outpost. Run per-platform
# (a binary is OS/arch-specific); CI builds the Linux x86_64 one on a tag.
set -eu

HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"

python -m pip install --quiet --upgrade pip pyinstaller
python -m pip install --quiet .

# pysnmp / pyasn1 / asyncssh load submodules dynamically, so collect them whole.
pyinstaller --onefile --clean --noconfirm --name danbyte-outpost \
  --collect-all pysnmp \
  --collect-all pyasn1 \
  --collect-submodules asyncssh \
  --collect-submodules icmplib \
  scripts/entrypoint.py

echo "Built: dist/danbyte-outpost"
"$HERE/dist/danbyte-outpost" --help >/dev/null && echo "smoke test: --help OK"
