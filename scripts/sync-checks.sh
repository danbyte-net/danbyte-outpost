#!/bin/sh
# Sync the vendored danbyte_checks/ from the Danbyte monorepo (its source of
# truth) into this repo. See docs/DEVELOPMENT.md + docs/COMPATIBILITY.md.
#
#   scripts/sync-checks.sh [path-to-monorepo]   (default: ../danbyte)
set -eu

MONO="${1:-../danbyte}"
SRC="$MONO/danbyte_checks"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
DST="$HERE/danbyte_checks"

[ -d "$SRC" ] || { echo "sync-checks: no danbyte_checks/ under '$MONO'" >&2; exit 1; }

# Compare + copy the checker modules (not the monorepo's own pyproject) and
# the data files they read (the service scan's fingerprints and its notice).
changed=0
for f in "$SRC"/*.py "$SRC"/data/*; do
  [ -f "$f" ] || continue
  rel="${f#"$SRC"/}"
  if ! diff -q "$f" "$DST/$rel" >/dev/null 2>&1; then
    echo "  ~ $rel"
    mkdir -p "$(dirname "$DST/$rel")"
    cp "$f" "$DST/$rel"
    changed=1
  fi
done

if [ "$changed" -eq 0 ]; then
  echo "sync-checks: already up to date."
else
  echo "sync-checks: done. Commit this as its own change, then bump the version."
fi
