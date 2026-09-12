#!/bin/sh
# Refresh site/js/engine from PharLap2's impl/js and record the commit. Never edit the copies.
set -e
cd "$(dirname "$0")/.."
SRC=${1:-../PharLap2}
for f in secp256k1 ecdsa rfc6979 bytes; do cp "$SRC/impl/js/$f.mjs" site/js/engine/; done
REV=$(git -C "$SRC" rev-parse --short HEAD)
printf 'engine/ = unmodified copies of PharLap2 impl/js at commit %s (secp256k1, ecdsa, rfc6979, bytes).\nRefresh with tools/sync-engine.sh; never edit here.\n' "$REV" > site/js/engine/README
echo "engine synced from PharLap2 $REV"
