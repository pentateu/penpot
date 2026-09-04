#!/bin/bash
# Patch penpot.jar with ISWE JWT source: unpack + overlay + repack.
# Usage: patch-jar.sh <penpot.jar path> <patch dir with app/auth.clj app/http/session.clj app/config.clj>
# Idempotent, reversible (keep a .orig copy before first run).
set -euo pipefail
JAR="${1:?jar path required}"
PATCH_DIR="${2:?patch dir required}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
if [ ! -e "${JAR}.orig" ]; then
  cp "$JAR" "${JAR}.orig"
  echo "saved orig ${JAR}.orig"
fi
unzip -q -o "$JAR" -d "$WORK"
cp "$PATCH_DIR/app/auth.clj" "$WORK/app/auth.clj"
cp "$PATCH_DIR/app/http/session.clj" "$WORK/app/http/session.clj"
cp "$PATCH_DIR/app/config.clj" "$WORK/app/config.clj"
# Rebuild jar preserving manifest (zip -f not used; full repack from unpacked tree).
# Keep original compression: use jar cf if available, else zip.
if command -v jar >/dev/null 2>&1; then
  (cd "$WORK" && jar cf "$JAR.new" .)
else
  (cd "$WORK" && zip -q -r "$JAR.new" .)
fi
mv "$JAR.new" "$JAR"
echo "patched $JAR"
ls -lh "$JAR"
