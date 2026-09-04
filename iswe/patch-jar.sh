#!/bin/sh
# Patch penpot.jar with ISWE JWT source: unpack + overlay + repack via python3 zipfile.
# Usage: patch-jar.sh <penpot.jar path> <patch dir with app/auth.clj app/http/session.clj app/config.clj>
# Idempotent, reversible (keep a .orig copy before first run). No unzip/zip/jar needed.
set -eu
JAR="${1:?jar path required}"
PATCH_DIR="${2:?patch dir required}"
if [ ! -e "${JAR}.orig" ]; then
  cp "$JAR" "${JAR}.orig"
  echo "saved orig ${JAR}.orig"
fi
PATCH_DIR="$PATCH_DIR" JAR="$JAR" python3 - <<'PY'
import os, shutil, tempfile, zipfile
jar_path = os.environ["JAR"]
patch_dir = os.environ["PATCH_DIR"]
work = tempfile.mkdtemp()
try:
    with zipfile.ZipFile(jar_path, "r") as z:
        z.extractall(work)
    for rel in ["app/auth.clj", "app/http/session.clj", "app/config.clj"]:
        src = os.path.join(patch_dir, rel)
        dst = os.path.join(work, rel)
        shutil.copyfile(src, dst)
        print(f"overlaid {rel}")
    new_path = jar_path + ".new"
    with zipfile.ZipFile(jar_path, "r") as zin:
        names = zin.namelist()
        comments = {n: zin.getinfo(n).comment for n in names}
    with zipfile.ZipFile(new_path, "w", zipfile.ZIP_DEFLATED) as zout:
        for root, _, files in os.walk(work):
            for fn in files:
                full = os.path.join(root, fn)
                arc = os.path.relpath(full, work)
                zout.write(full, arc)
    os.replace(new_path, jar_path)
    print(f"patched {jar_path}")
finally:
    shutil.rmtree(work, ignore_errors=True)
PY
echo "patched $JAR"
ls -lh "$JAR"
