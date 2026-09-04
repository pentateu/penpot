#!/bin/sh
# Patch penpot.jar with ISWE JWT source via entry-copy (preserve all entries).
# Usage: patch-jar.sh <penpot.jar path> <patch dir with app/auth.clj app/http/session.clj app/config.clj>
# Replaces only the 3 ISWE files, copies all other entries byte-identical
# (preserves order, compression, manifest-first). No .orig kept in image.
set -eu
JAR="${1:?jar path required}"
PATCH_DIR="${2:?patch dir required}"
PATCH_DIR="$PATCH_DIR" JAR="$JAR" python3 - <<'PY'
import os, zipfile
jar_path = os.environ["JAR"]
patch_dir = os.environ["PATCH_DIR"]
replace = {
    "app/auth.clj": os.path.join(patch_dir, "app/auth.clj"),
    "app/http/session.clj": os.path.join(patch_dir, "app/http/session.clj"),
    "app/config.clj": os.path.join(patch_dir, "app/config.clj"),
}
for arc, src in replace.items():
    assert os.path.isfile(src), f"missing patch file {src}"
new_path = jar_path + ".new"
with zipfile.ZipFile(jar_path, "r") as zin:
    with zipfile.ZipFile(new_path, "w") as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            if item.filename in replace:
                with open(replace[item.filename], "rb") as f:
                    data = f.read()
                print(f"overlaid {item.filename}")
            # Preserve ZipInfo (order, compress_type, date, perms) verbatim.
            zout.writestr(item, data)
os.replace(new_path, jar_path)
print(f"patched {jar_path}")
PY
echo "patched $JAR"
ls -lh "$JAR"
