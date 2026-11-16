#!/bin/bash
# Builder prefetch step for ou-ics (runs as the unprivileged build user WITH network; downloads wheels only, executes none of them):
#   debian/wheels/cp311  debian/wheels/cp312   binary wheels, every file verified against the sha256 hashes of ics/requirements.lock
#   debian/wheel-licenses.json                 METADATA licence fields of the cp312 set (the pure-python wheels are identical in both sets)
# --only-binary=:all: means a dependency without a wheel for either interpreter FAILS the build (no sdist is ever built).
set -euo pipefail
D="$1"
LOCK="$D/ics/requirements.lock"
[ -f "$LOCK" ] || { echo "no $LOCK"; exit 1; }
# pip comes from the interpreter's own ensurepip bundle (python3-venv): nothing is fetched to get pip itself
python3 -m venv /tmp/ou-pip
PIP=/tmp/ou-pip/bin/pip
PLAT=(--platform manylinux2014_x86_64 --platform manylinux_2_17_x86_64 --platform manylinux_2_28_x86_64 --platform manylinux_2_34_x86_64 --platform manylinux_2_5_x86_64 --platform manylinux1_x86_64 --platform any)
for v in 311 312; do
  mkdir -p "$D/debian/wheels/cp$v"
  $PIP download -q --disable-pip-version-check --require-hashes --no-deps --only-binary=:all: \
    --python-version "${v:0:1}.${v:1}" --implementation cp --abi "cp$v" "${PLAT[@]}" -d "$D/debian/wheels/cp$v" -r "$LOCK"
done
python3 -I "$D/debian/wheel-licenses.py" "$D/debian/wheels/cp312" "$D/debian/wheel-licenses.json"
echo "wheels: cp311 $(ls "$D/debian/wheels/cp311" | wc -l), cp312 $(ls "$D/debian/wheels/cp312" | wc -l)"
