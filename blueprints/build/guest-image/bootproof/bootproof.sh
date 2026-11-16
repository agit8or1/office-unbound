#!/usr/bin/env bash
# Boot proof of a golden image WITHOUT KVM (qemu TCG, software emulation) on the builder: first boot -> callback -> HMAC verified -> enrollment over pinned
# TLS -> secrets cleared. Run as root inside the builder (ou-img1). Usage: bootproof.sh <image.qcow2> [workdir]
# Needs: qemu-system-x86_64, a local PostgreSQL (roles ics_test_owner/ics_test_app, database ics_proof: see docs/status/golden-image-results.md),
# /opt/ics-venv (python venv of the ICS) and /opt/ics-src (the ics/ tree). The image is booted through a COPY-ON-WRITE overlay: it is never modified.
set -euo pipefail
IMG=${1:?usage: bootproof.sh <image.qcow2> [workdir]}
W=${2:-/var/tmp/bootproof}
HERE=$(cd "$(dirname "$0")" && pwd)
CB_PORT=${CB_PORT:-8445}; AGENT_FWD=${AGENT_FWD:-18443}; TIMEOUT=${TIMEOUT:-1200}
PGPASS=$(cat /var/tmp/proof-db.pass)
export ICS_PROOF_DB_APP="postgresql+psycopg://ics_test_app:$PGPASS@127.0.0.1:5432/ics_proof" ICS_PROOF_DB_OWNER="postgresql+psycopg://ics_test_owner:$PGPASS@127.0.0.1:5432/ics_proof"
rm -rf "$W"; mkdir -p "$W"; chmod 700 "$W"
qemu-img create -q -f qcow2 -F qcow2 -b "$(readlink -f "$IMG")" "$W/overlay.qcow2"
/opt/ics-venv/bin/python -I "$HERE/ics_side.py" "$W" "$CB_PORT" "$AGENT_FWD" "$TIMEOUT" > "$W/ics.log" 2>&1 &
ICS_PID=$!
for _ in $(seq 60); do [ -s "$W/smbios.json" ] && break; sleep 1; done
[ -s "$W/smbios.json" ] || { cat "$W/ics.log"; exit 1; }
SER=$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1]))["serial"])' "$W/smbios.json")
SKU=$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1]))["sku"])' "$W/smbios.json")
FAM=$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1]))["family"])' "$W/smbios.json")
FAM=${FAMILY_OVERRIDE:-$FAM}      # negative test: a certificate pin that is not the ICS's
echo "starting qemu TCG (no KVM), SMBIOS type 1 serial/sku/family set, user-mode network, agent port forwarded 127.0.0.1:$AGENT_FWD -> guest 8443"
date -u +%FT%TZ > "$W/qemu.start"
qemu-system-x86_64 -machine pc -accel tcg,thread=multi -cpu max -smp 2 -m 1024 -display none -serial "file:$W/console.log" -monitor none -no-reboot \
  -drive "file=$W/overlay.qcow2,if=none,id=d0" -device virtio-scsi-pci,id=s0 -device scsi-hd,drive=d0 \
  -nic "user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:$AGENT_FWD-:8443" -smbios "type=1,serial=$SER,sku=$SKU,family=$FAM" > "$W/qemu.err" 2>&1 &
QPID=$!
rc=0
wait "$ICS_PID" || rc=$?
date -u +%FT%TZ > "$W/qemu.end"
kill "$QPID" 2>/dev/null || true
wait "$QPID" 2>/dev/null || true
cat "$W/ics.log"
echo "ics_side exit code: $rc"
# evidence.json = the ics_side result + the sha256 of the image that was booted. The test runner (`ou-test-attest run image-first-boot <path>` makes the runner copy and boot the image in the boot-proof machine; this file is what its root helper reads,
# run under the ou-testrunner identity on the release host) checks it and signs the attestation that ou-image-sign record-test requires (review 6 H1).
python3 -I - "$W" "$(readlink -f "$IMG")" <<'PY' || true
import hashlib, json, sys
w, img = sys.argv[1:3]
txt = open(w + "/ics.log").read()
i = txt.rfind("\n{\n")
ev = json.loads(txt[i + 1:] if i >= 0 else txt[txt.index("{"):])
h = hashlib.sha256()
with open(img, "rb") as f:
    for c in iter(lambda: f.read(1 << 20), b""):
        h.update(c)
ev["image_sha256"] = h.hexdigest()
json.dump(ev, open(w + "/evidence.json", "w"), indent=1, sort_keys=True)
print("evidence.json written for image", ev["image_sha256"])
PY
sed 's/\x1b\[[0-9;]*m//g' "$W/console.log" | tr -d '\r' | tail -15
exit "$rc"
