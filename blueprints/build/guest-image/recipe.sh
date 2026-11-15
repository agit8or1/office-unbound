#!/usr/bin/env bash
# Office Unbound golden guest image (ADR-0008 recipe; docs/status/bootstrap-v2.md): upstream cloud image + node agent + ou-bootstrap.service.
# Run as root on the BUILDER (not the ICS). Re-runnable. Usage:   recipe.sh <debian-12|ubuntu-24.04> fetch | verify | build | sbom | manifest | all
#   - signing is a separate step on the offline release host:      recipe.sh <os> sign   (needs RELEASE_KEY, an ECDSA P-256 PEM)
# Output: $OUT/ou-golden-<os>-<date>.qcow2, .sbom.cdx.json, SHA256SUMS (+ SHA256SUMS.sig after `sign`). Nothing here talks to a Proxmox or an ICS.
#
# Supply chain (ADR-0008 steps 1, 5, 6, 8): the upstream image is accepted ONLY when (1) the upstream checksum file's detached signature verifies
# against the signing key whose fingerprint is PINNED in the os profile (operator action, out of band; the profile ships with the fingerprint unset
# and `fetch` refuses to run until it is pinned), and (2) the image's SHA-256/512 appears in that signed checksum file.
set -euo pipefail

OS=${1:?usage: recipe.sh <debian-12|ubuntu-24.04> <step>}
STEP=${2:-all}
HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=/dev/null
. "$HERE/os/$OS.env"
WORK=${WORK:-/var/tmp/ou-guest-image}
OUT=${OUT:-$WORK/out}
AGENT_SRC=${AGENT_SRC:-$HERE/../../../ics/agent}
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(date +%s)}
STAMP=$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y%m%d)
IMG=ou-golden-$OS-$STAMP.qcow2
mkdir -p "$WORK/up" "$OUT"

need() { command -v "$1" >/dev/null || { echo "missing tool: $1 ($2)" >&2; exit 2; }; }

check_serial() {   # review 5 L7: dated pin + freshness + never backwards
  [ -n "${UPSTREAM_SERIAL:-}" ] || { echo "os/$OS.env: UPSTREAM_SERIAL is not pinned (a dated upstream build such as 20261101-1234 or release-20261101); 'latest' is not accepted." >&2; exit 3; }
  local d; d=$(printf '%s' "$UPSTREAM_SERIAL" | grep -oE '[0-9]{8}' | head -1)
  [ -n "$d" ] || { echo "UPSTREAM_SERIAL has no YYYYMMDD date" >&2; exit 3; }
  local today; today=${OU_TODAY:-$(date -u +%Y%m%d)}
  if [ "${OU_ALLOW_STALE_UPSTREAM:-0}" != 1 ]; then
    local age=$(( ( $(date -u -d "$today" +%s) - $(date -u -d "$d" +%s) ) / 86400 ))
    [ "$age" -le "${UPSTREAM_MAX_AGE_DAYS:-60}" ] || { echo "upstream build $UPSTREAM_SERIAL is $age days old (max ${UPSTREAM_MAX_AGE_DAYS:-60}); pin a newer, verified build" >&2; exit 3; }
  fi
  local last; last=$(cat "$WORK/upstream-serial.last" 2>/dev/null | grep -oE '[0-9]{8}' | head -1 || true)
  if [ -n "$last" ] && [ "$d" -lt "$last" ]; then echo "upstream build $UPSTREAM_SERIAL ($d) is OLDER than the last accepted build ($last): refusing to go backwards" >&2; exit 3; fi
  UPSTREAM_BASE=${UPSTREAM_BASE:-$UPSTREAM_BASE_ROOT/$UPSTREAM_SERIAL}
}

do_fetch() {
  check_serial
  [ -n "${UPSTREAM_KEY_FPR:-}" ] || { echo "os/$OS.env: UPSTREAM_KEY_FPR is not pinned. Verify the upstream signing key out of band and pin its full fingerprint first." >&2; exit 3; }
  need curl curl; need gpg gnupg
  cd "$WORK/up"
  for f in "$UPSTREAM_IMAGE" "$UPSTREAM_SUMS" "$UPSTREAM_SUMS_SIG"; do curl -fsSLO --proto '=https' --tlsv1.2 "$UPSTREAM_BASE/$f"; done
  echo "fetched $(ls)"
}

do_verify() {
  need gpg gnupg; need sha256sum coreutils
  cd "$WORK/up"
  local gh; gh=$(mktemp -d); chmod 700 "$gh"
  [ -n "${UPSTREAM_KEY_FILE:-}" ] && [ -s "$UPSTREAM_KEY_FILE" ] || { echo "UPSTREAM_KEY_FILE (the upstream public key, obtained out of band) is required" >&2; exit 3; }
  gpg --homedir "$gh" --batch --import "$UPSTREAM_KEY_FILE" 2>/dev/null
  local have; have=$(gpg --homedir "$gh" --batch --with-colons --fingerprint | awk -F: '/^fpr:/{print $10; exit}')
  [ "$have" = "$UPSTREAM_KEY_FPR" ] || { echo "upstream key fingerprint $have != pinned $UPSTREAM_KEY_FPR" >&2; exit 4; }
  gpg --homedir "$gh" --batch --status-fd 1 --verify "$UPSTREAM_SUMS_SIG" "$UPSTREAM_SUMS" 2>/dev/null | grep -q "^\[GNUPG:\] VALIDSIG $UPSTREAM_KEY_FPR " \
    || { echo "signature of $UPSTREAM_SUMS does not verify against the pinned key" >&2; exit 4; }
  grep -F " $UPSTREAM_IMAGE" "$UPSTREAM_SUMS" | $UPSTREAM_SUM_TOOL -c - || { echo "image checksum mismatch" >&2; exit 4; }
  check_serial
  printf '%s\n' "$UPSTREAM_SERIAL" > "$WORK/upstream-serial.last"      # only after signature + checksum passed: the next build may not go below this
  echo "upstream image verified (signature + checksum), build $UPSTREAM_SERIAL"
}

do_build() {
  need qemu-img qemu-utils; need virt-customize libguestfs-tools
  cp "$WORK/up/$UPSTREAM_IMAGE" "$WORK/work.qcow2"
  qemu-img resize "$WORK/work.qcow2" 4G >/dev/null
  # the agent bundle is exactly the tree the ICS ships (ics/agent: ou_agent/ + deploy/); it is copied, never fetched
  rm -rf "$WORK/payload"; mkdir -p "$WORK/payload"
  cp -r "$AGENT_SRC/ou_agent" "$AGENT_SRC/deploy" "$WORK/payload/"
  find "$WORK/payload" -name __pycache__ -prune -exec rm -rf {} +
  cp "$HERE/customize.sh" "$HERE/ou-bootstrap.service" "$HERE/nftables.conf" "$HERE/sbom.py" "$WORK/payload/"
  virt-customize -a "$WORK/work.qcow2" --network --copy-in "$WORK/payload:/tmp" --run-command "OU_OS=$OS sh /tmp/payload/customize.sh" \
    --run-command "python3 /tmp/payload/sbom.py $OS > /root/ou-sbom.cdx.json" --copy-out /root/ou-sbom.cdx.json:"$WORK" \
    --delete /tmp/payload --delete /root/ou-sbom.cdx.json --truncate /etc/machine-id --delete /var/lib/dbus/machine-id
  qemu-img convert -O qcow2 -c "$WORK/work.qcow2" "$OUT/$IMG"
  mv "$WORK/ou-sbom.cdx.json" "$OUT/$IMG.sbom.cdx.json"
}

do_manifest() {
  cd "$OUT"
  sha256sum "$IMG" "$IMG.sbom.cdx.json" > SHA256SUMS
  echo "manifest:"; cat SHA256SUMS
}

do_sign() {   # on the OFFLINE release host: needs RELEASE_KEY (ECDSA P-256 PEM); openssl output is DER, stored base64 (what ics/guest/golden.py verifies)
  need openssl openssl
  [ -n "${RELEASE_KEY:-}" ] || { echo "RELEASE_KEY is required" >&2; exit 3; }
  cd "$OUT"
  openssl dgst -sha256 -sign "$RELEASE_KEY" -out SHA256SUMS.sig.der SHA256SUMS
  base64 -w0 SHA256SUMS.sig.der > SHA256SUMS.sig && rm SHA256SUMS.sig.der
  echo "signed SHA256SUMS ($(wc -c < SHA256SUMS.sig) bytes base64)"
}

case "$STEP" in
  fetch) do_fetch ;; verify) do_verify ;; build) do_build ;; manifest) do_manifest ;; sign) do_sign ;;
  all) do_fetch; do_verify; do_build; do_manifest; echo "now sign on the release host: recipe.sh $OS sign" ;;
  *) echo "unknown step $STEP" >&2; exit 2 ;;
esac
