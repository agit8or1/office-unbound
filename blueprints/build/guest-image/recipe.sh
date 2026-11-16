#!/usr/bin/env bash
# Office Unbound golden guest image (ADR-0008 recipe; docs/status/bootstrap-v2.md, docs/status/golden-image-results.md).
# Run as root on the BUILDER (an isolated unprivileged nspawn machine, e.g. ou-img1; NOT the ICS). Re-runnable.
#   recipe.sh <debian-12|ubuntu-24.04> fetch | verify | build | manifest | sign | all
# Needs on the builder: mmdebstrap, systemd-repart (>= 255 for ExcludeFiles), dosfstools, e2fsprogs, mtools, syslinux + syslinux-common, gdisk, util-linux,
# qemu-utils, gnupg, curl, python3.  Output: $OUT/ou-golden-<os>-<date>.qcow2, <img>.sbom.cdx.json, <img>.licenses.json, SHA256SUMS (+ SHA256SUMS.sig).
#
# Why this build method (evaluated 2026-11-15 in ou-img1, details in the results doc): an unprivileged nspawn has no loop devices, no nbd, no KVM and no
# libguestfs appliance, so "customise an upstream qcow2" (virt-customize, qemu-nbd, loop mount) cannot run. What does run: mmdebstrap builds a root TREE
# from the signed Debian archive (the archive Release signature is verified against PINNED keys), a chroot hook customises it, and systemd-repart +
# mkfs.ext4 -d / mcopy turn the tree into a partitioned raw image without any mount; syslinux (FAT, offset install) and systemd-boot make it bootable under
# SeaBIOS (the Proxmox default that image.import does not change) and UEFI. qemu-img converts raw -> qcow2.
#
# Supply chain: Debian = archive keys pinned by full fingerprint (os/debian-12.env, both authoritative sources recorded there). Ubuntu = detached
# signature of SHA256SUMS against the pinned cloud-image signing key + image hash from the signed file. A key whose fingerprint differs from the pin,
# a bad signature or a hash mismatch REFUSES (exit 4).
set -euo pipefail

OS=${1:?usage: recipe.sh <debian-12|ubuntu-24.04> <step>}
STEP=${2:-all}
HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=/dev/null
. "$HERE/os/$OS.env"
# shellcheck source=/dev/null
. "$HERE/tools.env"
WORK=${WORK:-/var/tmp/ou-guest-image}
OUT=${OUT:-$WORK/out}
KEYS=${KEYS:-$HERE/keys}
OU_REPO=${OU_REPO:-$WORK/ourrepo}                                  # the signed apt repo tree holding ou-node-agent (publish-dev.sh output)
OU_RELEASE_PUB=${OU_RELEASE_PUB:-$HERE/../keys/ou-release-lab.pub.asc}
OU_RELEASE_FPR=${OU_RELEASE_FPR:-$(cat "$HERE/../keys/ou-release-lab.FINGERPRINT")}
# REPRODUCIBILITY: SOURCE_DATE_EPOCH is REQUIRED (no wall clock fallback): it names the image and clamps every timestamp. Same recipe + same epoch +
# same package lock (os/<os>.packages.lock) => same image bytes (see docs/status/golden-image-prod-results.md for what is and is not identical).
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0}; export SOURCE_DATE_EPOCH
LOCK=${LOCK:-$HERE/os/$OS.packages.lock}
STAMP=$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y%m%d)
IMG=ou-golden-$OS-$STAMP.qcow2
mkdir -p "$WORK/up" "$OUT"

need() { command -v "$1" >/dev/null || { echo "missing tool: $1 ($2)" >&2; exit 2; }; }
fpr_list() { gpg --show-keys --with-colons "$1" 2>/dev/null | awk -F: '/^pub:/{p=1;next} /^fpr:/&&p{print $10;p=0}'; }

# ---------------------------------------------------------------- trust anchors
pinned_keyring() {   # Debian: builds the dearmored keyring from the key files shipped in keys/, REFUSING unless each file's primary fingerprint is a pinned one
  need gpg gnupg
  local f fp ok out=$1; : > "$out"
  for f in $ARCHIVE_KEY_FILES; do
    [ -s "$KEYS/$f" ] || { echo "missing key file $KEYS/$f" >&2; exit 3; }
    [ "$(fpr_list "$KEYS/$f" | wc -l)" = 1 ] || { echo "$f must hold exactly one primary key" >&2; exit 4; }
    fp=$(fpr_list "$KEYS/$f"); ok=0
    for p in $ARCHIVE_KEY_FPRS; do [ "$fp" = "$p" ] && ok=1; done
    [ $ok = 1 ] || { echo "REFUSED: key $f has fingerprint $fp which is not pinned in os/$OS.env" >&2; exit 4; }
    gpg --dearmor < "$KEYS/$f" >> "$out"
  done
  # every pinned fingerprint must be present (the pin list is exact, not a superset check on one side only)
  for p in $ARCHIVE_KEY_FPRS; do gpg --show-keys --with-colons "$out" 2>/dev/null | grep -q "^fpr:::::::::$p:" || { echo "REFUSED: pinned key $p missing" >&2; exit 4; }; done
}

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
  local MODE=${1:-$UPSTREAM_MODE}
  case "$MODE" in
    bootstrap) echo "bootstrap mode: nothing to download here; packages are fetched by mmdebstrap and verified against the pinned archive keys in the build step"; pinned_keyring "$WORK/up/archive-pinned.gpg" ;;
    cloudimage)
      check_serial
      [ -n "${UPSTREAM_KEY_FPR:-}" ] || { echo "os/$OS.env: UPSTREAM_KEY_FPR is not pinned" >&2; exit 3; }
      need curl curl; cd "$WORK/up"
      for f in "$UPSTREAM_IMAGE" "$UPSTREAM_SUMS" "$UPSTREAM_SUMS_SIG"; do curl -fsSLO --proto '=https' --tlsv1.2 "$UPSTREAM_BASE/$f"; done
      echo "fetched $(ls)" ;;
  esac
}

do_verify() {
  local MODE=${1:-$UPSTREAM_MODE}
  need gpg gnupg
  case "$MODE" in
    bootstrap) pinned_keyring "$WORK/up/archive-pinned.gpg"; echo "archive keys verified against the pinned fingerprints: $ARCHIVE_KEY_FPRS" ;;
    cloudimage)
      need sha256sum coreutils; cd "$WORK/up"
      local kf=${UPSTREAM_KEY_FILE:-$KEYS/${UPSTREAM_KEY_DEFAULT:-}}
      [ -s "$kf" ] || { echo "no upstream key file" >&2; exit 3; }
      local gh; gh=$(mktemp -d); chmod 700 "$gh"; trap 'rm -rf "$gh"' RETURN
      gpg --homedir "$gh" --batch --import "$kf" 2>/dev/null
      local have; have=$(gpg --homedir "$gh" --batch --with-colons --fingerprint | awk -F: '/^fpr:/{print $10; exit}')
      [ "$have" = "$UPSTREAM_KEY_FPR" ] || { echo "REFUSED: upstream key fingerprint $have != pinned $UPSTREAM_KEY_FPR" >&2; exit 4; }
      gpg --homedir "$gh" --batch --status-fd 1 --verify "$UPSTREAM_SUMS_SIG" "$UPSTREAM_SUMS" 2>/dev/null | grep -q "^\[GNUPG:\] VALIDSIG $UPSTREAM_KEY_FPR " \
        || { echo "REFUSED: signature of $UPSTREAM_SUMS does not verify against the pinned key" >&2; exit 4; }
      grep -F " *$UPSTREAM_IMAGE" "$UPSTREAM_SUMS" | $UPSTREAM_SUM_TOOL -c - || { echo "REFUSED: image checksum mismatch" >&2; exit 4; }
      check_serial
      printf '%s\n' "$UPSTREAM_SERIAL" > "$WORK/upstream-serial.last"      # only after signature + checksum passed: the next build may not go below this
      echo "upstream image verified (signature by the pinned key + checksum), build $UPSTREAM_SERIAL" ;;
  esac
}

# ---------------------------------------------------------------- build
fetch_syft() {
  [ -x "$WORK/tools/syft" ] && return 0
  need curl curl; mkdir -p "$WORK/tools"
  curl -fsSL --proto '=https' --tlsv1.2 -o "$WORK/tools/syft.tgz" "$SYFT_URL"
  echo "$SYFT_SHA256  $WORK/tools/syft.tgz" | sha256sum -c - >/dev/null || { echo "REFUSED: syft checksum mismatch" >&2; rm -f "$WORK/tools/syft.tgz"; exit 4; }
  tar -xzf "$WORK/tools/syft.tgz" -C "$WORK/tools" syft
}

do_build() {
  [ "$SOURCE_DATE_EPOCH" -gt 1000000000 ] || { echo "set SOURCE_DATE_EPOCH (unix seconds): a golden image is built for an explicit epoch, never for 'now'" >&2; exit 3; }
  [ "$UPSTREAM_MODE" = bootstrap ] || { echo "build for UPSTREAM_MODE=$UPSTREAM_MODE is not supported" >&2; exit 5; }
  for t in "mmdebstrap mmdebstrap" "systemd-repart systemd-repart" "mkfs.vfat dosfstools" "mkfs.ext4 e2fsprogs" "mcopy mtools" "syslinux syslinux" "sgdisk gdisk" "qemu-img qemu-utils" "sfdisk util-linux" "unshare util-linux"; do need ${t% *} ${t#* }; done
  do_verify
  fetch_syft
  local R=$WORK/rootfs PL=$WORK/payload
  rm -rf "$R" "$PL" "$WORK/raw.img"; mkdir -p "$PL"
  # ---- payload: exactly what is copied into the image root (the agent comes ONLY from the signed repo; the repo's Release signature is checked by apt)
  [ -s "$OU_REPO/dists/dev/InRelease" ] || { echo "no signed Office Unbound repo at $OU_REPO (agent-deb/build-deb.sh + publish-dev.sh)" >&2; exit 3; }
  cp -r "$OU_REPO" "$PL/ourrepo"
  cp "$OU_RELEASE_PUB" "$PL/ou-release.pub.asc"; echo "$OU_RELEASE_FPR" > "$PL/ou-release.FINGERPRINT"
  cp "$HERE/customize.sh" "$HERE/ou-bootstrap.service" "$HERE/ou-growroot.service" "$HERE/ou-growroot" "$HERE/ou-bootcfg" "$HERE/ou-seal" "$HERE/nftables.conf" "$PL/"
  # cloud-init is NOT installed (absent, not merely disabled); no ssh server. See tests/ for what the independent boot tester asserts.
  local PKGS="systemd-sysv,systemd-resolved,systemd-timesyncd,udev,dbus,dbus-user-session,libpam-systemd,kmod,iproute2,iputils-ping,ca-certificates,gnupg,apt-utils,\
$KERNEL_PKG,initramfs-tools,systemd-boot-efi,cloud-guest-utils,gdisk,fdisk,e2fsprogs,dosfstools,\
podman,uidmap,passt,crun,netavark,aardvark-dns,systemd-container,nftables,polkitd,python3,python3-cryptography,unattended-upgrades,netbase"
  PKGS=$(echo "$PKGS" | tr -d '\\\n ')
  local KR=$WORK/up/archive-pinned.gpg
  # package lock: when it exists every package of the image is pinned to the recorded version (apt preference, priority 1001). A pinned version that the
  # archive no longer serves makes the build REFUSE (no silent drift); `OU_RELOCK=1` (or a missing lock) resolves afresh and writes the new lock.
  local PREF=$WORK/ou-lock.pref; : > "$PREF"
  if [ -s "$LOCK" ] && [ "${OU_RELOCK:-0}" != 1 ]; then
    awk -F= 'NF==2{printf "Package: %s\nPin: version %s\nPin-Priority: 1001\n\n",$1,$2}' "$LOCK" > "$PREF"
    echo "using package lock $LOCK ($(wc -l < "$LOCK") packages)"
  else
    echo "NO package lock in use: this build resolves the archive of the moment and writes a new lock (not reproducible against an older one)" >&2
  fi
  local MIRRORS=("deb [signed-by=$KR] $MIRROR $SUITE $COMPONENTS" "deb [signed-by=$KR] $MIRROR $SUITE-updates $COMPONENTS" "deb [signed-by=$KR] $SECURITY_MIRROR $SECURITY_SUITE $COMPONENTS")
  # a private mount namespace: mmdebstrap's chroot mounts must not leak into (or break) the builder's own cgroup/proc mounts
  unshare -m --propagation private mmdebstrap --mode=root --variant=minbase --skip=check/empty --keyring="$KR" --include="$PKGS" \
    --aptopt='Apt::Install-Recommends "false"' \
    --setup-hook='mkdir -p "$1/etc/apt/preferences.d" && cp '"$PREF"' "$1/etc/apt/preferences.d/ou-lock"' \
    --customize-hook='sha256sum "$1"/var/lib/apt/lists/*InRelease | sed "s|  .*/lists/|  |" | sort -k2 > '"$WORK"'/inrelease.sha256' \
    --customize-hook='copy-in '"$PL"' /tmp' \
    --customize-hook='chroot "$1" env OU_OS='"$OS"' ROOT_UUID='"$ROOT_UUID"' ESP_UUID='"$ESP_UUID"' UNATTENDED_ORIGIN='"'$UNATTENDED_ORIGIN'"' SOURCE_DATE_EPOCH='"$SOURCE_DATE_EPOCH"' sh /tmp/payload/customize.sh' \
    "$SUITE" "$R" "${MIRRORS[@]}"
  # shipped apt sources: the same pinned-key entries (unattended-upgrades needs them), keyring = the pinned archive keyring
  install -m 0644 "$KR" "$R/usr/share/keyrings/ou-archive-pinned.gpg"
  cat > "$R/etc/apt/sources.list.d/$DISTRO.sources" <<EOT
Types: deb
URIs: $MIRROR
Suites: $SUITE $SUITE-updates
Components: $COMPONENTS
Signed-By: /usr/share/keyrings/ou-archive-pinned.gpg

Types: deb
URIs: $SECURITY_MIRROR
Suites: $SECURITY_SUITE
Components: $COMPONENTS
Signed-By: /usr/share/keyrings/ou-archive-pinned.gpg
EOT
  rm -f "$R/etc/apt/sources.list" "$R/etc/apt/preferences.d/ou-lock"
  install -D -m 0644 /usr/lib/syslinux/modules/bios/ldlinux.c32 "$R/boot/syslinux/ldlinux.c32"
  # ---- exact package list (the lock) of the FINAL tree; compare with the lock in use
  dpkg-query --admindir="$R/var/lib/dpkg" -W -f '${Package}=${Version}\n' | LC_ALL=C sort > "$WORK/packages.lock.new"
  if [ -s "$LOCK" ] && [ "${OU_RELOCK:-0}" != 1 ]; then
    diff -u "$LOCK" "$WORK/packages.lock.new" >&2 || { echo "REFUSED: the built package set differs from $LOCK (see diff); refresh the lock deliberately with OU_RELOCK=1" >&2; exit 6; }
  fi
  # ---- reproducible normalisation of the tree: files that only carry build-time state are removed, every timestamp is clamped to SOURCE_DATE_EPOCH
  rm -rf "$R/var/cache/ldconfig/aux-cache" "$R/var/cache/debconf"/*-old "$R/var/lib/dpkg"/*-old "$R/var/log/alternatives.log" "$R/var/log/dpkg.log" "$R/var/log/bootstrap.log" "$R/var/cache/apt"
  awk -F: -v OFS=: -v d=$(( SOURCE_DATE_EPOCH / 86400 )) '$3 ~ /^[0-9]+$/ && $3 > d {$3=d} {print}' "$R/etc/shadow" > "$R/etc/shadow.new"
  cat "$R/etc/shadow.new" > "$R/etc/shadow"; rm "$R/etc/shadow.new"
  find "$R" -xdev -newermt "@$SOURCE_DATE_EPOCH" -exec touch -h --date="@$SOURCE_DATE_EPOCH" {} + 2>/dev/null || true
  # ---- tree -> partitioned raw image (no mount, no loop device)
  local D=$WORK/repart.d; rm -rf "$D"; mkdir -p "$D"
  printf '[Partition]\nType=esp\nUUID=%s\nLabel=ou-boot\nFormat=vfat\nCopyFiles=/boot:/\nSizeMinBytes=256M\nSizeMaxBytes=256M\n' "$ESP_UUID" > "$D/10-boot.conf"
  printf '[Partition]\nType=root-x86-64\nUUID=%s\nLabel=ou-root\nFormat=ext4\nCopyFiles=/\nExcludeFiles=/boot\nMakeDirectories=/boot\n' "$ROOT_UUID" > "$D/20-root.conf"
  systemd-repart --empty=create --size="$IMAGE_SIZE" --definitions="$D" --root="$R" --seed=7c1c2cb3-8a63-4cf5-9a4f-0a0f1f2f3f40 --dry-run=no --offline=yes "$WORK/raw.img"
  # BIOS boot: protective-MBR boot code + legacy-bootable attribute on the FAT partition + syslinux installed into it (offset install, works on a plain file)
  dd if=/usr/lib/syslinux/mbr/gptmbr.bin of="$WORK/raw.img" bs=440 count=1 conv=notrunc status=none
  sgdisk -A 1:set:2 "$WORK/raw.img" >/dev/null
  local off; off=$(sfdisk -J "$WORK/raw.img" | python3 -I -c 'import json,sys;print(json.load(sys.stdin)["partitiontable"]["partitions"][0]["start"]*512)')
  syslinux --offset "$off" --directory /syslinux --install "$WORK/raw.img"
  # SBOM (syft, pinned) + licence scan over the final tree; the two non-deterministic CycloneDX fields (random serialNumber, wall-clock timestamp) are
  # replaced by values derived from the package lock and SOURCE_DATE_EPOCH
  "$WORK/tools/syft" scan "dir:$R" -o cyclonedx-json="$WORK/sbom.raw.json" -q
  python3 -I "$HERE/licensescan.py" "$WORK/sbom.raw.json" "$HERE/license-policy.yaml" "$OS" "$WORK/sbom.final.json" "$OUT/$IMG.licenses.json"
  python3 -I "$HERE/sbom_normalise.py" "$WORK/sbom.final.json" "$WORK/packages.lock.new" "$SOURCE_DATE_EPOCH"
  qemu-img convert -O qcow2 -c "$WORK/raw.img" "$OUT/$IMG"
  mv "$WORK/sbom.final.json" "$OUT/$IMG.sbom.cdx.json"
  cp "$WORK/packages.lock.new" "$OUT/$IMG.packages.lock"
  if [ ! -s "$LOCK" ] || [ "${OU_RELOCK:-0}" = 1 ]; then cp "$WORK/packages.lock.new" "$LOCK"; echo "wrote package lock $LOCK" >&2; fi
  python3 -I "$HERE/manifest.py" provenance --os "$OS" --epoch "$SOURCE_DATE_EPOCH" --recipe-dir "$HERE" --lock "$LOCK" --inrelease "$WORK/inrelease.sha256" \
    --commit "${OU_RECIPE_COMMIT:-unknown}" --tool "mmdebstrap=$(mmdebstrap --version)" --tool "systemd-repart=$(systemd-repart --version | head -1)" \
    --tool "mkfs.ext4=$(mkfs.ext4 -V 2>&1 | head -1)" --tool "qemu-img=$(qemu-img --version | head -1)" --tool "syft=$SYFT_VERSION" > "$OUT/$IMG.provenance.json"
  echo "built $OUT/$IMG ($(du -h "$OUT/$IMG" | cut -f1))"
}

# Manifest v2 (docs/status/golden-image-prod-results.md s4): ONE signed JSON document binding name, monotonic version, image / package-list / SBOM hashes,
# build provenance and the boot-test attestation. Built here UNSIGNED from the build outputs and the attestation that ou-test-attest produced for THIS image
# hash ($OUT/$IMG.attestation.json, never typed by hand). Version: OU_IMAGE_VERSION (integer, must exceed the last released one; the signer enforces it).
do_manifest() {
  cd "$OUT"
  [ -f "$IMG" ] || IMG=$(ls ou-golden-"$OS"-*.qcow2 | tail -1)
  python3 -I "$HERE/manifest.py" build --image "$IMG" --sbom "$IMG.sbom.cdx.json" --packages "$IMG.packages.lock" --provenance "$IMG.provenance.json" \
    --attestation "$IMG.attestation.json" --version "${OU_IMAGE_VERSION:?set OU_IMAGE_VERSION (monotonic integer)}" > manifest.json
  echo "manifest.json:"; cat manifest.json
}

# Signing is NOT done with a key reachable from the builder. The dedicated signer (signer/ou-image-sign, owned by the signer agent) must, for manifest v2,
# re-hash image/SBOM/package list itself, verify the ou-test-attest signature + that the attested sha256 is the image, take the version from its own
# monotonic state and sign the canonical manifest bytes (see docs/status/golden-image-prod-results.md "Signer contract"). Until that lands, the lab uses
# `manifest.py lab-sign` with a throw-away lab key (NOT a release key).
do_sign() {
  cd "$OUT"
  [ -f manifest.json ] || { echo "run the manifest step first" >&2; exit 3; }
  if [ -n "${OU_IMAGE_SIGN_CMD:-}" ]; then
    tar --owner=0 --group=0 --numeric-owner --mtime=@0 -c manifest.json "$IMG" "$IMG.sbom.cdx.json" "$IMG.packages.lock" "$IMG.provenance.json" "$IMG.attestation.json" | $OU_IMAGE_SIGN_CMD sign-manifest > "$WORK/signed.tar"
    tar -x -C "$OUT" -f "$WORK/signed.tar" --no-same-owner manifest.json manifest.json.sig
  else
    python3 -I "$HERE/manifest.py" lab-sign --manifest manifest.json --key "${OU_LAB_SIGN_KEY:?OU_LAB_SIGN_KEY (lab ECDSA P-256 private key PEM)}" > manifest.json.sig
  fi
  echo "signed manifest.json ($(wc -c < manifest.json.sig) bytes base64 signature)"
}

case "$STEP" in
  fetch) do_fetch ;; verify) do_verify ;; fetch-upstream) do_fetch cloudimage ;; verify-upstream) do_verify cloudimage ;; build) do_build ;; manifest) do_manifest ;; sign) do_sign ;;
  all) do_fetch; do_verify; do_build; echo "now: independent boot test (tests/image-first-boot via ou-test-attest), then manifest + sign on the release host" ;;
  *) echo "unknown step $STEP" >&2; exit 2 ;;
esac
