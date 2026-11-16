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
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(date +%s)}
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

do_fetch() {
  case "$UPSTREAM_MODE" in
    bootstrap) echo "bootstrap mode: nothing to download here; packages are fetched by mmdebstrap and verified against the pinned archive keys in the build step"; pinned_keyring "$WORK/up/archive-pinned.gpg" ;;
    cloudimage)
      [ -n "${UPSTREAM_KEY_FPR:-}" ] || { echo "os/$OS.env: UPSTREAM_KEY_FPR is not pinned" >&2; exit 3; }
      need curl curl; cd "$WORK/up"
      for f in "$UPSTREAM_IMAGE" "$UPSTREAM_SUMS" "$UPSTREAM_SUMS_SIG"; do curl -fsSLO --proto '=https' --tlsv1.2 "$UPSTREAM_BASE/$f"; done
      echo "fetched $(ls)" ;;
  esac
}

do_verify() {
  need gpg gnupg
  case "$UPSTREAM_MODE" in
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
      echo "upstream image verified (signature by the pinned key + checksum)" ;;
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
  [ "$UPSTREAM_MODE" = bootstrap ] || { echo "build for UPSTREAM_MODE=$UPSTREAM_MODE is not supported on an unprivileged builder (needs loop mount or libguestfs): see os/$OS.env" >&2; exit 5; }
  for t in "mmdebstrap mmdebstrap" "systemd-repart systemd-repart" "mkfs.vfat dosfstools" "mkfs.ext4 e2fsprogs" "mcopy mtools" "syslinux syslinux" "sgdisk gdisk" "qemu-img qemu-utils" "sfdisk util-linux" "unshare util-linux"; do need ${t% *} ${t#* }; done
  do_verify
  fetch_syft
  local R=$WORK/rootfs PL=$WORK/payload
  rm -rf "$R" "$PL" "$WORK/raw.img"; mkdir -p "$PL"
  # ---- payload: exactly what is copied into the image root (the agent comes ONLY from the signed repo; the repo's Release signature is checked by apt)
  [ -s "$OU_REPO/dists/dev/InRelease" ] || { echo "no signed Office Unbound repo at $OU_REPO (agent-deb/build-deb.sh + publish-dev.sh)" >&2; exit 3; }
  cp -r "$OU_REPO" "$PL/ourrepo"
  cp "$OU_RELEASE_PUB" "$PL/ou-release.pub.asc"; echo "$OU_RELEASE_FPR" > "$PL/ou-release.FINGERPRINT"
  cp "$HERE/customize.sh" "$HERE/ou-bootstrap.service" "$HERE/ou-growroot.service" "$HERE/ou-growroot" "$HERE/ou-bootcfg" "$HERE/nftables.conf" "$PL/"
  local PKGS="systemd-sysv,systemd-resolved,systemd-timesyncd,udev,dbus,dbus-user-session,libpam-systemd,kmod,iproute2,iputils-ping,ca-certificates,gnupg,apt-utils,\
linux-image-cloud-amd64,initramfs-tools,systemd-boot-efi,cloud-guest-utils,gdisk,fdisk,e2fsprogs,dosfstools,\
podman,uidmap,passt,crun,netavark,aardvark-dns,systemd-container,nftables,polkitd,python3,python3-cryptography,unattended-upgrades,cloud-init,\
netbase"
  PKGS=$(echo "$PKGS" | tr -d '\\\n ')
  local KR=$WORK/up/archive-pinned.gpg
  # a private mount namespace: mmdebstrap's chroot mounts must not leak into (or break) the builder's own cgroup/proc mounts
  unshare -m --propagation private mmdebstrap --mode=root --variant=minbase --skip=check/empty --keyring="$KR" --include="$PKGS" \
    --aptopt='Apt::Install-Recommends "false"' \
    --customize-hook='copy-in '"$PL"' /tmp' \
    --customize-hook='chroot "$1" env OU_OS='"$OS"' ROOT_UUID='"$ROOT_UUID"' ESP_UUID='"$ESP_UUID"' sh /tmp/payload/customize.sh' \
    "$DEBIAN_SUITE" "$R" \
    "deb [signed-by=$KR] $DEBIAN_MIRROR $DEBIAN_SUITE main" \
    "deb [signed-by=$KR] $DEBIAN_MIRROR $DEBIAN_SUITE-updates main" \
    "deb [signed-by=$KR] $DEBIAN_SECURITY_MIRROR $DEBIAN_SUITE-security main"
  # shipped apt sources: the same three pinned-key entries (unattended-upgrades needs them), keyring = the pinned archive keyring
  install -m 0644 "$KR" "$R/usr/share/keyrings/ou-debian-archive-pinned.gpg"
  cat > "$R/etc/apt/sources.list.d/debian.sources" <<EOF
Types: deb
URIs: $DEBIAN_MIRROR
Suites: $DEBIAN_SUITE $DEBIAN_SUITE-updates
Components: main
Signed-By: /usr/share/keyrings/ou-debian-archive-pinned.gpg

Types: deb
URIs: $DEBIAN_SECURITY_MIRROR
Suites: $DEBIAN_SUITE-security
Components: main
Signed-By: /usr/share/keyrings/ou-debian-archive-pinned.gpg
EOF
  rm -f "$R/etc/apt/sources.list"
  install -D -m 0644 /usr/lib/syslinux/modules/bios/ldlinux.c32 "$R/boot/syslinux/ldlinux.c32"
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
  # SBOM (syft, pinned) + licence scan over the final tree
  "$WORK/tools/syft" scan "dir:$R" -o cyclonedx-json="$WORK/sbom.raw.json" -q
  python3 -I "$HERE/licensescan.py" "$WORK/sbom.raw.json" "$HERE/license-policy.yaml" "$OS" "$WORK/sbom.final.json" "$OUT/$IMG.licenses.json"
  qemu-img convert -O qcow2 -c "$WORK/raw.img" "$OUT/$IMG"
  mv "$WORK/sbom.final.json" "$OUT/$IMG.sbom.cdx.json"
  echo "built $OUT/$IMG ($(du -h "$OUT/$IMG" | cut -f1))"
}

do_manifest() {
  cd "$OUT"
  [ -f "$IMG" ] || IMG=$(ls ou-golden-"$OS"-*.qcow2 | tail -1)
  sha256sum "$IMG" "$IMG.sbom.cdx.json" > SHA256SUMS
  echo "manifest:"; cat SHA256SUMS
}

# Signing is NOT done with a key reachable from the builder. On the release host the dedicated signer program does it: it re-hashes the files, needs a
# passing first-boot test record (ou-image-sign record-test) and prints SHA256SUMS + SHA256SUMS.sig. Lab usage (signer installed by install-image-signer.sh):
do_sign() {
  cd "$OUT"
  [ -f "$IMG" ] || IMG=$(ls ou-golden-"$OS"-*.qcow2 | tail -1)
  local SIGN=${OU_IMAGE_SIGN_CMD:-sudo -n -u ou-imgsign /usr/local/sbin/ou-image-sign}
  tar --owner=0 --group=0 --numeric-owner --mtime=@0 -c "$IMG" "$IMG.sbom.cdx.json" | $SIGN sign > "$WORK/signed.tar"
  tar -x -C "$OUT" -f "$WORK/signed.tar" --no-same-owner SHA256SUMS SHA256SUMS.sig
  echo "signed: $(cat SHA256SUMS | wc -l) manifest lines, signature $(wc -c < SHA256SUMS.sig) bytes base64"
}

case "$STEP" in
  fetch) do_fetch ;; verify) do_verify ;; build) do_build ;; manifest) do_manifest ;; sign) do_sign ;;
  all) do_fetch; do_verify; do_build; do_manifest; echo "now: boot proof (bootproof.sh), record-test, then recipe.sh $OS sign on the release host" ;;
  *) echo "unknown step $STEP" >&2; exit 2 ;;
esac
