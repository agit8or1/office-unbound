#!/usr/bin/env bash
# Office Unbound lab: restore an OpenCloud files-node backup onto a NEW, empty nspawn machine.
# Usage: sudo files-restore.sh <backup_dir> <new_machine> [base_image]
# Binary is re-fetched from the pinned upstream release and verified against versions.env AND the backup MANIFEST
# (we never restore executables from the backup). Refuses to touch an existing machine.
set -euo pipefail
B="${1:?backup dir}"; M="${2:?new machine name}"; BASE="${3:-ou-base-bookworm}"
HERE="$(cd "$(dirname "$0")" && pwd)"; . "$HERE/../common/versions.env"; . "$HERE/../common/packages.env"
# OU_INTO_EXISTING=1 (backup product, verification restore): restore the DATA into an already built scratch machine (running): services are stopped,
# /var/lib/opencloud is emptied first. Without it the machine must not exist (clone of the base image, as in the drill).
INTO="${OU_INTO_EXISTING:-0}"
get() { sed -n "s/^$1=//p" "$B/MANIFEST"; }
A="$(get archive_name)"; A="${A:-files.tgz}"
[ -f "$B/MANIFEST" ] && [ -f "$B/$A" ] || { echo "not a backup dir: $B" >&2; exit 2; }
[ "$INTO" = 1 ] || { machinectl show-image "$M" >/dev/null 2>&1 && { echo "refusing: machine $M already exists" >&2; exit 3; }; }
[ "$(sha256sum "$B/$A" | cut -d' ' -f1)" = "$(get archive_sha256)" ] || { echo "archive checksum mismatch" >&2; exit 4; }
[ "$(get opencloud_binary_sha256)" = "$OC_SHA256" ] || { echo "backup was taken with a binary that is not the pinned one" >&2; exit 5; }
UIDGID="$(get opencloud_uid_gid)"; OUID="${UIDGID%%:*}"; OGID="${UIDGID##*:}"

in_m() { systemd-run -M "$M" --wait -q -P --pipe /bin/bash -c "$1"; }
ROOTFS="/var/lib/machines/$M"
if [ "$INTO" = 1 ]; then
  in_m "systemctl stop opencloud-collaboration opencloud; rm -rf /var/lib/opencloud && mkdir -p /var/lib/opencloud"
  [ "$(in_m "sha256sum /usr/local/bin/opencloud" | cut -d' ' -f1)" = "$OC_SHA256" ] || { echo "scratch machine binary is not the pinned one" >&2; exit 5; }
else
machinectl clone "$BASE" "$M"
printf '[Exec]\nBoot=yes\nPrivateUsers=pick\n[Network]\nZone=oulab\n' > "/etc/systemd/nspawn/$M.nspawn"
machinectl start "$M"; systemctl set-property "systemd-nspawn@$M" MemoryMax=2G
for i in $(seq 1 30); do systemd-run -M "$M" --wait -q -P /bin/true 2>/dev/null && break; sleep 1; done

# lab name resolution (same block the ICS host uses)
sed -n '/# ou-lab hosts/,/^$/p' /etc/hosts | grep -v '^#' >> "$ROOTFS/etc/hosts"
in_m "for i in \$(seq 1 30); do ip -4 route | grep -q default && break; sleep 1; done; apt-get -qq update && DEBIAN_FRONTEND=noninteractive apt-get -qq install -y $FILES_PKGS >/dev/null"
in_m "getent group opencloud >/dev/null || groupadd -r -g $OGID opencloud; id opencloud >/dev/null 2>&1 || useradd -r -u $OUID -g $OGID -d /var/lib/opencloud -s /usr/sbin/nologin opencloud"
in_m "curl -fsSL -o /usr/local/bin/opencloud '$OC_URL' && echo '$OC_SHA256  /usr/local/bin/opencloud' | sha256sum -c --quiet && chmod 0755 /usr/local/bin/opencloud"

fi

CROOT="$(stat -c %u "$ROOTFS/root")"   # PrivateUsers=pick: container root = shifted host uid
install -m 0600 -o "$CROOT" -g "$CROOT" "$B/$A" "$ROOTFS/root/ou-restore.tgz"
in_m "cd / && tar --xattrs --xattrs-include='user.*' --acls --numeric-owner -xp$([ "$A" = files.tgz ] && echo z)f /root/ou-restore.tgz && rm -f /root/ou-restore.tgz"
in_m "update-ca-certificates >/dev/null 2>&1; rm -f /etc/nginx/sites-enabled/default; ln -sf /etc/nginx/sites-available/ou-lab-cloud /etc/nginx/sites-enabled/ou-lab-cloud; nginx -t -q"
GOT="$(in_m "python3 -c \"import os;print(sum(1 for r,d,f in os.walk('/var/lib/opencloud/storage') for x in d+f if os.listxattr(os.path.join(r,x),follow_symlinks=False)))\"")"
XA="$(get xattr_entries)"; XB="$(get xattr_entries_before)"; XB="${XB:-$XA}"   # online backups bracket the count (files created while tar ran)
{ [ "$GOT" -ge "$(( XB < XA ? XB : XA ))" ] && [ "$GOT" -le "$(( XB > XA ? XB : XA ))" ]; } || { echo "xattr count mismatch: restored=$GOT backup=$XB..$XA" >&2; exit 6; }
in_m "systemctl daemon-reload && systemctl enable -q --now opencloud opencloud-collaboration && systemctl restart nginx"
echo "restored $M from $B (xattr entries $GOT); IP: $(machinectl list --no-legend | awk -v m="$M" '$1==m{print $NF}')"
