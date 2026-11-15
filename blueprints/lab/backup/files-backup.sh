#!/usr/bin/env bash
# Office Unbound lab: consistent backup of an OpenCloud files node (nspawn machine) to the ICS host.
# Usage: sudo files-backup.sh <machine> [dest_root]
# Preserves user.oc.* xattrs (posix storage driver keeps file ids/metadata in xattrs — a plain copy LOSES them).
# Consistency: brief stop of opencloud + collaboration (lab method). Production: filesystem snapshot (LVM/ZFS/btrfs)
# with the same archive layout, no downtime.
set -euo pipefail
M="${1:?machine}"; DEST_ROOT="${2:-/var/backups/office-unbound/lab}"
TS="$(date -u +%Y%m%dT%H%M%SZ)"; DEST="$DEST_ROOT/$M/$TS"
install -d -m 0700 "$DEST"
in_m() { systemd-run -M "$M" --wait -q -P --pipe /bin/bash -c "$1"; }

PATHS="var/lib/opencloud etc/opencloud etc/ou-lab/tls usr/local/share/ca-certificates/ou-lab-ca.crt etc/nginx/sites-available/ou-lab-cloud etc/systemd/system/opencloud.service etc/systemd/system/opencloud-collaboration.service"
in_m "systemctl stop opencloud-collaboration opencloud"
trap 'in_m "systemctl start opencloud opencloud-collaboration" || true' EXIT
in_m "cd / && tar --xattrs --xattrs-include='user.*' --acls --numeric-owner -cpzf /root/ou-backup.tgz $PATHS"
in_m "systemctl start opencloud opencloud-collaboration"; trap - EXIT

ROOTFS="/var/lib/machines/$M"
install -m 0600 "$ROOTFS/root/ou-backup.tgz" "$DEST/files.tgz"; rm -f "$ROOTFS/root/ou-backup.tgz"
{
  echo "machine=$M"; echo "created_utc=$TS"
  echo "opencloud_binary_sha256=$(in_m 'sha256sum /usr/local/bin/opencloud' | cut -d' ' -f1)"
  echo "opencloud_version=$(in_m '/usr/local/bin/opencloud version 2>/dev/null | grep -m1 -i version' | tr -s ' ')"
  echo "opencloud_uid_gid=$(in_m 'id -u opencloud'):$(in_m 'id -g opencloud')"
  echo "xattr_entries=$(in_m "python3 -c \"import os;print(sum(1 for r,d,f in os.walk('/var/lib/opencloud/storage') for x in d+f if os.listxattr(os.path.join(r,x),follow_symlinks=False)))\"")"
  echo "archive_sha256=$(sha256sum "$DEST/files.tgz" | cut -d' ' -f1)"
  echo "archive_bytes=$(stat -c %s "$DEST/files.tgz")"
} > "$DEST/MANIFEST"
chmod 0600 "$DEST/MANIFEST"
echo "$DEST"
