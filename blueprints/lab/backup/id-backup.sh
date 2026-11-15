#!/usr/bin/env bash
# Office Unbound lab: online backup of an identity node (OpenLDAP + Keycloak + PostgreSQL) to the ICS host.
# Usage: sudo id-backup.sh <machine> [dest_root]. No service downtime: slapcat (cn=config + data) and pg_dump are online-consistent.
# Contains secrets (Keycloak DB/admin, LDAP admin/bind passwords, TLS keys) -> root-only 0600. CA private key is NOT included.
set -euo pipefail
M="${1:?machine}"; DEST_ROOT="${2:-/var/backups/office-unbound/lab}"
TS="$(date -u +%Y%m%dT%H%M%SZ)"; DEST="$DEST_ROOT/$M/$TS"; install -d -m 0700 "$DEST"
in_m() { systemd-run -M "$M" --wait -q -P --pipe /bin/bash -c "$1"; }
ROOTFS="/var/lib/machines/$M"; CROOT="$(stat -c %u "$ROOTFS/root")"   # PrivateUsers=pick uid shift
install -m 0700 -o "$CROOT" -g "$CROOT" "$(dirname "$0")/id-backup-inner.sh" "$ROOTFS/root/id-backup-inner.sh"
in_m "/root/id-backup-inner.sh && rm -f /root/id-backup-inner.sh"
install -m 0600 "$ROOTFS/root/ou-idbk.tar" "$DEST/identity.tar"; rm -f "$ROOTFS/root/ou-idbk.tar"
{
  echo "machine=$M"; echo "created_utc=$TS"
  echo "keycloak_version=$(in_m 'basename $(readlink -f /opt/keycloak)')"
  echo "ldap_data_entries=$(in_m 'slapcat -n 1 2>/dev/null | grep -c ^dn:')"
  echo "ldap_config_entries=$(in_m 'slapcat -n 0 2>/dev/null | grep -c ^dn:')"
  echo "keycloak_user_uid=$(in_m 'id -u keycloak'):$(in_m 'id -g keycloak')"
  echo "archive_sha256=$(sha256sum "$DEST/identity.tar" | cut -d' ' -f1)"
} > "$DEST/MANIFEST"; chmod 0600 "$DEST/MANIFEST"
echo "$DEST"
