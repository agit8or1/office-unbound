#!/usr/bin/env bash
# Office Unbound lab: ONLINE logical backup of a groupware node (source-built Gromox stack) to the ICS host.
# Usage: sudo gw-backup.sh <machine> [dest_root]
# No service stop/reload and no write to the node's persistent state (gw-backup-inner.sh is streamed over stdin, the archive comes back
# on stdout). Contains secrets (DB password, LDAP bind password, TLS server key, mail content) -> root-only 0600/0700.
# Executables are never backed up: gw-restore.sh rebuilds them from the pinned sources (common: build-from-source.sh).
set -euo pipefail
M="${1:?machine}"; DEST_ROOT="${2:-/var/backups/office-unbound/lab}"
HERE="$(cd "$(dirname "$0")" && pwd)"
TS="$(date -u +%Y%m%dT%H%M%SZ)"; DEST="$DEST_ROOT/$M/$TS"; install -d -m 0700 "$DEST"
umask 077
systemd-run -M "$M" --quiet --pipe --wait /bin/bash -s < "$HERE/gw-backup-inner.sh" > "$DEST/groupware.tar"
# end-to-end integrity of the stream: every member against the SHA256SUMS written inside the node
V="$(mktemp -d "$DEST/.verify.XXXX")"; tar -xf "$DEST/groupware.tar" -C "$V"
( cd "$V" && sha256sum -c --quiet SHA256SUMS ) || { echo "stream verification FAILED" >&2; rm -rf "$V"; exit 4; }
{
  echo "machine=$M"
  cat "$V/MANIFEST.part"
  echo "member_checksums=SHA256SUMS inside groupware.tar ($(wc -l < "$V/SHA256SUMS") files, verified after transfer)"
  echo "archive_sha256=$(sha256sum "$DEST/groupware.tar" | cut -d' ' -f1)"
  echo "archive_bytes=$(stat -c %s "$DEST/groupware.tar")"
} > "$DEST/MANIFEST"
chmod 0600 "$DEST/MANIFEST" "$DEST/groupware.tar"
echo "$DEST"
grep -q '^incomplete=0$' "$V/MANIFEST.part" || { rm -rf "$V"; echo "BACKUP INCOMPLETE: a mailbox with content could not be exported (see MANIFEST mbx_failed)" >&2; exit 5; }
rm -rf "$V"
