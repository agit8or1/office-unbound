#!/usr/bin/env bash
# Restore an ICS controller backup onto a NEW nspawn machine (drill). Usage: sudo ics-restore.sh <backup_dir> <new_machine> [base]
# The restored ICS starts PASSIVE (worker/monitor disabled). Cut-over (documented in docs/runbooks/ics-recovery.md) is a separate,
# deliberate operator step: stop the old controller, take over its IP/nginx front end, set ICS_WORKER_ENABLED/ICS_MONITOR_ENABLED=true.
set -euo pipefail
B="${1:?backup dir}"; M="${2:?new machine}"; BASE="${3:-ou-base-noble}"; HERE="$(cd "$(dirname "$0")" && pwd)"
[ -f "$B/MANIFEST" ] && [ -f "$B/ics-backup.tar" ] || { echo "not an ICS backup dir" >&2; exit 2; }
machinectl show-image "$M" >/dev/null 2>&1 && { echo "refusing: $M exists" >&2; exit 3; }
[ "$(sha256sum "$B/ics-backup.tar" | cut -d' ' -f1)" = "$(sed -n 's/^archive_sha256=//p' "$B/MANIFEST")" ] || { echo "checksum mismatch" >&2; exit 4; }
machinectl clone "$BASE" "$M"
printf '[Exec]\nBoot=yes\nPrivateUsers=pick\n[Network]\nZone=oulab\n' > "/etc/systemd/nspawn/$M.nspawn"
machinectl start "$M"; systemctl set-property "systemd-nspawn@$M" MemoryMax=1500M
for i in $(seq 1 30); do systemd-run -M "$M" --wait -q -P /bin/true 2>/dev/null && break; sleep 1; done
R="/var/lib/machines/$M"; CROOT="$(stat -c %u "$R/root")"
echo "127.0.0.1 $(cat "$R/etc/hostname")" >> "$R/etc/hosts"
install -m 0600 -o "$CROOT" -g "$CROOT" "$B/ics-backup.tar" "$R/root/ics-backup.tar"
install -m 0700 -o "$CROOT" -g "$CROOT" "$HERE/ics-restore-inner.sh" "$R/root/ics-restore-inner.sh"
systemd-run -M "$M" --wait -q -P --pipe /root/ics-restore-inner.sh; rm -f "$R/root/ics-restore-inner.sh"
echo "restored ICS (PASSIVE) into $M"
