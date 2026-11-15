#!/usr/bin/env bash
# Office Unbound lab: restore an identity-node backup onto a NEW nspawn machine. Usage: sudo id-restore.sh <backup_dir> <new_machine> [base]
# The restored node answers for auth./ldap.ou-lab.internal ITSELF (its own /etc/hosts) so verification hits the restore, not the original.
set -euo pipefail
B="${1:?backup dir}"; M="${2:?new machine}"; BASE="${3:-ou-base-noble}"
HERE="$(cd "$(dirname "$0")" && pwd)"; . "$HERE/../common/versions.env"; . "$HERE/../common/packages.env"
[ -f "$B/MANIFEST" ] && [ -f "$B/identity.tar" ] || { echo "not a backup dir" >&2; exit 2; }
machinectl show-image "$M" >/dev/null 2>&1 && { echo "refusing: $M exists" >&2; exit 3; }
get() { sed -n "s/^$1=//p" "$B/MANIFEST"; }
[ "$(sha256sum "$B/identity.tar" | cut -d' ' -f1)" = "$(get archive_sha256)" ] || { echo "archive checksum mismatch" >&2; exit 4; }
[ "$(get keycloak_version)" = "keycloak-$KC_VERSION" ] || { echo "backup Keycloak version != pinned" >&2; exit 5; }
UG="$(get keycloak_user_uid)"
machinectl clone "$BASE" "$M"
printf '[Exec]\nBoot=yes\nPrivateUsers=pick\n[Network]\nZone=oulab\n' > "/etc/systemd/nspawn/$M.nspawn"
machinectl start "$M"; systemctl set-property "systemd-nspawn@$M" MemoryMax=2G
for i in $(seq 1 30); do systemd-run -M "$M" --wait -q -P /bin/true 2>/dev/null && break; sleep 1; done
R="/var/lib/machines/$M"; CROOT="$(stat -c %u "$R/root")"
{ echo "127.0.0.1 $(cat "$R/etc/hostname" 2>/dev/null || echo localhost) auth.ou-lab.internal ldap.ou-lab.internal"; sed -n '/# ou-lab hosts/,/^$/p' /etc/hosts | grep -v -E '^#|auth\.ou-lab|ldap\.ou-lab'; } >> "$R/etc/hosts"
printf 'ID_PKGS="%s"\nKC_URL="%s"\nKC_SHA1="%s"\nKC_VERSION="%s"\n' "$ID_PKGS" "$KC_URL" "$KC_SHA1" "$KC_VERSION" > "$R/root/ou-env"
install -m 0600 -o "$CROOT" -g "$CROOT" "$B/identity.tar" "$R/root/identity.tar"; chown "$CROOT:$CROOT" "$R/root/ou-env"
install -m 0700 -o "$CROOT" -g "$CROOT" "$HERE/id-restore-inner.sh" "$R/root/id-restore-inner.sh"
systemd-run -M "$M" --wait -q -P --pipe /root/id-restore-inner.sh "${UG%%:*}" "${UG##*:}"
rm -f "$R/root/id-restore-inner.sh"
echo "restored $M; IP: $(machinectl list --no-legend | awk -v m="$M" '$1==m{print $NF}')"
