#!/usr/bin/env bash
# Office Unbound ICS controller backup (run as root on the ICS host). Online: pg_dump is transactionally consistent.
# Output contains EVERY ICS secret (vault/audit/signing keys, DB credentials, TLS CA key) -> root 0700/0600.
# TODO (production): encrypt to an offline recovery key (e.g. age) and copy off-host; record RPO.
set -euo pipefail
DEST_ROOT="${1:-/var/backups/office-unbound/ics}"; TS="$(date -u +%Y%m%dT%H%M%SZ)"; DEST="$DEST_ROOT/$TS"
install -d -m 0700 "$DEST"; umask 077; W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
sudo -u postgres pg_dump -Fc ics > "$W/ics.dump"
sudo -u postgres pg_dumpall --globals-only | grep -E '^(CREATE|ALTER) ROLE (ics_owner|ics_app)( |;)' > "$W/roles.sql"
tar --numeric-owner -cpzf "$W/etc.tgz" -C / etc/office-unbound/ics.env etc/office-unbound/ics-migrate.env etc/office-unbound/vault.key \
    etc/office-unbound/audit.key etc/office-unbound/ics-signing.key etc/office-unbound/tls etc/office-unbound/ics-admin-fw.nft \
    etc/systemd/system/ics.service etc/systemd/system/ics-migrate.service etc/systemd/system/ics-admin-fw.service etc/nginx/sites-available/ics.conf
# the deployed release that produced this DB schema (code only; the venv is rebuilt from requirements.lock with --require-hashes)
tar -cpzf "$W/release.tgz" -C /opt/office-unbound --exclude .venv --exclude __pycache__ ics
( cd "$W" && sha256sum ./* > SHA256SUMS ) && tar -cf "$DEST/ics-backup.tar" -C "$W" .
chmod 0600 "$DEST/ics-backup.tar"
{
  echo "created_utc=$TS"
  echo "alembic_head=$(sudo -u postgres psql -d ics -Atc 'select version_num from alembic_version')"
  echo "audit_events=$(sudo -u postgres psql -d ics -Atc 'select count(*) from audit_events')"
  echo "audit_head_hash=$(sudo -u postgres psql -d ics -Atc 'select hash from audit_events order by seq desc limit 1')"
  echo "users=$(sudo -u postgres psql -d ics -Atc 'select count(*) from users')"
  echo "release_sha256=$(sha256sum "$W/release.tgz" | cut -d' ' -f1)"
  echo "archive_sha256=$(sha256sum "$DEST/ics-backup.tar" | cut -d' ' -f1)"
} > "$DEST/MANIFEST"; chmod 0600 "$DEST/MANIFEST"
echo "$DEST"
