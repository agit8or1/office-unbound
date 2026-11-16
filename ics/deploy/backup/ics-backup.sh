#!/usr/bin/env bash
# Office Unbound ICS controller backup (run as root on the ICS host). Online: pg_dump is transactionally consistent.
# Output contains EVERY ICS secret (vault/audit/signing keys, DB credentials, TLS CA key) -> root 0700/0600 here, and the backup product
# (ADR-0010, tier "ics") puts it ONLY into an encrypted restic repository: the plain archive exists in the root-only staging dir for the
# duration of the run. Offline recovery key: docs/runbooks/ics-recovery.md.
# Parameters (environment; defaults = the production layout; a DEV ICS uses them to point at its own database and file tree, never at production):
#   OU_ICS_PREFIX   file-tree prefix (default empty: /etc/office-unbound, /opt/office-unbound)
#   OU_ICS_DB       database name (default ics)            OU_ICS_ROLES  role-name alternation (default ics_owner|ics_app)
#   OU_ICS_DB_OWNER database owner (default ics_owner)
set -euo pipefail
DEST_ROOT="${1:-/var/backups/office-unbound/ics}"; TS="$(date -u +%Y%m%dT%H%M%SZ)"; DEST="$DEST_ROOT/$TS"
P="${OU_ICS_PREFIX:-}"; DB="${OU_ICS_DB:-ics}"; ROLES="${OU_ICS_ROLES:-ics_owner|ics_app}"; OWNER="${OU_ICS_DB_OWNER:-ics_owner}"
[[ "$DB" =~ ^[a-z][a-z0-9_]{0,40}$ && "$ROLES" =~ ^[a-z0-9_|]{1,100}$ && "$OWNER" =~ ^[a-z][a-z0-9_]{0,40}$ ]] || { echo "bad OU_ICS_DB/ROLES/OWNER" >&2; exit 2; }
install -d -m 0700 "$DEST"; umask 077; W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
pq() { /usr/sbin/runuser -u postgres -- psql -d "$DB" -Atc "$1"; }
# restore evidence is read BEFORE the dump: the restored audit chain must contain this event with this hash (events appended during the dump are fine)
HEAD_SEQ="$(pq 'select max(seq) from audit_events')"; HEAD_HASH="$(pq "select hash from audit_events where seq = $HEAD_SEQ")"
/usr/sbin/runuser -u postgres -- pg_dump -Fc "$DB" > "$W/ics.dump"
/usr/sbin/runuser -u postgres -- pg_dumpall --globals-only | grep -E "^(CREATE|ALTER) ROLE ($ROLES)( |;)" > "$W/roles.sql"
printf 'db_name=%s\ndb_owner=%s\n' "$DB" "$OWNER" > "$W/meta.env"
# optional front-end files exist only on hosts installed with TLS (bootstrap.sh --skip-tls has none)
FILES=(etc/office-unbound/ics.env etc/office-unbound/ics-migrate.env etc/office-unbound/vault.key etc/office-unbound/audit.key etc/office-unbound/ics-signing.key
       etc/systemd/system/ics.service etc/systemd/system/ics-migrate.service)
for f in etc/office-unbound/tls etc/office-unbound/ics-admin-fw.nft etc/systemd/system/ics-admin-fw.service etc/nginx/sites-available/ics.conf; do
  [ -e "$P/$f" ] && FILES+=("$f"); done
tar --numeric-owner -cpzf "$W/etc.tgz" -C "${P:-/}" "${FILES[@]}"
# the deployed release that produced this DB schema (code only; the venv is rebuilt from requirements.lock with --require-hashes)
tar -cpzf "$W/release.tgz" -C "$P/opt/office-unbound" --exclude .venv --exclude __pycache__ ics $( [ -d "$P/opt/office-unbound/blueprints" ] && echo blueprints )
( cd "$W" && sha256sum ./* > SHA256SUMS ) && tar -cf "$DEST/ics-backup.tar" -C "$W" .
chmod 0600 "$DEST/ics-backup.tar"
{
  echo "created_utc=$TS"
  echo "db_name=$DB"
  echo "alembic_head=$(pq 'select version_num from alembic_version')"
  echo "audit_head_seq=$HEAD_SEQ"
  echo "audit_head_hash=$HEAD_HASH"
  echo "users=$(pq 'select count(*) from users')"
  echo "release_sha256=$(sha256sum "$W/release.tgz" | cut -d' ' -f1)"
  echo "archive_sha256=$(sha256sum "$DEST/ics-backup.tar" | cut -d' ' -f1)"
} > "$DEST/MANIFEST"; chmod 0600 "$DEST/MANIFEST"
echo "$DEST"
