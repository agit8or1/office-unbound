#!/usr/bin/env bash
# Office Unbound lab: ICS CONTROLLER tier of the backup product against a DEV ICS (never the production ics service/database). Idempotent.
# Usage: sudo lab-ics-tier-setup.sh <ics-repo-root> <dev-inst-dir> <test-env-file> <db-suffix> <scratch-machine> <login-canary-json-file>
#   1. builds a production-shaped file tree of the DEV ICS under /var/lib/ou-bkp-icsdev (root 0700): /etc/office-unbound/{ics.env,ics-migrate.env,
#      keys,units}, /opt/office-unbound/ics = the release (code of <ics-repo-root>)  - this is what ics-backup.sh archives instead of the production paths
#   2. /etc/ou-backup/ics.json (tier config, legacy namespace) + REST credentials of the legacy append-only/maintenance listeners
#      + the login canary (a low-privilege operator of the dev ICS) used by the restore verification
# The repository password comes from the ICS vault afterwards (ics.cli backup-node-secret | ou-backup --direct provision ics).
set -euo pipefail
R="${1:?repo root}"; INST="${2:?dev instance dir}"; ENVF="${3:?test env file}"; SUF="${4:?db suffix}"; SCR="${5:?scratch machine}"; CAN="${6:?login canary json}"
[[ "$SUF" =~ ^[a-z0-9]{1,12}$ && "$SCR" =~ ^[A-Za-z0-9-]{1,60}$ ]] || { echo "bad suffix/scratch" >&2; exit 2; }
SD="${OU_BKP_SECRETS:-/etc/office-unbound/backup-lab}"; BKP="${OU_BKP_MACHINE:-ou-bkp1}"; PFX=/var/lib/ou-bkp-icsdev
IP="$(systemd-run -M "$BKP" --wait -q -P --pipe /bin/bash -c "ip -4 -o addr show scope global | awk '{print \$4}' | cut -d/ -f1 | head -1")"
rm -rf "$PFX"; install -d -m 0700 "$PFX" "$PFX/etc/office-unbound" "$PFX/etc/systemd/system" "$PFX/opt/office-unbound"
APP="$(sed -n 's/^ICS_TEST_DATABASE_URL=//p' "$ENVF" | sed -E "s#/ics_test(_[a-z0-9]{1,12})?\$#/ics_test_$SUF#")"
OWN="$(sed -n 's/^ICS_TEST_OWNER_DATABASE_URL=//p' "$ENVF" | sed -E "s#/ics_test(_[a-z0-9]{1,12})?\$#/ics_test_$SUF#")"
( umask 077
  printf 'ICS_DATABASE_URL=%s\nICS_VAULT_KEY_FILE=/etc/office-unbound/vault.key\nICS_AUDIT_KEY_FILE=/etc/office-unbound/audit.key\nICS_SIGNING_KEY_FILE=/etc/office-unbound/ics-signing.key\nICS_ENABLE_DOCS=false\nICS_COOKIE_SECURE=false\nICS_MONITOR_ENABLED=false\n' "$APP" > "$PFX/etc/office-unbound/ics.env"
  printf 'ICS_MIGRATE_DATABASE_URL=%s\n' "$OWN" > "$PFX/etc/office-unbound/ics-migrate.env"
  cp "$INST/vault.key" "$PFX/etc/office-unbound/vault.key"; cp "$INST/audit.key" "$PFX/etc/office-unbound/audit.key"; cp "$INST/signing.key" "$PFX/etc/office-unbound/ics-signing.key" )
cp "$R/ics/deploy/ics.service" "$R/ics/deploy/ics-migrate.service" "$PFX/etc/systemd/system/"
tar -C "$R" --exclude .venv --exclude __pycache__ --exclude .pytest_cache -cf - ics | tar -C "$PFX/opt/office-unbound" -xf -
# helpers: hooks + restore script live in a root-owned copy
rm -rf /opt/office-unbound/lab/ics-backup; install -d -m 0755 /opt/office-unbound/lab/ics-backup; cp -a "$R/ics/deploy/backup/." /opt/office-unbound/lab/ics-backup/
chown -R root:root /opt/office-unbound/lab/ics-backup; chmod 0755 /opt/office-unbound/lab/ics-backup/*.sh
install -m 0755 -o root -g root "$R/ics/agent/deploy/runbooks/ou-backup" /usr/local/sbin/ou-backup
install -m 0755 -o root -g root "$R/ics/agent/deploy/runbooks/ou-backup-canary.py" /usr/local/sbin/ou-backup-canary.py
RS="$(sha256sum /usr/local/bin/restic | cut -d' ' -f1)"
install -d -m 0755 /etc/ou-backup; install -d -m 0700 /etc/ou-backup/creds /etc/ou-backup/creds/ics /var/lib/ou-backup /var/lib/ou-backup/stage
python3 - <<PY
import json
cfg = {"tier": "ics", "machine": "ics-dev-controller", "scratch": "$SCR", "canary": None, "repo_url": "https://$IP:8000/ics-dev", "maint_repo_url": "https://$IP:8001/ics-dev",
       "cacert": "/etc/ou-backup/bkp-ca.crt", "creds_dir": "/etc/ou-backup/creds/ics", "scripts_dir": "/opt/office-unbound/lab/ics-backup", "stage_dir": "/var/lib/ou-backup/stage",
       "restic": "/usr/local/bin/restic", "restic_sha256": "$RS", "backup_timeout": 600, "restore_timeout": 2400,
       "backup_env": {"OU_ICS_PREFIX": "$PFX", "OU_ICS_DB": "ics_test_$SUF", "OU_ICS_ROLES": "ics_test_owner|ics_test_app", "OU_ICS_DB_OWNER": "ics_test_owner"},
       "login_canary_file": "/etc/ou-backup/creds/ics/login-canary.json"}
open("/etc/ou-backup/ics.json", "w").write(json.dumps(cfg, indent=2) + "\n")
PY
chmod 0644 /etc/ou-backup/ics.json
install -m 0600 -o root -g root "$CAN" /etc/ou-backup/creds/ics/login-canary.json
printf '{"rest_user":"backup","rest_password":"%s","maint_user":"maint","maint_password":"%s"}' "$(cat "$SD/rest-backup.pw")" "$(cat "$SD/rest-maint.pw")" | /usr/local/sbin/ou-backup --direct provision ics >/dev/null
echo "ICS tier ready: dev tree $PFX (database ics_test_$SUF), repository https://$IP:8000/ics-dev, scratch $SCR"
