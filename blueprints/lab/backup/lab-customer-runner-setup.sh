#!/usr/bin/env bash
# Office Unbound lab: one customer PROFILE on the backup runner (T20 / agent AU). Idempotent. Needs lab-runner-setup.sh (restic, ou-backup, scripts).
# Usage: sudo lab-customer-runner-setup.sh <ics-repo-root> <profile> <tier> <source-machine> <scratch-machine|-> '<canary-json|->' [restore-env-json] [backup-env-json]
# Creates /etc/ou-backup/<profile>/<tier>.json (self-contained: own repository namespace c-<id>/<tier>, own credentials dir, own staging dir),
# installs that customer's REST credentials (REST user = profile; separate backup and maintenance passwords) and refreshes the helper + lab scripts.
# The restic repository password is NOT handled here: it is provisioned from the ICS vault (ics.cli backup-node-secret | ou-backup --direct --customer <profile> provision <tier>).
set -euo pipefail
R="${1:?ics repo root}"; P="${2:?profile}"; TIER="${3:?tier}"; SRC="${4:?source machine}"; SCR="${5:?scratch machine or -}"; CAN="${6:--}"; RENV="${7:-}"; BENV="${8:-}"
[[ "$P" =~ ^c-[0-9a-f]{32}$ ]] || { echo "bad profile" >&2; exit 2; }
SD="${OU_BKP_SECRETS:-/etc/office-unbound/backup-lab}"; BKP="${OU_BKP_MACHINE:-ou-bkp1}"
IP="$(systemd-run -M "$BKP" --wait -q -P --pipe /bin/bash -c "ip -4 -o addr show scope global | awk '{print \$4}' | cut -d/ -f1 | head -1")"
install -m 0755 -o root -g root "$R/ics/agent/deploy/runbooks/ou-backup" /usr/local/sbin/ou-backup
install -m 0755 -o root -g root "$R/ics/agent/deploy/runbooks/ou-backup-canary.py" /usr/local/sbin/ou-backup-canary.py
rm -rf /opt/office-unbound/lab; install -d -m 0755 /opt/office-unbound/lab
cp -a "$R/blueprints/lab/." /opt/office-unbound/lab/; chown -R root:root /opt/office-unbound/lab; chmod -R go-w /opt/office-unbound/lab
install -d -m 0755 /opt/office-unbound/lab/ics-backup; cp -a "$R/ics/deploy/backup/." /opt/office-unbound/lab/ics-backup/
RS="$(sha256sum /usr/local/bin/restic | cut -d' ' -f1)"
D="/etc/ou-backup/$P"; install -d -m 0755 "$D"; install -d -m 0700 "$D/creds" "$D/creds/$TIER" /var/lib/ou-backup /var/lib/ou-backup/stage "/var/lib/ou-backup/stage/$P"
python3 - "$P" "$TIER" "$SRC" "$SCR" "$CAN" "$RENV" "$BENV" <<PY
import json, sys
p, tier, src, scr, can, renv, benv = sys.argv[1:8]
cfg = {"tier": tier, "customer": p, "machine": src, "scratch": None if scr == "-" else scr, "canary": None if can == "-" else json.loads(can),
       "repo_url": f"https://$IP:8010/{p}/{tier}", "maint_repo_url": f"https://$IP:8011/{p}/{tier}", "cacert": "/etc/ou-backup/bkp-ca.crt",
       "creds_dir": f"/etc/ou-backup/{p}/creds/{tier}", "scripts_dir": "/opt/office-unbound/lab/ics-backup" if tier == "ics" else "/opt/office-unbound/lab/backup",
       "stage_dir": f"/var/lib/ou-backup/stage/{p}", "restic": "/usr/local/bin/restic", "restic_sha256": "$RS", "backup_timeout": 1800, "restore_timeout": 2400}
if renv:
    cfg["restore_env"] = json.loads(renv)
if benv:
    cfg["backup_env"] = json.loads(benv)
if tier == "ics":
    cfg["login_canary_file"] = f"/etc/ou-backup/{p}/creds/{tier}/login-canary.json"
open(f"/etc/ou-backup/{p}/{tier}.json", "w").write(json.dumps(cfg, indent=2) + "\n")
PY
chmod 0644 "$D/$TIER.json"
printf '{"rest_user":"%s","rest_password":"%s","maint_user":"%s","maint_password":"%s"}' "$P" "$(cat "$SD/cust/$P/rest-backup.pw")" "$P" "$(cat "$SD/cust/$P/rest-maint.pw")" \
  | /usr/local/sbin/ou-backup --direct --customer "$P" provision "$TIER" > /tmp/ou-prov.$$ || { cat /tmp/ou-prov.$$ >&2; rm -f /tmp/ou-prov.$$; exit 1; }
rm -f /tmp/ou-prov.$$
echo "profile $P tier $TIER installed (repository https://$IP:8010/$P/$TIER)"
