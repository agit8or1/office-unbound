#!/usr/bin/env bash
# Office Unbound lab: install the backup RUNNER on this host (the lab's nspawn machines are only reachable from the host via machinectl/systemd-run,
# so the host plays the node whose agent runs backup.run/backup.verify; on Proxmox VMs the same helper runs on each tier node or on a runner node).
# Usage: sudo lab-runner-setup.sh <ics-repo-root> [bkp-machine=ou-bkp1] [secrets_dir=/etc/office-unbound/backup-lab]
# Installs: /usr/local/bin/restic (pinned + verified), /usr/local/sbin/ou-backup{,-canary.py}, a root-owned copy of the lab scripts in /opt/office-unbound/lab,
# /etc/ou-backup/<tier>.json for files/identity/groupware, REST credentials (root 0600). The repository password is provisioned separately from the
# ICS vault: ics.cli backup-node-secret --policy NAME | sudo ou-backup --direct provision <tier>   (see docs/admin/backup-and-restore.md)
set -euo pipefail
R="${1:?ics repo root (the checkout that contains blueprints/ and ics/)}"; BKP="${2:-ou-bkp1}"; SD="${3:-/etc/office-unbound/backup-lab}"
. "$R/blueprints/lab/common/versions.env"
IP="$(systemd-run -M "$BKP" --wait -q -P --pipe /bin/bash -c "ip -4 -o addr show scope global | awk '{print \$4}' | cut -d/ -f1 | head -1")"
if ! /usr/local/bin/restic version 2>/dev/null | grep -q "restic $RESTIC_VERSION "; then
  W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
  curl -fsSL -o "$W/r.bz2" "$RESTIC_URL"; echo "$RESTIC_ASSET_SHA256  $W/r.bz2" | sha256sum -c --quiet
  bzip2 -dc "$W/r.bz2" > "$W/restic"; install -m 0755 "$W/restic" /usr/local/bin/restic
fi
RS="$(sha256sum /usr/local/bin/restic | cut -d' ' -f1)"
install -m 0755 -o root -g root "$R/ics/agent/deploy/runbooks/ou-backup" /usr/local/sbin/ou-backup
install -m 0755 -o root -g root "$R/ics/agent/deploy/runbooks/ou-backup-canary.py" /usr/local/sbin/ou-backup-canary.py
rm -rf /opt/office-unbound/lab; install -d -m 0755 /opt/office-unbound/lab
cp -a "$R/blueprints/lab/." /opt/office-unbound/lab/; chown -R root:root /opt/office-unbound/lab; chmod -R go-w /opt/office-unbound/lab
install -d -m 0755 /etc/ou-backup; install -d -m 0700 /var/lib/ou-backup /etc/ou-backup/creds
CA="$SD/bkp.crt"; install -m 0644 "$CA" /etc/ou-backup/bkp-ca.crt
mk() { # tier machine scratch canary-json
  install -d -m 0700 "/etc/ou-backup/creds/$1"
  python3 - "$@" <<PY
import json, sys
tier, machine, scratch, canary = sys.argv[1:5]
cfg = {"tier": tier, "machine": machine, "scratch": scratch or None, "canary": json.loads(canary) if canary else None,
       "repo_url": "https://$IP:8000/" + tier, "maint_repo_url": "https://$IP:8001/" + tier, "cacert": "/etc/ou-backup/bkp-ca.crt",
       "creds_dir": "/etc/ou-backup/creds/" + tier, "scripts_dir": "/opt/office-unbound/lab/backup", "stage_dir": "/var/lib/ou-backup/stage",
       "restic": "/usr/local/bin/restic", "restic_sha256": "$RS", "backup_timeout": 1800, "restore_timeout": 2400}
open("/etc/ou-backup/" + tier + ".json", "w").write(json.dumps(cfg, indent=2) + "\n")
PY
  chmod 0644 "/etc/ou-backup/$1.json"
  printf '{"rest_user":"backup","rest_password":"%s","maint_user":"maint","maint_password":"%s"}' "$(cat "$SD/rest-backup.pw")" "$(cat "$SD/rest-maint.pw")" \
    | /usr/local/sbin/ou-backup --direct provision "$1" >/dev/null
}
mk files ou-files1 ou-files-r1 '{"name_glob":"restore-drill-canary-*.docx"}'
mk identity ou-id1 ou-id-r1 '{"ldap_uid":"drillcanary","role_prefix":"drill-canary-"}'
mk groupware ou-gw1 ou-gw-r1 '{"mailbox":"alice@gw1.ou-lab.internal"}'
install -d -m 0700 /var/lib/ou-backup/stage
echo "runner installed; repository $IP (ca sha256 $(openssl x509 -in "$CA" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d : | tr A-F a-f)); restic $(restic version | cut -d' ' -f2)"
