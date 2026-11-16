#!/usr/bin/env bash
# Runs INSIDE a fresh Ubuntu 24.04 machine as root. Restores the ICS in PASSIVE mode (worker + monitor OFF) so a
# restored controller can never act on managed nodes while the original may still be alive (no split brain).
set -euo pipefail; umask 077
W=/root/ics-rs; rm -rf "$W"; mkdir "$W"; tar -xf /root/ics-backup.tar -C "$W"; cd "$W"; sha256sum -c --quiet SHA256SUMS
[ -f meta.env ] && . ./meta.env; DB="${db_name:-ics}"; OWNER="${db_owner:-ics_owner}"
# scratch reset (backup product verification into an existing machine): remove what an earlier restore created, then restore exactly like a new machine
if [ "${OU_RESET:-0}" = 1 ]; then
  systemctl stop ics ics-migrate 2>/dev/null || true
  for i in $(seq 1 60); do sudo -u postgres psql -qAtc 'select 1' >/dev/null 2>&1 && break; sleep 1; done
  for d in $(sudo -u postgres psql -qAtc "select datname from pg_database where datname like 'ics%'"); do sudo -u postgres psql -q -c "DROP DATABASE IF EXISTS $d"; done
  for r in $(sudo -u postgres psql -qAtc "select rolname from pg_roles where rolname like 'ics%'"); do sudo -u postgres psql -q -c "DROP ROLE IF EXISTS $r"; done
  rm -rf /etc/office-unbound /opt/office-unbound/ics
fi
for i in $(seq 1 30); do ip -4 route | grep -q default && break; sleep 1; done
apt-get -qq update; DEBIAN_FRONTEND=noninteractive apt-get -qq install -y python3-venv postgresql-16 >/dev/null
getent passwd ics >/dev/null || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin ics
tar --numeric-owner -xpzf etc.tgz -C /
[ ! -f artifacts-data.tgz ] || tar --numeric-owner -xpzf artifacts-data.tgz -C /   # ADR-0015: present only when taken with OU_ICS_BACKUP_ARTIFACT_DATA=1
# numeric gid of 'ics' differs on a new host: re-apply the intended ownership by name
chown root:ics /etc/office-unbound/ics.env /etc/office-unbound/vault.key /etc/office-unbound/audit.key /etc/office-unbound/ics-signing.key
chmod 0640 /etc/office-unbound/ics.env /etc/office-unbound/vault.key /etc/office-unbound/audit.key /etc/office-unbound/ics-signing.key
chown root:root /etc/office-unbound/ics-migrate.env; chmod 0600 /etc/office-unbound/ics-migrate.env; chmod 0711 /etc/office-unbound
# PASSIVE: never run jobs/monitoring/remediation until an operator performs the cut-over
sed -i -E '/^ICS_(WORKER|MONITOR)_ENABLED=/d' /etc/office-unbound/ics.env
printf 'ICS_WORKER_ENABLED=false\nICS_MONITOR_ENABLED=false\n' >> /etc/office-unbound/ics.env
# database: roles (with password hashes) + data
sudo -u postgres psql -q -v ON_ERROR_STOP=1 < roles.sql
sudo -u postgres createdb -O "$OWNER" "$DB"
sudo -u postgres pg_restore --exit-on-error -d "$DB" < ics.dump
# release + venv (hash-pinned)
# code + venv must be world-readable (read-only to the 'ics' service user): umask 022 here, secrets above stay 077
( umask 022
  install -d -m 0755 /opt/office-unbound; tar --no-same-owner -xzf release.tgz -C /opt/office-unbound; chown -R root:root /opt/office-unbound/ics
  python3 -m venv /opt/office-unbound/ics/.venv
  /opt/office-unbound/ics/.venv/bin/pip install -q --require-hashes -r /opt/office-unbound/ics/requirements.lock )
systemctl daemon-reload; systemctl start ics-migrate.service; systemctl start ics.service
[ ! -f /etc/office-unbound/callback.env ] || systemctl enable --now ics-bootstrap.service
rm -rf "$W" /root/ics-backup.tar
