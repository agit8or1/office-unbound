#!/usr/bin/env bash
# Runs INSIDE a fresh identity machine. Args: <keycloak_uid> <keycloak_gid>. Expects /root/identity.tar and env from packages/versions.
set -euo pipefail; umask 077
KUID="$1"; KGID="$2"; . /root/ou-env
W=/root/ou-idrs; rm -rf "$W"; mkdir "$W"; tar -xf /root/identity.tar -C "$W"; cd "$W"; sha256sum -c --quiet SHA256SUMS
# scratch reset (backup product verification into an existing machine): remove what a previous restore created so this run starts from the same state
if [ "${OU_RESET:-0}" = 1 ]; then
  systemctl stop keycloak 2>/dev/null || true
  for i in $(seq 1 60); do sudo -u postgres psql -qAtc 'select 1' >/dev/null 2>&1 && break; sleep 1; done   # a freshly booted scratch machine: wait for PostgreSQL
  sudo -u postgres psql -q -c 'DROP DATABASE IF EXISTS keycloak' >/dev/null
  sudo -u postgres psql -q -c 'DROP ROLE IF EXISTS keycloak' >/dev/null
fi
# service account with the original numeric ids BEFORE packages allocate system ids
getent group keycloak >/dev/null || groupadd -r -g "$KGID" keycloak
id keycloak >/dev/null 2>&1 || useradd -r -u "$KUID" -g "$KGID" -d /opt/keycloak -s /usr/sbin/nologin keycloak
for i in $(seq 1 30); do ip -4 route | grep -q default && break; sleep 1; done
apt-get -qq update; DEBIAN_FRONTEND=noninteractive apt-get -qq install -y $ID_PKGS >/dev/null
# Keycloak distribution from the pinned release (never from backup)
curl -fsSL -o /root/kc.tgz "$KC_URL"; echo "$KC_SHA1  /root/kc.tgz" | sha1sum -c --quiet
(umask 022; tar --no-same-owner -xzf /root/kc.tgz -C /opt); rm -f /root/kc.tgz; ln -sfn "/opt/keycloak-$KC_VERSION" /opt/keycloak
chown -R keycloak:keycloak "/opt/keycloak-$KC_VERSION"; chmod 0755 "/opt/keycloak-$KC_VERSION"   # mirrors install-kc.sh; HARDENING TODO: root-owned dist, build as root, only data/ writable
# config, TLS, secrets, unit (numeric owners from source; package-owned paths fixed by name below)
tar --numeric-owner -xpzf config.tgz -C /
chown -R openldap:openldap /etc/ldap/tls; update-ca-certificates >/dev/null 2>&1
chown -R keycloak:keycloak "/opt/keycloak-$KC_VERSION/data" "/opt/keycloak-$KC_VERSION/conf" 2>/dev/null || true
# OpenLDAP: replace package default config + data with the backup
systemctl stop slapd; rm -rf /etc/ldap/slapd.d/* /var/lib/ldap/*
slapadd -n 0 -F /etc/ldap/slapd.d -l ldap-config.ldif
slapadd -n 1 -F /etc/ldap/slapd.d -l ldap-data.ldif
chown -R openldap:openldap /etc/ldap/slapd.d /var/lib/ldap; systemctl start slapd
# listener config must match the source (drill finding: package default = plaintext ldap:/// on all interfaces, no ldaps)
grep -q "ldaps:///" /etc/default/slapd || { echo "restored slapd has no ldaps listener" >&2; exit 7; }
# PostgreSQL: roles (with password hashes) + keycloak database
# globals: skip the pre-existing superuser; everything else must apply cleanly
grep -v -E '^(CREATE|ALTER) ROLE postgres( |;)' pg-globals.sql | sudo -u postgres psql -q -v ON_ERROR_STOP=1 >/dev/null
sudo -u postgres createdb -O keycloak keycloak
sudo -u postgres pg_restore --exit-on-error -d keycloak < keycloak.dump
# Keycloak: optimized build with the same build options as install-kc.sh, then start
sudo -u keycloak env KC_DB=postgres KC_HEALTH_ENABLED=true /opt/keycloak/bin/kc.sh build >/dev/null
systemctl daemon-reload; systemctl enable -q --now keycloak
rm -rf "$W" /root/identity.tar /root/ou-env
