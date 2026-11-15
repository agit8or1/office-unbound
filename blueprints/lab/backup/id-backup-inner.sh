#!/usr/bin/env bash
# Runs INSIDE the identity machine (copied in by id-backup.sh). Online-consistent dumps; no downtime.
set -euo pipefail; umask 077
W=/root/ou-idbk; rm -rf "$W" /root/ou-idbk.tar; mkdir "$W"; cd "$W"
slapcat -n 0 -l ldap-config.ldif
slapcat -n 1 -l ldap-data.ldif
sudo -u postgres pg_dumpall --globals-only > pg-globals.sql
sudo -u postgres pg_dump -Fc keycloak > keycloak.dump
KC="$(readlink -f /opt/keycloak)"; KC="${KC#/}"
tar --numeric-owner -cpzf config.tgz -C / etc/keycloak "$KC/conf" "$KC/data/import" etc/ou-lab/tls etc/ldap/tls etc/default/slapd \
    usr/local/share/ca-certificates etc/systemd/system/keycloak.service root/ou-lab-secrets
sha256sum ./* > SHA256SUMS
tar -cf /root/ou-idbk.tar .
rm -rf "$W"
