#!/bin/bash
# Office Unbound lab: webmail SSO node. Keycloak (OIDC, code flow) -> grommunio-web (upstream WebAppKeyCloak) -> gromox zcore (auth_login_token, RS256 bearer).
# Runs on the ICS host (sudo + systemd-run -M). Prerequisite: machine $GW_MACHINE (default ou-gw-sso1) built by build-from-source.sh (all stages, EXIT=0).
# Steps: 1 base config (no SQL users)  2 nginx + sync/dav/web  3 LDAP auth (lab-ldap.sh)  4 Keycloak client ou-webmail  5 keycloak.json + bearer_pubkey + CA trust.
# Never prints secrets. Idempotent.
set -eu
export GW_MACHINE="${GW_MACHINE:-ou-gw-sso1}" GW_HOST="${GW_HOST:-sso.ou-lab.internal}"
M=$GW_MACHINE; ID=ou-id1; HERE="$(cd "$(dirname "$0")" && pwd)"
IDX() { sudo systemd-run -M $ID --quiet --pipe --wait /bin/bash -c "$1"; }
MX()  { sudo systemd-run -M $M --quiet --pipe --wait /bin/bash -c "$1"; }
MXENV="GW_HOST=$GW_HOST GW_USERS= GW_SHARED="

# refresh the machine-local copies of the scripts (they may be older than this checkout)
C=$(sudo stat -c %u /var/lib/machines/$M/root)
sudo tar -C "$HERE/.." -c --exclude=__pycache__ spike-groupware | sudo tar -x -C /var/lib/machines/$M/root/lab --no-same-owner --overwrite
sudo chown -R "$C:$C" /var/lib/machines/$M/root/lab
# 1+2: gromox config, TLS, MariaDB, postfix; nginx; sync/dav/web wiring. Machine-local scripts were copied by gw-restore.sh/create.
MX "cd /root/lab/spike-groupware && $MXENV bash lab-configure.sh && $MXENV bash lab-nginx.sh && bash lab-apps.sh" >/dev/null
MX "systemctl enable --now gromox-event gromox-midb gromox-http gromox-zcore gromox-delivery gromox-delivery-queue gromox-timer gromox-imap >/dev/null 2>&1; sleep 3"
# 3: LDAP authentication (read-only svc-gromox account already exists on ou-id1), user sync domain
"$HERE/lab-ldap.sh"

# 4: Keycloak client (admin password read inside ou-id1, never printed)
sudo install -m 0755 "$HERE/kc-webmail-client.py" /var/lib/machines/$ID/root/kc-webmail-client.py
IDX "export KC_URL=https://auth.ou-lab.internal KC_CA=/root/ou-lab-ca/ca.crt KC_ADMIN_USER=kcadmin WEBMAIL_URL=https://$GW_HOST OUT_SECRET_FILE=/root/ou-lab-secrets/kc-webmail-client-secret
KC_ADMIN_PASSWORD=\$(cat /root/ou-lab-secrets/keycloak-admin-password); export KC_ADMIN_PASSWORD; python3 /root/kc-webmail-client.py"

# 5: trust the lab CA (PHP curl uses the system store), realm public key -> /etc/gromox/bearer_pubkey, keycloak.json
sudo cat /var/lib/machines/$ID/etc/ou-lab/tls/ca.crt | MX 'cat > /usr/local/share/ca-certificates/ou-lab-ca.crt; update-ca-certificates >/dev/null'
SECRET=$(IDX 'cat /root/ou-lab-secrets/kc-webmail-client-secret')
printf '%s' "$SECRET" | MX "read -r S
cd /etc/gromox
KEY=\$(curl -fsS https://auth.ou-lab.internal/realms/ou-lab | python3 -c 'import sys,json;print(json.load(sys.stdin)[\"public_key\"])')
( umask 027; printf -- '-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n' \"\$(echo \$KEY | fold -w64)\" > bearer_pubkey
  cat > keycloak.json <<JSON
{\"realm\":\"ou-lab\",\"auth-server-url\":\"https://auth.ou-lab.internal/\",\"ssl-required\":\"external\",\"resource\":\"ou-webmail\",
 \"redirect-url\":\"https://$GW_HOST/web\",\"credentials\":{\"secret\":\"\$S\"},\"confidential-port\":0}
JSON
)
chown root:gromoxcf bearer_pubkey keycloak.json; chmod 0640 bearer_pubkey keycloak.json
usermod -aG gromoxcf groweb 2>/dev/null || true
systemctl restart gromox-zcore php8.2-fpm"
# 6: deep-link patch (upstream has no calendar/contacts URL action): copy patches, rebuild web
sudo install -d /var/lib/machines/$M/root/patches
sudo cp "$HERE"/../../build/grommunio-web/patches/*.patch /var/lib/machines/$M/root/patches/
sudo install -m 0755 "$HERE/webmail-patch-inner.sh" /var/lib/machines/$M/root/webmail-patch-inner.sh
MX "bash /root/webmail-patch-inner.sh"
echo "sso node ready: https://$GW_HOST/web/"
