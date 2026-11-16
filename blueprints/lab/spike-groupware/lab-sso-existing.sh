#!/bin/bash
# Webmail SSO for an EXISTING groupware node (steps 4-6 of lab-sso.sh: Keycloak client + keycloak.json + CA trust + deep-link web patch), plus
# the realm-key follower (lab-sso-keysync.sh) and php-gd. Does NOT touch the gromox binaries or the LDAP/auth config. Never prints secrets. Idempotent.
# usage: GW_MACHINE=ou-gw1 GW_HOST=gw1.ou-lab.internal ./lab-sso-existing.sh        (ICS host; sudo systemd-run -M)
# Break-glass (login page loops / Keycloak down): on the node `touch /etc/gromox/DISABLE_KEYCLOAK`-style is NOT available upstream; use
#   mv /etc/gromox/keycloak.json /etc/gromox/keycloak.json.off && systemctl restart php8.2-fpm      (re-enable: mv back)
set -eu
M="${GW_MACHINE:?}"; GW_HOST="${GW_HOST:?}"; ID=${ID_MACHINE:-ou-id1}; LD=${LAB_DOMAIN:-ou-lab.internal}; IDIP=${ID_IP:-192.168.186.241}; HERE="$(cd "$(dirname "$0")" && pwd)"
IDX() { sudo systemd-run -M $ID --quiet --pipe --wait /bin/bash -c "$1"; }
MX()  { sudo systemd-run -M $M --quiet --pipe --wait /bin/bash -c "$1"; }

# 0: auth.$LD must resolve on the node (hosts entry like ou-gw-sso1 has), php-gd (profile picture; without it the web UI aborts the hierarchy load)
MX "grep -q 'auth.$LD' /etc/hosts || echo '$IDIP auth.$LD' >> /etc/hosts
dpkg -s php8.2-gd >/dev/null 2>&1 || (apt-get update -qq >/dev/null; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq php8.2-gd >/dev/null)"

# 4: Keycloak client ou-webmail (shared across nodes: redirect URIs are merged, not replaced)
sudo install -m 0755 "$HERE/kc-webmail-client.py" /var/lib/machines/$ID/root/kc-webmail-client.py
IDX "export KC_URL=https://auth.$LD KC_CA=/root/ou-lab-ca/ca.crt KC_ADMIN_USER=kcadmin WEBMAIL_URL=https://$GW_HOST OUT_SECRET_FILE=/root/ou-lab-secrets/kc-webmail-client-secret
KC_ADMIN_PASSWORD=\$(cat /root/ou-lab-secrets/keycloak-admin-password); export KC_ADMIN_PASSWORD; python3 /root/kc-webmail-client.py"

# 5: trust the lab CA, realm key follower (writes /etc/gromox/bearer_pubkey), keycloak.json; restart only zcore + php-fpm
sudo cat /var/lib/machines/$ID/etc/ou-lab/tls/ca.crt | MX 'cat > /usr/local/share/ca-certificates/ou-lab-ca.crt; update-ca-certificates >/dev/null'
GW_MACHINE=$M "$HERE/lab-sso-keysync.sh" >/dev/null
SECRET=$(IDX 'cat /root/ou-lab-secrets/kc-webmail-client-secret')
printf '%s' "$SECRET" | MX "read -r S
cd /etc/gromox
( umask 027
  cat > keycloak.json <<JSON
{\"realm\":\"ou-lab\",\"auth-server-url\":\"https://auth.$LD/\",\"ssl-required\":\"external\",\"resource\":\"ou-webmail\",
 \"redirect-url\":\"https://$GW_HOST/web\",\"credentials\":{\"secret\":\"\$S\"},\"confidential-port\":0}
JSON
)
chown root:gromoxcf keycloak.json bearer_pubkey; chmod 0640 keycloak.json bearer_pubkey
usermod -aG gromoxcf groweb 2>/dev/null || true
systemctl restart gromox-zcore php8.2-fpm"
# 5a: M1 (security review 4): zcore.sock only for groweb/grosync/grodav (group gromox-zcore), applied after every zcore start by a drop-in
MX 'sh -s' < "$HERE/ou-zcore-lockdown.sh"; MX "systemctl restart gromox-zcore php8.2-fpm"
# 6: deep-link patch: rebuild only grommunio-web (build tree already on the node)
MX 'install -d /root/patches'
sudo cp "$HERE"/../../build/grommunio-web/patches/*.patch /var/lib/machines/$M/root/patches/
sudo install -m 0755 "$HERE/webmail-patch-inner.sh" /var/lib/machines/$M/root/webmail-patch-inner.sh
MX "bash /root/webmail-patch-inner.sh"
echo "sso enabled: https://$GW_HOST/web/"
