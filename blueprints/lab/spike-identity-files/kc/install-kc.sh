#!/usr/bin/env bash
# VM "kc": lab CA + PostgreSQL 16 + lldap + Keycloak (pinned, optimized build).
# Target OS: Ubuntu 24.04 LTS. Run as root from a checkout of blueprints/lab.
# STATUS: PREPARED, NOT EXECUTED. Expect to fix things on first real run.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB="$(cd "${HERE}/../../common" && pwd)"
. "${LAB}/lab.env"; . "${LAB}/versions.env"; . "${LAB}/lib.sh"
need_root; secrets_dir_init
[ -r /etc/os-release ] && . /etc/os-release
[ "${VERSION_ID:-}" = "24.04" ] || warn "tested-for OS is Ubuntu 24.04, found ${PRETTY_NAME:-unknown}"

log "packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq postgresql-${PG_MAJOR} openjdk-21-jre-headless curl ca-certificates openssl jq ufw gettext-base

add_lab_hosts

log "lab CA + TLS bundle for kc"
bash "${LAB}/lab-ca.sh"
cp "${CA_DIR}/out/kc.tar.gz" "${BUNDLE_PATH}"; chmod 0600 "${BUNDLE_PATH}"
install_bundle

# ---------------------------------------------------------------- PostgreSQL
log "PostgreSQL ${PG_MAJOR}: keycloak database (localhost only)"
KC_DB_PW="$(secret_get keycloak-db-password)"
sudo -u postgres psql -v ON_ERROR_STOP=1 -tAc "SELECT 1 FROM pg_roles WHERE rolname='keycloak'" | grep -q 1 || \
  sudo -u postgres psql -v ON_ERROR_STOP=1 <<SQL
CREATE ROLE keycloak LOGIN PASSWORD '${KC_DB_PW}';
SQL
sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='keycloak'" | grep -q 1 || \
  sudo -u postgres createdb -O keycloak keycloak

# ---------------------------------------------------------------- lldap
log "lldap ${LLDAP_VERSION}"
id lldap >/dev/null 2>&1 || useradd --system --home /var/lib/lldap --shell /usr/sbin/nologin lldap
install -d -o lldap -g lldap -m 0750 /var/lib/lldap
install -d -o root -g lldap -m 0750 /etc/lldap /etc/lldap/tls
if [ ! -x /opt/lldap/lldap ]; then
  tmp="$(mktemp -d)"; fetch "${LLDAP_URL}" "${tmp}/lldap.tgz"; verify_sha256 "${tmp}/lldap.tgz" "${LLDAP_SHA256}"
  tar -xzf "${tmp}/lldap.tgz" -C "${tmp}"; rm -rf /opt/lldap; mv "${tmp}/amd64-lldap" /opt/lldap; rm -rf "${tmp}"
  chown -R root:root /opt/lldap
fi
install -m 0640 -o root -g lldap "${TLS_DIR}/kc.crt" /etc/lldap/tls/kc.crt
install -m 0640 -o root -g lldap "${TLS_DIR}/kc.key" /etc/lldap/tls/kc.key
LLDAP_ADMIN_PW="$(secret_get lldap-admin-password)"
if [ ! -s /etc/lldap/lldap_config.toml ]; then
  ( umask 027
    cat > /etc/lldap/lldap_config.toml <<TOML
database_url = "sqlite:///var/lib/lldap/users.db?mode=rwc"
ldap_host = "0.0.0.0"
ldap_port = 3890
http_host = "127.0.0.1"
http_port = 17170
http_url = "http://127.0.0.1:17170"
ldap_base_dn = "${LDAP_BASE_DN}"
ldap_user_dn = "admin"
ldap_user_email = "admin@${MAIL_DOMAIN}"
ldap_user_pass = "${LLDAP_ADMIN_PW}"
jwt_secret = "$(secret_get lldap-jwt-secret)"
key_seed = "$(secret_get lldap-key-seed)"

[ldaps_options]
enabled = true
port = 6360
cert_file = "/etc/lldap/tls/kc.crt"
key_file = "/etc/lldap/tls/kc.key"
TOML
  )
  chown root:lldap /etc/lldap/lldap_config.toml
fi
cat > /etc/systemd/system/lldap.service <<'UNIT'
[Unit]
Description=lldap (lab LDAP directory)
After=network-online.target
Wants=network-online.target
[Service]
User=lldap
Group=lldap
WorkingDirectory=/opt/lldap
ExecStart=/opt/lldap/lldap run --config-file /etc/lldap/lldap_config.toml
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/lldap
PrivateTmp=true
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload; systemctl enable --now lldap
for i in $(seq 1 30); do curl -fsS -o /dev/null http://127.0.0.1:17170/ && break; sleep 1; done
bash "${HERE}/provision-lldap.sh" bind

# ---------------------------------------------------------------- Keycloak
log "Keycloak ${KC_VERSION}"
id keycloak >/dev/null 2>&1 || useradd --system --home /opt/keycloak --shell /usr/sbin/nologin keycloak
if [ ! -d "/opt/keycloak-${KC_VERSION}" ]; then
  tmp="$(mktemp -d)"; fetch "${KC_URL}" "${tmp}/kc.tgz"; verify_sha1 "${tmp}/kc.tgz" "${KC_SHA1}"
  tar -xzf "${tmp}/kc.tgz" -C /opt; rm -rf "${tmp}"
  chown -R keycloak:keycloak "/opt/keycloak-${KC_VERSION}"
fi
ln -sfn "/opt/keycloak-${KC_VERSION}" /opt/keycloak
install -d -o root -g keycloak -m 0750 /etc/keycloak
install -m 0644 "${TLS_DIR}/kc.crt" /etc/keycloak/tls.crt
install -m 0640 -o root -g keycloak "${TLS_DIR}/kc.key" /etc/keycloak/tls.key
install -m 0644 "${TLS_DIR}/ca.crt" /etc/keycloak/lab-ca.crt

( umask 027
  cat > /etc/keycloak/keycloak.env <<ENV
KC_DB=postgres
KC_DB_URL=jdbc:postgresql://127.0.0.1:5432/keycloak
KC_DB_USERNAME=keycloak
KC_DB_PASSWORD=${KC_DB_PW}
KC_HOSTNAME=https://${HOST_KC}
KC_HTTP_ENABLED=false
KC_HTTPS_PORT=443
KC_HTTPS_CERTIFICATE_FILE=/etc/keycloak/tls.crt
KC_HTTPS_CERTIFICATE_KEY_FILE=/etc/keycloak/tls.key
KC_TRUSTSTORE_PATHS=/etc/keycloak/lab-ca.crt
KC_HEALTH_ENABLED=true
KC_BOOTSTRAP_ADMIN_USERNAME=kcadmin
KC_BOOTSTRAP_ADMIN_PASSWORD=$(secret_get keycloak-admin-password)
ENV
)
chown root:keycloak /etc/keycloak/keycloak.env

log "kc.sh build (optimized)"
sudo -u keycloak env KC_DB=postgres KC_HEALTH_ENABLED=true /opt/keycloak/bin/kc.sh build

log "render realm import (bind password injected at runtime)"
install -d -o keycloak -g keycloak -m 0700 /opt/keycloak/data/import
BINDPW="$(secret_get ldap-bind-password)"
sed "s/__LDAP_BIND_PASSWORD__/${BINDPW}/" "${HERE}/realm-ou-lab.json" > /opt/keycloak/data/import/realm-ou-lab.json
chown keycloak:keycloak /opt/keycloak/data/import/realm-ou-lab.json; chmod 0600 /opt/keycloak/data/import/realm-ou-lab.json

cat > /etc/systemd/system/keycloak.service <<'UNIT'
[Unit]
Description=Keycloak (lab)
After=network-online.target postgresql.service lldap.service
Wants=network-online.target
[Service]
User=keycloak
Group=keycloak
EnvironmentFile=/etc/keycloak/keycloak.env
ExecStart=/opt/keycloak/bin/kc.sh start --optimized --import-realm
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
LimitNOFILE=65536
Restart=on-failure
TimeoutStartSec=300
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload; systemctl enable --now keycloak

# ---------------------------------------------------------------- firewall
log "ufw: ssh, 443 (keycloak), 6360 (ldaps from mail VM only); 9000 mgmt and lldap UI/3890 closed"
ufw --force reset >/dev/null
ufw default deny incoming >/dev/null; ufw default allow outgoing >/dev/null
ufw allow 22/tcp >/dev/null
ufw allow 443/tcp >/dev/null
ufw allow from "${IP_MAIL}" to any port 6360 proto tcp >/dev/null
ufw --force enable >/dev/null

log "waiting for Keycloak realm ${REALM}"
for i in $(seq 1 90); do
  curl -fsS --cacert "${TLS_DIR}/ca.crt" "https://${HOST_KC}/realms/${REALM}/.well-known/openid-configuration" >/dev/null 2>&1 && { OK=1; break; }
  sleep 4
done
[ "${OK:-0}" = 1 ] || die "Keycloak realm did not come up; journalctl -u keycloak"

cat <<EOS

kc VM done (untested script; verify each step). Next:
  1. Create test users:      sudo ${HERE}/provision-lldap.sh test-users
  2. Distribute TLS bundles: from the operator workstation run common/fetch-bundle.sh for files, office, mail
  3. Secrets (root-only):    ${SECRETS_DIR}/  (keycloak admin, DB, lldap admin, bind, test users)
  4. Check LDAP federation:  Keycloak admin console > ou-lab > User federation > lldap > Test connection / Sync
  5. Admin console URL:      https://${HOST_KC}/admin/  (user kcadmin)
EOS
