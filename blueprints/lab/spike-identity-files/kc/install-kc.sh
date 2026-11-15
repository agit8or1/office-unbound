#!/usr/bin/env bash
# VM "kc": lab CA + PostgreSQL 16 + OpenLDAP + Keycloak (pinned, optimized build).
# Target OS: Ubuntu 24.04 LTS. Run as root from a checkout of blueprints/lab.
# STATUS: executed in nspawn ou-id1 (Ubuntu 24.04), see docs/status/identity-files-lab-results.md.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB="$(cd "${HERE}/../../common" && pwd)"
. "${LAB}/lab.env"; . "${LAB}/versions.env"; . "${LAB}/lib.sh"
need_root; secrets_dir_init
[ -r /etc/os-release ] && . /etc/os-release
[ "${VERSION_ID:-}" = "24.04" ] || warn "tested-for OS is Ubuntu 24.04, found ${PRETTY_NAME:-unknown}"

log "packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq postgresql-${PG_MAJOR} openjdk-21-jre-headless curl ca-certificates openssl jq gettext-base

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

# ---------------------------------------------------------------- OpenLDAP (authoritative directory)
log "OpenLDAP (slapd) directory"
bash "${HERE}/install-openldap.sh" install
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
# lab-domain parametrisation (clean-room run): the realm file carries the default ou-lab.internal names
sed -e "s/__LDAP_BIND_PASSWORD__/${BINDPW}/" -e "s#dc=ou-lab,dc=internal#${LDAP_BASE_DN}#g" -e "s#ou-lab\.internal#${LAB_DOMAIN}#g" "${HERE}/realm-ou-lab.json" > /opt/keycloak/data/import/realm-ou-lab.json
chown -R keycloak:keycloak /opt/keycloak-${KC_VERSION}/data   # data/ was created root-owned by install -d (found in lab run: truststore write EACCES)
chmod 0600 /opt/keycloak/data/import/realm-ou-lab.json

cat > /etc/systemd/system/keycloak.service <<'UNIT'
[Unit]
Description=Keycloak (lab)
After=network-online.target postgresql.service slapd.service
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


log "waiting for Keycloak realm ${REALM}"
for i in $(seq 1 90); do
  curl -fsS --cacert "${TLS_DIR}/ca.crt" "https://${HOST_KC}/realms/${REALM}/.well-known/openid-configuration" >/dev/null 2>&1 && { OK=1; break; }
  sleep 4
done
[ "${OK:-0}" = 1 ] || die "Keycloak realm did not come up; journalctl -u keycloak"

cat <<EOS

kc VM done (untested script; verify each step). Next:
  1. Create test users:      sudo ${HERE}/install-openldap.sh test-users
  2. Distribute TLS bundles: from the operator workstation run common/fetch-bundle.sh for files, office, mail
  3. Secrets (root-only):    ${SECRETS_DIR}/  (keycloak admin, DB, ldap admin, bind, test users)
  4. Check LDAP federation:  Keycloak admin console > ou-lab > User federation > openldap > Test connection / Sync
  5. Admin console URL:      https://${HOST_KC}/admin/  (user kcadmin)
EOS
