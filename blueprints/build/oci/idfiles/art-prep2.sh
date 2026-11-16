#!/bin/bash
# LAB, inside the proof machine ou-art1 (root), phase 2 (after pkg.install_pinned installed slapd/postgresql/nginx and podman.pull_verified pulled the two
# images): directory + database + edge configuration, and the node-local state the container units need (podman secrets, named volumes with rendered config).
# These are the steps the ICS configuration templating has to take over ("render config from the catalog, write it where the unit reads it"): there is NO
# runbook for them yet (podman.deploy_unit takes no files and cannot create secrets), so the lab does them by hand and the results doc lists them as a gap.
# usage: art-prep2.sh <keycloak image ref@digest> <opencloud image ref@digest>
set -euo pipefail
cd /
KCIMG=$1; OCIMG=$2
LAB=/root/lab/common; HERE=/root/lab/spike-identity-files
. "$LAB/lab.env"; . "$LAB/lib.sh"
need_root
export LDAPTLS_CACERT=${TLS_DIR}/ca.crt

log "OpenLDAP: overlays, ACLs, base tree, bind user, test users"
bash "$HERE/kc/install-openldap.sh" install
bash "$HERE/kc/install-openldap.sh" test-users

log "PostgreSQL: keycloak role + database (localhost only)"
KC_DB_PW="$(secret_get keycloak-db-password)"
sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='keycloak'" | grep -q 1 || sudo -u postgres psql -v ON_ERROR_STOP=1 -c "CREATE ROLE keycloak LOGIN PASSWORD '${KC_DB_PW}'"
sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='keycloak'" | grep -q 1 || sudo -u postgres createdb -O keycloak keycloak

log "edge: nginx vhosts (TLS with the lab CA leafs)"
vhost() { # name host upstream cert
  local v=${1//-/_}
  cat > /etc/nginx/sites-available/$1 <<N
map \$http_upgrade \$connection_upgrade_$v { default upgrade; '' close; }
server { listen 80; server_name $2; return 301 https://\$host\$request_uri; }
server {
  listen 443 ssl; server_name $2;
  ssl_certificate /etc/ou-lab/tls/$4.crt; ssl_certificate_key /etc/ou-lab/tls/$4.key; ssl_protocols TLSv1.2 TLSv1.3;
  client_max_body_size 0; proxy_request_buffering off; proxy_buffering off; proxy_read_timeout 3600s;
  proxy_buffer_size 16k; proxy_buffers 8 16k;
  location / {
    proxy_pass $3; proxy_http_version 1.1; proxy_set_header Host \$host; proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; proxy_set_header X-Forwarded-Proto https; proxy_set_header X-Forwarded-Host \$host;
    proxy_set_header Upgrade \$http_upgrade; proxy_set_header Connection \$connection_upgrade_$v;
  }
}
N
  ln -sf /etc/nginx/sites-available/$1 /etc/nginx/sites-enabled/$1
}
vhost ou-auth "${HOST_KC}" http://127.0.0.1:8080 kc
vhost ou-cloud "${HOST_FILES}" http://127.0.0.1:9200 files
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl enable --now nginx && systemctl reload nginx

log "node-local state for the units (as ou-svc)"
UID_SVC=$(id -u ou-svc)
PM() { sudo -u ou-svc env HOME=/var/lib/ou-svc XDG_RUNTIME_DIR=/run/user/$UID_SVC /usr/bin/podman "$@"; }
secret() { PM secret rm "$1" >/dev/null 2>&1 || true; printf '%s' "$2" | PM secret create "$1" - >/dev/null; }
secret kc-db-password "$KC_DB_PW"
secret kc-admin-password "$(secret_get keycloak-admin-password)"
secret ldap-bind-password "$(secret_get ldap-bind-password)"
secret oc-admin-password "$(secret_get opencloud-internal-admin-password)"
# put files into a named volume: a throw-away container of the verified image, running as root of its own user namespace, stdin = a tar stream
vol_put() { # <volume> <image> <owner uid:gid> <tar-stream on stdin>
  PM volume create "$1" >/dev/null 2>&1 || true
  PM run --cgroups=disabled --rm -i --user 0 --entrypoint /bin/sh -v "$1:/d" "$2" -c "tar -xf - -C /d && chown -R $3 /d"
}
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
# --- Keycloak: realm import + data volume
mkdir -p "$W/kc/import"
BINDPW="$(secret_get ldap-bind-password)"
sed -e "s/__LDAP_BIND_PASSWORD__/${BINDPW}/" -e "s/dc=ou-lab,dc=internal/${LDAP_BASE_DN}/" -e "s/\.ou-lab\.internal/.${LAB_DOMAIN}/g" \
    -e 's/"realm": "ou-lab"/"realm": "'"${REALM}"'"/' "$HERE/kc/realm-ou-lab.json" > "$W/kc/import/realm-${REALM}.json"
chmod 0600 "$W/kc/import/realm-${REALM}.json"
tar -C "$W/kc" -cf - import | vol_put ou-identity-data "$KCIMG" 10130:10130
install -d "$W/tls"; cp "${TLS_DIR}/ca.crt" "$W/tls/ca.crt"
tar -C "$W/tls" -cf - ca.crt | vol_put ou-identity-tls "$KCIMG" 10130:10130
tar -C "$W/tls" -cf - ca.crt | vol_put ou-files-tls "$OCIMG" 10140:10140
# --- OpenCloud: rendered env file + csp in the config volume
mkdir -p "$W/oc"
sed -e "s#__FILES_HOST__#${HOST_FILES}#g" -e "s#__IDP_HOST__#${HOST_KC}#g" -e "s#__OFFICE_HOST__#${HOST_OFFICE}#g" -e "s#__REALM__#${REALM}#g" \
    -e "s#__LDAP_HOST__#${HOST_LDAP}#g" -e "s#__BASE_DN__#${LDAP_BASE_DN}#g" "$HERE/files/opencloud.env.tmpl" \
  | grep -v -e '^OC_CONFIG_DIR=' -e '^OC_BASE_DATA_PATH=' -e '^COLLABORATION_' \
  | sed -e 's#/etc/opencloud/csp.yaml#/var/lib/opencloud-config/csp.yaml#' -e 's#/etc/ou-lab/tls/ca.crt#/opt/ou-tls/ca.crt#' > "$W/oc/ou.env"
echo 'SSL_CERT_FILE=/opt/ou-tls/ca.crt' >> "$W/oc/ou.env"
sed -e "s#__IDP_HOST__#${HOST_KC}#g" -e "s#__OFFICE_HOST__#${HOST_OFFICE}#g" "$HERE/files/csp.yaml.tmpl" > "$W/oc/csp.yaml"
tar -C "$W/oc" -cf - ou.env csp.yaml | vol_put ou-files-config "$OCIMG" 10140:10140
PM volume create ou-files-data >/dev/null 2>&1 || true
PM run --cgroups=disabled --rm --user 0 --entrypoint /bin/sh -v ou-files-data:/d "$OCIMG" -c "chown 10140:10140 /d"
log "prep2 done"; PM volume ls
