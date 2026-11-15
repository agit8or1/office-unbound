#!/usr/bin/env bash
# VM "files": OpenCloud 9.1.0 (binary, systemd) behind nginx (lab CA cert),
# external Keycloak OIDC, built-in collaboration/WOPI service -> Collabora.
# Prereqs: kc VM done; office VM done (preferred); /root/ou-lab-bundle.tar.gz
# delivered by common/fetch-bundle.sh <kc> files <this-vm>.
# STATUS: PREPARED, NOT EXECUTED.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB="$(cd "${HERE}/../../common" && pwd)"
. "${LAB}/lab.env"; . "${LAB}/versions.env"; . "${LAB}/lib.sh"
need_root; secrets_dir_init
. /etc/os-release; [ "${VERSION_ID:-}" = "24.04" ] || warn "tested-for OS is Ubuntu 24.04"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq nginx curl ca-certificates openssl ufw jq
add_lab_hosts
install_bundle

log "OpenCloud ${OC_VERSION} binary"
if [ ! -x /usr/local/bin/opencloud ] || ! /usr/local/bin/opencloud version 2>/dev/null | grep -q "${OC_VERSION}"; then
  tmp="$(mktemp -d)"; fetch "${OC_URL}" "${tmp}/opencloud"; verify_sha256 "${tmp}/opencloud" "${OC_SHA256}"
  install -m 0755 "${tmp}/opencloud" /usr/local/bin/opencloud; rm -rf "${tmp}"
fi

id opencloud >/dev/null 2>&1 || useradd --system --home /var/lib/opencloud --shell /usr/sbin/nologin opencloud
install -d -o opencloud -g opencloud -m 0750 /var/lib/opencloud
install -d -o root -g opencloud -m 0750 /etc/opencloud
fstype="$(stat -f -c %T /var/lib/opencloud)"
case "${fstype}" in ext2/ext3|xfs|zfs|btrfs) ;; *) warn "/var/lib/opencloud is on '${fstype}'; posix storage needs ext4/xfs/zfs with xattrs";; esac

sed -e "s#__FILES_HOST__#${HOST_FILES}#g" -e "s#__IDP_HOST__#${HOST_KC}#g" -e "s#__OFFICE_HOST__#${HOST_OFFICE}#g" \
    -e "s#__REALM__#${REALM}#g" -e "s#__LDAP_HOST__#${HOST_LDAP}#g" "${HERE}/opencloud.env.tmpl" > /etc/opencloud/opencloud.env
sed -e "s#__IDP_HOST__#${HOST_KC}#g" -e "s#__OFFICE_HOST__#${HOST_OFFICE}#g" "${HERE}/csp.yaml.tmpl" > /etc/opencloud/csp.yaml
chown root:opencloud /etc/opencloud/opencloud.env /etc/opencloud/csp.yaml; chmod 0640 /etc/opencloud/opencloud.env /etc/opencloud/csp.yaml

if [ ! -s /etc/opencloud/opencloud.yaml ]; then
  log "opencloud init (generates JWT/transfer secrets + internal idm admin password into opencloud.yaml)"
  ADMIN_PW="$(secret_get opencloud-internal-admin-password)"
  sudo -u opencloud env OC_CONFIG_DIR=/etc/opencloud OC_BASE_DATA_PATH=/var/lib/opencloud \
    /usr/local/bin/opencloud init --insecure false --admin-password "${ADMIN_PW}" \
    || die "opencloud init failed; check 'opencloud init --help' for the 9.1.0 flag names (insecure/admin-password) and rerun"
  chown root:opencloud /etc/opencloud/opencloud.yaml; chmod 0640 /etc/opencloud/opencloud.yaml
fi

cat > /etc/systemd/system/opencloud.service <<'UNIT'
[Unit]
Description=OpenCloud (lab) incl. collaboration/WOPI service
After=network-online.target
Wants=network-online.target
[Service]
User=opencloud
Group=opencloud
EnvironmentFile=/etc/opencloud/opencloud.env
ExecStart=/usr/local/bin/opencloud server
Restart=always
RestartSec=5
LimitNOFILE=65536
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
UNIT

sed -e "s#__FILES_HOST__#${HOST_FILES}#g" "${HERE}/nginx-cloud.conf.tmpl" > /etc/nginx/sites-available/ou-lab-cloud
ln -sf /etc/nginx/sites-available/ou-lab-cloud /etc/nginx/sites-enabled/ou-lab-cloud
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl daemon-reload; systemctl enable --now opencloud; systemctl reload nginx

ufw --force reset >/dev/null; ufw default deny incoming >/dev/null; ufw default allow outgoing >/dev/null
ufw allow 22/tcp >/dev/null; ufw allow 80/tcp >/dev/null; ufw allow 443/tcp >/dev/null
ufw --force enable >/dev/null

log "waiting for OpenCloud"
for i in $(seq 1 60); do
  curl -fsS --cacert "${TLS_DIR}/ca.crt" "https://${HOST_FILES}/.well-known/openid-configuration" >/dev/null 2>&1 && { OK=1; break; }
  sleep 3
done
[ "${OK:-0}" = 1 ] && log "OpenCloud answering" || warn "OpenCloud not answering yet: journalctl -u opencloud"
cat <<EOS

files VM done (untested). Check:
  journalctl -u opencloud | grep -iE 'collaboration|discovery|oidc|error'
  curl --cacert ${TLS_DIR}/ca.crt https://${HOST_FILES}/.well-known/webfinger?resource=acct:x@${HOST_FILES}
Internal idm admin password (break-glass only, root-only): ${SECRETS_DIR}/opencloud-internal-admin-password
EOS
