#!/usr/bin/env bash
# VM "files": OpenCloud 9.1.0 (binary, systemd) behind nginx (lab CA cert),
# external Keycloak OIDC, built-in collaboration/WOPI service -> Collabora.
# Prereqs: kc VM done; office VM done (preferred); /root/ou-lab-bundle.tar.gz
# delivered by common/fetch-bundle.sh <kc> files <this-vm>.
# STATUS: executed in nspawn ou-files1 (see docs/status/identity-files-lab-results.md).
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB="$(cd "${HERE}/../../common" && pwd)"
. "${LAB}/lab.env"; . "${LAB}/versions.env"; . "${LAB}/lib.sh"
need_root; secrets_dir_init
. /etc/os-release; [ "${VERSION_ID:-}" = "24.04" ] || warn "tested-for OS is Ubuntu 24.04"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
. "$(dirname "$0")/../../common/packages.env"
apt-get install -y -qq $FILES_PKGS
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
    -e "s#__REALM__#${REALM}#g" -e "s#__LDAP_HOST__#${HOST_LDAP}#g" -e "s#__BASE_DN__#${LDAP_BASE_DN}#g" "${HERE}/opencloud.env.tmpl" > /etc/opencloud/opencloud.env
sed -e "s#__IDP_HOST__#${HOST_KC}#g" -e "s#__OFFICE_HOST__#${HOST_OFFICE}#g" "${HERE}/csp.yaml.tmpl" > /etc/opencloud/csp.yaml
chown root:opencloud /etc/opencloud/opencloud.env /etc/opencloud/csp.yaml; chmod 0640 /etc/opencloud/opencloud.env /etc/opencloud/csp.yaml

# LDAP bind password (read-only bind user): copied by the operator from the kc machine's ${SECRETS_DIR}/ldap-bind-password
[ -s "${SECRETS_DIR}/ldap-bind-password" ] || die "put the LDAP bind password in ${SECRETS_DIR}/ldap-bind-password (0600) first"
( umask 027; printf 'OC_LDAP_BIND_PASSWORD=%s\n' "$(cat "${SECRETS_DIR}/ldap-bind-password")" > /etc/opencloud/opencloud.secrets.env )
chown root:opencloud /etc/opencloud/opencloud.secrets.env
if [ ! -s /etc/opencloud/opencloud.yaml ]; then
  log "opencloud init (generates JWT/transfer secrets + internal idm admin password into opencloud.yaml)"
  ADMIN_PW="$(secret_get opencloud-internal-admin-password)"
  env OC_CONFIG_DIR=/etc/opencloud OC_BASE_DATA_PATH=/var/lib/opencloud \
    /usr/local/bin/opencloud init --insecure false --config-path /etc/opencloud --admin-password "${ADMIN_PW}" \
    || die "opencloud init failed; check 'opencloud init --help' for the 9.1.0 flag names (insecure/admin-password) and rerun"
  chown root:opencloud /etc/opencloud/opencloud.yaml; chmod 0640 /etc/opencloud/opencloud.yaml
fi

for u in opencloud opencloud-collaboration; do
  if [ "$u" = opencloud ]; then cmd="server"; desc="OpenCloud (lab)"; after="network-online.target"; else cmd="collaboration server"; desc="OpenCloud collaboration/WOPI service (lab)"; after="network-online.target opencloud.service"; fi
  cat > /etc/systemd/system/$u.service <<UNIT
[Unit]
Description=${desc}
After=${after}
Wants=network-online.target
$( [ "$u" = opencloud ] || echo "Requires=opencloud.service" )
[Service]
User=opencloud
Group=opencloud
EnvironmentFile=/etc/opencloud/opencloud.env
EnvironmentFile=/etc/opencloud/opencloud.secrets.env
$( [ "$u" = opencloud ] || echo "ExecStartPre=/bin/bash -c 'until (echo > /dev/tcp/127.0.0.1/9233) 2>/dev/null; do sleep 1; done; sleep 3'" )
ExecStart=/usr/local/bin/opencloud ${cmd}
Restart=always
RestartSec=5
LimitNOFILE=65536
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
UNIT
done

sed -e "s#__FILES_HOST__#${HOST_FILES}#g" "${HERE}/nginx-cloud.conf.tmpl" > /etc/nginx/sites-available/ou-lab-cloud
ln -sf /etc/nginx/sites-available/ou-lab-cloud /etc/nginx/sites-enabled/ou-lab-cloud
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl daemon-reload; systemctl enable --now opencloud; sleep 15
# OU_SKIP_COLLAB=1: stacks without a document-editing tier (tenant-isolation lab) do not start the WOPI service
[ "${OU_SKIP_COLLAB:-0}" = 1 ] || systemctl enable --now opencloud-collaboration; systemctl reload nginx || systemctl restart nginx


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
