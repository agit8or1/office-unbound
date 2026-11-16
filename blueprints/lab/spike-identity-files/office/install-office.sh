#!/usr/bin/env bash
# Machine "office": Collabora Online from the VENDOR .deb repo (CODE) behind nginx (lab CA cert).
# LAB FUNCTIONAL TESTING ONLY (ADR-0005/0007): production uses our own source build, not these packages.
# Executed in nspawn ou-office1 (Ubuntu 24.04); no Docker (replaces the docker.io/collabora/code image draft).
# Prereq: /root/ou-lab-bundle.tar.gz (CA + office cert/key) installed to /etc/ou-lab/tls via lib.sh install_bundle.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB="$(cd "${HERE}/../../common" && pwd)"
. "${LAB}/lab.env"; . "${LAB}/versions.env"; . "${LAB}/lib.sh"
need_root; secrets_dir_init
. /etc/os-release; [ "${VERSION_ID:-}" = "24.04" ] || warn "tested-for OS is Ubuntu 24.04"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq nginx-light curl ca-certificates openssl gnupg fonts-crosextra-carlito fonts-crosextra-caladea fonts-liberation
add_lab_hosts
[ -s "${TLS_DIR}/office.crt" ] || install_bundle

log "Collabora CODE vendor repo (${COLLABORA_DEB_REPO})"
curl -fsSL "${COLLABORA_KEY_URL}" -o /usr/share/keyrings/collaboraonline-release-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/collaboraonline-release-keyring.gpg] ${COLLABORA_DEB_REPO} ./" > /etc/apt/sources.list.d/collabora.list
apt-get update -qq
apt-get install -y -qq "coolwsd=${COLLABORA_COOLWSD_VERSION}" code-brand
apt-mark hold coolwsd code-brand >/dev/null
log "installed: $(dpkg-query -W -f='${Package} ${Version}\n' coolwsd code-brand collaboraoffice | tr '\n' ';')"

C=/etc/coolwsd/coolwsd.xml
ADMIN_PW="$(secret_get collabora-admin-password)"
coolconfig --config-file="$C" set ssl.enable false
coolconfig --config-file="$C" set ssl.termination true
coolconfig --config-file="$C" set ssl.ca_file_path "${TLS_DIR}/ca.crt"
coolconfig --config-file="$C" set ssl.ssl_verification true
coolconfig --config-file="$C" set net.listen loopback      # binds [::1]:9980 only (nginx proxies to [::1])
# Jails: inside an unprivileged nspawn (user namespace) CLONE_NEWNS/coolmount fail (EPERM) and Landlock is not
# enabled on this kernel, so coolwsd cannot build chroot jails. LAB ONLY: run without jails. Production must keep jails.
coolconfig --config-file="$C" set security.capabilities false
coolconfig --config-file="$C" set mount_jail_tree false
coolconfig --config-file="$C" set logging.level_startup warning
coolconfig --config-file="$C" set storage.wopi.alias_groups.mode groups 2>/dev/null || true
# PBKDF2 hash gets a fresh random salt on every call -> only set once (marker), else every re-run churns coolwsd.xml
if [ ! -e "${SECRETS_DIR}/.collabora-admin-set" ]; then
  coolconfig --config-file="$C" set-admin-password --user=admin --password="${ADMIN_PW}" >/dev/null 2>&1 && touch "${SECRETS_DIR}/.collabora-admin-set" || warn "set-admin-password failed (non-fatal)"
fi
# WOPI host allow-list: only the OpenCloud WOPI host
python3 - "$C" "${HOST_FILES}" <<'PY'
import re, sys
p, host = sys.argv[1], sys.argv[2]
s = open(p).read()
s = s.replace('<alias_groups desc="The WOPI hosts that may connect. In mode \'first\'', '<alias_groups desc="The WOPI hosts that may connect. In mode \'first\'', 1)
s = re.sub(r'(<alias_groups[^>]*?)mode="first"', r'\1mode="groups"', s, count=1)
grp = '\n            <group>\n                <host allow="true">https://%s:443</host>\n            </group>\n' % host
# idempotency (A22 clean-room): coolconfig rewrites the file with tab indentation, so compare on the host element, not on our whitespace
if '<host allow="true">https://%s:443</host>' % host not in s:
    # insert right after the opening tag of alias_groups
    s = re.sub(r'(<alias_groups[^>]*>)', lambda m: m.group(1) + grp, s, count=1)
open(p, 'w').write(s)
PY
systemctl enable --now coolwsd

sed -e "s#__OFFICE_HOST__#${HOST_OFFICE}#g" "${HERE}/nginx-office.conf.tmpl" > /etc/nginx/sites-available/ou-lab-office
ln -sf /etc/nginx/sites-available/ou-lab-office /etc/nginx/sites-enabled/ou-lab-office
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl enable nginx; systemctl reload nginx || systemctl restart nginx

log "waiting for discovery"
for i in $(seq 1 60); do
  curl -fsS --cacert "${TLS_DIR}/ca.crt" "https://${HOST_OFFICE}/hosting/discovery" >/dev/null 2>&1 && { OK=1; break; }
  sleep 3
done
[ "${OK:-0}" = 1 ] && log "Collabora discovery OK" || warn "no discovery yet: journalctl -u coolwsd"
log "Collabora admin console password (root-only): ${SECRETS_DIR}/collabora-admin-password"
