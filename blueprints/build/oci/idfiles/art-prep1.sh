#!/bin/bash
# LAB, inside the proof machine ou-art1 (root), phase 1: names, lab CA/TLS, secrets, debconf answers for slapd. Runs BEFORE the packages are installed by the
# pkg.install_pinned runbook (slapd's first configuration needs the debconf answers; the runbook itself passes no preseed).
# Expects /root/lab = blueprints/lab of this repository.
set -euo pipefail
mkdir -p /etc/ou-lab
cat > /etc/ou-lab/lab-local.env <<'E'
# one machine plays the identity AND the files tier: both names resolve to this machine
IP_KC=192.168.186.248
IP_FILES=192.168.186.248
IP_OFFICE=192.168.186.248
E
HERE=/root/lab/spike-identity-files/kc
LAB=/root/lab/common
. "$LAB/lab.env"; . "$LAB/lib.sh"
need_root; secrets_dir_init
add_lab_hosts
bash "$LAB/lab-ca.sh"
cp "${CA_DIR}/out/kc.tar.gz" "${BUNDLE_PATH}"; chmod 0600 "${BUNDLE_PATH}"
install_bundle
tar -xzf "${CA_DIR}/out/files.tar.gz" -C "${TLS_DIR}"; chmod 0644 "${TLS_DIR}"/*.crt; chmod 0600 "${TLS_DIR}"/*.key
ADMIN_PW="$(secret_get ldap-admin-password)"
debconf-set-selections <<DEB
slapd slapd/internal/generated_adminpw password ${ADMIN_PW}
slapd slapd/internal/adminpw password ${ADMIN_PW}
slapd slapd/password1 password ${ADMIN_PW}
slapd slapd/password2 password ${ADMIN_PW}
slapd slapd/domain string ${LAB_DOMAIN}
slapd shared/organization string Office Unbound LAB
slapd slapd/no_configuration boolean false
slapd slapd/purge_database boolean true
slapd slapd/move_old_database boolean true
DEB
# slapd was installed by the first runbook run without answers: remove it so the runbook reinstall configures the lab domain
DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq slapd ldap-utils >/dev/null 2>&1 || true
rm -rf /var/lib/ldap /etc/ldap/slapd.d
ls "${TLS_DIR}"; echo prep1 done
