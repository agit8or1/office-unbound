#!/usr/bin/env bash
# VM "mail": grommunio COMMUNITY repo, Ubuntu 24.04, pinned package versions.
# PHASE 1 of 2 (this script): host prep, apt repo + pins, secrets, install grommunio-setup.
# PHASE 2 (manual, interactive): `grommunio-setup` dialog - answers are printed at the end.
# PHASE 3: post-setup-grommunio.sh (LDAP -> lldap, lab TLS check, outbound mail OFF).
#
# STATUS: PREPARED, NOT EXECUTED. grommunio-setup is dialog-driven; whether it
# can run fully unattended from GSETUP_* variables is UNVERIFIED, so phase 2 is
# deliberately manual.
#
# Isolation guarantees of this blueprint:
#   * no public MX / DNS: lab domain only, names pinned in /etc/hosts
#   * outbound SMTP: default_transport=error in postfix + ufw egress deny 25/465/587
#   * no certbot/ACME: lab-CA cert from the kc VM
# Repo evidence (checked 2026-11-15):
#   https://download.grommunio.com/community/Ubuntu_24.04/dists/Ubuntu_24.04/main/binary-amd64/Packages
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB="$(cd "${HERE}/../common" && pwd)"
. "${LAB}/lab.env"; . "${LAB}/versions.env"; . "${LAB}/lib.sh"
need_root; secrets_dir_init
. /etc/os-release; [ "${VERSION_ID:-}" = "24.04" ] || die "this blueprint targets Ubuntu 24.04 (repo path ${GROMMUNIO_REPO_URL})"

mem_kb="$(awk '/MemTotal/{print $2}' /proc/meminfo)"
[ "${mem_kb}" -ge 5800000 ] || warn "grommunio quickstart wants >= 6 GB RAM, have $((mem_kb/1024)) MB"
ip -6 addr show dev lo | grep -q '::1' || die "IPv6 loopback (::1) required by grommunio"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl ca-certificates gpg openssl ufw jq dialog ldap-utils

add_lab_hosts
install_bundle
# combined PEM (leaf + CA) for the setup dialog "own certificate" option
cat "${TLS_DIR}/mail.crt" "${TLS_DIR}/ca.crt" > "${TLS_DIR}/mail-fullchain.pem"; chmod 0644 "${TLS_DIR}/mail-fullchain.pem"

# ---- apt repo (community, best effort / unsupported by grommunio GmbH)
install -d -m 0755 /etc/apt/keyrings
EXPECTED_FPR="87B1B28E1E1F6721798CD1CDF448DE9B1BE231D9"   # observed 2026-11-15 from ${GROMMUNIO_KEY_URL} (trust on first use; confirm out of band)
tmpk="$(mktemp)"; fetch "${GROMMUNIO_KEY_URL}" "${tmpk}"
fpr="$(gpg --with-colons --show-keys "${tmpk}" | awk -F: '/^fpr/{print $10; exit}')"
[ "${fpr}" = "${EXPECTED_FPR}" ] || die "grommunio signing key fingerprint changed (${fpr}); verify before continuing"
gpg --batch --yes --dearmor -o /etc/apt/keyrings/download.grommunio.com.gpg "${tmpk}"; rm -f "${tmpk}"
cat > /etc/apt/sources.list.d/grommunio.sources <<SRC
Types: deb
URIs: ${GROMMUNIO_REPO_URL}
Suites: ${GROMMUNIO_REPO_SUITE}
Components: main
Signed-By: /etc/apt/keyrings/download.grommunio.com.gpg
SRC
# Pin the exact versions recorded in common/versions.env. If the community repo
# has rolled these builds away (it may keep only the newest), apt will fail
# loudly: update versions.env deliberately, do NOT unpin.
cat > /etc/apt/preferences.d/ou-lab-grommunio <<PIN
Package: gromox
Pin: version ${GROMOX_PKG_VERSION}
Pin-Priority: 1001

Package: grommunio-web
Pin: version ${GROMMUNIO_WEB_PKG_VERSION}
Pin-Priority: 1001

Package: grommunio-sync
Pin: version ${GROMMUNIO_SYNC_PKG_VERSION}
Pin-Priority: 1001

Package: grommunio-dav
Pin: version ${GROMMUNIO_DAV_PKG_VERSION}
Pin-Priority: 1001

Package: grommunio-admin-api
Pin: version ${GROMMUNIO_ADMIN_API_PKG_VERSION}
Pin-Priority: 1001

Package: grommunio-setup
Pin: version ${GROMMUNIO_SETUP_PKG_VERSION}
Pin-Priority: 1001
PIN
apt-get update -qq
apt-cache policy gromox grommunio-setup | sed -n 1,12p
apt-get install -y grommunio-setup="${GROMMUNIO_SETUP_PKG_VERSION}"

# ---- outbound mail kill switch BEFORE postfix is configured by setup
log "ufw: block outbound SMTP/submission; allow lab subnet inbound only"
LAB_NET="${IP_KC%.*}.0/24"
ufw --force reset >/dev/null
ufw default deny incoming >/dev/null; ufw default allow outgoing >/dev/null
ufw deny out 25/tcp >/dev/null; ufw deny out 465/tcp >/dev/null; ufw deny out 587/tcp >/dev/null
ufw allow from "${LAB_NET}" to any port 22,25,80,143,443,465,587,993 proto tcp >/dev/null
ufw --force enable >/dev/null

ADMIN_PW="$(secret_get grommunio-admin-password)"
DB_PW="$(secret_get grommunio-db-password)"
cat <<EOS

Phase 1 done. Phase 2 (manual, as root, interactive terminal: ssh -t):

  export GSETUP_ADMIN_PASSWORD="\$(cat ${SECRETS_DIR}/grommunio-admin-password)"
  export GSETUP_DB_PASSWORD="\$(cat ${SECRETS_DIR}/grommunio-db-password)"
  export GSETUP_SITE_FQDN="${HOST_MAIL}"
  grommunio-setup -X          # -X: repo already configured by this script

Dialog answers: database = create new (user grommunio, db grommunio, local); FQDN = ${HOST_MAIL};
mail domain = ${MAIL_DOMAIN}; TLS = "own certificate": bundle ${TLS_DIR}/mail-fullchain.pem,
key ${TLS_DIR}/mail.key (NOT Let's Encrypt, NOT self-signed); decline optional extras
(chat/files/meet/archive). If setup refuses -X or prompts for something not listed, record
it in the test report; that is a finding, not an error in the lab.

Phase 3: sudo ${HERE}/post-setup-grommunio.sh
EOS
