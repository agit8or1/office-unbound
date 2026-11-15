#!/usr/bin/env bash
# PHASE 3 for VM "mail": after grommunio-setup. Binds gromox to lldap, forces
# outbound mail off, imports the lab users, prints a verification summary.
# STATUS: PREPARED, NOT EXECUTED. Commands use the real admin-api CLI names
# (ldap reload/downsync -c/info/show, domain query) read from
# github.com/grommunio/admin-api cli/*.py; config key names from
# https://docs.grommunio.com/man/ldap_adaptor-4gx/ . lldap attribute choices
# (entryUUID, cn as display name) are UNVERIFIED against lldap v0.6.3.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB="$(cd "${HERE}/../common" && pwd)"
. "${LAB}/lab.env"; . "${LAB}/versions.env"; . "${LAB}/lib.sh"
need_root
[ -e /etc/grommunio-common/setup_done ] || die "run grommunio-setup (phase 2) first"
command -v grommunio-admin >/dev/null || die "grommunio-admin CLI missing"

BIND_PW_FILE="${SECRETS_DIR}/ldap-bind-password"
[ -s "${BIND_PW_FILE}" ] || die "put the lldap bind password (from kc:${SECRETS_DIR}/ldap-bind-password) into ${BIND_PW_FILE} (root-only, 0600): ssh <kc> sudo cat ... | sudo install -m600 /dev/stdin ${BIND_PW_FILE}"
[ "$(stat -c %a "${BIND_PW_FILE}")" = 600 ] || die "${BIND_PW_FILE} must be mode 600"

log "libldap trust for the lab CA"
install -d /etc/ldap
grep -q '^TLS_CACERT' /etc/ldap/ldap.conf 2>/dev/null || echo 'TLS_CACERT /etc/ssl/certs/ca-certificates.crt' >> /etc/ldap/ldap.conf

log "gromox ldap_adaptor.cfg -> lldap over LDAPS (also read by admin-api)"
( umask 037
  cat > /etc/gromox/ldap_adaptor.cfg <<CFG
ldap_host = ldaps://${HOST_LDAP}:6360
ldap_bind_user = uid=${LDAP_BIND_USER},${LDAP_PEOPLE_DN}
ldap_bind_pass = $(cat "${BIND_PW_FILE}")
ldap_search_base = ${LDAP_PEOPLE_DN}
ldap_mail_attr = mail
ldap_object_id = entryUUID
ldap_user_filter = (objectClass=person)
ldap_user_displayname = cn
CFG
)
chown root:gromox /etc/gromox/ldap_adaptor.cfg; chmod 0640 /etc/gromox/ldap_adaptor.cfg

log "reload LDAP in admin-api, show status"
grommunio-admin ldap reload || warn "ldap reload failed"
grommunio-admin ldap info    || warn "ldap info failed (bind/TLS?)"

log "isolated test domain ${MAIL_DOMAIN}"
if ! grommunio-admin domain query domainname 2>/dev/null | grep -qx "${MAIL_DOMAIN}"; then
  grommunio-admin domain create "${MAIL_DOMAIN}" --maxUser 25 || warn "domain create failed (maybe created by setup under another syntax)"
fi

log "import lab users from lldap (people matching objectClass=person)"
grommunio-admin ldap downsync -c || warn "downsync failed; run 'grommunio-admin ldap search' to debug"
grommunio-admin user query username status 2>/dev/null | head -20 || true

log "postfix: outbound relay OFF (all non-local destinations error out)"
postconf -e "default_transport = error:ou-lab outbound mail disabled"
postconf -e "relay_transport = error:ou-lab outbound mail disabled"
postconf -e "relayhost ="
postconf -e "smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination"
systemctl reload postfix || systemctl restart postfix
log "queue must stay empty of external mail:"; postqueue -p | tail -2 || true

log "TLS check against lab CA (expects verify ok)"
for p in 443 ; do
  echo | openssl s_client -connect "127.0.0.1:${p}" -servername "${HOST_MAIL}" -CAfile "${TLS_DIR}/ca.crt" 2>/dev/null | grep -E 'Verify return code' || true
done

cat <<EOS

Summary: bound to ${HOST_LDAP} as ${LDAP_BIND_USER}; domain ${MAIL_DOMAIN}; outbound mail disabled.
Not verified by this script (do by hand / tests/): IMAP/SMTP auth as alice, autodiscover XML,
MAPI/HTTP, EWS, ActiveSync. Record 'dpkg -l | grep -E "gromox|grommunio"' in the test report.
EOS
