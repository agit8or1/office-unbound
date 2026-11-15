#!/usr/bin/env bash
# Authoritative per-customer directory: OpenLDAP (slapd 2.6, Ubuntu 24.04) with memberof + refint + ppolicy
# overlays, LDAPS on 636 (lab CA leaf), read-only bind user for Keycloak/OpenCloud/gromox.
# Replaces lldap (see docs/status/identity-files-lab-results.md, decision section).
# STATUS: executed in nspawn ou-id1 (see results file). Run as root after lab-ca bundle is installed in /etc/ou-lab/tls.
#   install-openldap.sh            -> install + configure slapd, base tree, groups, bind user
#   install-openldap.sh test-users -> 5 lab users (alice admin, bob user, carol spaceadmin, dave guest, erin no role)
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB="$(cd "${HERE}/../../common" && pwd)"
. "${LAB}/lab.env"; . "${LAB}/lib.sh"
need_root; secrets_dir_init
BASE="${LDAP_BASE_DN}"
ADMIN_DN="cn=admin,${BASE}"
ADMIN_PW="$(secret_get ldap-admin-password)"
BIND_DN="cn=${LDAP_BIND_USER},ou=system,${BASE}"
BIND_PW="$(secret_get ldap-bind-password)"
export LDAPTLS_CACERT="${TLS_DIR}/ca.crt"
# ldapadd/ldapmodify over ldapi with root EXTERNAL for cn=config; admin simple bind over ldaps for data
cfg() { ldapmodify -Q -Y EXTERNAL -H ldapi:/// "$@"; }
dat() { LDAPTLS_CACERT="${TLS_DIR}/ca.crt" ldapadd -x -H "ldaps://${HOST_LDAP}" -D "${ADMIN_DN}" -y <(printf '%s' "${ADMIN_PW}") "$@"; }
datmod() { LDAPTLS_CACERT="${TLS_DIR}/ca.crt" ldapmodify -x -H "ldaps://${HOST_LDAP}" -D "${ADMIN_DN}" -y <(printf '%s' "${ADMIN_PW}") "$@"; }

install_slapd() {
  export DEBIAN_FRONTEND=noninteractive
  if ! dpkg -s slapd >/dev/null 2>&1; then
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
    apt-get install -y -qq slapd ldap-utils
  fi
  # TLS material readable by the openldap user
  install -d -o root -g openldap -m 0750 /etc/ldap/tls
  install -m 0644 "${TLS_DIR}/ca.crt" /etc/ldap/tls/ca.crt
  install -m 0644 "${TLS_DIR}/kc.crt" /etc/ldap/tls/server.crt
  install -m 0640 -o root -g openldap "${TLS_DIR}/kc.key" /etc/ldap/tls/server.key
  sed -i 's#^SLAPD_SERVICES=.*#SLAPD_SERVICES="ldap://127.0.0.1:389/ ldaps:/// ldapi:///"#' /etc/default/slapd
  cfg <<LDIF
dn: cn=config
changetype: modify
replace: olcTLSCACertificateFile
olcTLSCACertificateFile: /etc/ldap/tls/ca.crt
-
replace: olcTLSCertificateFile
olcTLSCertificateFile: /etc/ldap/tls/server.crt
-
replace: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: /etc/ldap/tls/server.key
-
replace: olcTLSProtocolMin
olcTLSProtocolMin: 3.3
LDIF
  systemctl restart slapd
  # overlays
  for m in memberof refint ppolicy; do
    ldapsearch -LLL -Q -Y EXTERNAL -H ldapi:/// -b cn=module{0},cn=config olcModuleLoad 2>/dev/null | grep -q "${m}" && continue
    cfg <<LDIF
dn: cn=module{0},cn=config
changetype: modify
add: olcModuleLoad
olcModuleLoad: ${m}
LDIF
  done
  DB="$(ldapsearch -Q -Y EXTERNAL -H ldapi:/// -b cn=config "(olcSuffix=${BASE})" dn | awk '/^dn:/{print $2}')"
  [ -n "${DB}" ] || die "no database for ${BASE}"
  ldapsearch -LLL -Q -Y EXTERNAL -H ldapi:/// -b "${DB}" "(olcOverlay=memberof)" dn | grep -q memberof || {
    ldapadd -Q -Y EXTERNAL -H ldapi:/// <<LDIF
dn: olcOverlay=memberof,${DB}
objectClass: olcOverlayConfig
objectClass: olcMemberOf
olcOverlay: memberof
olcMemberOfRefInt: TRUE
olcMemberOfGroupOC: groupOfNames
olcMemberOfMemberAD: member
olcMemberOfMemberOfAD: memberOf

dn: olcOverlay=refint,${DB}
objectClass: olcOverlayConfig
objectClass: olcRefintConfig
olcOverlay: refint
olcRefintAttribute: member
olcRefintAttribute: memberOf

dn: olcOverlay=ppolicy,${DB}
objectClass: olcOverlayConfig
objectClass: olcPPolicyConfig
olcOverlay: ppolicy
olcPPolicyDefault: cn=default,ou=policies,${BASE}
olcPPolicyHashCleartext: TRUE
olcPPolicyUseLockout: TRUE
LDIF
  }
  # ACLs: userPassword only for auth/self; bind user + admin read everything else; self read; no anonymous reads
  cfg <<LDIF
dn: ${DB}
changetype: modify
replace: olcAccess
olcAccess: {0}to attrs=userPassword by self write by anonymous auth by * none
olcAccess: {1}to attrs=pwdAccountLockedTime,pwdFailureTime,pwdChangedTime,pwdHistory by dn.exact="${BIND_DN}" read by * none
olcAccess: {2}to * by dn.exact="${BIND_DN}" read by self read by * none
-
replace: olcDbIndex
olcDbIndex: objectClass eq
olcDbIndex: cn,uid,mail eq,sub
olcDbIndex: member,memberOf eq
olcDbIndex: entryUUID,entryCSN eq
LDIF
}

base_tree() {
  ldapsearch -LLL -x -H "ldaps://${HOST_LDAP}" -D "${ADMIN_DN}" -y <(printf '%s' "${ADMIN_PW}") -b "ou=system,${BASE}" -s base dn 2>/dev/null | grep -q '^dn:' && return 0
  export LDAPTLS_CACERT="${TLS_DIR}/ca.crt"
  dat <<LDIF
dn: ou=people,${BASE}
objectClass: organizationalUnit
ou: people

dn: ou=groups,${BASE}
objectClass: organizationalUnit
ou: groups

dn: ou=system,${BASE}
objectClass: organizationalUnit
ou: system

dn: ou=policies,${BASE}
objectClass: organizationalUnit
ou: policies

dn: cn=default,ou=policies,${BASE}
objectClass: device
objectClass: pwdPolicy
cn: default
pwdAttribute: userPassword
pwdLockout: TRUE
pwdLockoutDuration: 0
pwdMaxFailure: 10
pwdFailureCountInterval: 300
pwdAllowUserChange: TRUE
pwdMinLength: 8

dn: ${BIND_DN}
objectClass: organizationalRole
objectClass: simpleSecurityObject
cn: ${LDAP_BIND_USER}
userPassword: $(slappasswd -s "${BIND_PW}")
LDIF
  # role groups. groupOfNames needs >=1 member: seed with the bind user (it holds no OpenCloud rights: it is not in ou=people)
  for g in opencloudAdmin opencloudSpaceAdmin opencloudUser opencloudGuest mail-users; do
    dat <<LDIF
dn: cn=${g},ou=groups,${BASE}
objectClass: groupOfNames
cn: ${g}
member: ${BIND_DN}
LDIF
  done
}

test_users() {
  export LDAPTLS_CACERT="${TLS_DIR}/ca.crt"
  out="${SECRETS_DIR}/test-users.env"; touch "${out}"; chmod 0600 "${out}"   # never truncated: a re-run keeps existing users and their passwords
  n=2000
  for spec in alice:opencloudAdmin bob:opencloudUser carol:opencloudSpaceAdmin dave:opencloudGuest erin:; do
    u="${spec%%:*}"; g="${spec#*:}"; U="$(echo "$u" | tr a-z A-Z)"; n=$((n+1))
    if ldapsearch -LLL -x -H "ldaps://${HOST_LDAP}" -D "${ADMIN_DN}" -y <(printf '%s' "${ADMIN_PW}") -b "uid=${u},ou=people,${BASE}" -s base dn 2>/dev/null | grep -q '^dn:'; then
      log "test user ${u} exists, skipped"; continue
    fi
    pw="$(gen_secret)"
    dat <<LDIF
dn: uid=${u},ou=people,${BASE}
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
uid: ${u}
cn: Lab ${u^}
sn: Lab
givenName: ${u^}
displayName: Lab ${u^}
mail: ${u}@${MAIL_DOMAIN}
userPassword: $(slappasswd -s "${pw}")
LDIF
    for grp in ${g} mail-users; do
      [ -n "${grp}" ] || continue
      datmod <<LDIF
dn: cn=${grp},ou=groups,${BASE}
changetype: modify
add: member
member: uid=${u},ou=people,${BASE}
LDIF
    done
    printf 'OU_PASSWORD_%s=%s\n' "${U}" "${pw}" >> "${out}"
  done
  log "test users created; passwords in ${out} (root-only)"
}

case "${1:-install}" in
  install) install_slapd; base_tree; log "OpenLDAP ready: ldaps://${HOST_LDAP} base ${BASE}";;
  test-users) test_users;;
  *) die "usage: $0 [install|test-users]";;
esac
