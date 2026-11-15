#!/usr/bin/env bash
# Dedicated, narrowly scoped LDAP account for the ICS (user lifecycle actions). Run as root on the directory host (ou-id1).
# cn=svc-ics,ou=system,<base> may ONLY:
#   * ou=people: add/modify/delete entries (any attribute except it can WRITE but never READ userPassword; it may set pwdAccountLockedTime)
#   * ou=groups: read group entries and add/remove `member` values (it can NOT create/delete groups or change other attributes)
# It has no access to ou=system / ou=policies / cn=config and is not the rootdn. Rules {0}..{3} of the earlier scripts keep their meaning.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB="$(cd "${HERE}/../../common" && pwd)"
. "${LAB}/lab.env"; . "${LAB}/lib.sh"
need_root; secrets_dir_init
BASE="${LDAP_BASE_DN}"; ADMIN_DN="cn=admin,${BASE}"
ICS_DN="cn=svc-ics,ou=system,${BASE}"; ICS_PW="$(secret_get ldap-ics-password)"
GX_DN="cn=svc-gromox,ou=system,${BASE}"; BIND_DN="cn=${LDAP_BIND_USER},ou=system,${BASE}"
export LDAPTLS_CACERT="${TLS_DIR}/ca.crt"
if ! ldapsearch -LLL -x -H "ldaps://${HOST_LDAP}" -D "${ADMIN_DN}" -y "${SECRETS_DIR}/ldap-admin-password" -b "${ICS_DN}" -s base dn 2>/dev/null | grep -q '^dn:'; then
  ldapadd -x -H "ldaps://${HOST_LDAP}" -D "${ADMIN_DN}" -y "${SECRETS_DIR}/ldap-admin-password" >/dev/null <<LDIF
dn: ${ICS_DN}
objectClass: organizationalRole
objectClass: simpleSecurityObject
cn: svc-ics
userPassword: $(slappasswd -s "${ICS_PW}")
LDIF
fi
DB="$(ldapsearch -Q -Y EXTERNAL -H ldapi:/// -b cn=config "(olcSuffix=${BASE})" dn | awk '/^dn:/{print $2}')"
ldapmodify -Q -Y EXTERNAL -H ldapi:/// <<LDIF
dn: ${DB}
changetype: modify
replace: olcAccess
olcAccess: {0}to dn.subtree="ou=people,${BASE}" attrs=userPassword by dn.exact="${ICS_DN}" =w by self write by anonymous auth by * none
olcAccess: {1}to attrs=userPassword by self write by anonymous auth by * none
olcAccess: {2}to attrs=pwdAccountLockedTime by dn.exact="${ICS_DN}" manage by dn.exact="${BIND_DN}" read by dn.exact="${GX_DN}" read by * none
olcAccess: {3}to attrs=pwdFailureTime,pwdChangedTime,pwdHistory by dn.exact="${BIND_DN}" read by dn.exact="${ICS_DN}" read by * none
olcAccess: {4}to dn.subtree="ou=people,${BASE}" attrs=entry,objectClass,uid,mail,cn,sn,givenName,displayName,entryUUID,memberOf by dn.exact="${GX_DN}" read by * break
olcAccess: {5}to dn.subtree="ou=people,${BASE}" by dn.exact="${ICS_DN}" write by * break
olcAccess: {6}to dn.subtree="ou=groups,${BASE}" attrs=member by dn.exact="${ICS_DN}" write by * break
olcAccess: {7}to dn.subtree="ou=groups,${BASE}" attrs=entry,cn,objectClass,entryUUID by dn.exact="${ICS_DN}" read by * break
olcAccess: {8}to * by dn.exact="${BIND_DN}" read by self read by * none
LDIF
log "svc-ics ready (password in ${SECRETS_DIR}/ldap-ics-password)"
