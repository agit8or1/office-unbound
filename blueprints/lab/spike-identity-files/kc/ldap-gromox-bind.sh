#!/usr/bin/env bash
# Dedicated read-only LDAP account for Gromox (ldap_adaptor + the OU provisioning sync). Run as root on the directory host (ou-id1).
# cn=svc-gromox,ou=system,<base>: may only SEARCH/READ under ou=people the attributes gromox needs
#   (entry, objectClass, uid, mail, cn, sn, givenName, displayName, entryUUID, memberOf, pwdAccountLockedTime).
# It can NOT read userPassword (rule {0} stays first) nor other subtrees; svc-bind (Keycloak/OpenCloud) is unchanged.
# Gromox authenticates users by search(mail=<login>) as svc-gromox, then a simple BIND as the found DN with the user's password.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB="$(cd "${HERE}/../../common" && pwd)"
. "${LAB}/lab.env"; . "${LAB}/lib.sh"
need_root; secrets_dir_init
BASE="${LDAP_BASE_DN}"; ADMIN_DN="cn=admin,${BASE}"
GX_DN="cn=svc-gromox,ou=system,${BASE}"; GX_PW="$(secret_get ldap-gromox-password)"
BIND_DN="cn=${LDAP_BIND_USER},ou=system,${BASE}"
export LDAPTLS_CACERT="${TLS_DIR}/ca.crt"
if ! ldapsearch -LLL -x -H "ldaps://${HOST_LDAP}" -D "${ADMIN_DN}" -y "${SECRETS_DIR}/ldap-admin-password" -b "${GX_DN}" -s base dn 2>/dev/null | grep -q '^dn:'; then
  ldapadd -x -H "ldaps://${HOST_LDAP}" -D "${ADMIN_DN}" -y "${SECRETS_DIR}/ldap-admin-password" >/dev/null <<LDIF
dn: ${GX_DN}
objectClass: organizationalRole
objectClass: simpleSecurityObject
cn: svc-gromox
userPassword: $(slappasswd -s "${GX_PW}")
LDIF
fi
DB="$(ldapsearch -Q -Y EXTERNAL -H ldapi:/// -b cn=config "(olcSuffix=${BASE})" dn | awk '/^dn:/{print $2}')"
ldapsearch -LLL -Q -Y EXTERNAL -H ldapi:/// -b "${DB}" -s base olcAccess | tr -d '\n ' | grep -q 'svc-gromox' && { log "ACL already present"; exit 0; }
ldapmodify -Q -Y EXTERNAL -H ldapi:/// <<LDIF
dn: ${DB}
changetype: modify
replace: olcAccess
olcAccess: {0}to attrs=userPassword by self write by anonymous auth by * none
olcAccess: {1}to attrs=pwdAccountLockedTime,pwdFailureTime,pwdChangedTime,pwdHistory by dn.exact="${BIND_DN}" read by dn.exact="${GX_DN}" read by * none
olcAccess: {2}to dn.subtree="ou=people,${BASE}" attrs=entry,objectClass,uid,mail,cn,sn,givenName,displayName,entryUUID,memberOf by dn.exact="${GX_DN}" read by * break
olcAccess: {3}to * by dn.exact="${BIND_DN}" read by self read by * none
LDIF
log "svc-gromox ready (password in ${SECRETS_DIR}/ldap-gromox-password)"
