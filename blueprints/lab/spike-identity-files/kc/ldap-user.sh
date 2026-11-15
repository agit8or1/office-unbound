#!/usr/bin/env bash
# Directory-side user lifecycle helper (what ICS will do via its own LDAP client). Run as root on the machine with the directory.
#   ldap-user.sh add <uid> <group|-> ; ldap-user.sh lock <uid> ; ldap-user.sh unlock <uid> ; ldap-user.sh delete <uid>
# "lock" = ppolicy permanent lock (pwdAccountLockedTime=000001010000Z): the account can no longer BIND (so Keycloak's
# LDAP password check fails) and OpenCloud's user filter (!(pwdAccountLockedTime=*)) stops resolving it.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB="$(cd "${HERE}/../../common" && pwd)"
. "${LAB}/lab.env"; . "${LAB}/lib.sh"
need_root
export LDAPTLS_CACERT="${TLS_DIR}/ca.crt"
BASE="${LDAP_BASE_DN}"; ADMIN_DN="cn=admin,${BASE}"
mod() { ldapmodify -x -H "ldaps://${HOST_LDAP}" -D "${ADMIN_DN}" -y "${SECRETS_DIR}/ldap-admin-password"; }
u="${2:?uid}"; dn="uid=${u},ou=people,${BASE}"
case "${1:-}" in
  add)
    g="${3:--}"; pw="$(gen_secret)"
    ldapadd -x -H "ldaps://${HOST_LDAP}" -D "${ADMIN_DN}" -y "${SECRETS_DIR}/ldap-admin-password" >/dev/null <<LDIF
dn: ${dn}
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
    for grp in ${g} mail-users; do [ "${grp}" = - ] && continue
      mod >/dev/null <<LDIF
dn: cn=${grp},ou=groups,${BASE}
changetype: modify
add: member
member: ${dn}
LDIF
    done
    printf 'OU_PASSWORD_%s=%s\n' "$(echo "${u}" | tr a-z A-Z)" "${pw}" >> "${SECRETS_DIR}/test-users.env"
    log "added ${u} (password in ${SECRETS_DIR}/test-users.env)";;
  lock)   mod >/dev/null <<LDIF
dn: ${dn}
changetype: modify
replace: pwdAccountLockedTime
pwdAccountLockedTime: 000001010000Z
LDIF
    log "locked ${u}";;
  unlock) mod >/dev/null <<LDIF
dn: ${dn}
changetype: modify
delete: pwdAccountLockedTime
LDIF
    log "unlocked ${u}";;
  delete) ldapdelete -x -H "ldaps://${HOST_LDAP}" -D "${ADMIN_DN}" -y "${SECRETS_DIR}/ldap-admin-password" "${dn}"; log "deleted ${u}";;
  *) die "usage: $0 add|lock|unlock|delete <uid> [group]";;
esac
