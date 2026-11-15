#!/usr/bin/env bash
# Provision lldap content via its GraphQL API. Run as root on the kc VM.
#   provision-lldap.sh bind         -> read-only bind user + role groups (run by install-kc.sh)
#   provision-lldap.sh test-users   -> 5 lab test users; passwords generated at runtime
# Passwords are written ONLY to root-only files under ${SECRETS_DIR}.
# STATUS: UNTESTED. GraphQL mutation names taken from lldap v0.6.3 schema.graphql
# (createUser/createGroup/addUserToGroup); lldap_set_password flag names UNVERIFIED.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB="$(cd "${HERE}/../../common" && pwd)"
. "${LAB}/lab.env"; . "${LAB}/lib.sh"
need_root; secrets_dir_init
command -v jq >/dev/null || die "jq required"

API="http://127.0.0.1:17170"
ADMIN_PW="$(cat "${SECRETS_DIR}/lldap-admin-password")"

login() {
  TOKEN="$(jq -n --arg u admin --arg p "${ADMIN_PW}" '{username:$u,password:$p}' \
    | curl -fsS -H 'Content-Type: application/json' -d @- "${API}/auth/simple/login" | jq -r .token)"
  [ -n "${TOKEN}" ] && [ "${TOKEN}" != null ] || die "lldap admin login failed"
}
gql() { # gql 'query' 'json-variables'
  local vars="${2:-}"; [ -n "${vars}" ] || vars='{}'
  jq -n --arg q "$1" --argjson v "${vars}" '{query:$q,variables:$v}' \
    | curl -fsS -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' -d @- "${API}/api/graphql"
}
user_exists()  { gql '{users{id}}' | jq -e --arg id "$1" '.data.users[]|select(.id==$id)' >/dev/null; }
group_id()     { gql '{groups{id displayName}}' | jq -r --arg n "$1" '.data.groups[]|select(.displayName==$n)|.id'; }
ensure_group() {
  local id; id="$(group_id "$1")"
  if [ -z "${id}" ]; then
    id="$(gql 'mutation($n:String!){createGroup(name:$n){id}}' "$(jq -n --arg n "$1" '{n:$n}')" | jq -r .data.createGroup.id)"
  fi
  echo "${id}"
}
ensure_user() { # id email displayName first last
  user_exists "$1" && return 0
  gql 'mutation($u:CreateUserInput!){createUser(user:$u){id}}' \
    "$(jq -n --arg i "$1" --arg e "$2" --arg d "$3" --arg f "$4" --arg l "$5" '{u:{id:$i,email:$e,displayName:$d,firstName:$f,lastName:$l}}')" \
    | jq -e '.data.createUser.id' >/dev/null || die "createUser $1 failed"
}
add_to_group() { # user group-name
  local gid; gid="$(ensure_group "$2")"
  gql 'mutation($u:String!,$g:Int!){addUserToGroup(userId:$u,groupId:$g){ok}}' \
    "$(jq -n --arg u "$1" --argjson g "${gid}" '{u:$u,g:$g}')" >/dev/null || true   # already-member is not an error
}
set_password() { # user password
  /opt/lldap/lldap_set_password --base-url "${API}" --token "${TOKEN}" --username "$1" --password "$2" >/dev/null \
    || die "lldap_set_password failed for $1 (check flag names with --help)"
}

login
case "${1:-}" in
  bind)
    for g in opencloudAdmin opencloudSpaceAdmin opencloudUser opencloudGuest mail-users; do ensure_group "$g" >/dev/null; done
    ensure_user "${LDAP_BIND_USER}" "${LDAP_BIND_USER}@${MAIL_DOMAIN}" "LDAP read-only bind" "svc" "bind"
    set_password "${LDAP_BIND_USER}" "$(secret_get ldap-bind-password)"
    add_to_group "${LDAP_BIND_USER}" lldap_strict_readonly
    log "bind user + groups ready"
    ;;
  test-users)
    out="${SECRETS_DIR}/test-users.env"; : > "${out}"; chmod 0600 "${out}"
    # name:group (empty group = intentionally NO OpenCloud role claim)
    for spec in alice:opencloudAdmin bob:opencloudUser carol:opencloudSpaceAdmin dave:opencloudGuest erin:; do
      u="${spec%%:*}"; g="${spec#*:}"; U="$(echo "$u" | tr a-z A-Z)"
      ensure_user "$u" "${u}@${MAIL_DOMAIN}" "Lab ${u^}" "${u^}" "Lab"
      pw="$(gen_secret)"; set_password "$u" "${pw}"
      [ -n "$g" ] && add_to_group "$u" "$g"
      add_to_group "$u" mail-users
      printf 'OU_PASSWORD_%s=%s\n' "${U}" "${pw}" >> "${out}"
    done
    log "test users created; passwords in ${out} (root-only). Fetch to the test shell with:"
    log "  set -a; eval \"\$(ssh <kc> sudo cat ${out})\"; set +a"
    ;;
  *) die "usage: $0 bind|test-users" ;;
esac
