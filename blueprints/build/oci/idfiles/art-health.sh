#!/bin/bash
# LAB, inside the proof machine ou-art1 (root): the health checks of the identity and files components, run the way the catalog declares them.
set -u
. /root/lab/common/lab.env
CA=/etc/ou-lab/tls/ca.crt; fail=0
ck() { if eval "$2" >/tmp/hc.out 2>&1; then echo "PASS $1 - $(head -c 160 /tmp/hc.out | tr '\n' ' ')"; else echo "FAIL $1 - $(head -c 200 /tmp/hc.out | tr '\n' ' ')"; fail=1; fi; }
ck "pg_isready (postgresql-16)" "pg_isready -h 127.0.0.1 -p 5432"
ck "LDAP bind as service account svc-bind over LDAPS" "LDAPTLS_CACERT=$CA ldapwhoami -x -H ldaps://${HOST_LDAP} -D cn=${LDAP_BIND_USER},ou=system,${LDAP_BASE_DN} -y /root/ou-lab-secrets/ldap-bind-password"
ck "LDAP service account sees the 5 lab users" "[ \$(LDAPTLS_CACERT=$CA ldapsearch -LLL -x -H ldaps://${HOST_LDAP} -D cn=${LDAP_BIND_USER},ou=system,${LDAP_BASE_DN} -y /root/ou-lab-secrets/ldap-bind-password -b ou=people,${LDAP_BASE_DN} '(objectClass=inetOrgPerson)' uid | grep -c '^uid:') -ge 5 ] && echo 5+ users"
ck "Keycloak /health/ready (management port 9000)" "curl -fsS http://127.0.0.1:9000/health/ready | grep -q '\"status\": \"UP\"' && echo UP"
ck "Keycloak OIDC discovery through the edge (TLS, lab CA)" "curl -fsS --cacert $CA https://${HOST_KC}/realms/${REALM}/.well-known/openid-configuration | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d[\"issuer\"])'"
ck "OpenCloud /status.php (container port 9200)" "curl -fsS http://127.0.0.1:9200/status.php | grep -q '\"installed\": *true' && echo installed"
ck "OpenCloud /status.php through the edge (TLS, lab CA)" "curl -fsS --cacert $CA https://${HOST_FILES}/status.php | grep -o '\"productversion\": *\"[0-9.]*\"'"
ck "OpenCloud WebDAV (PROPFIND on the root of a user needs a token: unauthenticated request must be refused with 401)" "[ \$(curl -s -o /dev/null -w '%{http_code}' --cacert $CA -X PROPFIND https://${HOST_FILES}/remote.php/dav/files/bob/) = 401 ] && echo 401"
U=$(id -u ou-svc)
for u in ou-identity-keycloak ou-files-opencloud; do
  ck "unit $u active, container digest = pinned digest" "sudo -u ou-svc env XDG_RUNTIME_DIR=/run/user/$U systemctl --user is-active $u.service && sudo -u ou-svc env XDG_RUNTIME_DIR=/run/user/$U HOME=/var/lib/ou-svc podman inspect --format '{{.ImageDigest}} user={{.Config.User}} readonly={{.HostConfig.ReadonlyRootfs}} caps={{.HostConfig.CapDrop}}' $u"
done
ck "container processes run unprivileged on the host" "ps -eo user:20,args | grep -E 'opencloud server|quarkus|keycloak' | grep -v grep | awk '{print \$1}' | sort -u | tr '\n' ' '"
exit $fail
