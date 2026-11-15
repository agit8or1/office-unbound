#!/bin/bash
# End-to-end Keycloak key rotation test against a groupware node running ou-sync-bearer-key (see lab-sso-keysync.sh).
# Real bob access tokens are fed to zcore mapi_logon_token on the node (same layer webmail uses). Never prints tokens or passwords.
#   1 baseline token accepted  2 ADD a new higher-priority realm key, sync timer stopped -> new token REJECTED (the failure the job prevents)
#   3 run the sync job -> new token ACCEPTED, old-key token rejected (one-key limitation)  4 REMOVE the key (rollback) -> rejected until sync, then accepted
# usage: SSO_WORK=<dir with lab-ca.crt> GW_MACHINE=ou-gw-sso1 bash webmail_sso_keyrotation.sh      (ICS host)
set -u
S=${SSO_WORK:?dir containing lab-ca.crt}; M=${GW_MACHINE:-ou-gw-sso1}
HERE="$(cd "$(dirname "$0")" && pwd)"; SG="$HERE/../spike-groupware"
IDX() { sudo systemd-run -M ou-id1 --quiet --pipe --wait "$@"; }
NODE() { sudo systemd-run -M $M --quiet --pipe --wait /bin/bash -c "$1"; }
PW=$(IDX /bin/cat /root/ou-lab-secrets/test-users.env | sed -n 's/^OU_PASSWORD_BOB=//p')
token() { curl -sS --cacert $S/lab-ca.crt --resolve auth.ou-lab.internal:443:192.168.186.241 https://auth.ou-lab.internal/realms/ou-lab/protocol/openid-connect/token \
  -d grant_type=password -d client_id=ou-lab-test -d username=bob --data-urlencode "password=$PW" -d scope=openid | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])'; }
logon() {  # $1 label, $2 token -> ACCEPTED/rejected from the node's zcore
  printf '%s' "$2" | NODE 'read -r T; export T; php -r '"'"'try { echo mapi_logon_token(getenv("T")) ? "ACCEPTED" : "rejected"; } catch(Throwable $e){ echo "rejected"; }'"'"'' | sed "s/^/  $1: /"; echo; }
kid() { printf '%s' "$1" | python3 -c 'import sys,json,base64;h=sys.stdin.read().split(".")[0];print(json.loads(base64.urlsafe_b64decode(h+"="*(-len(h)%4)))["kid"])'; }
sudo install -m 0755 "$SG/kc-rotate-key.py" /var/lib/machines/ou-id1/root/kc-rotate-key.py
sudo install -m 0644 "$SG/kc_lib.py" /var/lib/machines/ou-id1/root/kc_lib.py
IDX /usr/bin/python3 /root/kc-rotate-key.py remove >/dev/null
NODE 'systemctl stop ou-sync-bearer-key.timer; /usr/local/sbin/ou-sync-bearer-key' | sed 's/^/  [sync] /'
echo "1 baseline"; T0=$(token); echo "  token kid=$(kid "$T0")"; logon "T0 (old key)" "$T0"
echo "2 rotate (add key), sync stopped"; IDX /usr/bin/python3 /root/kc-rotate-key.py add; T1=$(token); echo "  token kid=$(kid "$T1")"
logon "T1 (new key, before sync)" "$T1"
echo "3 sync job"; NODE '/usr/local/sbin/ou-sync-bearer-key' | sed 's/^/  [sync] /'
logon "T1 (new key, after sync)" "$T1"; logon "T0 (old key, after sync)" "$T0"
echo "4 rollback (remove key), sync stopped"; IDX /usr/bin/python3 /root/kc-rotate-key.py remove; T2=$(token); echo "  token kid=$(kid "$T2")"
logon "T2 (old key again, before sync)" "$T2"
NODE '/usr/local/sbin/ou-sync-bearer-key' | sed 's/^/  [sync] /'
logon "T2 (old key again, after sync)" "$T2"
NODE 'systemctl start ou-sync-bearer-key.timer'
unset PW T0 T1 T2
