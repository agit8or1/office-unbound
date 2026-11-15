#!/bin/bash
# Integration test of blueprints/build/gromox/patches/0001-authmgr-bearer-claims.patch on a BUILD/TEST machine (never ou-gw1!).
# Prerequisite: the machine has the patched gromox built in /usr/src/ou/gromox (make libgromox_auth.la). Real bob tokens (client ou-lab-test: aud=account)
# are fed to zcore mapi_logon_token under different bearer_issuer/bearer_audience settings. Never prints tokens or passwords.
# usage: SSO_WORK=<dir with lab-ca.crt> GW_MACHINE=ou-aa-gx1 bash gromox_bearer_claims_test.sh      (ICS host)
set -u
S=${SSO_WORK:?dir containing lab-ca.crt}; M=${GW_MACHINE:?test machine}
[ "$M" = ou-gw1 ] && { echo "refusing: ou-gw1 is live"; exit 2; }
NODE() { sudo systemd-run -M $M --quiet --pipe --wait /bin/bash -c "$1"; }
PW=$(sudo systemd-run -M ou-id1 --quiet --pipe --wait /bin/cat /root/ou-lab-secrets/test-users.env | sed -n 's/^OU_PASSWORD_BOB=//p')
TOK=$(curl -sS --cacert $S/lab-ca.crt --resolve auth.ou-lab.internal:443:192.168.186.241 https://auth.ou-lab.internal/realms/ou-lab/protocol/openid-connect/token \
  -d grant_type=password -d client_id=ou-lab-test -d username=bob --data-urlencode "password=$PW" -d scope=openid | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
unset PW
ISS=https://auth.ou-lab.internal/realms/ou-lab
NODE 'L=/usr/lib/x86_64-linux-gnu; [ -e $L/libgromox_auth.so.0.0.0.orig ] || cp -a $L/libgromox_auth.so.0.0.0 $L/libgromox_auth.so.0.0.0.orig; install -m 0755 /usr/src/ou/gromox/.libs/libgromox_auth.so.0.0.0 $L/libgromox_auth.so.0.0.0; cp -a /etc/gromox/gromox.cfg /etc/gromox/gromox.cfg.pre-bearer 2>/dev/null; true'
# forged variants of the real token (alg none / HS256 header, same payload+signature)
python3 - "$TOK" "$S" <<'EOF'
import sys, json, base64
tok, S = sys.argv[1:3]
h, p, s = tok.split('.')
e = lambda o: base64.urlsafe_b64encode(json.dumps(o, separators=(',', ':')).encode()).rstrip(b'=').decode()
json.dump({"real": tok, "alg_none": e({"alg": "none", "typ": "JWT"}) + "." + p + ".", "alg_hs256_header": e({"alg": "HS256", "typ": "JWT"}) + "." + p + "." + s,
           "alg_rs512_header": e({"alg": "RS512", "typ": "JWT"}) + "." + p + "." + s,
           # L1: exp/nbf above INT64_MAX in a FORGED token (wrong signature) must be rejected without taking zcore down
           "forged_exp_uint64": e({"alg": "RS256", "typ": "JWT"}) + "." + e({"exp": 18446744073709551615, "email": "bob@ou-lab.internal"}) + "." + s,
           "forged_nbf_huge": e({"alg": "RS256", "typ": "JWT"}) + "." + e({"exp": 9999999999, "nbf": 18446744073709551615, "email": "bob@ou-lab.internal"}) + "." + s,
           "forged_exp_1e19": e({"alg": "RS256"}) + "." + base64.urlsafe_b64encode(b'{"exp":1e19,"email":"bob@ou-lab.internal"}').rstrip(b'=').decode() + "." + s}, open(S + "/toks.json", "w"))
EOF
sudo install -m 0600 $S/toks.json /var/lib/machines/$M/root/toks.json; rm -f $S/toks.json
U=$(sudo stat -c %u /var/lib/machines/$M/root); sudo chown $U:$U /var/lib/machines/$M/root/toks.json
run() {  # $1 label  $2 cfg lines
  NODE "sed -i '/^bearer_issuer\|^bearer_audience/d' /etc/gromox/gromox.cfg; printf '%b' '$2' >> /etc/gromox/gromox.cfg; systemctl restart gromox-zcore; sleep 3
  php -r '\$t=json_decode(file_get_contents(\"/root/toks.json\"),true); foreach(\$t as \$k=>\$v){ try { \$s=mapi_logon_token(\$v); echo \"    \", str_pad(\$k,18), (\$s?\"ACCEPTED\":\"rejected\"), \"\\n\"; } catch(Throwable \$e){ echo \"    \", str_pad(\$k,18), \"rejected\\n\"; } }'; echo \"    zcore after run: \$(systemctl is-active gromox-zcore) NRestarts=\$(systemctl show -p NRestarts --value gromox-zcore)\"" | sed "1i\\  [$1]"
}
run "no policy (legacy default)" ''
run "audience=ou-webmail (token is for account)" "bearer_audience=ou-webmail\\n"
run "audience=account + correct issuer" "bearer_audience=account\\nbearer_issuer=$ISS\\n"
run "audience=account + wrong issuer" "bearer_audience=account\\nbearer_issuer=https://evil.example/realms/x\\n"
NODE "sed -i '/^bearer_issuer\|^bearer_audience/d' /etc/gromox/gromox.cfg; rm -f /root/toks.json; systemctl restart gromox-zcore"
