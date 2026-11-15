#!/bin/bash
# negative tests of gromox auth_login_token (zcore) with tampered/foreign tokens. Never prints tokens or passwords.
# usage: SSO_WORK=<dir with lab-ca.crt> bash webmail_sso_negative.sh   (ICS host; needs sudo systemd-run -M ou-id1/ou-gw-sso1)
set -u
S=${SSO_WORK:?dir containing lab-ca.crt (the OU lab CA from ou-id1)}
M=ou-gw-sso1
PW=$(sudo systemd-run -M ou-id1 -P --wait -q /bin/cat /root/ou-lab-secrets/test-users.env | sed -n 's/^OU_PASSWORD_BOB=//p')
TOK=$(curl -sS --cacert $S/lab-ca.crt --resolve auth.ou-lab.internal:443:192.168.186.241 https://auth.ou-lab.internal/realms/ou-lab/protocol/openid-connect/token \
  -d grant_type=password -d client_id=ou-lab-test -d username=bob --data-urlencode "password=$PW" -d scope=openid | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
unset PW
python3 - "$TOK" "$S" <<'EOF'
import sys, json, base64, time
tok, S = sys.argv[1], sys.argv[2]
h, p, s = tok.split('.')
def d(x): return json.loads(base64.urlsafe_b64decode(x + '=' * (-len(x) % 4)))
def e(o): return base64.urlsafe_b64encode(json.dumps(o, separators=(',', ':')).encode()).rstrip(b'=').decode()
pl = d(p)
print("claims: aud=%s azp=%s email=%s alg=%s" % (pl.get('aud'), pl.get('azp'), pl.get('email'), d(h).get('alg')), file=sys.stderr)
out = {}
out['valid_other_client'] = tok
q = dict(pl); q['email'] = 'alice@ou-lab.internal'; out['tampered_email'] = h + '.' + e(q) + '.' + s
q = dict(pl); q['exp'] = int(time.time()) - 60; out['expired_claim_resigned_badly'] = h + '.' + e(q) + '.' + s
out['alg_none'] = e({'alg': 'none', 'typ': 'JWT'}) + '.' + p + '.'
out['empty_sig'] = h + '.' + p + '.'
out['garbage'] = 'not-a-jwt'
out['truncated_sig'] = tok[:-10]
json.dump(out, open(S + '/toks.json', 'w'))
EOF
sudo install -m 0600 $S/toks.json /var/lib/machines/$M/root/toks.json 2>/dev/null
sudo chown "$(sudo stat -c %u /var/lib/machines/$M/root):$(sudo stat -c %u /var/lib/machines/$M/root)" /var/lib/machines/$M/root/toks.json
sudo systemd-run -M $M -P --wait -q /bin/bash -c 'php -r '"'"'$t=json_decode(file_get_contents("/root/toks.json"),true); foreach($t as $k=>$v){ try { $s=mapi_logon_token($v); echo str_pad($k,30), ($s?"ACCEPTED":"rejected"), "\n"; } catch(Throwable $e){ echo str_pad($k,30), "rejected (", get_class($e), ")\n"; } }'"'"'; rm -f /root/toks.json'
rm -f $S/toks.json
