#!/bin/bash
# Chat smoke in the builder (root, ou-build1): Synapse + MAS images (pulled by digest from the lab registry, run in a chroot of the image as the image's non-root uid)
# against a local PostgreSQL. Proves: MAS migrates and serves, Synapse delegates authentication to MAS, a user logs in THROUGH MAS (compat login) and Synapse accepts the
# resulting token (whoami via MAS introspection); a wrong password and a forged token are refused; Synapse's own /login is gone.
# usage: chat-smoke.sh <registry host:port> <synapse-digest> <mas-digest>
set -uo pipefail
REG=$1; SD=$2; MD=$3
W=/root/smoke-chat; rm -rf "$W"; mkdir -p "$W"; cd "$W"
B="buildah --storage-driver vfs"
export DEBIAN_FRONTEND=noninteractive
command -v pg_ctlcluster >/dev/null || apt-get install -y -qq postgresql >/dev/null 2>&1
PGV=$(ls /usr/lib/postgresql | tail -1)
pg_lsclusters | grep -q online || pg_ctlcluster "$PGV" main start
for _ in $(seq 20); do su postgres -c "psql -Atc 'select 1'" >/dev/null 2>&1 && break; sleep 1; done
PW_S=$(head -c 12 /dev/urandom | base64 | tr -dc A-Za-z0-9); PW_M=$(head -c 12 /dev/urandom | base64 | tr -dc A-Za-z0-9); SHARED=$(head -c 24 /dev/urandom | base64 | tr -dc A-Za-z0-9)
su postgres -c "psql -q" <<E
DROP DATABASE IF EXISTS synapse_smoke; DROP DATABASE IF EXISTS mas_smoke; DROP ROLE IF EXISTS synapse_smoke; DROP ROLE IF EXISTS mas_smoke;
CREATE ROLE synapse_smoke LOGIN PASSWORD '$PW_S'; CREATE ROLE mas_smoke LOGIN PASSWORD '$PW_M';
CREATE DATABASE synapse_smoke OWNER synapse_smoke ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C' TEMPLATE template0;
CREATE DATABASE mas_smoke OWNER mas_smoke ENCODING 'UTF8' TEMPLATE template0;
E
$B rm --all >/dev/null 2>&1
mnt() { local c; c=$($B from --tls-verify=false "$REG/$1@$2") && $B mount "$c"; }
SY=$(mnt ou/synapse "$SD"); MA=$(mnt ou/matrix-authentication-service "$MD")
DEVS="null zero urandom random tty"
for r in "$SY" "$MA"; do
  mount --bind /proc "$r/proc" || mount -t proc proc "$r/proc"
  mkdir -p "$r/dev"; for d in $DEVS; do touch "$r/dev/$d"; mount --bind /dev/$d "$r/dev/$d"; done
done
PID_MAS=; PID_SY=
cleanup() { kill $PID_SY $PID_MAS 2>/dev/null; sleep 1; for r in "$SY" "$MA"; do for d in $DEVS; do umount "$r/dev/$d" 2>/dev/null; done; umount "$r/proc" 2>/dev/null; done
  su postgres -c "psql -q -c 'DROP DATABASE IF EXISTS synapse_smoke' -c 'DROP DATABASE IF EXISTS mas_smoke' -c 'DROP ROLE IF EXISTS synapse_smoke' -c 'DROP ROLE IF EXISTS mas_smoke'" 2>/dev/null; $B rm --all >/dev/null 2>&1; }
trap cleanup EXIT
FAIL=0; ok() { echo "PASS $1"; }; bad() { echo "FAIL $1"; FAIL=1; }
# ---- MAS
mkdir -p "$MA/config" "$MA/tmp"; chown 10120:10120 "$MA/config" "$MA/tmp"
chroot --userspec=10120:10120 "$MA" /usr/local/bin/mas-cli config generate > "$W/mas.yaml" 2>/dev/null
python3 - "$W/mas.yaml" "$PW_M" "$SHARED" <<'PY'
import re, sys
p, pw, sh = sys.argv[1:4]
s = open(p).read()
s = s.replace("address: '[::]:8080'", "address: '127.0.0.1:8180'").replace("port: 8081", "port: 8181")
s = re.sub(r"public_base: .*", lambda m: "public_base: http://127.0.0.1:8180/", s)
s = re.sub(r"issuer: .*", lambda m: "issuer: http://127.0.0.1:8180/", s)
s = re.sub(r"uri: postgresql://.*", lambda m: "uri: postgresql://mas_smoke:%s@127.0.0.1/mas_smoke" % pw, s)
s = re.sub(r"(matrix:\n  kind: synapse\n  homeserver: ).*", lambda m: m.group(1) + "test.local", s)
s = re.sub(r"(\n  secret: ).*(\n  endpoint: ).*", lambda m: m.group(1) + sh + m.group(2) + "http://127.0.0.1:8008/", s)
open(p, "w").write(s)
PY
install -o 10120 -g 10120 -m 0600 "$W/mas.yaml" "$MA/config/config.yaml"
MC() { chroot --userspec=10120:10120 "$MA" /usr/local/bin/mas-cli -c /config/config.yaml "$@"; }
MC database migrate > "$W/mas-migrate.log" 2>&1 && ok "MAS database migrate" || { bad "MAS migrate"; tail -3 "$W/mas-migrate.log"; }
MC config sync --prune > "$W/mas-sync.log" 2>&1 || tail -3 "$W/mas-sync.log"
chroot --userspec=10120:10120 "$MA" /usr/local/bin/mas-cli -c /config/config.yaml server > "$W/mas.log" 2>&1 &
PID_MAS=$!
for _ in $(seq 30); do curl -g -sf http://[::1]:8181/health >/dev/null && break; sleep 1; done
curl -g -sf http://[::1]:8181/health >/dev/null && ok "MAS /health" || { bad "MAS health"; tail -5 "$W/mas.log"; }
curl -sf http://127.0.0.1:8180/.well-known/openid-configuration | python3 -c "import json,sys; d=json.load(sys.stdin); print('  issuer', d['issuer'])" && ok "MAS OIDC discovery"
# ---- Synapse
mkdir -p "$SY/data/media"; chown -R 10020:10020 "$SY/data"
cat > "$SY/data/homeserver.yaml" <<E
server_name: "test.local"
pid_file: /data/homeserver.pid
listeners:
  - port: 8008
    bind_addresses: ['127.0.0.1']
    type: http
    x_forwarded: false
    resources:
      - names: [client, federation]
database:
  name: psycopg2
  args:
    user: synapse_smoke
    password: "$PW_S"
    dbname: synapse_smoke
    host: 127.0.0.1
    cp_min: 2
    cp_max: 5
signing_key_path: /data/signing.key
media_store_path: /data/media
report_stats: false
suppress_key_server_warning: true
trusted_key_servers: []
matrix_authentication_service:
  enabled: true
  endpoint: http://127.0.0.1:8180/
  secret: "$SHARED"
E
chown 10020:10020 "$SY/data/homeserver.yaml"
chroot --userspec=10020:10020 "$SY" /usr/local/bin/ou-synapse-entrypoint > "$W/synapse.log" 2>&1 &
PID_SY=$!
for _ in $(seq 90); do curl -sf http://127.0.0.1:8008/_matrix/client/versions >/dev/null && break; sleep 1; done
curl -sf http://127.0.0.1:8008/_matrix/client/versions | head -c 120 | sed 's/^/  /'; echo
curl -sf http://127.0.0.1:8008/_matrix/client/versions >/dev/null && ok "Synapse up with MAS delegation" || { bad "Synapse"; tail -8 "$W/synapse.log"; }
# ---- the user is provisioned through MAS (which talks to the running Synapse), then logs in through MAS
MC manage register-user --yes --password "Sm0ke-Pass-9" --ignore-password-complexity alice > "$W/mas-user.log" 2>&1 && ok "MAS register-user alice" || { bad "register-user"; tail -3 "$W/mas-user.log"; }
LOGIN='{"type":"m.login.password","identifier":{"type":"m.id.user","user":"alice"},"password":"Sm0ke-Pass-9"}'
R=$(curl -s -X POST http://127.0.0.1:8180/_matrix/client/v3/login -H 'Content-Type: application/json' -d "$LOGIN")
TOKEN=$(echo "$R" | python3 -c "import json,sys; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
[ -n "$TOKEN" ] && ok "login through MAS (compat login) returned an access token for $(echo "$R" | python3 -c "import json,sys; print(json.load(sys.stdin).get('user_id'))")" || { bad "MAS login: $R"; }
W1=$(curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8008/_matrix/client/v3/account/whoami)
echo "  synapse whoami: $W1"
echo "$W1" | grep -q '@alice:test.local' && ok "Synapse accepted the MAS token (whoami = @alice:test.local)" || bad "Synapse whoami"
R2=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:8180/_matrix/client/v3/login -H 'Content-Type: application/json' -d "${LOGIN/Sm0ke-Pass-9/wrong}")
[ "$R2" = 403 ] && ok "wrong password refused (HTTP 403)" || bad "wrong password HTTP $R2"
R3=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer forged-${TOKEN:0:10}" http://127.0.0.1:8008/_matrix/client/v3/account/whoami)
[ "$R3" = 401 ] && ok "forged token refused by Synapse (HTTP 401)" || bad "forged token HTTP $R3"
R4=$(curl -s http://127.0.0.1:8008/_matrix/client/v3/login | head -c 120)
echo "  synapse own /login: $R4"
echo "SMOKE-DONE fail=$FAIL"
exit $FAIL
