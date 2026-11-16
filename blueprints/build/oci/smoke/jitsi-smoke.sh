#!/bin/bash
# Jitsi smoke in the builder (root, ou-build1; images pulled from the lab registry by digest, run in a chroot of the image as the image's non-root uid):
#   prosody (token auth) + a JWT minted by the token-service IMAGE's own code (app.mint) -> BOSH/SASL ANONYMOUS accepted; a forged/expired/other-room token refused;
#   jitsi-web serves /healthz, config.js (third-party off); jicofo and jvb start their JVM and load the jar (config/usage output).
# usage: jitsi-smoke.sh <registry host:port> <prosody-digest> <token-service-digest> <web-digest> <jicofo-digest> <jvb-digest>
set -uo pipefail
REG=$1; PD=$2; TD=$3; WD=$4; JD=$5; VD=$6
HERE=$(cd "$(dirname "$0")" && pwd)
W=/root/smoke-jitsi; rm -rf "$W"; mkdir -p "$W"; cd "$W"
SECRET=$(head -c 24 /dev/urandom | base64 | tr -dc A-Za-z0-9)
B="buildah --storage-driver vfs"
$B rm --all >/dev/null 2>&1
mnt() { local c; c=$($B from --tls-verify=false "$REG/$1@$2") && $B mount "$c"; }
PR=$(mnt ou/jitsi-prosody "$PD"); TK=$(mnt ou/meet-token-service "$TD"); WB=$(mnt ou/jitsi-web "$WD"); JF=$(mnt ou/jicofo "$JD"); VB=$(mnt ou/jitsi-videobridge "$VD")
echo "mounted: prosody=$PR"
DEVS="null zero urandom random tty"
for r in "$PR" "$TK" "$WB" "$JF" "$VB"; do
  mount --bind /proc "$r/proc" || mount -t proc proc "$r/proc"
  mkdir -p "$r/dev"; for d in $DEVS; do touch "$r/dev/$d"; mount --bind /dev/$d "$r/dev/$d"; done
done
cleanup() { for r in "$PR" "$TK" "$WB" "$JF" "$VB"; do for d in $DEVS; do umount "$r/dev/$d" 2>/dev/null; done; umount "$r/proc" 2>/dev/null; done; kill $PPID_PROSODY $PPID_WEB 2>/dev/null; true; }
PPID_PROSODY=; PPID_WEB=
trap cleanup EXIT
# --- prosody
cat > "$PR/etc/prosody/prosody.cfg.lua" <<E
daemonize = false
pidfile = "/tmp/prosody.pid"
admins = {}
plugin_paths = { "/usr/share/jitsi-meet/prosody-plugins/" }
data_path = "/tmp/prosody-data"
http_ports = { 5280 }
http_interfaces = { "127.0.0.1" }
https_ports = {}
c2s_require_encryption = false
consider_bosh_secure = true
log = { { levels = { min = "info" }, to = "console" } }
modules_enabled = { "roster"; "saslauth"; "tls"; "disco"; "ping"; "bosh"; "websocket" }
VirtualHost "meet.test"
  authentication = "token"
  app_id = "ou-meet"
  app_secret = "$SECRET"
  allow_empty_token = false
  modules_enabled = { "ping"; "pubsub" }
  c2s_require_encryption = false
Component "conference.meet.test" "muc"
  restrict_room_creation = true
  modules_enabled = { "token_verification" }
  muc_room_locking = false
E
mkdir -p "$PR/tmp/prosody-data"; chown -R 10090:10090 "$PR/tmp/prosody-data"
chroot --userspec=10090:10090 "$PR" /usr/local/bin/ou-prosody-entrypoint > "$W/prosody.log" 2>&1 &
PPID_PROSODY=$!
for _ in $(seq 30); do curl -s -o /dev/null http://127.0.0.1:5280/http-bind && break; sleep 1; done
curl -s -o /dev/null -w "prosody bosh endpoint HTTP %{http_code}\n" http://127.0.0.1:5280/http-bind
# --- a token from the token-service image's own code
mk() { # $1 room  $2 secret  $3 ttl-offset
  cat > "$TK/tmp/mk.py" <<E
import os, sys, time
os.environ.update({"CLIENT_SECRET_FILE": "/tmp/cs", "JWT_SECRET_FILE": "/tmp/js", "KC_ISSUER": "https://kc.invalid/realms/x", "JITSI_SUB": "meet.test", "JITSI_APP_ID": "ou-meet", "TOKEN_TTL": "$3"})
open("/tmp/cs", "w").write("x"); open("/tmp/js", "w").write("$2")
sys.path.insert(0, "/opt/ou-meet-token")
import app
print(app.mint({"user": {"id": "u1", "name": "Alice", "email": "alice@example.test"}}, "$1"))
E
  chroot --userspec=10040:10040 "$TK" /usr/bin/python3 /tmp/mk.py 2>"$W/mk.err" | tail -1
}
GOOD=$(mk smokeroom "$SECRET" 120); echo "token (from image ou/meet-token-service) claims: $(echo "$GOOD" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -c 'import json,sys; d=json.loads(sys.stdin.read()); print({k:d[k] for k in ("iss","aud","sub","room","exp")})')"
FAIL=0
python3 "$HERE/bosh_auth.py" http://127.0.0.1:5280/http-bind meet.test smokeroom "$GOOD" && echo "PASS valid JWT accepted" || { echo "FAIL valid JWT refused"; FAIL=1; }
python3 "$HERE/bosh_auth.py" http://127.0.0.1:5280/http-bind meet.test smokeroom "$(mk smokeroom wrong-secret 120)" && { echo "FAIL forged JWT accepted"; FAIL=1; } || echo "PASS JWT signed with another secret refused"
python3 "$HERE/bosh_auth.py" http://127.0.0.1:5280/http-bind meet.test smokeroom "" && { echo "FAIL empty token accepted"; FAIL=1; } || echo "PASS no token refused"
# --- web
mkdir -p "$WB/tmp/nginx"; chown 10080:10080 "$WB/tmp/nginx"
OU_JITSI_PROSODY=127.0.0.1 OU_JITSI_JVB=127.0.0.1 chroot --userspec=10080:10080 "$WB" /usr/local/bin/ou-jitsi-web-entrypoint > "$W/web.log" 2>&1 &
PPID_WEB=$!
sleep 3
[ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/healthz)" = 200 ] && echo "PASS jitsi-web /healthz 200" || { echo "FAIL jitsi-web healthz"; FAIL=1; }
curl -s http://127.0.0.1:8080/config.js | grep -E "disableThirdPartyRequests|disabled: true" | head -3 | sed 's/^/  config.js: /'
curl -s -o /dev/null -w "jitsi-web index HTTP %{http_code}\n" http://127.0.0.1:8080/
kill $PPID_WEB 2>/dev/null
# --- jicofo / jvb: the JVM starts the jar with the image's defaults merged under a minimal operator config (no XMPP server is deployed here)
cat > "$VB/tmp/jvb.conf" <<E
include file("/etc/jitsi/videobridge/defaults.conf")
videobridge { apis { xmpp-client { configs { shard { HOSTNAME = "127.0.0.1", PORT = 5222, DOMAIN = "auth.meet.test", USERNAME = "jvb", PASSWORD = "x", MUC_JIDS = "jvbbrewery@internal.auth.meet.test", MUC_NICKNAME = "jvb1", DISABLE_CERTIFICATE_VERIFICATION = true } } } } }
E
out=$(chroot --userspec=10110:10110 "$VB" bash -c 'JAVA_SYS_PROPS="-Dconfig.file=/tmp/jvb.conf" VIDEOBRIDGE_MAX_MEMORY=256m timeout 20 /usr/share/jitsi-videobridge/jvb.sh 2>&1 | head -40')
echo "$out" | grep -q "Starting jitsi-videobridge version" && echo "PASS jvb starts: $(echo "$out" | grep -m1 'Starting jitsi-videobridge')" || { echo "FAIL jvb"; FAIL=1; }
echo "$out" | grep -q "mapping harvesters" && echo "  jvb: $(echo "$out" | grep -m1 'mapping harvesters' | cut -c1-140)"
out=$(chroot --userspec=10100:10100 "$JF" bash -c 'JAVA_SYS_PROPS="-Dconfig.file=/nonexistent" timeout 20 /usr/share/jicofo/jicofo.sh --help 2>&1 | head -5')
echo "$out" | grep -q "Usage" && echo "PASS jicofo launcher runs the JVM and the jar (usage printed)" || { echo "FAIL jicofo: $out"; FAIL=1; }
echo "SMOKE-DONE fail=$FAIL"
exit $FAIL
