#!/usr/bin/env bash
# Run as root INSIDE ou-meet1 (copy blueprints/lab/spike-collab to /root/spike-collab):
#   Jitsi Meet from the official Debian repo (pinned via JITSI_PINS in versions.env), nginx TLS from the lab CA bundle,
#   Prosody JWT auth (HS256, shared secret with the Office Unbound token service), allow_empty_token=false.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/versions.env"
SEC=/root/ou-lab-secrets
HOST=meet.ou-lab.internal
export DEBIAN_FRONTEND=noninteractive
install -d -m 0700 "$SEC"
gen() { [ -s "$SEC/$1" ] || { umask 077; openssl rand -hex 32 | tr -d '\n' > "$SEC/$1"; }; cat "$SEC/$1"; }

apt-get update -qq
apt-get install -y -qq curl gnupg ca-certificates nginx openjdk-17-jre-headless apt-transport-https >/dev/null
curl -fsSL "$JITSI_APT_KEY_URL" | gpg --dearmor > /usr/share/keyrings/jitsi-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/jitsi-keyring.gpg] https://download.jitsi.org stable/" > /etc/apt/sources.list.d/jitsi-stable.list
apt-get update -qq

debconf-set-selections <<EOF
jitsi-videobridge2 jitsi-videobridge/jvb-hostname string ${HOST}
jitsi-meet-web-config jitsi-meet/cert-choice select I want to use my own certificate
jitsi-meet-web-config jitsi-meet/cert-path-crt string /etc/ou-lab/tls/meet.crt
jitsi-meet-web-config jitsi-meet/cert-path-key string /etc/ou-lab/tls/meet.key
jitsi-meet-web-config jitsi-meet/jaas-choice boolean false
jitsi-meet-prosody jitsi-meet-prosody/jvb-hostname string ${HOST}
jitsi-meet jitsi-meet/email string
EOF
# shellcheck disable=SC2086
apt-get install -y -qq ${JITSI_PINS} jitsi-meet-tokens >/dev/null 2>&1 || apt-get install -y ${JITSI_PINS} jitsi-meet-tokens
apt-mark hold jitsi-meet jitsi-meet-web jitsi-meet-web-config jitsi-meet-prosody jitsi-meet-tokens jitsi-videobridge2 jicofo >/dev/null

# fallback if the package postinst did not create the nginx site (it skips when it believes this is a reconfigure)
if [ ! -f /etc/nginx/sites-available/${HOST}.conf ]; then
  cp /usr/share/jitsi-meet-web-config/jitsi-meet.example /etc/nginx/sites-available/${HOST}.conf
  ln -sf /etc/nginx/sites-available/${HOST}.conf /etc/nginx/sites-enabled/${HOST}.conf
  sed -i "s/jitsi-meet.example.com/${HOST}/g; s|ssl_certificate_key /etc/jitsi/meet/.*key|ssl_certificate_key /etc/ou-lab/tls/meet.key|; s|ssl_certificate /etc/jitsi/meet/.*crt|ssl_certificate /etc/ou-lab/tls/meet.crt|" /etc/nginx/sites-available/${HOST}.conf
  rm -f /etc/nginx/sites-enabled/default
fi
SECRET=$(gen jitsi-jwt-secret)
CFG=/etc/prosody/conf.avail/${HOST}.cfg.lua
# main VirtualHost: token auth, no anonymous room creation
python3 "$HERE/patch-prosody-jwt.py" "$CFG" "$SECRET"
chmod 0640 "$CFG"; chown root:prosody "$CFG"
# Jitsi web: require auth on the front end too (shows login prompt otherwise): keep default; tokens come via ?jwt=
# memory caps (2G machine)
sed -i 's|^#\? \?VIDEOBRIDGE_MAX_MEMORY=.*|VIDEOBRIDGE_MAX_MEMORY=384m|' /etc/jitsi/videobridge/config 2>/dev/null || true
grep -q '^JICOFO_MAX_MEMORY' /etc/jitsi/jicofo/config 2>/dev/null && sed -i 's|^JICOFO_MAX_MEMORY=.*|JICOFO_MAX_MEMORY=256m|' /etc/jitsi/jicofo/config || echo 'JICOFO_MAX_MEMORY=256m' >> /etc/jitsi/jicofo/config
# Ubuntu 24.04: prosody runs on lua5.4 but lua-inspect (needed by jitsi mod_auth_token/token_verification) only ships 5.1-5.3 -> reuse the pure-Lua 5.3 file
[ -e /usr/share/lua/5.4/inspect.lua ] || ln -s ../5.3/inspect.lua /usr/share/lua/5.4/inspect.lua
systemctl restart prosody jicofo jitsi-videobridge2 nginx
sleep 5
systemctl is-active prosody jicofo jitsi-videobridge2 nginx
dpkg -l | awk '/^ii +(jitsi|jicofo|prosody|lua-)/{print $2,$3}'
