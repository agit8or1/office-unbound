#!/usr/bin/env bash
# Run as root INSIDE ou-meet1 after 20-install-meet.sh. Needs /root/ou-lab-secrets/kc-ou-meet-client-secret (copied by the host).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SEC=/root/ou-lab-secrets
export DEBIAN_FRONTEND=noninteractive
[ -s "$SEC/kc-ou-meet-client-secret" ] && [ -s "$SEC/jitsi-jwt-secret" ] || { echo "missing secrets"; exit 1; }
apt-get install -y -qq python3-fastapi python3-uvicorn python3-httpx python3-jwt >/dev/null
id oumeet-token >/dev/null 2>&1 || useradd --system --home /opt/ou-meet-token --shell /usr/sbin/nologin oumeet-token
install -d -m 0755 /opt/ou-meet-token /etc/ou-meet-token
install -m 0644 "$HERE/meet-token/app.py" /opt/ou-meet-token/app.py
install -m 0640 -o root -g oumeet-token "$SEC/kc-ou-meet-client-secret" /etc/ou-meet-token/client-secret
install -m 0640 -o root -g oumeet-token "$SEC/jitsi-jwt-secret" /etc/ou-meet-token/jwt-secret
cat > /etc/systemd/system/ou-meet-token.service <<'EOF'
[Unit]
Description=Office Unbound Jitsi token service
After=network-online.target
[Service]
User=oumeet-token
WorkingDirectory=/opt/ou-meet-token
Environment=CLIENT_SECRET_FILE=/etc/ou-meet-token/client-secret JWT_SECRET_FILE=/etc/ou-meet-token/jwt-secret TOKEN_TTL=120
ExecStart=/usr/bin/python3 -m uvicorn app:app --host 127.0.0.1 --port 8090 --no-access-log
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
MemoryMax=128M
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/nginx/sites-available/meet-auth.conf <<'EOF'
server {
  listen 443 ssl; server_name meet-auth.ou-lab.internal;
  ssl_certificate /etc/ou-lab/tls/meet.crt;
  ssl_certificate_key /etc/ou-lab/tls/meet.key;
  location / { proxy_pass http://127.0.0.1:8090; proxy_set_header Host $host; proxy_set_header X-Forwarded-Proto https; }
}
EOF
ln -sf /etc/nginx/sites-available/meet-auth.conf /etc/nginx/sites-enabled/meet-auth.conf
systemctl daemon-reload; systemctl enable --now ou-meet-token; nginx -t && systemctl reload nginx
sleep 2; curl -s http://127.0.0.1:8090/healthz; echo
