#!/usr/bin/env bash
# Run as root INSIDE ou-pbx2 (done by 10-deploy-pbx2.sh). Debian 12. Installs ou-asterisk (Asterisk 22 LTS, ADR-0008 pipeline) FROM THE SIGNED OFFICE UNBOUND
# REPO ONLY (no Ubuntu package, no upstream binaries), plus nginx-light, the provisioner and the softphone. Site configuration lives in /etc/asterisk/ou/
# (the package's own conffiles are not edited, so package upgrades never prompt).
# Expects /root/stage/{pbx,phone,secrets,ou-release-<suite>.pub.asc,ou-release-<suite>.FINGERPRINT}. Env: REPO_URL, REPO_SUITE.
set -euo pipefail
ST=/root/stage
export DEBIAN_FRONTEND=noninteractive
: "${REPO_URL:?}"; SUITE=${REPO_SUITE:-dev}
KEYRING=/usr/share/keyrings/ou-release-$SUITE.gpg
FPR=$(cat $ST/ou-release-$SUITE.FINGERPRINT)
got=$(gpg --show-keys --with-colons $ST/ou-release-$SUITE.pub.asc | awk -F: '/^fpr/{print $10; exit}')
[ "$got" = "$FPR" ] || { echo "release key fingerprint mismatch: $got != $FPR"; exit 1; }
gpg --dearmor < $ST/ou-release-$SUITE.pub.asc > $KEYRING
echo "deb [signed-by=$KEYRING] $REPO_URL $SUITE main" > /etc/apt/sources.list.d/office-unbound.list
echo 'Acquire::AllowReleaseInfoChange "false";' > /etc/apt/apt.conf.d/50ou-release-strict
apt-get update -qq
for f in /var/lib/apt/lists/*_dists_${SUITE}_InRelease; do grep -q "^Suite: $SUITE$" "$f" && grep -q "^Codename: $SUITE$" "$f" || { echo "channel confusion: Release is not of suite $SUITE"; exit 1; }; done
apt-get install -y -qq --no-install-recommends gnupg ca-certificates >/dev/null
apt-get install -y -qq --no-install-recommends ou-asterisk nginx-light python3-fastapi python3-uvicorn python3-ldap3 python3-httpx python3-jwt baresip sox sudo >/dev/null   # sudo: only used by the lab test suites (sudo -u ou-pbx ou-pbx ...)
apt-cache policy ou-asterisk | sed -n 1,4p; dpkg -s ou-asterisk | grep -E '^(Version|Status)'
asterisk -V

# ---- users, dirs, secrets
id ou-pbx >/dev/null 2>&1 || useradd --system --home /var/lib/ou-pbx --shell /usr/sbin/nologin -G asterisk ou-pbx
install -d -m 0700 -o ou-pbx -g ou-pbx /var/lib/ou-pbx
install -d -m 0755 /etc/ou-pbx /opt/ou-pbx /opt/ou-phone /etc/ou-lab
install -d -m 2770 -o ou-pbx -g asterisk /etc/asterisk/ou
install -d -m 0755 /etc/asterisk/ou-templates
install -m 0640 -o root -g ou-pbx "$ST/secrets/ldap-bind.pw" /etc/ou-pbx/ldap-bind.pw
install -m 0640 -o root -g ou-pbx "$ST/secrets/phone-client-secret" /etc/ou-pbx/phone-client-secret
install -m 0644 "$ST/secrets/gw1-ca.crt" /etc/ou-lab/gw1-ca.crt
install -m 0644 /etc/ou-lab/tls/pbx.crt /etc/asterisk/pbx.crt
install -m 0640 -o root -g asterisk /etc/ou-lab/tls/pbx.key /etc/asterisk/pbx.key
cat > /etc/ou-pbx/ou-pbx.json <<'EOF'
{
  "ldap": {"host": "ldap.ou-lab.internal", "ca": "/etc/ou-lab/tls/ca.crt", "bind_dn": "cn=svc-bind,ou=system,dc=ou-lab,dc=internal",
           "bind_pw_file": "/etc/ou-pbx/ldap-bind.pw", "people_dn": "ou=people,dc=ou-lab,dc=internal"},
  "realm": "ou-pbx", "domain": "pbx2.ou-lab.internal", "wss_url": "wss://pbx2.ou-lab.internal:8089/ws",
  "state_dir": "/var/lib/ou-pbx", "ast_dir": "/etc/asterisk/ou", "voicemail_conf": "/etc/asterisk/ou/voicemail_ou.conf",
  "server_email": "voicemail@pbx2.ou-lab.internal",
  "smtp": {"host": "gw1.ou-lab.internal", "port": 25, "ca": "/etc/ou-lab/gw1-ca.crt", "from": "voicemail@pbx2.ou-lab.internal"}
}
EOF
install -m 0644 "$ST/pbx/ou_pbx.py" /opt/ou-pbx/ou_pbx.py
install -m 0755 "$ST/pbx/ou-pbx-mail" /usr/local/sbin/ou-pbx-mail
printf '#!/bin/sh\nexec python3 /opt/ou-pbx/ou_pbx.py "$@"\n' > /usr/local/bin/ou-pbx; chmod 0755 /usr/local/bin/ou-pbx
cp -r "$ST/phone/static" /opt/ou-phone/ && install -m 0644 "$ST/phone/phone_app.py" /opt/ou-phone/phone_app.py
[ -d "$ST/pbx/templates" ] && cp "$ST"/pbx/templates/* /etc/asterisk/ou-templates/ || true

# ---- site configuration (only /etc/asterisk/ou/*; the package conffiles include these with #tryinclude)
cat > /etc/asterisk/ou/pjsip_site.conf <<'EOF'
; Office Unbound lab PBX transports. Endpoints/auth/aors are GENERATED into pjsip_ou.conf from LDAP by ou-pbx.
[transport-tls]
type=transport
protocol=tls
bind=0.0.0.0:5061
cert_file=/etc/asterisk/pbx.crt
priv_key_file=/etc/asterisk/pbx.key
method=tlsv1_2
cipher=ECDHE-RSA-AES256-GCM-SHA384,ECDHE-RSA-AES128-GCM-SHA256

[transport-wss]
type=transport
protocol=wss
bind=0.0.0.0
EOF
cat > /etc/asterisk/ou/http_site.conf <<'EOF'
enabled=yes
bindaddr=127.0.0.1
bindport=8088
tlsenable=yes
tlsbindaddr=0.0.0.0:8089
tlscertfile=/etc/asterisk/pbx.crt
tlsprivatekey=/etc/asterisk/pbx.key
EOF
printf '[general]\ndefault_realm=ou-pbx\n' > /dev/null
# initial (empty) generated config, then start
: > /etc/asterisk/ou/pjsip_ou.conf
printf '[general]\nformat=wav49|gsm\n\n[ou]\n' > /etc/asterisk/ou/voicemail_ou.conf
printf '[ou-internal]\n[ou-emergency]\n' > /etc/asterisk/ou/extensions_ou.conf
chown ou-pbx:asterisk /etc/asterisk/ou/*; chmod 0660 /etc/asterisk/ou/*
# sound language directory: Debian's en prompts live in en_US_f_Allison
ls /usr/share/asterisk/sounds | head -5
[ -e /usr/share/asterisk/sounds/en ] || ln -s en_US_f_Allison /usr/share/asterisk/sounds/en
systemctl daemon-reload
systemctl enable --now ou-asterisk
sleep 4; systemctl is-active ou-asterisk
asterisk -rx 'core show version'; asterisk -rx 'module show like res_pjsip.so' | tail -2

# ---- softphone + sync units, nginx (as in the lab spike; Asterisk unit is ou-asterisk here)
cat > /etc/systemd/system/ou-phone.service <<'EOF'
[Unit]
Description=Office Unbound web softphone + SIP credential endpoint
After=network-online.target ou-asterisk.service
[Service]
User=ou-pbx
Group=ou-pbx
SupplementaryGroups=asterisk
WorkingDirectory=/opt/ou-phone
Environment=CLIENT_SECRET_FILE=/etc/ou-pbx/phone-client-secret OU_PBX_LIB=/opt/ou-pbx STATIC_DIR=/opt/ou-phone/static CLIENT_ID=ou-phone2 PUBLIC_BASE=https://phone2.ou-lab.internal
ExecStart=/usr/bin/python3 -m uvicorn phone_app:app --host 127.0.0.1 --port 8095 --no-access-log
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/ou-pbx /etc/asterisk/ou /run/asterisk
MemoryMax=160M
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/ou-pbx-sync.service <<'EOF'
[Unit]
Description=Office Unbound PBX: sync extensions from LDAP
[Service]
Type=oneshot
User=ou-pbx
Group=ou-pbx
SupplementaryGroups=asterisk
ExecStart=/usr/local/bin/ou-pbx sync
EOF
cat > /etc/systemd/system/ou-pbx-sync.timer <<'EOF'
[Unit]
Description=Office Unbound PBX LDAP sync (every 15 s)
[Timer]
OnBootSec=20s
OnUnitInactiveSec=15s
AccuracySec=1s
[Install]
WantedBy=timers.target
EOF
cat > /etc/nginx/sites-available/phone.conf <<'EOF'
server {
  listen 443 ssl; server_name phone2.ou-lab.internal;
  ssl_certificate /etc/ou-lab/tls/pbx.crt;
  ssl_certificate_key /etc/ou-lab/tls/pbx.key;
  ssl_protocols TLSv1.2 TLSv1.3;
  location / { proxy_pass http://127.0.0.1:8095; proxy_set_header Host $host; proxy_set_header X-Forwarded-Proto https; }
}
server { listen 80 default_server; return 444; }
EOF
rm -f /etc/nginx/sites-enabled/default; ln -sf /etc/nginx/sites-available/phone.conf /etc/nginx/sites-enabled/phone.conf
systemctl daemon-reload
systemctl enable --now ou-phone ou-pbx-sync.timer
sed -i "s/^worker_processes.*/worker_processes 1;/" /etc/nginx/nginx.conf
nginx -t && systemctl restart nginx
sleep 2; curl -s http://127.0.0.1:8095/healthz; echo
