#!/usr/bin/env bash
# Run as root INSIDE ou-pbx1 (done by 10-host-deploy.sh). Expects /root/stage/{pbx,phone,secrets} (copied by the host script).
# Installs Asterisk 20.6.0 (Ubuntu 24.04 universe package, version-pinned + held), nginx-light, the provisioner and the softphone.
set -euo pipefail
ST=/root/stage
export DEBIAN_FRONTEND=noninteractive
AST_VER="1:20.6.0~dfsg+~cs6.13.40431414-2build5"
apt-get install -y -qq --no-install-recommends "asterisk=$AST_VER" "asterisk-modules=$AST_VER" "asterisk-config=$AST_VER" asterisk-core-sounds-en \
  nginx-light python3-fastapi python3-uvicorn python3-ldap3 python3-httpx python3-jwt python3-cryptography baresip sox >/dev/null
apt-mark hold asterisk asterisk-modules asterisk-config >/dev/null

# ---- users, dirs, secrets
id ou-pbx >/dev/null 2>&1 || useradd --system --home /var/lib/ou-pbx --shell /usr/sbin/nologin -G asterisk ou-pbx
id ou-phone >/dev/null 2>&1 || useradd --system --home /nonexistent --shell /usr/sbin/nologin ou-phone   # M11: the web app is NOT in group asterisk
install -d -m 0700 -o ou-pbx -g ou-pbx /var/lib/ou-pbx
install -d -m 0755 /etc/ou-pbx /opt/ou-pbx /opt/ou-phone
install -d -m 2770 -o ou-pbx -g asterisk /etc/asterisk/ou
install -d -m 0755 /etc/asterisk/ou-templates
install -m 0640 -o root -g ou-pbx "$ST/secrets/ldap-bind-password" /etc/ou-pbx/ldap-bind.pw
install -m 0640 -o root -g ou-phone "$ST/secrets/kc-ou-phone-client-secret" /etc/ou-pbx/phone-client-secret
install -m 0644 "$ST/secrets/gw1-ca.crt" /etc/ou-lab/gw1-ca.crt
install -m 0644 /etc/ou-lab/tls/pbx.crt /etc/asterisk/pbx.crt
install -m 0640 -o root -g asterisk /etc/ou-lab/tls/pbx.key /etc/asterisk/pbx.key
cat > /etc/ou-pbx/ou-pbx.json <<'EOF'
{
  "ldap": {"host": "ldap.ou-lab.internal", "ca": "/etc/ou-lab/tls/ca.crt", "bind_dn": "cn=svc-bind,ou=system,dc=ou-lab,dc=internal",
           "bind_pw_file": "/etc/ou-pbx/ldap-bind.pw", "people_dn": "ou=people,dc=ou-lab,dc=internal"},
  "realm": "ou-pbx", "domain": "pbx.ou-lab.internal", "wss_url": "wss://pbx.ou-lab.internal:8089/ws",
  "state_dir": "/var/lib/ou-pbx", "ast_dir": "/etc/asterisk/ou", "voicemail_conf": "/etc/asterisk/ou/voicemail_ou.conf",
  "server_email": "voicemail@pbx.ou-lab.internal",
  "smtp": {"host": "gw1.ou-lab.internal", "port": 25, "ca": "/etc/ou-lab/gw1-ca.crt", "from": "voicemail@pbx.ou-lab.internal"}
}
EOF
install -m 0644 "$ST/pbx/ou_pbx.py" /opt/ou-pbx/ou_pbx.py
install -m 0644 "$ST/pbx/ou_pbx_helper.py" /opt/ou-pbx/ou_pbx_helper.py
install -m 0755 "$ST/pbx/ou-pbx-mail" /usr/local/sbin/ou-pbx-mail
printf '#!/bin/sh\nexec python3 /opt/ou-pbx/ou_pbx.py "$@"\n' > /usr/local/bin/ou-pbx; chmod 0755 /usr/local/bin/ou-pbx
cp -r "$ST/phone/static" /opt/ou-phone/ && install -m 0644 "$ST/phone/phone_app.py" /opt/ou-phone/phone_app.py
cp "$ST"/pbx/templates/* /etc/asterisk/ou-templates/

# ---- Asterisk config (everything else stays at package defaults; unused ports: no AMI, no ARI, no plain SIP/UDP/TCP)
grep -q '^\[files\]' /etc/asterisk/asterisk.conf || printf '\n[files]\nastctlpermissions=0660\nastctlowner=asterisk\nastctlgroup=asterisk\n' >> /etc/asterisk/asterisk.conf
cat > /etc/asterisk/pjsip.conf <<'EOF'
; Office Unbound lab PBX. Transports are static; endpoints/auth/aors are GENERATED into ou/pjsip_ou.conf from LDAP by ou-pbx.
[global]
type=global
user_agent=OU-PBX
default_realm=ou-pbx

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

#include "ou/pjsip_ou.conf"
EOF
cat > /etc/asterisk/http.conf <<'EOF'
[general]
enabled=yes
bindaddr=127.0.0.1
bindport=8088
tlsenable=yes
tlsbindaddr=0.0.0.0:8089
tlscertfile=/etc/asterisk/pbx.crt
tlsprivatekey=/etc/asterisk/pbx.key
EOF
# chan_sip (legacy, deprecated, ships in the Ubuntu build) would otherwise grab the /ws WebSocket and answer with its own auth: found in the lab run
cat > /etc/asterisk/modules.conf <<'EOF'
[modules]
autoload=yes
noload => chan_sip.so
noload => chan_iax2.so
noload => chan_skinny.so
noload => chan_unistim.so
noload => chan_mgcp.so
noload => chan_alsa.so
noload => chan_console.so
noload => chan_dahdi.so
noload => res_phoneprov.so
noload => res_hep.so
noload => app_voicemail_imap.so
noload => app_voicemail_odbc.so
noload => pbx_lua.so
noload => pbx_ael.so
noload => res_xmpp.so
noload => chan_motif.so
EOF
printf '[general]\nenabled=no\n' > /etc/asterisk/manager.conf
printf '[general]\nenabled=no\n' > /etc/asterisk/ari.conf
cat > /etc/asterisk/rtp.conf <<'EOF'
[general]
rtpstart=10000
rtpend=10200
strictrtp=yes
icesupport=yes
EOF
cat > /etc/asterisk/extensions.conf <<'EOF'
; GENERATED contexts live in ou/extensions_ou.conf. There is NO outbound/PSTN route in this PBX (see ou-templates/ for the disabled trunk template).
[general]
static=yes
writeprotect=yes
[globals]
#include "ou/extensions_ou.conf"
EOF
# voicemail_ou.conf carries its own [general] + [ou]; voicemail.conf is just the include
printf '#include "ou/voicemail_ou.conf"\n' > /etc/asterisk/voicemail.conf
printf '[general]\nenable=yes\nunanswered=yes\n[csv]\nusegmtime=yes\nloguniqueid=yes\nloguserfield=no\n' > /etc/asterisk/cdr.conf
chown -R root:asterisk /etc/asterisk && chmod 0750 /etc/asterisk
chown root:asterisk /etc/asterisk/ou-templates; chmod 2770 /etc/asterisk/ou; chown ou-pbx:asterisk /etc/asterisk/ou

# ---- initial (empty) generated config, then start
for f in pjsip_ou.conf extensions_ou.conf; do : > /etc/asterisk/ou/$f; done
printf '[general]\nformat=wav49|gsm\n\n[ou]\n' > /etc/asterisk/ou/voicemail_ou.conf
printf '[ou-internal]\n[ou-emergency]\n' > /etc/asterisk/ou/extensions_ou.conf
chown ou-pbx:asterisk /etc/asterisk/ou/*; chmod 0660 /etc/asterisk/ou/*
systemctl enable asterisk; systemctl restart asterisk
sleep 3; systemctl is-active asterisk

# ---- softphone + sync units, nginx
# M11: the helper alone holds the asterisk group + config write access; it listens on a unix socket usable only by ou-phone (0660 ou-pbx:ou-phone + SO_PEERCRED)
cat > /etc/systemd/system/ou-pbx-helper.socket <<'EOF'
[Unit]
Description=Office Unbound PBX provisioning helper socket (ou-phone only)
[Socket]
ListenStream=/run/ou-pbx/helper.sock
SocketUser=ou-pbx
SocketGroup=ou-phone
SocketMode=0660
DirectoryMode=0755   # socket itself is 0660 ou-pbx:ou-phone + SO_PEERCRED
[Install]
WantedBy=sockets.target
EOF
cat > /etc/systemd/system/ou-pbx-helper.service <<'EOF'
[Unit]
Description=Office Unbound PBX provisioning helper (issue/revoke web credentials, nothing else)
After=asterisk.service
[Service]
User=ou-pbx
Group=ou-pbx
SupplementaryGroups=asterisk
Environment=OU_PBX_LIB=/opt/ou-pbx OU_HELPER_PEER_USER=ou-phone
ExecStart=/usr/bin/python3 /opt/ou-pbx/ou_pbx_helper.py
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/ou-pbx /etc/asterisk/ou /run/asterisk
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
MemoryMax=160M
EOF
cat > /etc/systemd/system/ou-phone.service <<'EOF'
[Unit]
Description=Office Unbound web softphone + SIP credential endpoint (unprivileged)
After=network-online.target ou-pbx-helper.socket
Requires=ou-pbx-helper.socket
[Service]
User=ou-phone
Group=ou-phone
WorkingDirectory=/opt/ou-phone
Environment=CLIENT_SECRET_FILE=/etc/ou-pbx/phone-client-secret STATIC_DIR=/opt/ou-phone/static OU_HELPER_SOCKET=/run/ou-pbx/helper.sock WSS_URL=wss://pbx.ou-lab.internal:8089/ws
ExecStart=/usr/bin/python3 -m uvicorn phone_app:app --host 127.0.0.1 --port 8095 --no-access-log
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
CapabilityBoundingSet=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
InaccessiblePaths=/etc/asterisk /var/lib/ou-pbx /run/asterisk
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
  listen 443 ssl; server_name phone.ou-lab.internal;
  ssl_certificate /etc/ou-lab/tls/pbx.crt;
  ssl_certificate_key /etc/ou-lab/tls/pbx.key;
  ssl_protocols TLSv1.2 TLSv1.3;
  location / { proxy_pass http://127.0.0.1:8095; proxy_set_header Host $host; proxy_set_header X-Forwarded-Proto https; }
}
server { listen 80 default_server; return 444; }
EOF
rm -f /etc/nginx/sites-enabled/default; ln -sf /etc/nginx/sites-available/phone.conf /etc/nginx/sites-enabled/phone.conf
systemctl daemon-reload
systemctl enable ou-pbx-helper.socket ou-phone ou-pbx-sync.timer
systemctl stop ou-phone ou-pbx-helper.service ou-pbx-helper.socket 2>/dev/null; systemctl start ou-pbx-helper.socket ou-phone ou-pbx-sync.timer   # stop+start: a re-deploy must pick up the new code/units (restart of a socket whose service runs is refused)
sed -i "s/^worker_processes.*/worker_processes 1;/" /etc/nginx/nginx.conf
nginx -t && systemctl restart nginx
sleep 2; curl -s http://127.0.0.1:8095/healthz; echo
# L7: provisioning secrets must not stay behind in the staging dir (they are installed with their final owners above)
find /root/stage/secrets -type f -exec shred -u {} + 2>/dev/null; rmdir /root/stage/secrets 2>/dev/null || true
