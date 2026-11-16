#!/bin/bash
# Install the realm-key follower on a groupware node (systemd timer, every 30 s): /etc/gromox/bearer_pubkey <- Keycloak's active RS256 key (see ou-sync-bearer-key.py).
# usage: GW_MACHINE=ou-gw1 ./lab-sso-keysync.sh        (ICS host; sudo systemd-run -M)
set -eu
M="${GW_MACHINE:?node name}"; LD=${LAB_DOMAIN:-ou-lab.internal}; HERE="$(cd "$(dirname "$0")" && pwd)"
# installed from INSIDE the machine so the file belongs to the container root (a host-side `install` leaves an unmapped uid: nobody:nogroup, replaceable by a container-root rename; review 4 L4)
sudo systemd-run -M $M --quiet --pipe --wait /bin/sh -c 'install -m 0755 -o root -g root /dev/stdin /usr/local/sbin/ou-sync-bearer-key' < "$HERE/ou-sync-bearer-key.py"
sudo systemd-run -M $M --quiet --pipe --wait /bin/sh -c 'test -s /usr/local/share/ca-certificates/ou-lab-ca.crt || { echo "pinned CA /usr/local/share/ca-certificates/ou-lab-ca.crt missing: the follower refuses the system bundle" >&2; exit 4; }'
sudo systemd-run -M $M --quiet --pipe --wait /bin/bash -c 'cat > /etc/systemd/system/ou-sync-bearer-key.service <<EOF
[Unit]
Description=Follow the Keycloak realm signing key (gromox bearer_pubkey)
After=network-online.target
[Service]
Type=oneshot
Environment=KC_REALM_URL=https://auth.'$LD'/realms/ou-lab
ExecStart=/usr/local/sbin/ou-sync-bearer-key
NoNewPrivileges=true
ProtectHome=true
PrivateTmp=true
EOF
cat > /etc/systemd/system/ou-sync-bearer-key.timer <<EOF
[Unit]
Description=Follow the Keycloak realm signing key every 30 s
[Timer]
OnBootSec=20s
OnUnitActiveSec=30s
AccuracySec=5s
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload; systemctl enable --now ou-sync-bearer-key.timer >/dev/null 2>&1; systemctl start ou-sync-bearer-key.service; journalctl -u ou-sync-bearer-key -n 2 --no-pager -o cat'
