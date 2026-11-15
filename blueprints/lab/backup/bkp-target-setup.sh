#!/usr/bin/env bash
# Office Unbound lab: set up the backup TARGET machine (restic rest-server) on an nspawn machine (bookworm, zone oulab). Idempotent.
# Usage: sudo bkp-target-setup.sh [machine=ou-bkp1] [secrets_dir=/etc/office-unbound/backup-lab]
# Two HTTPS listeners on the same repository store (/srv/restic):
#   :8000  --append-only   what the backup runners use: they can add snapshots/packs but cannot delete or overwrite history
#   :8001  full access     maintenance only (forget + prune); its credential exists only on the maintenance runner
# TLS: a self-signed server certificate for the machine's address (SAN IP + DNS); clients pin it (RESTIC_CACERT). Secrets (REST credentials) are
# generated here, stored root-only in <secrets_dir>, hashed (bcrypt) in the machine, and never printed.
set -euo pipefail
M="${1:-ou-bkp1}"; SD="${2:-/etc/office-unbound/backup-lab}"
HERE="$(cd "$(dirname "$0")" && pwd)"; . "$HERE/../common/versions.env"
in_m() { systemd-run -M "$M" --wait -q -P --pipe /bin/bash -c "$1"; }
put() { in_m "cat > '$1' && chmod $2 '$1'"; }   # stdin -> file inside the machine
install -d -m 0700 "$SD"
IP="$(in_m "ip -4 -o addr show scope global | awk '{print \$4}' | cut -d/ -f1 | head -1")"
echo "target address: $IP"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT; cd "$W"
# --- binary (verified against the pin before it goes anywhere)
curl -fsSL -o rs.tgz "$REST_SERVER_URL"; echo "$REST_SERVER_SHA256  rs.tgz" | sha256sum -c --quiet
tar -xzf rs.tgz --strip-components=1 --wildcards '*/rest-server'; install -m 0755 rest-server "$W/rest-server.bin"
# --- TLS (self-signed, 825 days) and credentials
if [ ! -s "$SD/bkp.crt" ]; then
  ( umask 077; openssl req -x509 -newkey rsa:3072 -nodes -keyout "$SD/bkp.key" -out "$SD/bkp.crt" -days 825 -sha256 \
      -subj "/O=Office Unbound LAB ONLY/CN=$M" -addext "subjectAltName=DNS:$M,DNS:$M.ou-lab.internal,IP:$IP" 2>/dev/null )
  chmod 0644 "$SD/bkp.crt"
fi
for u in backup maint; do [ -s "$SD/rest-$u.pw" ] || ( umask 077; openssl rand -hex 24 > "$SD/rest-$u.pw" ); done
# rest-server 0.14 reads bcrypt entries (an $apr1$ entry was rejected as "Invalid htpasswd entry" in the lab run)
htp() { python3 -c 'import bcrypt,sys; print(sys.argv[1] + ":" + bcrypt.hashpw(sys.stdin.read().strip().encode(), bcrypt.gensalt(12)).decode())' "$1" < "$SD/rest-$1.pw"; }
# --- machine
in_m "id restsrv >/dev/null 2>&1 || useradd -r -M -d /srv/restic -s /usr/sbin/nologin restsrv; install -d -o restsrv -g restsrv -m 0700 /srv/restic; install -d -m 0755 /etc/rest-server"
put /usr/local/bin/rest-server.new 0755 < rest-server.bin; in_m "mv -f /usr/local/bin/rest-server.new /usr/local/bin/rest-server"   # atomic: the old binary may be running
put /etc/rest-server/tls.crt 0644 < "$SD/bkp.crt"
put /etc/rest-server/tls.key 0640 < "$SD/bkp.key"; in_m "chgrp restsrv /etc/rest-server/tls.key"
htp backup | put /etc/rest-server/htpasswd-backup 0640; htp maint | put /etc/rest-server/htpasswd-maint 0640
in_m "chgrp restsrv /etc/rest-server/htpasswd-*"
unit() { # name port extra
cat <<UNIT
[Unit]
Description=restic rest-server ($1)
After=network-online.target
[Service]
User=restsrv
ExecStart=/usr/local/bin/rest-server --path /srv/restic --listen :$2 --tls --tls-cert /etc/rest-server/tls.crt --tls-key /etc/rest-server/tls.key --htpasswd-file /etc/rest-server/htpasswd-$1 $3
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/srv/restic
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectControlGroups=true
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
[Install]
WantedBy=multi-user.target
UNIT
}
unit backup 8000 --append-only | put /etc/systemd/system/rest-server-backup.service 0644
unit maint 8001 "" | put /etc/systemd/system/rest-server-maint.service 0644
in_m "hostnamectl set-hostname $M 2>/dev/null || true; systemctl daemon-reload && systemctl enable -q rest-server-backup rest-server-maint && systemctl restart rest-server-backup rest-server-maint; sleep 1; systemctl is-active rest-server-backup rest-server-maint"
echo "rest-server $REST_SERVER_VERSION on $M ($IP): append-only :8000, maintenance :8001; cert sha256 $(openssl x509 -in "$SD/bkp.crt" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d : | tr A-F a-f)"
