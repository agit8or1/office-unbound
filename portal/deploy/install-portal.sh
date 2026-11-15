#!/bin/bash
# Install the portal INSIDE the machine (ou-portal1, Ubuntu 24.04) as root. Pre-staged by the operator (see portal/README.md):
#   /etc/ou-portal/tls/portal.{crt,key}   TLS cert from the lab CA (blueprints/lab/common/lab-ca.sh)
#   /etc/ou-portal/client-secret          Keycloak client secret of `ou-portal`
#   /usr/local/share/ca-certificates/*.crt lab CAs (then update-ca-certificates)
#   /root/portal-src.tar.gz               this directory's app/ + deploy/
# Python deps come from Ubuntu packages (no pip, no CDN): fastapi 0.101, uvicorn 0.27, httpx 0.26, jinja2, PyJWT, cryptography.
set -euo pipefail
SRC="${1:-/root/portal-src.tar.gz}"
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
  python3-fastapi python3-uvicorn python3-httpx python3-jinja2 python3-jwt python3-cryptography python3-multipart python3-h11
id ou-portal >/dev/null 2>&1 || useradd --system --home /opt/ou-portal --shell /usr/sbin/nologin ou-portal
install -d -o root -g ou-portal -m 0750 /etc/ou-portal /etc/ou-portal/tls
rm -rf /opt/ou-portal.new && mkdir /opt/ou-portal.new && tar -xzf "$SRC" -C /opt/ou-portal.new
rm -rf /opt/ou-portal.old; [ -d /opt/ou-portal ] && mv /opt/ou-portal /opt/ou-portal.old
mv /opt/ou-portal.new /opt/ou-portal && chown -R root:root /opt/ou-portal
[ -f /etc/ou-portal/portal.env ] || install -m 0640 -g ou-portal /opt/ou-portal/deploy/portal.env.example /etc/ou-portal/portal.env
chgrp ou-portal /etc/ou-portal/client-secret /etc/ou-portal/tls/portal.key; chmod 0640 /etc/ou-portal/client-secret /etc/ou-portal/tls/portal.key
install -m 0644 /opt/ou-portal/deploy/ou-portal.service /etc/systemd/system/ou-portal.service
systemctl daemon-reload && systemctl enable ou-portal >/dev/null && systemctl restart ou-portal
sleep 2; systemctl is-active ou-portal
