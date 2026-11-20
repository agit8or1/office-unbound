#!/usr/bin/env bash
# Builds the user portal as `ou-portal_<ver>-ou<N>_all.deb` from portal/ (reproducible: fixed mtimes, root:root, no compiled content). Python
# dependencies are Ubuntu packages (no pip). Installed NOT enabled and without configuration: the deployment's agent runbook cfg.portal writes
# /etc/ou-portal/portal.env + client-secret and starts it. Listens on 127.0.0.1:8090 (plain HTTP) behind the VM's TLS proxy / the edge.
# Usage: build-deb.sh <outdir>   (needs dpkg-deb; SOURCE_DATE_EPOCH honoured). Admit + sign with the agent's publish-dev.sh (OU_COMPONENT=ou-portal).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
SRC=${PORTAL_SRC:-$HERE/../../../portal}
OUTDIR=${1:?usage: build-deb.sh <outdir>}
REV=${OU_REVISION:-ou1}
VER=$(python3 -I -c "import re,sys;print(re.search(r'PORTAL_VERSION\s*=\s*\"([^\"]+)\"',open(sys.argv[1]).read()).group(1))" "$SRC/app/version.py")-$REV
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-1763200000}
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
R=$T/root
install -d -m 0755 "$R/opt/ou-portal" "$R/usr/lib/systemd/system" "$R/usr/lib/sysusers.d" "$R/DEBIAN" "$R/usr/share/doc/ou-portal"
cp -r "$SRC/app" "$R/opt/ou-portal/"
chmod -R u+rwX,go+rX,go-w "$R/opt/ou-portal"
find "$R" -name __pycache__ -prune -exec rm -rf {} +
echo 'u ou-portal - "Office Unbound user portal" /nonexistent /usr/sbin/nologin' > "$R/usr/lib/sysusers.d/ou-portal.conf"
printf 'Office Unbound user portal: see the licence of the Office Unbound source tree.\n' > "$R/usr/share/doc/ou-portal/copyright"
cat > "$R/usr/lib/systemd/system/ou-portal.service" <<'UNIT'
[Unit]
Description=Office Unbound user portal
After=network-online.target
Wants=network-online.target
ConditionPathExists=/etc/ou-portal/portal.env

[Service]
Type=simple
User=ou-portal
Group=ou-portal
WorkingDirectory=/opt/ou-portal
EnvironmentFile=/etc/ou-portal/portal.env
ExecStart=/usr/bin/python3 -m uvicorn app.main:create_app --factory --host 127.0.0.1 --port 8090 --proxy-headers --forwarded-allow-ips 127.0.0.1 \
  --no-server-header --no-access-log --workers 1
Restart=on-failure
RestartSec=3
CapabilityBoundingSet=
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service
SystemCallArchitectures=native
UMask=0077
MemoryMax=512M

[Install]
WantedBy=multi-user.target
UNIT
cat > "$R/DEBIAN/control" <<CTL
Package: ou-portal
Version: $VER
Architecture: all
Maintainer: Office Unbound <packages@office-unbound.invalid>
Section: web
Priority: optional
Depends: python3, python3-fastapi, python3-uvicorn, python3-httpx, python3-jinja2, python3-jwt, python3-cryptography, python3-multipart, python3-h11, systemd
Description: Office Unbound user portal (single sign-on start page)
 Mail, calendar, contacts, files and documents behind one Keycloak sign-in. Installed NOT configured and NOT enabled: the deployment's
 agent runbook cfg.portal writes its settings and starts it.
CTL
cat > "$R/DEBIAN/postinst" <<'PI'
#!/bin/sh
set -e
if [ "$1" = configure ]; then
  systemd-sysusers /usr/lib/sysusers.d/ou-portal.conf
  chown -R root:root /opt/ou-portal; chmod -R go-w /opt/ou-portal
  if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null || true
    # an upgrade of a configured portal restarts it on the new code
    if systemctl is-active --quiet ou-portal; then systemctl restart ou-portal || true; fi
  fi
fi
exit 0
PI
chmod 0755 "$R/DEBIAN/postinst"
find "$R" -type d -exec chmod 0755 {} +
find "$R" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
mkdir -p "$OUTDIR"
dpkg-deb --root-owner-group -Zxz --build "$R" "$OUTDIR/ou-portal_${VER}_all.deb" >/dev/null
sha256sum "$OUTDIR/ou-portal_${VER}_all.deb"
