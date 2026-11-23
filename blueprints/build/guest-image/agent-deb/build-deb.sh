#!/usr/bin/env bash
# Builds the node agent as `ou-node-agent_<ver>-ou<N>_all.deb` from ics/agent (reproducible: fixed mtimes, root:root, no compiled content).
# The deb is then admitted + signed into the apt repository by the dedicated release signer (publish-dev.sh); the golden image installs it with apt from a
# repository whose Release is verified against the pinned release key. Usage: build-deb.sh <outdir>   (needs dpkg-deb; SOURCE_DATE_EPOCH honoured)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
SRC=${AGENT_SRC:-$HERE/../../../../ics/agent}
OUTDIR=${1:?usage: build-deb.sh <outdir>}
REV=${OU_REVISION:-ou1}
VER=$(python3 -I -c "import re,sys;print(re.search(r'__version__\s*=\s*\"([^\"]+)\"',open(sys.argv[1]).read()).group(1))" "$SRC/ou_agent/__init__.py")-$REV
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-1763200000}
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
R=$T/root
install -d -m 0755 "$R/opt/ou-agent" "$R/usr/lib/systemd/system" "$R/usr/lib/sysusers.d" "$R/usr/lib/tmpfiles.d" "$R/DEBIAN" "$R/usr/share/doc/ou-node-agent"
cp -r "$SRC/ou_agent" "$SRC/deploy" "$R/opt/ou-agent/"
find "$R" -name __pycache__ -prune -exec rm -rf {} +
# unit files live in /usr/lib/systemd/system (not /etc); deploy/ keeps the originals for the first-boot renderers
install -m 0644 "$SRC/deploy/ou-agent.service" "$R/usr/lib/systemd/system/ou-agent.service"
for u in "$SRC"/deploy/runbooks/ou-rb-*@.service; do install -m 0644 "$u" "$R/usr/lib/systemd/system/$(basename "$u")"; done
echo 'u ou-agent - "Office Unbound node agent" /nonexistent /usr/sbin/nologin' > "$R/usr/lib/sysusers.d/ou-agent.conf"
printf 'd /var/lib/ou-agent 0700 ou-agent ou-agent -\nd /etc/ou-agent 0755 root root -\n' > "$R/usr/lib/tmpfiles.d/ou-agent.conf"
printf 'Office Unbound node agent: see the licence of the Office Unbound source tree.\n' > "$R/usr/share/doc/ou-node-agent/copyright"
cat > "$R/DEBIAN/control" <<CTL
Package: ou-node-agent
Version: $VER
Architecture: all
Maintainer: Office Unbound <packages@office-unbound.invalid>
Section: admin
Priority: optional
Depends: python3, python3-cryptography, polkitd, nftables, systemd
Description: Office Unbound node agent (signed allowlisted runbooks only)
 Installed NOT initialised and NOT enabled: no keys, certificate or token ship in the package. ou-bootstrap.service generates them per VM at first boot.
CTL
cat > "$R/DEBIAN/postinst" <<'PI'
#!/bin/sh
set -e
if [ "$1" = configure ]; then
  systemd-sysusers /usr/lib/sysusers.d/ou-agent.conf
  systemd-tmpfiles --create /usr/lib/tmpfiles.d/ou-agent.conf
  chown -R root:root /opt/ou-agent; chmod -R go-w /opt/ou-agent
  # in-place upgrade ($2 = the version replaced): restart the running agent once apt has finished, from a transient timer OUTSIDE the
  # agent's cgroup (a direct restart would kill the apt process the agent's package runbook is still waiting on). First install: no restart,
  # ou-bootstrap starts the agent at first boot.
  if [ -n "$2" ] && systemctl is-active --quiet ou-agent.service; then
    systemd-run --quiet --collect --on-active=20 --unit="ou-agent-upgrade-restart-$(date +%s)" systemctl try-restart ou-agent.service || true
  fi
fi
exit 0
PI
chmod 0755 "$R/DEBIAN/postinst"
find "$R" -type d -exec chmod 0755 {} +
find "$R" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
mkdir -p "$OUTDIR"
dpkg-deb --root-owner-group -Zxz --build "$R" "$OUTDIR/ou-node-agent_${VER}_all.deb" >/dev/null
sha256sum "$OUTDIR/ou-node-agent_${VER}_all.deb"
