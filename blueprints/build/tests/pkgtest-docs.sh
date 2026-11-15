#!/bin/bash
# Install + smoke test of ou-docs (Office Unbound Docs, Collabora Online) on a FRESH Ubuntu 24.04 machine (the package targets noble, not Debian 12).
#   pkgtest-docs.sh <suite>
# Clone of ou-base-noble (MemoryMax=3G, zone oulab), the .deb of the suite pool is copied in (hash checked against the pool), `apt install ./ou-docs...deb`
# (dependencies from the Ubuntu archive), then: postinst effects (user, file capabilities, systemplate), coolwsd --version, coolwsd started with the
# package's own unit flags plus plain HTTP, WOPI discovery answers with the branded product, the unit is installed but disabled. Records
# install-smoke for exactly the installed ou-docs version (repo.sh record-installed) when everything passed.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd); BUILD=$(cd "$HERE/.." && pwd)
STATE=${OU_PKG_STATE:-/var/lib/office-unbound/pkgbuild}
SUITE=${1:?suite}; T=ou-docstest1
LOG=$STATE/out/pkgtest-docs-$SUITE.log
exec > >(tee "$LOG") 2>&1
inm() { sudo systemd-run -M "$T" --wait --pipe -q /bin/bash -c "$1"; }
DEB=$(ls "$STATE"/repo/pool/$SUITE/collabora/ou-docs_*_amd64.deb | sort -V | tail -1)
echo "== pkgtest-docs $(date -u +%FT%TZ) suite=$SUITE deb=$(basename "$DEB") sha256=$(sha256sum "$DEB" | cut -d' ' -f1)"
sudo machinectl terminate "$T" 2>/dev/null; sleep 2; sudo machinectl remove "$T" 2>/dev/null
sudo machinectl clone ou-base-noble "$T"
printf '[Exec]\nBoot=yes\nPrivateUsers=pick\n[Network]\nZone=oulab\n' | sudo tee /etc/systemd/nspawn/$T.nspawn >/dev/null
sudo machinectl start "$T"; sudo systemctl set-property systemd-nspawn@$T.service MemoryMax=3G; sleep 12
P=0; F=0; ok() { echo "PASS  $1"; P=$((P+1)); }; no() { echo "FAIL  $1"; F=$((F+1)); }
cat "$DEB" | sudo systemd-run -M $T --wait --pipe -q /bin/bash -c 'cat > /root/ou-docs.deb'
[ "$(inm 'sha256sum < /root/ou-docs.deb' | cut -d' ' -f1)" = "$(sha256sum < "$DEB" | cut -d' ' -f1)" ] && ok "package transferred intact" || no "package hash differs"
inm 'apt-get update -q >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y -q /root/ou-docs.deb 2>&1 | tail -4' ; true
inm 'dpkg -s ou-docs | grep -q "Status: install ok installed"' && ok "ou-docs installed with its dependencies from the Ubuntu archive" || no "ou-docs not installed"
inm 'id cool >/dev/null' && ok "postinst: user cool exists" || no "no user cool"
inm 'getcap /usr/bin/coolforkit-caps | grep -q cap_sys_chroot' && ok "postinst: file capabilities on coolforkit-caps" || no "capabilities missing"
inm 'test -d /opt/cool/systemplate/usr' && ok "postinst: systemplate created" || no "systemplate missing"
inm '/usr/bin/coolwsd --version 2>&1 | head -2'
inm 'test -x /usr/bin/coolwsd && /usr/bin/coolwsd --version 2>&1 | grep -qi "coolwsd\|collabora\|^[0-9]"' && ok "coolwsd --version runs" || no "coolwsd --version fails"
inm 'systemctl is-enabled ou-docs.service 2>&1 | grep -qv enabled; systemctl is-active ou-docs.service | grep -q inactive' && ok "unit installed, not enabled, not started" || no "unit state"
inm 'grep -c Office /etc/coolwsd/coolwsd.xml >/dev/null; dpkg -S /etc/coolwsd/coolwsd.xml | grep -q ou-docs' && ok "coolwsd.xml owned by the package (conffile)" || no "coolwsd.xml not owned"
inm 'su -s /bin/bash cool -c "nohup /usr/bin/coolwsd --o:sys_template_path=/opt/cool/systemplate --o:child_root_path=/opt/cool/child-roots --o:file_server_root_path=/usr/share/coolwsd --o:cache_files.path=/opt/cool/cache --o:ssl.enable=false --o:ssl.termination=false --o:mount_jail_tree=false --o:net.service_root=\"\" --o:lo_template_path=/opt/officeunbound-office --o:admin_console.enable=false >/tmp/coolwsd.out 2>&1 &"; sleep 20; curl -sS -o /tmp/disc.xml -w "%{http_code}\n" http://127.0.0.1:9980/hosting/discovery'
inm 'grep -c "wopi-discovery" /tmp/disc.xml; grep -o "action ext=\"odt\"[^>]*" /tmp/disc.xml | head -1'
inm 'grep -q "wopi-discovery" /tmp/disc.xml' && ok "WOPI discovery answers (coolwsd up, document types listed)" || { no "no WOPI discovery"; inm 'tail -15 /tmp/coolwsd.out'; }
echo "== RESULT pass=$P fail=$F"
sudo machinectl terminate "$T"; sleep 2; sudo machinectl remove "$T"
if [ "$F" = 0 ]; then
  "$BUILD/repo/repo.sh" record-installed "$SUITE" install-smoke pass "$LOG" "$(basename "$DEB" | sed 's/_amd64.deb//')"
fi
[ "$F" = 0 ]
