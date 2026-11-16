#!/bin/bash
# Runs INSIDE the machine that holds a staged DESTDIR tree (ou-build1 for Office Unbound Docs). ADR-0008 "prebuilt-stage" components.
#   package-prebuilt-inner.sh ou-docs <deb-version> <stage-tree> <out-dir> <epoch>
# Builds ONE .deb from the stage tree (hard-link copy, the stage tree is never modified), Depends computed with dpkg-shlibdeps over every ELF file.
set -euo pipefail
NAME=$1; VER=$2; TREE=$3; OUT=$4; SDE=$5
PRESPAWN=${OU_PRESPAWN:-16}; W=/root/build/pkg; export SOURCE_DATE_EPOCH=$SDE LC_ALL=C.UTF-8 TZ=UTC
rm -rf "$W"; mkdir -p "$W/root" "$OUT"
cp -al "$TREE/." "$W/root/"
R=$W/root
# web server examples are not conffiles of the package: move them to the doc examples
mkdir -p "$R/usr/share/doc/$NAME/examples"
for d in nginx apache2; do [ -d "$R/etc/$d" ] && mv "$R/etc/$d" "$R/usr/share/doc/$NAME/examples/$d"; done
# systemd unit (not enabled by the package). Readiness (ou3): ExecStartPost blocks "systemctl start/restart" until a real conversion works through a
# kit (ou-docs-ready), so an upgrade/restart only reports success when documents can be opened; num_prespawn_children is raised from 4 (see
# docs/status/docs-reliability-results.md). A failed readiness wait does NOT fail the unit ("-" prefix): it only delays the start.
install -d "$R/usr/lib/systemd/system" "$R/usr/libexec/ou-docs"
X=${PKG_EXTRA:-/root/build/pkg-extra}
for f in ou-docs-ready; do install -m0755 "$X/$f" "$R/usr/libexec/ou-docs/$f"; done
install -m0644 "$X/ou-docs-health.socket" "$X/ou-docs-health@.service" "$R/usr/lib/systemd/system/"
install -m0644 "$X/nginx-ou-ready.conf" "$R/usr/share/doc/$NAME/examples/nginx-ou-ready.conf"
cat > "$R/usr/lib/systemd/system/ou-docs.service" <<U
[Unit]
Description=Office Unbound Docs (coolwsd)
After=network.target

[Service]
User=cool
Group=cool
ExecStart=/usr/bin/coolwsd --o:sys_template_path=/opt/cool/systemplate --o:child_root_path=/opt/cool/child-roots --o:file_server_root_path=/usr/share/coolwsd --o:cache_files.path=/opt/cool/cache --o:lo_template_path=/opt/officeunbound-office --o:logging.file[@enable]=false --o:num_prespawn_children=$PRESPAWN
ExecStartPost=-/usr/libexec/ou-docs/ou-docs-ready --wait 150
TimeoutStartSec=200
Restart=on-failure
KillMode=control-group
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
U
# Depends: shared-library dependencies of every ELF file in the tree (private engine libraries in /opt/officeunbound-office/program are searched with -l)
mkdir -p "$W/sd/debian"
printf 'Source: %s\nSection: web\nPriority: optional\nMaintainer: x <x@x>\n\nPackage: %s\nArchitecture: amd64\nDescription: x\n' "$NAME" "$NAME" > "$W/sd/debian/control"
cd "$W/sd"
find "$R" -type f \( -perm -u+x -o -name '*.so*' \) -print0 | xargs -0 file | awk -F: '/ELF/ {print $1}' > "$W/elf.list"
echo "ELF files: $(wc -l < "$W/elf.list")"
xargs -a "$W/elf.list" -d '\n' dpkg-shlibdeps --ignore-missing-info -l"$R/opt/officeunbound-office/program" -O -e 2> "$W/shlibdeps.err" > "$W/shlibs.out" || { tail -20 "$W/shlibdeps.err"; true; }
DEPS=$(sed -n 's/^shlibs:Depends=//p' "$W/shlibs.out" | head -1)
[ -n "$DEPS" ] || { echo "no shlibs:Depends computed"; tail -20 "$W/shlibdeps.err"; exit 1; }
cp "$W/shlibdeps.err" "$OUT/shlibdeps.err"
SIZE=$(du -sk "$R" | cut -f1)
mkdir -p "$R/DEBIAN"
cat > "$R/DEBIAN/control" <<C
Package: $NAME
Version: $VER
Architecture: amd64
Maintainer: Office Unbound Build <build@officeunbound.com>
Section: web
Priority: optional
Installed-Size: $SIZE
Depends: $DEPS, adduser, libcap2-bin
Conflicts: coolwsd, code, collabora-online
Replaces: coolwsd, code, collabora-online
Homepage: https://officeunbound.com
Description: Office Unbound Docs (Collabora Online + LibreOffice-derived engine, Office Unbound build)
 Online document editing server (coolwsd, WOPI) built from the pinned upstream tag
 cp-26.04.6-1 with the Office Unbound branding patches and the "OfficeUnbound-LOKit"
 engine distro. The tree is the staged output of blueprints/build/collabora/recipe.sh
 (engine not rebuilt by the package step); built for Ubuntu 24.04. The service unit
 ou-docs.service is installed but neither enabled nor started; configuration is
 /etc/coolwsd/coolwsd.xml (conffile).
C
echo /etc/coolwsd/coolwsd.xml > "$R/DEBIAN/conffiles"
cat > "$R/DEBIAN/postinst" <<'P'
#!/bin/sh
set -e
if [ "$1" = configure ]; then
  id cool >/dev/null 2>&1 || adduser --quiet --system --group --home /opt/cool cool
  setcap cap_fowner,cap_chown,cap_sys_chroot=ep /usr/bin/coolforkit-caps
  setcap cap_sys_admin=ep /usr/bin/coolmount || true
  rm -rf /opt/cool/systemplate
  mkdir -p /opt/cool/child-roots /opt/cool/cache
  coolwsd-systemplate-setup /opt/cool/systemplate /opt/officeunbound-office >/var/log/ou-docs-systemplate-setup.log 2>&1
  chown -R cool:cool /opt/cool /etc/coolwsd
  # the engine files have just been replaced: warm the page cache of the new tree (a cold tree made the first kits slow after an upgrade)
  find /opt/officeunbound-office/program /opt/cool/systemplate -type f -exec cat {} + >/dev/null 2>&1 || true
  # units that were running before the upgrade (ou-docs.service, or the lab/deploy override coolwsd.service) are restarted on the NEW tree and
  # only return once a document conversion works (ExecStartPost), so "upgrade done" means "kits ready"
  if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    for u in ou-docs.service coolwsd.service; do
      if [ -e /run/ou-docs-was-active."$u" ] || systemctl is-active --quiet "$u" 2>/dev/null; then rm -f /run/ou-docs-was-active."$u"; systemctl restart "$u" || echo "WARNING: $u did not come back ready" >&2; fi
    done
    systemctl enable --now ou-docs-health.socket >/dev/null 2>&1 || true
  fi
fi
exit 0
P
cat > "$R/DEBIAN/prerm" <<'P'
#!/bin/sh
set -e
if [ "$1" = remove ] || [ "$1" = upgrade ]; then
  for u in ou-docs.service coolwsd.service; do
    if systemctl is-active --quiet "$u" 2>/dev/null; then : > /run/ou-docs-was-active."$u"; systemctl stop "$u" 2>/dev/null || true; fi
  done
fi
exit 0
P
chmod 0755 "$R/DEBIAN/postinst" "$R/DEBIAN/prerm"
( cd "$R" && find . -type f ! -path './DEBIAN/*' -print0 | sort -z | xargs -0 md5sum > DEBIAN/md5sums )
dpkg-deb --root-owner-group -Zzstd -z9 --build "$R" "$OUT/${NAME}_${VER}_amd64.deb"
cd "$OUT"; sha256sum ./*.deb | tee SHA256SUMS
dpkg-deb -f "$OUT/${NAME}_${VER}_amd64.deb" Depends
