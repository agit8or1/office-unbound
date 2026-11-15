#!/bin/bash
# runs INSIDE the sso node (called by lab-sso.sh): apply blueprints/build/grommunio-web/patches/*.patch (copied to /root/patches) to the
# grommunio-web source tree, rebuild, redeploy (keeps config.php). Idempotent: patches already applied are skipped.
set -eu
cd /usr/src/ou/grommunio-web
for P in /root/patches/*.patch; do
  if patch -p1 -R --dry-run -s < "$P" >/dev/null 2>&1; then echo "already applied: $P"; else patch -p1 < "$P"; fi
done
export PATH=/opt/node/bin:$PATH HOME=/root
make -j2 2>&1 | tail -3
rm -rf /usr/share/grommunio-web.new
cp -a deploy /usr/share/grommunio-web.new
cp /usr/share/grommunio-web/config.php /usr/share/grommunio-web.new/config.php
rm -rf /usr/share/grommunio-web
mv /usr/share/grommunio-web.new /usr/share/grommunio-web
systemctl restart php8.2-fpm
grep -c "'context'" /usr/share/grommunio-web/server/includes/util.php
grep -rl "ContextURLAction" /usr/share/grommunio-web/client 2>/dev/null | head -3
