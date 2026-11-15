#!/bin/bash
# gw1: wire grommunio-sync (ActiveSync) + grommunio-dav (CalDAV/CardDAV) into php-fpm + nginx. Runs inside ou-gw1 as root,
# after build-from-source.sh stages mapihdr/sync/dav and lab-configure.sh + lab-nginx.sh.
set -eu
getent passwd grosync >/dev/null || useradd -r -d /var/lib/grosync -s /usr/sbin/nologin grosync
getent passwd grodav  >/dev/null || useradd -r -d /var/lib/grommunio-dav -s /usr/sbin/nologin grodav
install -d -o grosync -g grosync /var/lib/grosync /var/log/grommunio-sync
install -d -o grodav -g grodav /var/lib/grommunio-dav /var/log/grommunio-dav
install -d /run/php-fpm; echo "d /run/php-fpm 0755 root root -" > /etc/tmpfiles.d/php-fpm-ou.conf  # /run is tmpfs; pools put sockets here
# mapi extension for php-fpm (gromox's make install only wires the CLI)
cp /etc/php/8.2/cli/conf.d/mapi.ini /etc/php/8.2/mods-available/mapi.ini
phpenmod -s fpm mapi
# sync config: lab has no admin-api, so no provisioning policy endpoint -> PROVISIONING off
cp /usr/share/grommunio-sync/config.php /usr/share/grommunio-sync/config.php.orig 2>/dev/null || true
sed -i "s|define('PROVISIONING', true);|define('PROVISIONING', false);|" /usr/share/grommunio-sync/config.php
sed -i "s|define('LOGLEVEL', LOGLEVEL_INFO);|define('LOGLEVEL', LOGLEVEL_DEBUG);|" /usr/share/grommunio-sync/config.php
sed -i "s|define('DEVELOPER_MODE', true);|define('DEVELOPER_MODE', false);|" /usr/share/grommunio-dav/config.php
sed 's/grommunio-sync-pool/grommunio-sync/; s/pm.max_children = 150/pm.max_children = 10/; s/pm.start_servers = 8/pm.start_servers = 2/; s/pm.max_spare_servers = 12/pm.max_spare_servers = 3/; s/pm.min_spare_servers = 4/pm.min_spare_servers = 1/; /^rlimit_core/d' \
  /usr/src/ou/grommunio-sync/build/pool-grommunio-sync.conf > /etc/php/8.2/fpm/pool.d/grommunio-sync.conf
sed 's/grommunio-dav-pool/grommunio-dav/' /usr/src/ou/grommunio-dav/build/pool-grommunio-dav.conf \
  | sed 's/pm.max_children = [0-9]*/pm.max_children = 10/; s/pm.start_servers = [0-9]*/pm.start_servers = 2/; s/pm.max_spare_servers = [0-9]*/pm.max_spare_servers = 3/; s/pm.min_spare_servers = [0-9]*/pm.min_spare_servers = 1/; /^rlimit_core/d' > /etc/php/8.2/fpm/pool.d/grommunio-dav.conf
grep -E "^\[|^listen =|^user" /etc/php/8.2/fpm/pool.d/grommunio-{sync,dav}.conf
cat > /etc/nginx/ou-locations/20-sync.conf <<'EOF'
location /Microsoft-Server-ActiveSync {
  include fastcgi_params;
  fastcgi_param SCRIPT_FILENAME /usr/share/grommunio-sync/index.php;
  fastcgi_param REMOTE_USER "";
  fastcgi_param HTTP_PROXY "";
  fastcgi_param PHP_VALUE "memory_limit=500M\npost_max_size=102M\nmax_execution_time=3660";
  fastcgi_read_timeout 3660;
  fastcgi_pass unix:/run/php-fpm/php-grommunio-sync-fpm.sock;
}
EOF
cat > /etc/nginx/ou-locations/30-dav.conf <<'EOF'
rewrite ^/.well-known/caldav /dav redirect;
rewrite ^/.well-known/carddav /dav redirect;
location /dav {
  include fastcgi_params;
  fastcgi_param SCRIPT_FILENAME /usr/share/grommunio-dav/server.php;
  fastcgi_param REMOTE_USER "";
  fastcgi_param HTTP_PROXY "";
  fastcgi_read_timeout 360;
  fastcgi_pass unix:/run/php-fpm/php-grommunio-dav-fpm.sock;
}
EOF
systemctl enable --now redis-server
systemctl restart php8.2-fpm
nginx -t && systemctl reload nginx

## ---- grommunio-web (built by build-from-source.sh stage 'web' into /usr/share/grommunio-web) ----
if [ -d /usr/share/grommunio-web ]; then
getent passwd groweb >/dev/null || useradd -r -d /var/lib/groweb -s /usr/sbin/nologin groweb
install -d -o groweb -g groweb /var/lib/groweb /var/lib/grommunio-web /var/lib/grommunio-web/session /var/lib/grommunio-web/tmp
[ -f /usr/share/grommunio-web/config.php ] || cp /usr/share/grommunio-web/config.php.dist /usr/share/grommunio-web/config.php
sed 's/grommunio-web-pool/grommunio-web/; s/pm.max_children = [0-9]*/pm.max_children = 10/; s/pm.start_servers = [0-9]*/pm.start_servers = 2/; s/pm.max_spare_servers = [0-9]*/pm.max_spare_servers = 3/; s/pm.min_spare_servers = [0-9]*/pm.min_spare_servers = 1/; /^rlimit_core/d' \
  /usr/src/ou/grommunio-web/build/pool-grommunio-web.conf > /etc/php/8.2/fpm/pool.d/grommunio-web.conf
cat > /etc/nginx/ou-locations/40-web.conf <<'EOF'
location = / { return 301 "/web/"; }
location = /web { return 301 "/web/$is_args$args"; }
location /web/ {
  alias /usr/share/grommunio-web/;
  index index.php;
  gzip_static on;
  location ~ ^/web/(.+\.php)$ {
    include fastcgi_params;
    fastcgi_param REMOTE_USER "";
    fastcgi_param SCRIPT_FILENAME /usr/share/grommunio-web/$1;
    fastcgi_param PHP_VALUE "post_max_size=31M\nupload_max_filesize=30M\nmax_execution_time=3660\nsession.cookie_secure=on\nsession.save_path=/var/lib/grommunio-web/session";
    fastcgi_read_timeout 360s;
    fastcgi_pass unix:/run/php-fpm/php-grommunio-web-fpm.sock;
  }
}
EOF
systemctl restart php8.2-fpm; nginx -t && systemctl reload nginx
fi
# M1 (security review 4): zcore.sock group-restricted to the php-fpm pool users (takes effect after the next zcore + php-fpm restart)
sh "$(dirname "$0")/ou-zcore-lockdown.sh"
