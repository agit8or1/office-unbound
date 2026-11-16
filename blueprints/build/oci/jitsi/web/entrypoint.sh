#!/bin/sh
# renders the nginx config (upstream names from the environment: OU_JITSI_PROSODY, OU_JITSI_JVB; they resolve at request time through the container network) and runs nginx as uid 10080
set -eu
P=${OU_JITSI_PROSODY:-prosody}; J=${OU_JITSI_JVB:-jvb}
case "$P$J" in *[!A-Za-z0-9.-]*) echo "bad upstream name" >&2; exit 2;; esac
mkdir -p /tmp/nginx
sed -e "s/@PROSODY@/$P/g" -e "s/@JVB@/$J/g" /etc/ou-jitsi/nginx.conf.tmpl > /tmp/nginx/nginx.conf
exec nginx -c /tmp/nginx/nginx.conf -e /tmp/nginx/error.log -g 'daemon off;'
