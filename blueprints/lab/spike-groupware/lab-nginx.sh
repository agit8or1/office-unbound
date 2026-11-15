#!/bin/bash
# nginx front for gw1: TLS on 443; proxy MAPI/HTTP, EWS, OAB, Autodiscover to gromox-http (127.0.0.1:10080).
# sync/dav/web locations are appended by the corresponding stages of lab-apps.sh.
set -eu
HOSTN=${GW_HOST:-gw1.ou-lab.internal}   # override for additional nodes (lab-sso.sh)
rm -f /etc/nginx/sites-enabled/default
sed -i 's/^worker_processes .*/worker_processes 2;/' /etc/nginx/nginx.conf
mkdir -p /etc/nginx/ou-locations
cat > /etc/nginx/conf.d/gw1.conf <<EOF
server {
  listen 443 ssl;
  server_name $HOSTN autodiscover.$HOSTN;
  ssl_certificate /etc/ou-lab-tls/server-chain.pem;
  ssl_certificate_key /etc/ou-lab-tls/server.key;
  ssl_protocols TLSv1.2 TLSv1.3;
  client_max_body_size 100m;
  root /var/www/html;
  include /etc/nginx/ou-locations/*.conf;
}
server { listen 80; server_name _; return 301 https://\$host\$request_uri; }
EOF
cat > /etc/nginx/ou-locations/10-gromox.conf <<'EOF'
location ~* ^/(mapi|EWS|OAB|autodiscover|Autodiscover|rpc|rpcwithcert)(/|$) {
  proxy_pass http://127.0.0.1:10080;
  proxy_http_version 1.1;
  proxy_set_header Host $host;
  proxy_set_header Connection "";
  proxy_set_header X-Forwarded-Proto https;
  proxy_buffering off; proxy_request_buffering off;
  proxy_read_timeout 300s;
}
EOF
nginx -t && systemctl enable nginx && systemctl restart nginx
