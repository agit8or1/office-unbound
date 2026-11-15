#!/usr/bin/env bash
# Run as root INSIDE ou-chat1 (copy blueprints/lab/spike-collab + common to /root/spike-collab):
#   PostgreSQL 16 + Synapse (matrix.org Debian package, pinned) + MAS (release binary, sha256-pinned, upstream = Keycloak)
#   + Element Web (release tarball, sha256-pinned) + nginx (TLS from the lab CA bundle in /etc/ou-lab/tls).
# Prereq: /root/ou-lab-secrets/kc-ou-matrix-client-secret (client secret of Keycloak client `ou-matrix`, copied by the host script).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/versions.env"
SEC=/root/ou-lab-secrets
TLS=/etc/ou-lab/tls
MAS_ULID=01HQW90Z35CMXFJWQPHC3BGZGQ
SERVER_NAME=matrix.ou-lab.internal
export DEBIAN_FRONTEND=noninteractive
install -d -m 0700 "$SEC"
[ -s "$SEC/kc-ou-matrix-client-secret" ] || { echo "missing kc-ou-matrix-client-secret"; exit 1; }
gen() { [ -s "$SEC/$1" ] || { umask 077; openssl rand -hex 24 | tr -d '\n' > "$SEC/$1"; }; cat "$SEC/$1"; }

apt-get update -qq
apt-get install -y -qq curl gnupg ca-certificates nginx-light postgresql python3-yaml lsb-release >/dev/null

# --- PostgreSQL (small footprint for the 1.5G cap) ---
cat > /etc/postgresql/16/main/conf.d/ou-small.conf <<'EOF'
shared_buffers = 64MB
work_mem = 4MB
maintenance_work_mem = 32MB
max_connections = 40
effective_cache_size = 256MB
EOF
systemctl restart postgresql
SYN_PW=$(gen pg-synapse-password); MAS_PW=$(gen pg-mas-password)
su postgres -c "psql -qtA" <<SQL
DO \$\$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='synapse') THEN CREATE ROLE synapse LOGIN PASSWORD '${SYN_PW}'; END IF;
IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='mas') THEN CREATE ROLE mas LOGIN PASSWORD '${MAS_PW}'; END IF; END \$\$;
SQL
su postgres -c "psql -qtA -c \"SELECT 1 FROM pg_database WHERE datname='synapse'\"" | grep -q 1 || su postgres -c "createdb -O synapse -E UTF8 --lc-collate=C --lc-ctype=C -T template0 synapse"
su postgres -c "psql -qtA -c \"SELECT 1 FROM pg_database WHERE datname='mas'\"" | grep -q 1 || su postgres -c "createdb -O mas -E UTF8 -l C.UTF-8 -T template0 mas"

# --- Synapse (official package, pinned) ---
curl -fsSL "$MATRIX_APT_KEY_URL" -o /usr/share/keyrings/matrix-org-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/matrix-org-archive-keyring.gpg] https://packages.matrix.org/debian/ $(lsb_release -cs) main" > /etc/apt/sources.list.d/matrix-org.list
apt-get update -qq
echo "matrix-synapse-py3 matrix-synapse/server-name string ${SERVER_NAME}" | debconf-set-selections
echo "matrix-synapse-py3 matrix-synapse/report-stats boolean false" | debconf-set-selections
apt-get install -y -qq "matrix-synapse-py3=${SYNAPSE_DEB_VERSION}" >/dev/null
apt-mark hold matrix-synapse-py3 >/dev/null

MAS_SECRET=$(gen mas-synapse-shared-secret)
cat > /etc/matrix-synapse/conf.d/ou-lab.yaml <<EOF
server_name: ${SERVER_NAME}
public_baseurl: https://${SERVER_NAME}/
report_stats: false
database:
  name: psycopg2
  args:
    user: synapse
    password: ${SYN_PW}
    dbname: synapse
    host: 127.0.0.1
    cp_min: 2
    cp_max: 6
caches:
  global_factor: 0.5
max_upload_size: 50M
enable_registration: false
password_config:
  enabled: false
suppress_key_server_warning: true
trusted_key_servers: []
federation_domain_whitelist: []
matrix_authentication_service:
  enabled: true
  endpoint: http://127.0.0.1:8080/
  secret: ${MAS_SECRET}
EOF
chown root:matrix-synapse /etc/matrix-synapse/conf.d/ou-lab.yaml; chmod 0640 /etc/matrix-synapse/conf.d/ou-lab.yaml
# the package default config enables a 'database: sqlite' in conf.d/ ; drop it
rm -f /etc/matrix-synapse/conf.d/server_name.yaml.bak
grep -l "sqlite" /etc/matrix-synapse/conf.d/*.yaml 2>/dev/null | grep -v ou-lab || true
systemctl stop matrix-synapse || true

# --- MAS ---
id mas >/dev/null 2>&1 || useradd --system --home /var/lib/mas --create-home --shell /usr/sbin/nologin mas
install -d /opt/mas /etc/mas
if [ ! -x /opt/mas/mas-cli ]; then
  curl -fsSL "$MAS_URL" -o /tmp/mas.tgz
  echo "${MAS_SHA256}  /tmp/mas.tgz" | sha256sum -c -
  tar -xzf /tmp/mas.tgz -C /opt/mas; rm /tmp/mas.tgz
fi
if [ ! -s /etc/mas/config.yaml ]; then
  /opt/mas/mas-cli config generate -o /etc/mas/config.gen.yaml
  ADMIN_SEC=$(gen mas-admin-client-secret)
  python3 - "$MAS_PW" "$MAS_SECRET" "$MAS_ULID" "$SERVER_NAME" "$ADMIN_SEC" <<'PY'
import sys, yaml
pw, secret, ulid, sn, admin_sec = sys.argv[1:6]
c = yaml.safe_load(open('/etc/mas/config.gen.yaml'))
c['http']['listeners'] = [
  {'name': 'web', 'resources': [{'name': n} for n in ('discovery', 'human', 'oauth', 'compat', 'graphql', 'assets', 'adminapi')],
   'binds': [{'address': '127.0.0.1:8080'}]},
  {'name': 'internal', 'resources': [{'name': 'health'}], 'binds': [{'address': '127.0.0.1:8081'}]}]
c['http']['trusted_proxies'] = ['127.0.0.1/32']
c['http']['public_base'] = 'https://mas.ou-lab.internal/'
c['http']['issuer'] = 'https://mas.ou-lab.internal/'
c['database'] = {'uri': f'postgresql://mas:{pw}@127.0.0.1/mas', 'max_connections': 6, 'min_connections': 0}
c['matrix'] = {'homeserver': sn, 'secret': secret, 'endpoint': 'http://127.0.0.1:8008/'}
c['passwords'] = {'enabled': False}
c['account'] = {'password_registration_enabled': False, 'password_change_allowed': False, 'password_recovery_enabled': False,
                'email_change_allowed': False, 'displayname_change_allowed': False}
c['upstream_oauth2'] = {'providers': [{
  'id': ulid, 'human_name': 'Office Unbound SSO', 'issuer': 'https://auth.ou-lab.internal/realms/ou-lab',
  'client_id': 'ou-matrix', 'client_secret_file': '/etc/mas/kc-ou-matrix-client-secret',
  'token_endpoint_auth_method': 'client_secret_basic', 'scope': 'openid profile email', 'pkce_method': 'always', 'on_backchannel_logout': 'logout_all',
  'claims_imports': {
    'localpart': {'action': 'require', 'template': '{{ user.preferred_username }}'},
    'displayname': {'action': 'force', 'template': '{{ user.name }}'},
    'email': {'action': 'force', 'template': '{{ user.email }}', 'set_email_verification': 'always'}}}]}
# service client for the ICS lifecycle integration (lock/deactivate users, kill sessions) via the MAS admin API
c['clients'] = [{'client_id': '01JZ3QTC0C0PGGYC4MPXMFE0BN', 'client_auth_method': 'client_secret_basic', 'client_secret': admin_sec}]
c['policy'] = c.get('policy', {})
c['policy']['data'] = {**c['policy'].get('data', {}), 'admin_clients': ['01JZ3QTC0C0PGGYC4MPXMFE0BN']}
yaml.safe_dump(c, open('/etc/mas/config.yaml', 'w'), sort_keys=False)
PY
  rm /etc/mas/config.gen.yaml
fi
install -m 0640 -o root -g mas "$SEC/kc-ou-matrix-client-secret" /etc/mas/kc-ou-matrix-client-secret
chown root:mas /etc/mas/config.yaml; chmod 0640 /etc/mas/config.yaml
cat > /etc/systemd/system/mas.service <<EOF
[Unit]
Description=matrix-authentication-service
After=network-online.target postgresql.service
Wants=network-online.target
[Service]
User=mas
WorkingDirectory=/opt/mas
ExecStartPre=/opt/mas/mas-cli --config /etc/mas/config.yaml database migrate
ExecStart=/opt/mas/mas-cli --config /etc/mas/config.yaml server
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
StateDirectory=mas
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now mas
systemctl enable --now matrix-synapse

# --- Element Web ---
if [ ! -f /opt/element/version ] || [ "$(cat /opt/element/version)" != "$ELEMENT_VERSION" ]; then
  curl -fsSL "$ELEMENT_URL" -o /tmp/element.tgz
  echo "${ELEMENT_SHA256}  /tmp/element.tgz" | sha256sum -c -
  rm -rf /opt/element; install -d /opt/element
  tar -xzf /tmp/element.tgz -C /opt/element --strip-components=1; rm /tmp/element.tgz
  echo "$ELEMENT_VERSION" > /opt/element/version
fi
cat > /opt/element/config.json <<EOF
{
  "default_server_config": {"m.homeserver": {"base_url": "https://${SERVER_NAME}", "server_name": "${SERVER_NAME}"}},
  "disable_custom_urls": true, "disable_guests": true, "disable_login_language_selector": false,
  "brand": "Office Unbound Chat (lab)", "show_labs_settings": false,
  "features": {"feature_group_calls": false},
  "jitsi": {"preferred_domain": "meet.ou-lab.internal"},
  "element_call": {"use_exclusively": false},
  "default_country_code": "US", "room_directory": {"servers": []}
}
EOF

# --- nginx ---
cat > /etc/nginx/sites-available/ou-chat <<'EOF'
server { listen 80 default_server; return 301 https://$host$request_uri; }
ssl_certificate /etc/ou-lab/tls/chat.crt;
ssl_certificate_key /etc/ou-lab/tls/chat.key;
ssl_protocols TLSv1.2 TLSv1.3;
server {
  listen 443 ssl; server_name chat.ou-lab.internal;
  root /opt/element; index index.html;
  add_header X-Frame-Options SAMEORIGIN always;
  add_header X-Content-Type-Options nosniff always;
  add_header Content-Security-Policy "frame-ancestors 'self'" always;
  location = /config.json { add_header Cache-Control no-cache; }
  location / { try_files $uri $uri/ =404; }
}
server {
  listen 443 ssl; server_name matrix.ou-lab.internal;
  client_max_body_size 55M;
  location ~ ^/_matrix/client/(r0|v3|unstable)/(login|logout|refresh) { proxy_pass http://127.0.0.1:8080; proxy_set_header Host mas.ou-lab.internal; proxy_set_header X-Forwarded-For $remote_addr; }
  location ~ ^/(_matrix|_synapse/client|\.well-known/matrix) {
    proxy_pass http://127.0.0.1:8008; proxy_set_header X-Forwarded-For $remote_addr; proxy_set_header X-Forwarded-Proto https; proxy_set_header Host $host;
  }
  location = /.well-known/matrix/client { default_type application/json; add_header Access-Control-Allow-Origin * always;
    return 200 '{"m.homeserver":{"base_url":"https://matrix.ou-lab.internal"},"org.matrix.msc2965.authentication":{"issuer":"https://mas.ou-lab.internal/","account":"https://mas.ou-lab.internal/account/"}}'; }
}
server {
  listen 443 ssl; server_name mas.ou-lab.internal 192.168.186.245;
  location /api/admin/ { allow 192.168.186.0/24; deny all; proxy_pass http://127.0.0.1:8080; proxy_set_header Host $host; proxy_set_header X-Forwarded-For $remote_addr; proxy_set_header X-Forwarded-Proto https; }
  location / { proxy_pass http://127.0.0.1:8080; proxy_set_header Host mas.ou-lab.internal; proxy_set_header X-Forwarded-For $remote_addr; proxy_set_header X-Forwarded-Proto https; }
}
EOF
rm -f /etc/nginx/sites-enabled/default; ln -sf /etc/nginx/sites-available/ou-chat /etc/nginx/sites-enabled/ou-chat
nginx -t && systemctl restart nginx
dpkg -l matrix-synapse-py3 postgresql-16 nginx-light | awk '/^ii/{print $2,$3}'
/opt/mas/mas-cli --version; cat /opt/element/version
