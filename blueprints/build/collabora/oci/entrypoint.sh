#!/bin/sh
# Office Unbound Docs container entrypoint. Configuration comes only from the environment (no secrets):
#   OU_WOPI_HOST   required, e.g. https://cloud.example.com:443 (the ONLY WOPI host allowed to connect)
#   OU_CA_FILE     optional path (mounted read-only) of the CA that signed the WOPI host's certificate
#   OU_SERVER_NAME optional external host name
#   OU_HELP_BASE_URL optional documentation base URL (coolwsd help_url; shown to users; default: empty = Help buttons hidden). The deployment sets it to <customer portal>/help.
#   OU_PRESPAWN    optional number of pre-started document processes (default 16; see docs/status/docs-reliability-results.md)
# Files (not environment): /opt/ou-tls/proof_key = this deployment's WOPI proof key (PEM RSA private key, mode 0600, owner 10001), written by the
# ICS into the read-only tls volume; /etc/coolwsd/proof_key is a symlink to it (the rootfs is read-only, so nothing is copied). Absent: coolwsd
# starts without proof keys (WOPI hosts that verify proofs, e.g. OpenCloud, then refuse every document). Present but not a PEM key: exit 64.
# TLS is terminated by the reverse proxy in front (ssl.enable=false, ssl.termination=true).
set -eu
[ -n "${OU_WOPI_HOST:-}" ] || { echo "OU_WOPI_HOST is required (single WOPI host allowlist)" >&2; exit 64; }
case "$OU_WOPI_HOST" in *[!A-Za-z0-9_./:@,+=-]*) echo "OU_WOPI_HOST has invalid characters" >&2; exit 64;; esac
PK=/opt/ou-tls/proof_key
if [ -e "$PK" ] || [ -L "$PK" ]; then
  [ -f "$PK" ] && [ -r "$PK" ] || { echo "$PK is not a readable regular file" >&2; exit 64; }
  first=$(head -n 1 "$PK")
  case "$first" in
    "-----BEGIN RSA PRIVATE KEY-----") end="-----END RSA PRIVATE KEY-----";;
    "-----BEGIN PRIVATE KEY-----") end="-----END PRIVATE KEY-----";;
    *) echo "$PK is not a PEM RSA private key" >&2; exit 64;;
  esac
  grep -qxF -e "$end" "$PK" || { echo "$PK is not a complete PEM private key" >&2; exit 64; }
  [ "$(readlink /etc/coolwsd/proof_key 2>/dev/null || true)" = "$PK" ] \
    || echo "WARNING: /etc/coolwsd/proof_key does not lead to $PK (image older than 26.04.6-ou4?); coolwsd will run without WOPI proof keys" >&2
else
  echo "WARNING: no WOPI proof key at $PK: coolwsd sends no X-WOPI-Proof headers and WOPI hosts that verify them (OpenCloud) refuse every document" >&2
fi
W=/opt/ou-docs/work
mkdir -p "$W/child-roots" "$W/cache"
set -- /usr/bin/coolwsd \
  --o:sys_template_path=/opt/ou-docs/systemplate --o:child_root_path="$W/child-roots" \
  --o:file_server_root_path=/usr/share/coolwsd --o:cache_files.path="$W/cache" \
  --o:lo_template_path=/opt/officeunbound-office --o:mount_jail_tree=false \
  --o:logging.color=false --o:logging.level=warning --o:logging.level_startup=warning \
  --o:ssl.enable=false --o:ssl.termination=true --o:ssl.ssl_verification=true \
  --o:num_prespawn_children="${OU_PRESPAWN:-16}" \
  --o:net.listen=any --o:fetch_update_check=0 --o:allow_update_popup=false --o:admin_console.enable=false \
  --o:storage.wopi.alias_groups[@mode]=groups \
  --o:storage.wopi.alias_groups.group[0].host="$OU_WOPI_HOST" --o:storage.wopi.alias_groups.group[0].host[@allow]=true
case "${OU_HELP_BASE_URL:-}" in *[!A-Za-z0-9_./:@,+=%-]*) echo "OU_HELP_BASE_URL has invalid characters" >&2; exit 64;; esac
[ -z "${OU_HELP_BASE_URL:-}" ] || set -- "$@" --o:help_url="$OU_HELP_BASE_URL"
[ -z "${OU_CA_FILE:-}" ] || set -- "$@" --o:ssl.ca_file_path="$OU_CA_FILE"
[ -z "${OU_SERVER_NAME:-}" ] || set -- "$@" --o:server_name="$OU_SERVER_NAME"
exec "$@"
