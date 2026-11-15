#!/bin/sh
# Office Unbound Docs container entrypoint. Configuration comes only from the environment (no secrets):
#   OU_WOPI_HOST   required, e.g. https://cloud.example.com:443 (the ONLY WOPI host allowed to connect)
#   OU_CA_FILE     optional path (mounted read-only) of the CA that signed the WOPI host's certificate
#   OU_SERVER_NAME optional external host name
# TLS is terminated by the reverse proxy in front (ssl.enable=false, ssl.termination=true).
set -eu
[ -n "${OU_WOPI_HOST:-}" ] || { echo "OU_WOPI_HOST is required (single WOPI host allowlist)" >&2; exit 64; }
case "$OU_WOPI_HOST" in *[!A-Za-z0-9_./:@,+=-]*) echo "OU_WOPI_HOST has invalid characters" >&2; exit 64;; esac
W=/opt/ou-docs/work
mkdir -p "$W/child-roots" "$W/cache"
set -- /usr/bin/coolwsd \
  --o:sys_template_path=/opt/ou-docs/systemplate --o:child_root_path="$W/child-roots" \
  --o:file_server_root_path=/usr/share/coolwsd --o:cache_files.path="$W/cache" \
  --o:lo_template_path=/opt/officeunbound-office --o:mount_jail_tree=false \
  --o:logging.color=false --o:logging.level=warning --o:logging.level_startup=warning \
  --o:ssl.enable=false --o:ssl.termination=true --o:ssl.ssl_verification=true \
  --o:net.listen=any --o:fetch_update_check=0 --o:allow_update_popup=false --o:admin_console.enable=false \
  --o:storage.wopi.alias_groups[@mode]=groups \
  --o:storage.wopi.alias_groups.group[0].host="$OU_WOPI_HOST" --o:storage.wopi.alias_groups.group[0].host[@allow]=true
[ -z "${OU_CA_FILE:-}" ] || set -- "$@" --o:ssl.ca_file_path="$OU_CA_FILE"
[ -z "${OU_SERVER_NAME:-}" ] || set -- "$@" --o:server_name="$OU_SERVER_NAME"
exec "$@"
