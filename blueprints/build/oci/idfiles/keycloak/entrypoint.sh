#!/bin/bash
# Office Unbound Keycloak entrypoint. Configuration = environment of the unit (podman.deploy_unit env/secrets) plus an OPTIONAL rendered file
# in the data volume (OU_ENV_FILE, default /opt/keycloak/data/ou.env): KEY=VALUE lines, parsed (never sourced/evaluated), for values the unit spec's
# env character class cannot carry. Realm files found in /opt/keycloak/data/import are imported on first start. No secret is baked into the image.
set -eu
ENVF=${OU_ENV_FILE:-/opt/keycloak/data/ou.env}
if [ -r "$ENVF" ]; then
  while IFS= read -r l || [ -n "$l" ]; do
    case $l in ''|'#'*) continue;; esac
    k=${l%%=*}; v=${l#*=}
    [[ $k =~ ^[A-Z][A-Z0-9_]{0,63}$ ]] || { echo "ou-keycloak: refusing env file line with invalid key" >&2; exit 64; }
    export "$k=$v"
  done < "$ENVF"
fi
args=("$@")
if [ "${1:-}" = start ] && compgen -G "/opt/keycloak/data/import/*.json" >/dev/null; then args+=(--import-realm); fi
exec /opt/keycloak/bin/kc.sh "${args[@]}"
