#!/bin/bash
# Office Unbound OpenCloud entrypoint. Configuration = environment of the unit plus an OPTIONAL rendered file in the config volume
# (OU_ENV_FILE, default $OC_CONFIG_DIR/ou.env; KEY=VALUE lines, parsed, never evaluated) for values the unit spec's env character class cannot carry
# (LDAP filters contain parentheses and *). First start: `opencloud init` generates the internal secrets into $OC_CONFIG_DIR/opencloud.yaml, with the
# admin password taken from the podman secret exposed as OU_INIT_ADMIN_PASSWORD. No secret is baked into the image.
set -eu
CFG=${OC_CONFIG_DIR:-/etc/opencloud}
ENVF=${OU_ENV_FILE:-$CFG/ou.env}
if [ -r "$ENVF" ]; then
  while IFS= read -r l || [ -n "$l" ]; do
    case $l in ''|'#'*) continue;; esac
    k=${l%%=*}; v=${l#*=}
    [[ $k =~ ^[A-Z][A-Z0-9_]{0,63}$ ]] || { echo "ou-opencloud: refusing env file line with invalid key" >&2; exit 64; }
    export "$k=$v"
  done < "$ENVF"
fi
if [ ! -s "$CFG/opencloud.yaml" ]; then
  : "${OU_INIT_ADMIN_PASSWORD:?first start needs OU_INIT_ADMIN_PASSWORD (podman secret)}"
  /usr/bin/opencloud init --insecure false --config-path "$CFG" --admin-password "$OU_INIT_ADMIN_PASSWORD"
fi
unset OU_INIT_ADMIN_PASSWORD
exec /usr/bin/opencloud "$@"
