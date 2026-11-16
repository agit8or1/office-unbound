#!/bin/sh
set -eu
CFG=${PROSODY_CONFIG:-/etc/prosody/prosody.cfg.lua}
[ -r "$CFG" ] || { echo "no $CFG: mount the prosody configuration" >&2; exit 2; }
grep -Eq '^[[:space:]]*daemonize[[:space:]]*=[[:space:]]*false' "$CFG" || { echo "refusing to start: the configuration must say daemonize = false (foreground, no pid games)" >&2; exit 2; }
exec prosody --config "$CFG" 2>&1
