#!/bin/sh
# Telemetry guard: Synapse's report_stats sends anonymous statistics to matrix.org. Refuse to start unless the config sets it to false explicitly.
set -eu
CFG=${SYNAPSE_CONFIG_PATH:-/data/homeserver.yaml}
[ -r "$CFG" ] || { echo "missing $CFG (mount the homeserver config)" >&2; exit 1; }
grep -Eq '^report_stats:[[:space:]]*false[[:space:]]*$' "$CFG" || { echo "refusing to start: $CFG must contain 'report_stats: false' (no telemetry)" >&2; exit 1; }
exec /opt/synapse/bin/python3 -m synapse.app.homeserver -c "$CFG"
