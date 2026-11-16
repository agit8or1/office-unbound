#!/bin/bash
set -eu
CFG=${MAS_CONFIG:-/config/config.yaml}
[ -r "$CFG" ] || { echo "no $CFG: mount the MAS configuration (mas-cli config generate)" >&2; exit 2; }
# telemetry stays off: refuse a configuration that sets up an exporter (sentry dsn, otlp/jaeger/prometheus/datadog tracing or metrics exporters)
if grep -Eiq '^[[:space:]]*(dsn|exporter)[[:space:]]*:' "$CFG" && grep -Eiq 'sentry|otlp|jaeger|zipkin|prometheus|datadog' "$CFG"; then
  if [ "${OU_ALLOW_TELEMETRY:-0}" != 1 ]; then echo "refusing to start: the configuration enables a telemetry exporter (set OU_ALLOW_TELEMETRY=1 only with the operator's written decision)" >&2; exit 2; fi
fi
exec /usr/local/bin/mas-cli -c "$CFG" "$@"
