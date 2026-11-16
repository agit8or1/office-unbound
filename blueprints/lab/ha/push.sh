#!/bin/bash
# HOST side (sudo available): copy this checkout's ICS code + catalog + the HA harness into /root/src of the given lab machines.
#   blueprints/lab/ha/push.sh ou-ha1 ou-ha2 ou-ha-node1
set -euo pipefail
cd "$(dirname "$0")/../../.."
for m in "$@"; do
  tar -c --exclude=__pycache__ --exclude=.venv --exclude=node_modules ics VERSION VERSIONS.json blueprints/catalog blueprints/lab/ha \
    | sudo systemd-run -M "$m" --pipe --wait -q /bin/bash -c 'rm -rf /root/src && mkdir -p /root/src && tar -x -C /root/src'
done
