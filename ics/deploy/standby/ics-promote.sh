#!/usr/bin/env bash
# Fenced promotion of THIS standby controller to primary (ADR-0012; docs/runbooks/ics-recovery.md). Run as root on the standby.
#   sudo ics-promote.sh [--fence-old-dsn-file F] [--confirm "promote <hostname>"] [--no-announce]
# Refuses while the old primary is still streaming (unless it can be fenced in its database first), asks for a typed confirmation,
# bumps the controller epoch + audits `controller.promoted`, verifies the audit chain, flips ICS_ROLE and restarts ics.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }
cd /opt/office-unbound/ics
exec env ICS_ENV_FILE=/etc/office-unbound/ics.env .venv/bin/python -m ics.cli promote "$@"
