#!/bin/bash
# Record the result of a pkgtest run for every component and promote dev -> staging -> stable, demonstrating the gate.
#   promote-all.sh <pkgtest-log> <approver>
# Refusals are expected and printed first (no record; failed record; stable without approval), then the real promotion.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd); R=$HERE/../repo/repo.sh
LOG=$1; APPROVER=${2:-}
COMPS="libhx wmime gromox mapi-header-php grommunio-sync grommunio-dav grommunio-web admin-api"
echo "--- 1. promote with no test record (must be refused)"
$R promote dev staging gromox || true
echo "--- 2. promote after a recorded FAILURE (must be refused)"
$R record-test gromox install-smoke fail "$LOG"; $R promote dev staging gromox || true
echo "--- 3. record the passing pkgtest run for all components"
grep -q 'rc=0' "$LOG" || { echo "pkgtest log does not end with rc=0, refusing to record a pass"; exit 1; }
for c in $COMPS; do $R record-test "$c" install-smoke pass "$LOG"; done
echo "--- 4. dev -> staging"
for c in $COMPS; do $R promote dev staging "$c" | tail -1; done
echo "--- 5. staging -> stable without approval (must be refused)"
$R promote staging stable gromox || true
echo "--- 6. staging -> stable with approval record"
for c in $COMPS; do $R promote staging stable "$c" --approved-by "$APPROVER" | tail -1; done
