#!/bin/bash
# Run the document-tier acceptance tests (t03 t04 t05 t08) through OpenCloud from the ICS host. Passwords are loaded from ou-id1 without printing.
# env: OU_VENV (python venv with blueprints/lab/tests/requirements.txt), OU_CA_WORK (dir for the CA copy), LOGDIR (one log per test)
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd); T="$HERE/../tests"
: "${OU_VENV:?}" "${LOGDIR:?}"; CA=${OU_CA_WORK:-$LOGDIR}/ca.crt; mkdir -p "$LOGDIR"
sudo systemd-run -M ou-id1 --quiet --pipe --wait /bin/cat /root/ou-lab-ca/ca.crt > "$CA"
set -a; eval "$(sudo systemd-run -M ou-id1 --quiet --pipe --wait /bin/cat /root/ou-lab-secrets/test-users.env | grep -E '^(export )?OU_PASSWORD_[A-Z]+=')" 2>/dev/null; set +a
export OU_CA_FILE="$CA" OU_RESTART_CMD='sudo systemctl -M {machine} restart {unit}' OU_MACHINE_FILES=ou-files1 OU_MACHINE_OFFICE=ou-office1 OU_MACHINE_KC=ou-id1
rc=0
for t in ${TESTS:-t03_office_roundtrip t04_wopi t05_versions t08_office_concurrency}; do
  s=$(date +%s); "$OU_VENV/bin/python" -I "$T/$t.py" > "$LOGDIR/$t.log" 2>&1; c=$?; e=$(( $(date +%s) - s ))
  echo "$t exit=$c ${e}s: $(grep -E '^-- ' "$LOGDIR/$t.log" | tail -1)"; [ $c -ne 0 ] && rc=1
done
exit $rc
