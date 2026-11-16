#!/bin/bash
# Reproduce the "No child available" t08 failure on ou-office1 (agent BK): restart coolwsd with a COLD page cache for the engine tree,
# optionally under CPU load, run t08 the moment the service reports healthy, count failures and journal warnings.
# env: OU_VENV OU_CA_WORK LOGDIR (as docs-suite.sh); ROUNDS (5); COLD (1 = evict the engine files from the page cache);
# LOAD (busy loops inside ou-office1, 0 = none); LABEL. Counts the journal warning "No child available" per round (the defect's signature).
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
: "${OU_VENV:?}" "${OU_CA_WORK:?}" "${LOGDIR:?}"
ROUNDS=${ROUNDS:-5}; COLD=${COLD:-1}; LOAD=${LOAD:-0}; LABEL=${LABEL:-run}; M=ou-office1
ROOT=/var/lib/machines/$M
mkdir -p "$LOGDIR"
ex() { sudo systemd-run -M $M --quiet --pipe --wait /bin/sh -c "$1"; }
evict() { sudo python3 -I -c '
import os, sys
root = sys.argv[1]; n = 0
for d in ("opt/officeunbound-office", "opt/cool/systemplate", "usr/share/coolwsd", "usr/bin"):
    for dp, _, fs in os.walk(os.path.join(root, d)):
        for f in fs:
            p = os.path.join(dp, f)
            try:
                fd = os.open(p, os.O_RDONLY); os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED); os.close(fd); n += 1
            except OSError: pass
print("evicted", n, "files")
' "$ROOT"; }
stop_load() { sudo systemctl -M $M stop ou-bk-load.service 2>/dev/null; sudo systemctl -M $M reset-failed ou-bk-load.service 2>/dev/null; true; }
trap stop_load EXIT
fails=0
for r in $(seq 1 "$ROUNDS"); do
  stop_load
  ex 'systemctl stop coolwsd; rm -rf /opt/cool/child-roots/* 2>/dev/null; true'
  [ "$COLD" = 1 ] && evict
  if [ "$LOAD" -gt 0 ]; then
    ex "systemd-run --unit=ou-bk-load --quiet /bin/sh -c 'for i in \$(seq $LOAD); do (while :; do :; done) & done; wait'"
  fi
  t0=$(date +%s)
  # a unit WITHOUT ExecStartPost returns as soon as coolwsd forked; the fixed unit returns only when a conversion works through a kit
  ex 'systemctl start coolwsd'
  t1=$(date +%s)
  # health as the old check saw it: HTTP 200 on discovery
  until ex 'curl -g -fsS -o /dev/null --max-time 2 http://[::1]:9980/hosting/discovery' >/dev/null 2>&1; do sleep 0.3; done
  t2=$(date +%s)
  [ "${WAIT_KITS:-0}" = 1 ] && ex '/usr/libexec/ou-docs/ou-docs-ready --wait 150' >/dev/null 2>&1
  mark=$(date '+%Y-%m-%d %H:%M:%S')
  OU_VENV=$OU_VENV OU_CA_WORK=$OU_CA_WORK LOGDIR=$LOGDIR/$LABEL-r$r TESTS=t08_office_concurrency bash "$HERE/docs-suite.sh" > "$LOGDIR/$LABEL-r$r.out" 2>&1; rc=$?
  nochild=$(ex "journalctl -u coolwsd --no-pager --since '$mark' -o cat | grep -c 'No child available'")
  printf '%s r%d start_returned_after=%ss discovery_200_after=%ss t08_rc=%d nochild_warnings=%s load=%s cold=%s | %s\n' "$LABEL" "$r" "$((t1-t0))" "$((t2-t0))" "$rc" "$nochild" "$LOAD" "$COLD" "$(tail -1 "$LOGDIR/$LABEL-r$r.out" | cut -c1-140)" | tee -a "$LOGDIR/summary.txt"
  [ $rc -ne 0 ] && fails=$((fails+1))
done
echo "$LABEL: $fails/$ROUNDS rounds failed" | tee -a "$LOGDIR/summary.txt"
