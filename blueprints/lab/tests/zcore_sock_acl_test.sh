#!/bin/bash
# Security review 4, M1 regression: only the php-fpm pool users (groweb/grosync/grodav) may connect to zcore.sock; every other local uid is refused.
# usage (ICS host): bash zcore_sock_acl_test.sh <machine> [machine...]      (e.g. ou-gw1 ou-gw-sso1). Read-only: only connect() attempts.
set -u
PROBE='import socket
s = socket.socket(socket.AF_UNIX)
try:
    s.connect("/run/gromox/zcore.sock")
    print("allow")
except OSError:
    print("deny")'
fail=0
for M in "$@"; do
  echo "== $M"
  sudo systemd-run -M "$M" --quiet --pipe --wait /bin/sh -c 'stat -c "socket %A %U:%G" /run/gromox/zcore.sock; stat -c "dir    %A %U:%G" /run/gromox'
  for u in nobody www-data postfix redis ou-wipe groweb grosync grodav; do
    case $u in groweb|grosync|grodav) want=allow;; *) want=deny;; esac
    if ! sudo systemd-run -M "$M" --quiet --pipe --wait /bin/sh -c "id $u >/dev/null 2>&1"; then echo "  $u: (no such user, skipped)"; continue; fi
    got=$(printf '%s\n' "$PROBE" | sudo systemd-run -M "$M" --quiet --pipe --wait /bin/sh -c "exec setpriv --reuid=$u --regid=\$(id -g $u) --init-groups /usr/bin/python3 -" 2>&1 | tail -1)
    if [ "$got" = "$want" ]; then r=ok; else r=FAIL; fail=1; fi
    printf '  %-9s connect=%-6s expected=%-6s %s\n' "$u" "$got" "$want" "$r"
  done
done
if [ $fail = 0 ]; then echo "RESULT PASS"; else echo "RESULT FAIL"; fi
exit $fail
