#!/usr/bin/env bash
# Run on the OPERATOR workstation (not on a VM). Streams a role's TLS bundle
# from the kc VM to the target VM through this machine's memory/pipe; nothing
# is written to the workstation disk. Requires ssh access (key auth) + sudo on both.
#
#   ./fetch-bundle.sh <kc-ssh-target> <role: files|office|mail> <target-ssh-target>
#
# nspawn lab (no ssh in the machines): a target written as "machine:<name>" is reached with
# `sudo systemd-run -M <name> --pipe` from the ICS host instead (A22 clean-room run):
#   ./fetch-bundle.sh machine:ou-cr-id files machine:ou-cr-files
set -euo pipefail
[ $# -eq 3 ] || { echo "usage: $0 <kc-ssh|machine:NAME> <files|office|mail> <target-ssh|machine:NAME>" >&2; exit 2; }
KC="$1"; ROLE="$2"; TARGET="$3"
case "$ROLE" in files|office|mail) ;; *) echo "bad role" >&2; exit 2;; esac
# rexec <target> <remote command> : stdin/stdout pass through
rexec() {
  case "$1" in
    machine:*) sudo systemd-run -M "${1#machine:}" --pipe --wait -q --collect /bin/bash -c "$2" ;;
    *) ssh "$1" "$2" ;;
  esac
}
rexec "$KC" "$( [[ $KC == machine:* ]] && echo '' || echo 'sudo ' )cat /root/ou-lab-ca/out/${ROLE}.tar.gz" \
  | rexec "$TARGET" "$( [[ $TARGET == machine:* ]] && echo '' || echo 'sudo ' )sh -c 'umask 077; cat > /root/ou-lab-bundle.tar.gz'"
echo "bundle for ${ROLE} installed on ${TARGET}:/root/ou-lab-bundle.tar.gz"
