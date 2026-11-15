#!/usr/bin/env bash
# Run on the OPERATOR workstation (not on a VM). Streams a role's TLS bundle
# from the kc VM to the target VM through this machine's memory/pipe; nothing
# is written to the workstation disk. Requires ssh access (key auth) + sudo on both.
#
#   ./fetch-bundle.sh <kc-ssh-target> <role: files|office|mail> <target-ssh-target>
set -euo pipefail
[ $# -eq 3 ] || { echo "usage: $0 <kc-ssh> <files|office|mail> <target-ssh>" >&2; exit 2; }
KC="$1"; ROLE="$2"; TARGET="$3"
case "$ROLE" in files|office|mail) ;; *) echo "bad role" >&2; exit 2;; esac
ssh "$KC" "sudo cat /root/ou-lab-ca/out/${ROLE}.tar.gz" \
  | ssh "$TARGET" 'sudo install -m 0600 -o root -g root /dev/stdin /root/ou-lab-bundle.tar.gz'
echo "bundle for ${ROLE} installed on ${TARGET}:/root/ou-lab-bundle.tar.gz"
