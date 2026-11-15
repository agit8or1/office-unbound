#!/usr/bin/env bash
# Operator side. Copies the read-only LDAP bind password (consumed by install-files.sh and the groupware
# lab-ldap.sh) from the kc machine to <target>:/root/ou-lab-secrets/ldap-bind-password (0600), through a pipe.
#   ./fetch-bind-password.sh <kc-ssh|machine:NAME> <target-ssh|machine:NAME>
# Previously a manual, undocumented step ("copied by the operator"); found by the A22 clean-room run.
set -euo pipefail
[ $# -eq 2 ] || { echo "usage: $0 <kc> <target>" >&2; exit 2; }
rexec() {
  case "$1" in
    machine:*) sudo systemd-run -M "${1#machine:}" --pipe --wait -q --collect /bin/bash -c "$2" ;;
    *) ssh "$1" "sudo bash -c '$2'" ;;
  esac
}
rexec "$1" 'cat /root/ou-lab-secrets/ldap-bind-password' \
  | rexec "$2" 'umask 077; mkdir -p /root/ou-lab-secrets; chmod 700 /root/ou-lab-secrets; cat > /root/ou-lab-secrets/ldap-bind-password'
echo "bind password installed on $2"
