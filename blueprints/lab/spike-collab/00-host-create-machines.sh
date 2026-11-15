#!/usr/bin/env bash
# Run on the ICS host (needs sudo). Creates ou-chat1 (Synapse/MAS/Element) and ou-meet1 (Jitsi + token service)
# as clones of ou-base-noble, static IPs, memory caps, lab CA trust + role cert bundle.
# Prereq: lab CA leaf certs `chat` and `meet` exist (run common/lab-ca.sh inside ou-id1; see README.md).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/../common/lab.env"
M=/var/lib/machines
CAOUT="$M/ou-id1/root/ou-lab-ca/out"
mk() { # name ip memmax role
  local n=$1 ip=$2 mem=$3 role=$4
  sudo test -d "$M/$n" || sudo machinectl clone ou-base-noble "$n"
  printf '[Exec]\nBoot=yes\nPrivateUsers=pick\n\n[Network]\nZone=oulab\n' | sudo tee /etc/systemd/nspawn/$n.nspawn >/dev/null
  # files must be created INSIDE the machine (PrivateUsers=pick: host-root-owned files show as nobody there)
  inm() { sudo systemd-run -M "$n" --pipe --wait --quiet "$@"; }
  printf '[Match]\nName=host0\n[Network]\nAddress=%s/24\nGateway=192.168.186.1\nDNS=192.168.22.1\n' "$ip" | inm tee /etc/systemd/network/05-static.network >/dev/null
  inm tee /etc/hosts >/dev/null <<H
127.0.0.1	localhost
::1		localhost ip6-localhost ip6-loopback
127.0.1.1 $n
$IP_KC auth.$LAB_DOMAIN
$IP_CHAT $HOST_CHAT $HOST_MATRIX $HOST_MAS
$IP_MEET $HOST_MEET $HOST_MEETAUTH
H
  sudo systemctl set-property "systemd-nspawn@$n" MemoryMax="$mem"
  sudo machinectl start "$n" || true
  for i in $(seq 30); do sudo systemd-run -M "$n" --pipe --wait true >/dev/null 2>&1 && break; sleep 1; done
  inm mkdir -p /etc/ou-lab/tls
  sudo cat "$CAOUT/$role.tar.gz" | inm tar -xz -C /etc/ou-lab/tls
  inm rm -f /etc/systemd/network/80-host0.network
  inm cp /etc/ou-lab/tls/ca.crt /usr/local/share/ca-certificates/ou-lab-ca.crt
  sudo systemd-run -M "$n" --pipe --wait bash -c 'apt-get update -qq && apt-get install -y -qq ca-certificates >/dev/null && update-ca-certificates >/dev/null && chmod 0755 /etc/ou-lab /etc/ou-lab/tls && echo trust-ok'
}
mk ou-chat1 "$IP_CHAT" 1536M chat
mk ou-meet1 "$IP_MEET" 2G meet
