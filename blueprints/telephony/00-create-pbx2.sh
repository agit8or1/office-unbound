#!/usr/bin/env bash
# Run on the ICS host (needs sudo). Creates ou-pbx2: Debian 12 (clone of ou-base-bookworm), MemoryMax=768M, static 192.168.186.248, names
# pbx2./phone2.ou-lab.internal (the reference ou-pbx1 keeps .247 / pbx. / phone.; another lab machine took that address while ou-pbx2 was being tested,
# so ou-pbx2 has its own identity). The server certificate and the Keycloak client come from 05-own-identity.sh; the lab CA is copied from ou-pbx1's
# filesystem (ou-id1 untouched).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/../lab/common/lab.env"
M=/var/lib/machines; n=ou-pbx2; mem=768M
sudo test -d "$M/$n" || sudo machinectl clone ou-base-bookworm "$n"
printf '[Exec]\nBoot=yes\nPrivateUsers=pick\n\n[Network]\nZone=oulab\n' | sudo tee /etc/systemd/nspawn/$n.nspawn >/dev/null
sudo systemctl set-property "systemd-nspawn@$n" MemoryMax="$mem"
sudo machinectl start "$n" || true
for i in $(seq 40); do sudo systemd-run -M "$n" --pipe --wait --quiet true >/dev/null 2>&1 && break; sleep 1; done
inm() { sudo systemd-run -M "$n" --pipe --wait --quiet "$@"; }
printf '[Match]\nName=host0\n[Network]\nAddress=%s/24\nGateway=192.168.186.1\nDNS=192.168.22.1\n' "192.168.186.248" | inm tee /etc/systemd/network/05-static.network >/dev/null
inm tee /etc/hosts >/dev/null <<H
127.0.0.1	localhost
127.0.1.1 $n ou-base
192.168.186.248 pbx2.$LAB_DOMAIN phone2.$LAB_DOMAIN
$IP_KC auth.$LAB_DOMAIN ldap.$LAB_DOMAIN
192.168.186.218 gw1.$LAB_DOMAIN
H
inm rm -f /etc/systemd/network/80-host0.network
inm systemctl restart systemd-networkd
inm mkdir -p /etc/ou-lab/tls
sudo cat "$M/ou-pbx1/etc/ou-lab/tls/ca.crt" | inm tee /etc/ou-lab/tls/ca.crt >/dev/null
inm cp /etc/ou-lab/tls/ca.crt /usr/local/share/ca-certificates/ou-lab-ca.crt
sudo systemd-run -M "$n" --pipe --wait bash -c 'chmod 0755 /etc/ou-lab /etc/ou-lab/tls; apt-get update -qq && apt-get install -y -qq ca-certificates >/dev/null && update-ca-certificates >/dev/null && echo trust-ok'
echo "ou-pbx2 ready at 192.168.186.248; next: 05-own-identity.sh, 10-deploy-pbx2.sh"
