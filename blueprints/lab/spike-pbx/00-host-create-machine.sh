#!/usr/bin/env bash
# Run on the ICS host (needs sudo). Creates ou-pbx1 (Asterisk + web softphone) as a clone of ou-base-noble (Ubuntu 24.04 (asterisk is NOT in Debian 12/13 archives, only sid)),
# static IP, MemoryMax=768M, lab CA trust + a server cert for pbx./phone.ou-lab.internal.
# The cert is signed HERE with the lab CA key READ from ou-id1's filesystem (ou-id1 itself is not modified).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/../common/lab.env"
M=/var/lib/machines; n=ou-pbx1; mem=768M
CA="$M/ou-id1/root/ou-lab-ca"
free -g | sed -n 2p
sudo test -d "$M/$n" || sudo machinectl clone ou-base-noble "$n"
printf '[Exec]\nBoot=yes\nPrivateUsers=pick\n\n[Network]\nZone=oulab\n' | sudo tee /etc/systemd/nspawn/$n.nspawn >/dev/null
sudo systemctl set-property "systemd-nspawn@$n" MemoryMax="$mem"
sudo machinectl start "$n" || true
for i in $(seq 40); do sudo systemd-run -M "$n" --pipe --wait --quiet true >/dev/null 2>&1 && break; sleep 1; done
inm() { sudo systemd-run -M "$n" --pipe --wait --quiet "$@"; }
printf '[Match]\nName=host0\n[Network]\nAddress=%s/24\nGateway=192.168.186.1\nDNS=192.168.22.1\n' "$IP_PBX" | inm tee /etc/systemd/network/05-static.network >/dev/null
inm tee /etc/hosts >/dev/null <<H
127.0.0.1	localhost
127.0.1.1 $n ou-base
$IP_PBX $HOST_PBX $HOST_PHONE
$IP_KC auth.$LAB_DOMAIN ldap.$LAB_DOMAIN
192.168.186.218 gw1.$LAB_DOMAIN
H
inm rm -f /etc/systemd/network/80-host0.network
inm systemctl restart systemd-networkd
# --- server cert (name-constrained CA: DNS ou-lab.internal + IP 192.168.186.0/24)
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
sudo cat "$CA/ca.key" > "$T/ca.key"; sudo cat "$CA/ca.crt" > "$T/ca.crt"; chmod 600 "$T/ca.key"
cat > "$T/pbx.cnf" <<CNF
[req]
distinguished_name=dn
req_extensions=v3
prompt=no
[dn]
O=Office Unbound LAB ONLY
CN=$HOST_PBX
[v3]
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=@san
[san]
DNS.1=$HOST_PBX
DNS.2=$HOST_PHONE
IP.1=$IP_PBX
CNF
openssl genrsa -out "$T/pbx.key" 2048 2>/dev/null
openssl req -new -key "$T/pbx.key" -config "$T/pbx.cnf" -out "$T/pbx.csr"
openssl x509 -req -in "$T/pbx.csr" -CA "$T/ca.crt" -CAkey "$T/ca.key" -set_serial 0x$(openssl rand -hex 8) -days 397 -sha256 \
  -extfile "$T/pbx.cnf" -extensions v3 -out "$T/pbx.crt" 2>/dev/null
inm mkdir -p /etc/ou-lab/tls
inm tee /etc/ou-lab/tls/ca.crt < "$T/ca.crt" >/dev/null
inm tee /etc/ou-lab/tls/pbx.crt < "$T/pbx.crt" >/dev/null
inm bash -c 'umask 077; cat > /etc/ou-lab/tls/pbx.key' < "$T/pbx.key"
inm cp /etc/ou-lab/tls/ca.crt /usr/local/share/ca-certificates/ou-lab-ca.crt
sudo systemd-run -M "$n" --pipe --wait bash -c 'chmod 0755 /etc/ou-lab /etc/ou-lab/tls; apt-get update -qq && apt-get install -y -qq ca-certificates >/dev/null && update-ca-certificates >/dev/null && echo trust-ok'
echo "ou-pbx1 ready at $IP_PBX; host /etc/hosts needs: $IP_PBX $HOST_PBX $HOST_PHONE"
