#!/usr/bin/env bash
# Run on the ICS host. Gives ou-pbx2 its OWN network identity so it can run next to other PBX lab machines (another agent's clone of ou-pbx1 took
# 192.168.186.247 / pbx.ou-lab.internal while ou-pbx2 was being tested: two machines with one address broke both runs):
#   ou-pbx2 = 192.168.186.248, names pbx2.ou-lab.internal / phone2.ou-lab.internal, own server certificate (signed by the lab CA key READ from
#   ou-id1's filesystem, as in the spike), own Keycloak client `ou-phone2` (confidential, code + PKCE). Host /etc/hosts gets one line.
# Idempotent. Secrets are never printed.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; . "$HERE/../lab/common/lab.env"
n=ou-pbx2; IP=192.168.186.248; PB=pbx2.$LAB_DOMAIN; PH=phone2.$LAB_DOMAIN
inm() { sudo systemd-run -M "$n" --pipe --wait --quiet "$@"; }
inm mkdir -p /root/stage/secrets
grep -q "$PB" /etc/hosts || echo "$IP $PB $PH" | sudo tee -a /etc/hosts >/dev/null
# --- address + names inside the machine
printf '[Match]\nName=host0\n[Network]\nAddress=%s/24\nGateway=192.168.186.1\nDNS=192.168.22.1\n' "$IP" | inm tee /etc/systemd/network/05-static.network >/dev/null
inm bash -c "sed -i '/pbx.ou-lab.internal/d; /pbx2.ou-lab.internal/d' /etc/hosts; echo '$IP $PB $PH' >> /etc/hosts; echo '127.0.1.1 ou-lab' >> /etc/hosts"
inm systemctl restart systemd-networkd
# --- server certificate for the new names (name-constrained lab CA: DNS ou-lab.internal + IP 192.168.186.0/24)
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
CA=/var/lib/machines/ou-id1/root/ou-lab-ca
sudo cat "$CA/ca.key" > "$T/ca.key"; sudo cat "$CA/ca.crt" > "$T/ca.crt"; chmod 600 "$T/ca.key"
cat > "$T/pbx.cnf" <<CNF
[req]
distinguished_name=dn
req_extensions=v3
prompt=no
[dn]
O=Office Unbound LAB ONLY
CN=$PB
[v3]
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=@san
[san]
DNS.1=$PB
DNS.2=$PH
IP.1=$IP
CNF
openssl genrsa -out "$T/pbx.key" 2048 2>/dev/null
openssl req -new -key "$T/pbx.key" -config "$T/pbx.cnf" -out "$T/pbx.csr"
openssl x509 -req -in "$T/pbx.csr" -CA "$T/ca.crt" -CAkey "$T/ca.key" -set_serial 0x$(openssl rand -hex 8) -days 397 -sha256 -extfile "$T/pbx.cnf" -extensions v3 -out "$T/pbx.crt" 2>/dev/null
inm tee /etc/ou-lab/tls/pbx.crt < "$T/pbx.crt" >/dev/null
inm bash -c 'umask 077; cat > /etc/ou-lab/tls/pbx.key' < "$T/pbx.key"
# --- Keycloak client ou-phone2 (admin password read from ou-id1, held in a 0600 temp file only)
sudo systemd-run -M ou-id1 --quiet --pipe --wait cat /root/ou-lab-secrets/keycloak-admin-password > "$T/kcpw"; chmod 600 "$T/kcpw"
sudo systemd-run -M ou-id1 --quiet --pipe --wait cat /etc/ou-lab/tls/ca.crt > "$T/kc-ca.crt"
mkdir -p "$T/sec"
KC_URL=https://auth.$LAB_DOMAIN KC_CA="$T/kc-ca.crt" KC_ADMIN_PASSWORD_FILE="$T/kcpw" SECRET_DIR="$T/sec" CLIENT_ID=ou-phone2 PHONE_HOST=$PH \
  python3 "$HERE/kc-phone-client.py"
cat "$T/sec/kc-ou-phone2-client-secret" | inm bash -c 'umask 077; cat > /root/stage/secrets/phone-client-secret'
echo "ou-pbx2 identity: $IP $PB $PH, client ou-phone2"
