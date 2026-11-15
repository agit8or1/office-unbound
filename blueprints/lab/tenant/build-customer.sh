#!/usr/bin/env bash
# Build ONE independent customer stack (identity tier + files tier) in nspawn machines, using the unchanged
# documented installers (spike-identity-files/{kc,files}) with a per-customer lab.env. Run on the lab host as a sudoer.
#   build-customer.sh a|b            (customer a: 192.168.186.61/.62, custa.ou-lab.internal; b: .71/.72, custb...)
# Every customer gets: own lab CA (generated on its id machine, never shared), own OpenLDAP, own Postgres, own Keycloak
# realm (custa / custb), own OpenCloud, own generated secrets (/root/ou-lab-secrets inside each machine).
# Nothing is copied between customers. Not for production: production = separate VM/VLAN per customer (ADR-0006).
set -euo pipefail
S="${1:?a|b}"
case "$S" in a) IPID=192.168.186.61; IPF=192.168.186.62;; b) IPID=192.168.186.71; IPF=192.168.186.72;; *) echo "a|b" >&2; exit 2;; esac
HERE="$(cd "$(dirname "$0")" && pwd)"; LABROOT="$(cd "$HERE/.." && pwd)"
ID="ou-c${S}-id"; FILES="ou-c${S}-files"; DOM="cust${S}.ou-lab.internal"; REALM="cust${S}"
free_mb=$(awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo)
[ "$free_mb" -ge 2048 ] || { echo "ABORT: only ${free_mb} MiB available (<2 GiB)" >&2; exit 1; }
mk() { # name ip mem
  local m="$1" ip="$2" mem="$3"
  if ! sudo test -d "/var/lib/machines/$m"; then
    sudo machinectl clone ou-base-noble "$m"
    printf '[Exec]\nBoot=yes\nPrivateUsers=pick\n\n[Network]\nZone=oulab\n' | sudo tee "/etc/systemd/nspawn/$m.nspawn" >/dev/null
    sudo rm -f "/var/lib/machines/$m/etc/systemd/network/80-host0.network"
    printf '[Match]\nName=host0\n[Network]\nAddress=%s/24\nGateway=192.168.186.1\nDNS=192.168.22.1\n' "$ip" | sudo tee "/var/lib/machines/$m/etc/systemd/network/05-static.network" >/dev/null
    echo "$m" | sudo tee "/var/lib/machines/$m/etc/hostname" >/dev/null
    sudo systemctl set-property "systemd-nspawn@$m" MemoryMax="$mem"
  fi
  sudo machinectl start "$m" 2>/dev/null || true
}
inm() { local m="$1"; shift; sudo systemd-run -M "$m" --quiet --pipe --wait "$@"; }
mk "$ID" "$IPID" 2G; mk "$FILES" "$IPF" 1536M
for i in $(seq 1 30); do inm "$ID" /bin/true 2>/dev/null && inm "$FILES" /bin/true 2>/dev/null && break; sleep 2; done
# per-customer lab.env: same variable names, own domain / realm / base DN / addresses
ENVF="$(mktemp)"
sed -e "s/^LAB_DOMAIN=.*/LAB_DOMAIN=\"${DOM}\"/" -e "s/^REALM=.*/REALM=\"${REALM}\"/" \
    -e "s/^IP_KC=.*/IP_KC=\"${IPID}\"/" -e "s/^IP_FILES=.*/IP_FILES=\"${IPF}\"/" -e "s/^IP_OFFICE=.*/IP_OFFICE=\"${IPF}\"/" \
    -e 's/^LDAP_BASE_DN=.*/LDAP_BASE_DN="dc='"${REALM}"',dc=ou-lab,dc=internal"/' \
    -e '/^IP_\(PORTAL\|CHAT\|MEET\|PBX\)=/d' -e '/^IP_MAIL=/d' "$LABROOT/common/lab.env" > "$ENVF"
echo 'IP_MAIL="'"${IPF}"'"' >> "$ENVF"
for m in "$ID" "$FILES"; do
  tar -C "$LABROOT/.." -cf - lab | inm "$m" /bin/bash -c 'rm -rf /root/lab; tar -C /root -xf -'
  cat "$ENVF" | inm "$m" /bin/bash -c 'cat > /root/lab/common/lab.env'
done
rm -f "$ENVF"
echo "== identity tier on $ID"
[ "${OU_RESUME_FILES:-0}" = 1 ] || inm "$ID" /bin/bash -c 'bash /root/lab/spike-identity-files/kc/install-kc.sh && bash /root/lab/spike-identity-files/kc/install-openldap.sh test-users'
echo "== moving files-role bundle + LDAP bind secret $ID -> $FILES (pipe, nothing on host disk)"
inm "$ID" /bin/cat /root/ou-lab-ca/out/files.tar.gz | inm "$FILES" /bin/bash -c 'umask 077; cat > /root/ou-lab-bundle.tar.gz'
inm "$ID" /bin/cat /root/ou-lab-secrets/ldap-bind-password | inm "$FILES" /bin/bash -c 'umask 077; install -d -m 0700 /root/ou-lab-secrets; cat > /root/ou-lab-secrets/ldap-bind-password'
echo "== files tier on $FILES"
inm "$FILES" /bin/bash -c 'OU_SKIP_COLLAB=1 bash /root/lab/spike-identity-files/files/install-files.sh'
echo "customer ${S} built: auth.${DOM} ${IPID}, cloud.${DOM} ${IPF}"
echo "== ICS service identities on $ID (svc-ics LDAP account + Keycloak client ou-ics), per customer"
inm "$ID" /bin/bash -c "bash /root/lab/spike-identity-files/kc/ldap-ics-bind.sh && KC_URL=https://auth.${DOM} KC_CA=/etc/ou-lab/tls/ca.crt KC_REALM=${REALM} KC_ADMIN_USER=kcadmin KC_ADMIN_PASSWORD=\$(cat /root/ou-lab-secrets/keycloak-admin-password) OUT_SECRET_FILE=/root/ou-lab-secrets/kc-ics-client-secret python3 /root/lab/spike-identity-files/kc/kc-ics-client.py"
