#!/usr/bin/env bash
# Run on the ICS host after 00-host-create-machine.sh and kc-phone-client.py. Pushes the staging dir into ou-pbx1 and runs 20-install-pbx.sh.
# Secrets are read here (host, root) and written root-only inside the machine; nothing is printed.
#   SECRET_DIR   dir containing kc-ou-phone-client-secret (output of kc-phone-client.py)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
n="${PBX_MACHINE:-ou-pbx1}"; : "${SECRET_DIR:?}"
inm() { sudo systemd-run -M "$n" --pipe --wait --quiet "$@"; }
inm rm -rf /root/stage; inm mkdir -p /root/stage/secrets /root/stage/phone
tar -C "$HERE" -cz pbx 20-install-pbx.sh | inm tar -xz -C /root/stage
tar -C "$HERE/phone" -cz static phone_app.py | inm tar -xz -C /root/stage/phone
sudo cat /var/lib/machines/ou-id1/root/ou-lab-secrets/ldap-bind-password | inm bash -c 'umask 077; cat > /root/stage/secrets/ldap-bind-password'
cat "$SECRET_DIR/kc-ou-phone-client-secret" | inm bash -c 'umask 077; cat > /root/stage/secrets/kc-ou-phone-client-secret'
cat /etc/office-unbound/lab/gw1-ca.crt | inm bash -c 'cat > /root/stage/secrets/gw1-ca.crt'
sudo systemd-run -M "$n" --pipe --wait bash /root/stage/20-install-pbx.sh
