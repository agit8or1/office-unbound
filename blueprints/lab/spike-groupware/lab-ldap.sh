#!/bin/bash
# Office Unbound: switch Gromox user auth/identity to the authoritative OpenLDAP (ou-id1). Run from the ICS host (needs sudo + systemd-run -M).
# Steps actually executed in the lab (2026-11-15). Idempotent. Never prints secrets.
#   1. ou-id1: kc/ldap-gromox-bind.sh  (read-only svc-gromox + ACL)
#   2. ou-gw1: lab CA of the directory, ldap.conf (TLS_REQCERT demand), ldap_adaptor.cfg (0640 root:gromoxcf), apt python3-ldap3/pymysql/ldap-utils
#   3. ou-gw1: gw-ldap-sync.py -> /usr/local/sbin; postfix accepts the directory mail domain; reload gromox (restart ONLY if gromox-imap is active)
set -eu
ID=${ID_MACHINE:-ou-id1}; LD=${LAB_DOMAIN:-ou-lab.internal}; BDN="dc=${LD//./,dc=}"; IDIP=${ID_IP:-192.168.186.241}; GW=${GW_MACHINE:-ou-gw1}; GWH=${GW_HOST:-gw1.ou-lab.internal}; HERE="$(cd "$(dirname "$0")" && pwd)"; KC="$HERE/../spike-identity-files/kc"
IDX() { sudo systemd-run -M $ID --quiet --pipe --wait /bin/bash -c "$1"; }
GWX() { sudo systemd-run -M $GW --quiet --pipe --wait /bin/bash -c "$1"; }
sudo cp "$KC/ldap-gromox-bind.sh" /var/lib/machines/$ID/root/lab/spike-identity-files/kc/; IDX /root/lab/spike-identity-files/kc/ldap-gromox-bind.sh
sudo cat /var/lib/machines/$ID/etc/ou-lab/tls/ca.crt | GWX 'install -d /etc/ou-lab-ldap; cat > /etc/ou-lab-ldap/ca.crt'
sudo cat /var/lib/machines/$ID/root/ou-lab-secrets/ldap-gromox-password | GWX '(umask 077; cat > /etc/ou-lab-ldap/svc-gromox.pw); chown root:gromoxcf /etc/ou-lab-ldap/svc-gromox.pw; chmod 0640 /etc/ou-lab-ldap/svc-gromox.pw'
GWX 'LD='$LD' IDIP='$IDIP' BDN='"$BDN"'
grep -q ldap.$LD /etc/hosts || echo "$IDIP ldap.$LD" >> /etc/hosts
DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends ldap-utils python3-ldap3 python3-pymysql >/dev/null
install -d /etc/ldap; printf "TLS_CACERT /etc/ou-lab-ldap/ca.crt\nTLS_REQCERT demand\n" > /etc/ldap/ldap.conf
PW=$(cat /etc/ou-lab-ldap/svc-gromox.pw)
( umask 027; cat > /etc/gromox/ldap_adaptor.cfg <<CFG
ldap_host=ldaps://ldap.$LD
ldap_start_tls=false
ldap_bind_user=cn=svc-gromox,ou=system,$BDN
ldap_bind_pass=$PW
ldap_search_base=ou=people,$BDN
ldap_mail_attr=mail
ldap_object_id=entryUUID
ldap_user_filter=(&(objectClass=inetOrgPerson)(mail=*))
ldap_user_displayname=displayName
ou_entitlement_group=cn=mail-users,ou=groups,$BDN
CFG
); chown root:gromoxcf /etc/gromox/ldap_adaptor.cfg
postconf -e "virtual_mailbox_domains='"$GWH"', $LD" && postfix reload'
GWX 'cat > /usr/local/sbin/gw-ldap-sync.py; chmod 755 /usr/local/sbin/gw-ldap-sync.py' < "$HERE/gw-ldap-sync.py"
# gromox reads ldap_adaptor.cfg at start: coordinate with other operators (gromox-imap must be active)
[ "$(sudo systemctl -M $GW is-active gromox-imap)" = active ] || { echo "gromox-imap inactive: restart gromox-http/zcore/imap later"; exit 0; }
GWX 'systemctl restart gromox-http gromox-zcore gromox-imap'
GWX '/usr/local/sbin/gw-ldap-sync.py --create-domain'
