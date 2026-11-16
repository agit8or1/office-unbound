#!/bin/bash
# Office Unbound groupware node: outgoing SMTP for Gromox + client mail submission (587 STARTTLS, 465 TLS) with SASL against Gromox/LDAP.
# Runs INSIDE the groupware node (ou-gw1 or any new one) as root; idempotent; called by lab-configure.sh and by the node upgrade
# (blueprints/lab/upgrade/gw-pkg-inner.sh) so an existing node picks the same configuration up. Lab results: docs/status/gw-client-fixes-results.md.
#
#  1. Gromox hands EWS/MAPI/zcore/delivery-rule mail to the local MTA through `outgoing_smtp_url` in /etc/gromox/gromox.cfg. It must be an explicit IPv4
#     loopback URL: the upstream default (sendmail://localhost) does not exist in our mail library build ("No factory available", E-3117) and a host
#     NAME such as `localhost` can resolve to ::1 while Postfix listens on IPv4 only (inet_protocols=ipv4).
#  2. Port 587 (submission, STARTTLS mandatory, SASL) and 465 (smtps) for mail clients. The portal's autoconfig/mobileconfig advertise exactly these.
#     SASL: Postfix -> Cyrus SASL -> saslauthd (PAM `smtp` service) -> pam_gromox -> Gromox authmgr (SQL password or LDAP bind), so a directory
#     user logs in with the same password as IMAP. Port 25 is NOT changed (relay only for mynetworks, no AUTH).
#  3. Authenticated senders may only use their own address or an alias (reject_sender_login_mismatch against the Gromox users/aliases tables).
#     Sending as a shared mailbox over SMTP is deliberately not offered (use EWS/MAPI send-as, see the results document).
#
# Env: GW_TLS_CERT / GW_TLS_KEY (default: the lab files), GW_DB_CRED_FILE (default /etc/postfix/mysql-vmbox.cf, source of the DB credentials).
set -eu
CERT=${GW_TLS_CERT:-/etc/ou-lab-tls/server-chain.pem}
KEY=${GW_TLS_KEY:-/etc/ou-lab-tls/server.key}
VMBOX=${GW_DB_CRED_FILE:-/etc/postfix/mysql-vmbox.cf}
export DEBIAN_FRONTEND=noninteractive
changed_gromox=0

## ---- 1. Gromox outgoing SMTP -------------------------------------------------------------------------------------------------------------------
GCFG=/etc/gromox/gromox.cfg
if grep -q '^outgoing_smtp_url=' "$GCFG"; then
  grep -q '^outgoing_smtp_url=smtp://127.0.0.1:25$' "$GCFG" || { sed -i 's|^outgoing_smtp_url=.*|outgoing_smtp_url=smtp://127.0.0.1:25|' "$GCFG"; changed_gromox=1; }
else
  printf 'outgoing_smtp_url=smtp://127.0.0.1:25\n' >> "$GCFG"; changed_gromox=1
fi

## ---- 2. submission -------------------------------------------------------------------------------------------------------------------------------
apt-get install -y -q --no-install-recommends sasl2-bin libsasl2-modules >/dev/null
[ -r "$VMBOX" ] || { echo "gw-mta: $VMBOX missing (run lab-configure.sh first)"; exit 1; }
# PAM service used by saslauthd (service name = smtp)
cat > /etc/pam.d/smtp <<'EOF'
#%PAM-1.0
auth    required pam_gromox.so
account required pam_permit.so
EOF
# saslauthd inside Postfix's chroot-visible directory (Debian layout); postfix must be in group sasl to reach the socket
install -d -o root -g sasl -m 0710 /var/spool/postfix/var/run/saslauthd
cat > /etc/default/saslauthd <<'EOF'
# managed by Office Unbound gw-mta.sh
START=yes
DESC="SASL Authentication Daemon"
NAME="saslauthd"
MECHANISMS="pam"
MECH_OPTIONS=""
THREADS=5
OPTIONS="-r -c -m /var/spool/postfix/var/run/saslauthd"   # -r: pass user@realm to PAM unsplit (pam_gromox needs the full address)
EOF
usermod -aG sasl postfix
install -d -m 0755 /etc/postfix/sasl
cat > /etc/postfix/sasl/smtpd.conf <<'EOF'
pwcheck_method: saslauthd
saslauthd_path: /var/spool/postfix/var/run/saslauthd/mux
mech_list: PLAIN LOGIN
EOF
# sender -> login maps (own address + aliases), same DB account the virtual-mailbox map uses
DBU=$(sed -n 's/^user=//p' "$VMBOX"); DBP=$(sed -n 's/^password=//p' "$VMBOX"); DBN=$(sed -n 's/^dbname=//p' "$VMBOX")
umask 027
cat > /etc/postfix/mysql-sender-login.cf <<EOF
user=$DBU
password=$DBP
dbname=$DBN
hosts=127.0.0.1
query=SELECT username FROM users WHERE username='%s' AND address_status IN (0,4) UNION SELECT mainname FROM aliases WHERE aliasname='%s'
EOF
chgrp postfix /etc/postfix/mysql-sender-login.cf; chmod 0640 /etc/postfix/mysql-sender-login.cf
umask 022

postconf -e "smtpd_sasl_type=cyrus" "smtpd_sasl_path=smtpd" "cyrus_sasl_config_path=/etc/postfix/sasl" \
  "smtpd_sasl_security_options=noanonymous" "smtpd_sasl_local_domain=" "broken_sasl_auth_clients=yes" \
  "smtpd_tls_cert_file=$CERT" "smtpd_tls_key_file=$KEY" \
  "smtpd_tls_protocols=!SSLv2,!SSLv3,!TLSv1,!TLSv1.1" "smtpd_tls_mandatory_protocols=!SSLv2,!SSLv3,!TLSv1,!TLSv1.1"
# global smtpd_sasl_auth_enable stays "no": AUTH is offered only by the two client-facing services below, never on :25
SUBOPT="-o syslog_name=postfix/submission -o smtpd_tls_security_level=encrypt -o smtpd_tls_auth_only=yes -o smtpd_sasl_auth_enable=yes
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
  -o smtpd_sender_login_maps=mysql:/etc/postfix/mysql-sender-login.cf -o smtpd_sender_restrictions=reject_sender_login_mismatch,reject_unlisted_sender
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject -o milter_macro_daemon_name=ORIGINATING"
set_svc() { # name type extra-options
  local n=$1 t=$2 x=$3 line
  line="$n $t n - n - - smtpd $(echo "$SUBOPT" | tr '\n' ' ') $x"
  postconf -M "$n/$t=$line"
}
set_svc submission inet ""
set_svc smtps inet "-o syslog_name=postfix/smtps -o smtpd_tls_wrappermode=yes"
systemctl enable --now saslauthd >/dev/null 2>&1 || true
systemctl restart saslauthd
postfix check
systemctl reload postfix 2>/dev/null || systemctl restart postfix

if [ "$changed_gromox" = 1 ]; then
  # only services that exist and run; they read outgoing_smtp_url at start
  for u in gromox-http gromox-zcore gromox-delivery; do systemctl is-active --quiet $u && systemctl restart $u || true; done
fi
echo "gw-mta: outgoing_smtp_url=$(sed -n 's/^outgoing_smtp_url=//p' "$GCFG"); submission 587 (STARTTLS) + 465 (TLS) with SASL"
