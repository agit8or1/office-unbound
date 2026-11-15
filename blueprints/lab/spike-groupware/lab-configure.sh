#!/bin/bash
# Office Unbound groupware lab: configure Gromox (built by build-from-source.sh) on the lab machine.
# Runs INSIDE ou-gw1 as root. No admin-api: domain/users are created with SQL + gromox-mkprivate/mkpublic.
# Idempotent-ish: re-running skips things that exist. Secrets go to /root/lab-creds.env (0600), never stdout.
set -eu
HOSTN=gw1.ou-lab.internal
DOM=$HOSTN                      # mail domain == lab hostname (test domain, no public DNS)
USERS="alice bob carol dave erin frank grace"
SHARED="support"
CREDS=/root/lab-creds.env
export DEBIAN_FRONTEND=noninteractive

hostnamectl set-hostname $HOSTN 2>/dev/null || hostname $HOSTN
grep -q "$HOSTN" /etc/hosts || echo "127.0.1.1 $HOSTN ou-lab" >> /etc/hosts
apt-get install -y -q --no-install-recommends postfix-mysql >/dev/null
systemd-sysusers /usr/lib/sysusers.d/gromox.conf 2>/dev/null || systemd-sysusers
systemd-tmpfiles --create 2>/dev/null || true
install -d -o gromox -g gromox -m 0770 /var/lib/gromox /var/lib/gromox/queue /var/lib/gromox/queue/mess /var/lib/gromox/queue/save /var/lib/gromox/queue/cache /var/log/gromox /var/tmp/gromox-fpm
install -d -o root -g gromoxcf -m 0750 /etc/gromox
[ -f $CREDS ] || ( umask 077; echo "DBPASS=$(openssl rand -hex 16)" > $CREDS
  for u in $USERS $SHARED; do echo "PW_$u=$(openssl rand -base64 12 | tr -d '/+=')" >> $CREDS; done )
. $CREDS

## --- TLS: lab-only CA + server cert (SAN: hostname + IP) ---
if [ ! -f /etc/ou-lab-tls/server.crt ]; then
  install -d -m 0755 /etc/ou-lab-tls; cd /etc/ou-lab-tls
  IP=$(ip -4 -o addr show host0 | awk '{print $4}' | cut -d/ -f1)
  openssl req -x509 -newkey rsa:3072 -nodes -days 825 -keyout ca.key -out ca.crt -subj "/CN=OU Lab CA gw1 (lab only)"
  openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=$HOSTN"
  printf "subjectAltName=DNS:$HOSTN,DNS:autodiscover.$HOSTN,IP:$IP\nextendedKeyUsage=serverAuth\n" > san.ext
  openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 825 -out server.crt -extfile san.ext
  cat server.crt ca.crt > server-chain.pem
  chmod 0644 ca.crt server.crt server-chain.pem; chmod 0640 server.key; chgrp gromoxcf server.key; chmod 0600 ca.key
  usermod -aG gromoxcf www-data || true
fi

## --- MariaDB ---
systemctl enable --now mariadb
mysql -e "CREATE DATABASE IF NOT EXISTS email CHARACTER SET utf8mb4;
 CREATE USER IF NOT EXISTS 'gromox'@'localhost' IDENTIFIED BY '$DBPASS';
 GRANT ALL ON email.* TO 'gromox'@'localhost';
 CREATE USER IF NOT EXISTS 'gromox'@'127.0.0.1' IDENTIFIED BY '$DBPASS';  -- postfix (chrooted) uses TCP
 GRANT ALL ON email.* TO 'gromox'@'127.0.0.1'; FLUSH PRIVILEGES;"
cat > /etc/gromox/mysql_adaptor.cfg <<EOF
mysql_username=gromox
mysql_password=$DBPASS
mysql_dbname=email
mysql_host=localhost
schema_upgrade=host:$HOSTN
EOF
chown root:gromoxcf /etc/gromox/mysql_adaptor.cfg; chmod 0640 /etc/gromox/mysql_adaptor.cfg
gromox-dbop -C || true

## --- gromox service configs ---
cat > /etc/gromox/gromox.cfg <<EOF
oxdisco_exonym=$HOSTN
host_id=$HOSTN
# listen binds are read from gromox.cfg (not per-daemon cfg)
http_listen=127.0.0.1:10080
http_listen_tls=
lda_listen=127.0.0.1:24
lda_listen_tls=
imap_listen=0.0.0.0:143
imap_listen_tls=0.0.0.0:993
EOF
cat > /etc/gromox/http.cfg <<EOF
http_support_tls=false
http_auth_basic=true
EOF
cat > /etc/gromox/smtp.cfg <<EOF
command_protocol=both
EOF
cat > /etc/gromox/imap.cfg <<EOF
imap_support_tls=true
imap_certificate_path=/etc/ou-lab-tls/server-chain.pem
imap_private_key_path=/etc/ou-lab-tls/server.key
EOF
chown root:gromoxcf /etc/gromox/*.cfg; chmod 0640 /etc/gromox/*.cfg

## --- domain + users (SQL path, replaces admin-api) ---
mysql email -e "INSERT IGNORE INTO orgs (id,name,description) VALUES (1,'lab','gw1 lab');
 INSERT IGNORE INTO domains (org_id,domainname,homedir,max_user,title,end_day,domain_status)
   VALUES (1,'$DOM','/var/lib/gromox/domain/$DOM',0,'gw1 lab','2099-01-01',0);"
DID=$(mysql -N email -e "SELECT id FROM domains WHERE domainname='$DOM'")
mkuser() { # local status
  local l=$1 st=$2 pw; pw=$(eval echo \$PW_$l); local h; h=$(openssl passwd -6 "$pw")
  local md=/var/lib/gromox/user/$l@$DOM
  mysql email -e "INSERT IGNORE INTO users (username,password,domain_id,group_id,maildir,privilege_bits,address_status,lang,timezone)
    VALUES ('$l@$DOM','$h',$DID,0,'$md',15,$st,'en','UTC')"
  # PR_DISPLAY_TYPE_EX (0x39050003)=0 mailuser, PR_DISPLAY_NAME (0x3001001F)  -- admin-api normally writes these
  mysql email -e "INSERT IGNORE INTO user_properties (user_id,proptag,propval_str) SELECT id,0x39050003,'0' FROM users WHERE username='$l@$DOM';
    INSERT IGNORE INTO user_properties (user_id,proptag,propval_str) SELECT id,0x3001001F,'${l^} (lab)' FROM users WHERE username='$l@$DOM'"
  install -d -o gromox -g gromox -m 0770 $md $md/exmdb $md/tmp $md/tmp/imap.rfc822 $md/config $md/cid
  [ -f $md/exmdb/exchange.sqlite3 ] || gromox-mkprivate "$l@$DOM"
  [ -f $md/exmdb/midb.sqlite3 ] || gromox-mkmidb "$l@$DOM"   # without this IMAP SELECT fails: 'Unable to read midb.sqlite'
}
install -d -o gromox -g gromox -m 0770 /var/lib/gromox/user /var/lib/gromox/domain /var/lib/gromox/domain/$DOM
for u in $USERS; do mkuser $u 0; done
mkuser $SHARED 4
# Shared mailbox ACL (admin-api normally does this via MAPI): grant alice+bob rightsAll(1531) on root(1), IPM subtree(9), inbox(13), calendar(15)
for f in 1 9 13 15; do for g in alice bob; do
  sqlite3 /var/lib/gromox/user/$SHARED@$DOM/exmdb/exchange.sqlite3 "INSERT OR REPLACE INTO permissions (folder_id,username,permission) VALUES ($f,'$g@$DOM',1531)"; done; done
[ -f /var/lib/gromox/domain/$DOM/exmdb/exchange.sqlite3 ] || { install -d -o gromox -g gromox /var/lib/gromox/domain/$DOM/exmdb; gromox-mkpublic $DOM; }
chown -R gromox:gromox /var/lib/gromox; chmod -R g+rwX /var/lib/gromox

## --- php-fpm pool for gromox (sync/dav/web later), nginx ---
install -d -o gromox -g gromox /var/log/gromox /run/php-fpm
sed 's|/run/php-fpm/php-gromox-fpm.sock|/run/php-fpm/php-gromox-fpm.sock|' /usr/share/gromox/fpm-gromox.conf.sample > /etc/php/8.2/fpm/pool.d/gromox.conf
# php-mapi for CLI is wired by gromox make install (/etc/php/8.2/cli/conf.d/mapi.ini); FPM is wired in lab-apps.sh

## --- postfix: virtual domain -> gromox LMTP on 127.0.0.1:24, no outbound relay ---
cat > /etc/postfix/mysql-vmbox.cf <<EOF
user=gromox
password=$DBPASS
dbname=email
hosts=127.0.0.1
query=SELECT username FROM users WHERE username='%s' AND address_status IN (0,4)
EOF
chgrp postfix /etc/postfix/mysql-vmbox.cf; chmod 0640 /etc/postfix/mysql-vmbox.cf
postconf -e "myhostname=$HOSTN" "mydestination=localhost" "virtual_mailbox_domains=$DOM" \
  "virtual_mailbox_maps=mysql:/etc/postfix/mysql-vmbox.cf" "virtual_transport=lmtp:[127.0.0.1]:24" \
  "inet_interfaces=all" "inet_protocols=ipv4" "mynetworks=127.0.0.0/8 192.168.0.0/16" \
  "default_transport=error:lab: no outbound relay" "relayhost=" \
  "smtpd_tls_cert_file=/etc/ou-lab-tls/server-chain.pem" "smtpd_tls_key_file=/etc/ou-lab-tls/server.key" "smtpd_tls_security_level=may"
usermod -aG gromoxcf postfix || true
echo done-configure
