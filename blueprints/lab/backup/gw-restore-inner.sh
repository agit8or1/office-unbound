#!/usr/bin/env bash
# Runs INSIDE the new groupware machine (copied in by gw-restore.sh) after build-from-source.sh finished.
# Order: verify backup + pins -> config -> system wiring -> MariaDB -> (re)create stores -> services -> logical import -> ACLs -> verify counts.
# Never prints secrets (DB password only passes through the mariadb client's stdin).
set -euo pipefail; umask 022
log() { echo "[gw-restore-inner] $*" >&2; }
trap 'log "ERR line $LINENO: $BASH_COMMAND"' ERR
W=/root/ou-restore; rm -rf "$W"; mkdir -m 0700 "$W"; cd "$W"
tar -xf /root/ou-restore.tar; M=/root/ou-restore.MANIFEST
die() { log "FATAL: $*"; exit "${2:-1}"; }
mf() { sed -n "s/^$1=//p" "$M"; }
sha256sum -c --quiet SHA256SUMS || die "member checksum mismatch" 4
# --- pins: the rebuilt source tree must be the one the backup was taken from (executables are NOT in the backup)
for l in $(grep '^pin\.' "$M" | cut -d= -f1); do
  d="${l#pin.}"; want="$(sed -n "s/^$l=//p" "$M" | cut -d' ' -f2)"; got="$(git -C "/usr/src/ou/$d" rev-parse HEAD)"
  [ "$want" = "$got" ] || die "pin mismatch $d: backup $want, built $got" 5
done; log "all $(grep -c '^pin\.' "$M") source pins match"
[ "$(sha256sum /usr/libexec/gromox/http | cut -d' ' -f1)" = "$(mf gromox_binary_sha256)" ] && log "gromox http binary sha256 identical to original" || log "NOTE gromox http binary sha256 differs from original (build not bit-reproducible; source pins identical)"
# --- identity of the node (gromox resolves its own hostname: getaddrinfo failure otherwise; groupware-lab-results finding 3)
HN="$(mf hostname)"; hostname "$HN"; echo "$HN" > /etc/hostname
getent hosts "$HN" >/dev/null || die "hostname $HN does not resolve (own /etc/hosts missing)"
# --- system wiring that lab-configure.sh / lab-apps.sh do on a fresh node (accounts, dirs, tmpfiles); config comes from the backup
export DEBIAN_FRONTEND=noninteractive
systemd-sysusers /usr/lib/sysusers.d/gromox.conf 2>/dev/null || systemd-sysusers
systemd-tmpfiles --create 2>/dev/null || true
getent passwd grosync >/dev/null || useradd -r -d /var/lib/grosync -s /usr/sbin/nologin grosync
getent passwd grodav  >/dev/null || useradd -r -d /var/lib/grommunio-dav -s /usr/sbin/nologin grodav
getent passwd groweb  >/dev/null || useradd -r -d /var/lib/groweb -s /usr/sbin/nologin groweb
tar -xpzf config.tgz -C /      # names (not numbers) map owners: gromoxcf etc. exist now
usermod -aG gromoxcf www-data; usermod -aG gromoxcf postfix
install -d -o gromox -g gromox -m 0770 /var/lib/gromox /var/lib/gromox/user /var/lib/gromox/domain /var/lib/gromox/queue /var/lib/gromox/queue/mess /var/lib/gromox/queue/save /var/lib/gromox/queue/cache /var/log/gromox /var/tmp/gromox-fpm
install -d -o grosync -g grosync /var/lib/grosync /var/log/grommunio-sync; install -d -o grodav -g grodav /var/lib/grommunio-dav /var/log/grommunio-dav
install -d -o groweb -g groweb /var/lib/groweb /var/lib/grommunio-web /var/lib/grommunio-web/session /var/lib/grommunio-web/tmp
install -d /run/php-fpm; systemd-tmpfiles --create /etc/tmpfiles.d/php-fpm-ou.conf 2>/dev/null || true
phpenmod -s fpm mapi
install -m 0755 /root/gw-ldap-sync.py /usr/local/sbin/gw-ldap-sync.py
update-ca-certificates >/dev/null 2>&1 || true
rm -f /etc/nginx/sites-enabled/default
# --- MariaDB: db + users from the restored mysql_adaptor.cfg, then the dump
systemctl enable --now mariadb
DBPASS="$(sed -n 's/^mysql_password=//p' /etc/gromox/mysql_adaptor.cfg)"; DBU="$(sed -n 's/^mysql_username=//p' /etc/gromox/mysql_adaptor.cfg)"; DBN="$(sed -n 's/^mysql_dbname=//p' /etc/gromox/mysql_adaptor.cfg)"
[ "$(mysql -N -e "select count(*) from information_schema.schemata where schema_name='$DBN'")" = 0 ] || die "database $DBN already exists: not a fresh node" 3
mysql <<SQL
CREATE DATABASE $DBN CHARACTER SET utf8mb4;
CREATE USER '$DBU'@'localhost' IDENTIFIED BY '$DBPASS'; GRANT ALL ON $DBN.* TO '$DBU'@'localhost';
CREATE USER '$DBU'@'127.0.0.1' IDENTIFIED BY '$DBPASS'; GRANT ALL ON $DBN.* TO '$DBU'@'127.0.0.1'; FLUSH PRIVILEGES;
SQL
mysql "$DBN" < db.sql
[ "$(mysql -N "$DBN" -e 'select count(*) from users')" = "$(mf users_rows)" ] || die "users row count != manifest" 6
log "database restored ($(mf users_rows) users)"
# --- stores: recreate from the DB rows (exactly what lab-configure.sh does), public stores from the sqlite online backup
while IFS=$'\t' read -r dom dir; do
  install -d -o gromox -g gromox -m 0770 "$dir" "$dir/exmdb"
  [ -f "pub/$dom.exchange.sqlite3" ] || die "no public-store backup for $dom" 6
  [ -f "$dir/exmdb/exchange.sqlite3" ] || { gromox-mkpublic "$dom" >/dev/null; rm -f "$dir/exmdb/exchange.sqlite3"{,-wal,-shm}; install -m 0660 -o gromox -g gromox "pub/$dom.exchange.sqlite3" "$dir/exmdb/exchange.sqlite3"; }
done < <(mysql -N "$DBN" -e 'select domainname,homedir from domains')
while IFS=$'\t' read -r user md; do
  install -d -o gromox -g gromox -m 0770 "$md" "$md/exmdb" "$md/tmp" "$md/tmp/imap.rfc822" "$md/config" "$md/cid"
  [ -f "$md/exmdb/exchange.sqlite3" ] || gromox-mkprivate "$user" >/dev/null
  [ -f "$md/exmdb/midb.sqlite3" ] || gromox-mkmidb "$user" >/dev/null
done < <(mysql -N "$DBN" -e 'select username,maildir from users')
chown -R gromox:gromox /var/lib/gromox; chmod -R g+rwX /var/lib/gromox
# --- services (the gromox units were installed by make install; the enable set is the one running on the original)
systemctl daemon-reload
systemctl enable --now redis-server php8.2-fpm
systemctl enable --now gromox-event gromox-http gromox-zcore gromox-midb gromox-imap gromox-delivery gromox-delivery-queue gromox-timer
for i in $(seq 1 30); do ss -ltn | grep -q ':10080 ' && ss -ltn | grep -q ':993 ' && break; sleep 1; done
# --- logical import (GW07 recipe: -x, IPM_SUBTREE export) + ACL rows (exm2mt does not carry ACLs)
fail=0
for f in mbx/*.mt; do
  u="$(basename "$f" .mt)"
  gromox-import -u "$u" -x -c < "$f" > "mbx/$u.import.log" 2>&1 || { log "IMPORT FAILED $u: $(tail -2 "mbx/$u.import.log")"; fail=1; continue; }
  dir="$(mysql -N "$DBN" -e "select maildir from users where username='$u'")"
  [ -s "mbx/$u.perm.sql" ] && sqlite3 "$dir/exmdb/exchange.sqlite3" < "mbx/$u.perm.sql"
done
[ "$fail" = 0 ] || die "some imports failed" 7
# stores were written behind the daemons' back (ACL rows): restart the gromox frontends so no cached ACLs/midb state survives
systemctl restart gromox-http gromox-zcore gromox-midb gromox-imap
for i in $(seq 1 30); do ss -ltn | grep -q ':10080 ' && ss -ltn | grep -q ':993 ' && break; sleep 1; done
while IFS=$'\t' read -r u; do gromox-mbop -u "$u" sync-midb -f all >/dev/null 2>&1 || true; done < <(grep -h '^mbx|' "$M" | cut -d'|' -f2)
# lifecycle quarantine (store dir mode) is filesystem-only state: re-apply it
grep '^dirmode|' "$M" | while IFS='|' read -r _ u mode; do chmod "$mode" "$(mysql -N "$DBN" -e "select maildir from users where username='$u'")"; done
# --- postfix / nginx last: only now does the node accept connections for the mail names it resolves to itself
postfix check; systemctl enable --now postfix; systemctl restart postfix
nginx -t; systemctl enable --now nginx; systemctl restart nginx
# --- verify every mailbox against the manifest (SQL on the restored store, same query as the backup)
cnt() { sqlite3 -readonly "$1/exmdb/exchange.sqlite3" "WITH RECURSIVE t(f) AS (SELECT 9 UNION ALL SELECT folder_id FROM folders JOIN t ON parent_id=t.f WHERE is_search=0)
    SELECT (SELECT count(*) FROM messages WHERE parent_fid IN (SELECT f FROM t) AND is_associated=0 AND is_deleted=0 AND parent_attid IS NULL),
           (SELECT count(*) FROM messages WHERE parent_fid=13 AND is_associated=0 AND is_deleted=0 AND parent_attid IS NULL),
           (SELECT count(*) FROM messages WHERE parent_fid=15 AND is_associated=0 AND is_deleted=0 AND parent_attid IS NULL)" | tr '|' ' '; }
bad=0; n=0; msgs=0
while IFS='|' read -r _ u st total inbox cal _rest; do
  dir="$(mysql -N "$DBN" -e "select maildir from users where username='$u'")"
  got="$(cnt "$dir")"
  if [ "$got" = "$total $inbox $cal" ]; then n=$((n+1)); msgs=$((msgs+total)); else log "COUNT MISMATCH $u: restored '$got' manifest '$total $inbox $cal'"; bad=1; fi
done < <(grep '^mbx|' "$M")
[ "$bad" = 0 ] || die "restored mailbox counts differ from manifest" 8
log "VERIFIED: $n mailboxes, $msgs messages (IPM_SUBTREE), counts total/inbox/calendar identical to manifest"
date -u +%FT%TZ > /root/ou-restore.done; rm -rf "$W" /root/ou-restore.MANIFEST /root/gw-ldap-sync.py
for s in mariadb nginx postfix php8.2-fpm redis-server gromox-http gromox-zcore gromox-imap gromox-midb gromox-delivery gromox-delivery-queue gromox-event gromox-timer; do printf '%s=%s ' "$s" "$(systemctl is-active $s)"; done; echo
