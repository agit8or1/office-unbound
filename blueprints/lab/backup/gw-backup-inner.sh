#!/usr/bin/env bash
# Runs INSIDE the groupware machine (piped in by gw-backup.sh on stdin) and writes ONE tar stream to stdout (logs -> stderr).
# ONLINE and READ-ONLY with respect to the machine's persistent state: no service stop/restart/reload, no config edit, nothing
# written outside a transient tmpfs scratch dir (/run/ou-gwbk.*, removed on exit). Safe to run against a live, monitored node.
#   * MariaDB: mysqldump --single-transaction (InnoDB-consistent snapshot) of the gromox database
#   * config files the stack needs (gromox, nginx, php-fpm pools, postfix, lab TLS WITHOUT the CA key, ldap_adaptor + bind secret, app configs)
#   * per-mailbox logical export: gromox-exm2mt -u USER -ars IPM_SUBTREE (the form proven in GW07) + ACL rows of the store (not exported by exm2mt)
#   * public stores: sqlite3 .backup (online backup API) because exm2mt cannot export a public store
#   * manifest lines: pinned source SHAs, package versions, per mailbox message counts (SQL on the store, before AND after the export)
set -euo pipefail; umask 077
W="$(mktemp -d /run/ou-gwbk.XXXXXX)"; trap 'rm -rf "$W"' EXIT
cd "$W"; mkdir mbx pub
log() { echo "[gw-backup-inner] $*" >&2; }
DBN=email
# --- 1. database
mysqldump --single-transaction --skip-extended-insert --routines --triggers --events --default-character-set=utf8mb4 "$DBN" > db.sql
log "db dump $(wc -c < db.sql) bytes"
# --- 2. config
CFG=(etc/gromox etc/ou-lab-tls etc/ou-lab-ldap etc/ldap/ldap.conf etc/nginx/nginx.conf etc/nginx/conf.d etc/nginx/ou-locations
     etc/php/8.2/fpm/pool.d etc/php/8.2/mods-available/mapi.ini etc/mailname etc/postfix/main.cf etc/postfix/master.cf etc/postfix/mysql-vmbox.cf
     etc/tmpfiles.d/php-fpm-ou.conf usr/share/grommunio-sync/config.php usr/share/grommunio-dav/config.php usr/share/grommunio-web/config.php)
EX=(); for f in "${CFG[@]}"; do [ -e "/$f" ] && EX+=("$f") || log "WARN config path absent: /$f"; done
# the lab CA PRIVATE key (and serial/csr) are deliberately not backed up
# owner NAMES are stored (no --numeric-owner): uids/gids of postfix, gromoxcf, ... differ between nodes (restore finding)
tar -cpzf config.tgz -C / --exclude=etc/ou-lab-tls/ca.key --exclude=etc/ou-lab-tls/ca.srl --exclude=etc/ou-lab-tls/server.csr "${EX[@]}"
# --- 3. mailboxes
cnt() { # store-dir -> "total inbox calendar" (non-FAI, non-deleted messages below IPM_SUBTREE(9); inbox=13, calendar=15)
  sqlite3 -readonly "$1/exmdb/exchange.sqlite3" "WITH RECURSIVE t(f) AS (SELECT 9 UNION ALL SELECT folder_id FROM folders JOIN t ON parent_id=t.f WHERE is_search=0)
    SELECT (SELECT count(*) FROM messages WHERE parent_fid IN (SELECT f FROM t) AND is_associated=0 AND is_deleted=0 AND parent_attid IS NULL),
           (SELECT count(*) FROM messages WHERE parent_fid=13 AND is_associated=0 AND is_deleted=0 AND parent_attid IS NULL),
           (SELECT count(*) FROM messages WHERE parent_fid=15 AND is_associated=0 AND is_deleted=0 AND parent_attid IS NULL)" | tr '|' ' '
}
{
  echo "created_utc=$(date -u +%Y%m%dT%H%M%SZ)"
  echo "hostname=$(hostname)"
  echo "os=$(. /etc/os-release; echo "$PRETTY_NAME")"
  for d in libhx wmime gromox mapi-header-php grommunio-sync grommunio-dav grommunio-web; do
    p=/usr/src/ou/$d; [ -d "$p/.git" ] && echo "pin.$d=$(git -C "$p" describe --tags --exact-match 2>/dev/null || echo ?) $(git -C "$p" rev-parse HEAD)"
  done
  for p in mariadb-server nginx php8.2-fpm postfix redis-server; do echo "pkg.$p=$(dpkg-query -W -f='${Version}' $p 2>/dev/null)"; done
  echo "gromox_binary_sha256=$(sha256sum /usr/libexec/gromox/http | cut -d' ' -f1)"
  echo "domains=$(mysql -N "$DBN" -e 'select group_concat(domainname) from domains')"
  echo "users_rows=$(grep -c '^INSERT INTO `users` VALUES' db.sql)"   # rows IN THE DUMP (live users may change while we run)
} > manifest.part
n=0; skipped=0; INCOMPLETE=0
while IFS=$'\t' read -r user dir status; do
  # only users that are in the dump: a row created after the dump would have no DB row on the restore side
  if ! grep '^INSERT INTO `users` VALUES' db.sql | grep -qF ",'$user',"; then log "$user created after the db dump: not in this backup"; continue; fi
  if [ ! -f "$dir/exmdb/exchange.sqlite3" ]; then log "no store for $user ($dir): skipped"; skipped=$((skipped+1)); continue; fi
  b="$(cnt "$dir")"
  mode="$(stat -c %a "$dir")"; [ "$mode" = 770 ] || echo "dirmode|$user|$mode" >> manifest.part   # e.g. 0 = quarantined by the user-lifecycle tooling (filesystem-only state!)
  if ! gromox-exm2mt -u "$user" -ars IPM_SUBTREE > "mbx/$user.mt" 2> "mbx/$user.err"; then
    # exm2mt runs as the gromox user: a store dir with mode 000 (lifecycle quarantine) cannot be exported logically. Empty store: nothing to save.
    # Store with content: fall back to a RAW but consistent copy (sqlite online-backup API as root; attachment blobs from cid/).
    log "EXPORT FAILED for $user (store dir mode $mode, $b messages: total inbox calendar): $(tail -2 "mbx/$user.err")"
    rm -f "mbx/$user.mt" "mbx/$user.err"
    if [ "${b%% *}" = 0 ]; then echo "mbx_failed|$user|$status|${b// /|}|dirmode $mode" >> manifest.part; continue; fi
    if sqlite3 -readonly "$dir/exmdb/exchange.sqlite3" ".backup '$W/mbx/$user.exchange.sqlite3'" && tar -C "$dir" -cf "mbx/$user.cid.tar" cid 2>/dev/null; then
      a="$(cnt "$dir")"
      echo "mbxraw|$user|$status|${b// /|}|recount ${a// /,}|$(wc -c < "mbx/$user.exchange.sqlite3")|$(sha256sum < "mbx/$user.exchange.sqlite3" | cut -d' ' -f1)" >> manifest.part
      log "  -> raw sqlite fallback stored for $user"
    else
      echo "mbx_failed|$user|$status|${b// /|}|dirmode $mode" >> manifest.part; INCOMPLETE=1
    fi
    continue
  fi
  a="$(cnt "$dir")"
  sqlite3 -readonly "$dir/exmdb/exchange.sqlite3" "select 'INSERT OR REPLACE INTO permissions(folder_id,username,permission) VALUES('||folder_id||','||quote(username)||','||permission||');' from permissions" > "mbx/$user.perm.sql" 2>/dev/null || : > "mbx/$user.perm.sql"
  rm -f "mbx/$user.err"
  [ "$a" = "$b" ] || log "WARN $user changed during export (before: $b, after: $a)"
  echo "mbx|$user|$status|${b// /|}|recount ${a// /,}|$(wc -c < "mbx/$user.mt")|$(sha256sum < "mbx/$user.mt" | cut -d' ' -f1)" >> manifest.part
  n=$((n+1))
done < <(mysql -N "$DBN" -e 'select username,maildir,address_status from users order by id')
log "exported $n mailboxes ($skipped without store)"
# --- 4. public stores (sqlite online-backup API: consistent while the store is in use)
while IFS=$'\t' read -r dom dir; do
  [ -f "$dir/exmdb/exchange.sqlite3" ] || continue
  sqlite3 -readonly "$dir/exmdb/exchange.sqlite3" ".backup '$W/pub/$dom.exchange.sqlite3'"
  echo "pub|$dom|$(sha256sum < "pub/$dom.exchange.sqlite3" | cut -d' ' -f1)" >> manifest.part
done < <(mysql -N "$DBN" -e 'select domainname,homedir from domains')
echo "incomplete=$INCOMPLETE" >> manifest.part
mv manifest.part MANIFEST.part
find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
tar -cf - .
