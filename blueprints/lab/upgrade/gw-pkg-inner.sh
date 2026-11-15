#!/bin/bash
# Runs INSIDE a groupware node (piped on stdin by gw-pkg-upgrade.sh). Phases:
#   pre        record the installed state (read-only except /var/backups/ou-prepkg/<ts>/)
#   migrate    source-built /usr install -> signed ou-* packages from the channel, exact versions, apt-mark hold, config + data preserved
#   change     apt install exactly the versions in $PINS (upgrade or downgrade, held packages allowed), restart, report timing
#   status     what is installed / held / running
# Env: REPO_URL CHANNEL KEY_FPR PINS ("pkg=version ...") BK (backup dir, default newest /var/backups/ou-prepkg/*)
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive LC_ALL=C.UTF-8
PHASE=${1:?phase}
BKROOT=/var/backups/ou-prepkg
SVCS_STOP="gromox-delivery-queue gromox-delivery gromox-imap gromox-http gromox-zcore gromox-midb gromox-timer gromox-event"
SVCS_START="gromox-event gromox-timer gromox-midb gromox-zcore gromox-http gromox-imap gromox-delivery gromox-delivery-queue"
t() { date +%s.%N; }
el() { python3 -c "print(round($(t)-$1,1))"; }
log() { echo "[$(date -u +%T)] $*"; }

pre() {
  TS=$(date -u +%Y%m%dT%H%M%SZ); BK=$BKROOT/$TS; install -d -m 0700 "$BK"
  { echo "# installed state of $(hostname) before migration, $TS"
    for d in libhx wmime gromox gromox-ac mapi-header-php grommunio-sync grommunio-dav grommunio-web; do
      [ -d /usr/src/ou/$d ] && echo "src.$d=$(cd /usr/src/ou/$d && /usr/bin/git describe --tags --always 2>/dev/null) $(cd /usr/src/ou/$d && /usr/bin/git rev-parse HEAD 2>/dev/null)"
    done
    echo "dpkg-owned gromox/ou packages: $(dpkg -l 'ou-*' 'gromox*' 'grommunio*' 'libhx*' 2>/dev/null | grep -c '^ii' || true)"
    echo "kernel=$(uname -r) os=$(. /etc/os-release; echo "$PRETTY_NAME")"
    echo "listening: $(ss -ltn | awk 'NR>1{print $4}' | sort -u | tr '\n' ' ')"
    for u in $SVCS_STOP php8.2-fpm nginx mariadb postfix redis-server; do echo "svc.$u=$(systemctl is-active $u 2>/dev/null)"; done
  } > "$BK/state.txt"
  # file inventory with checksums of everything the source install put outside /var and /etc (binaries, libs, php ext, units, web trees)
  { ls -1d /usr/libexec/gromox/* /usr/sbin/gromox-* /usr/bin/gromox-* /usr/lib/x86_64-linux-gnu/libgromox* /usr/lib/x86_64-linux-gnu/libgx* /usr/lib/x86_64-linux-gnu/libHX* \
          /usr/lib/x86_64-linux-gnu/libwmime* /usr/lib/php/*/mapi.so /usr/lib/systemd/system/gromox-* 2>/dev/null
    find /usr/share/gromox /usr/share/grommunio-sync /usr/share/grommunio-dav /usr/share/grommunio-web -type f 2>/dev/null
  } | sort -u > "$BK/files.list"
  xargs -a "$BK/files.list" -d '\n' sha256sum 2>/dev/null > "$BK/files.sha256" || true
  echo "gromox_binaries_sha256: $(sha256sum /usr/libexec/gromox/http /usr/libexec/gromox/imap /usr/libexec/gromox/event | awk '{print substr($1,1,16)}' | tr '\n' ' ')" >> "$BK/state.txt"
  # restore-from-source-built path: tar of those files (rollback path 2)
  tar -C / -cf "$BK/source-built.tar" --null -T <(sed 's#^/##' "$BK/files.list" | tr '\n' '\0') 2>/dev/null
  tar -C / -cf "$BK/config.tar" etc/gromox etc/ou-rb etc/php/8.2/mods-available/mapi.ini etc/nginx etc/ldap etc/ou-lab-tls usr/share/grommunio-sync/config.php usr/share/grommunio-dav/config.php usr/share/grommunio-web/config.php 2>/dev/null || true
  chmod 0600 "$BK"/*; echo "$BK" > "$BKROOT/LATEST"
  echo "state recorded in $BK: $(wc -l < "$BK/files.list") files, source-built.tar $(du -h "$BK/source-built.tar" | cut -f1)"; cat "$BK/state.txt"
}

apt_setup() {
  install -d -m 0755 /usr/share/keyrings
  curl -fsS "$REPO_URL/ou-release-lab.pub.asc" -o /tmp/ou-release.asc
  got=$(gpg --show-keys --with-colons /tmp/ou-release.asc | awk -F: '/^fpr/{print $10; exit}')
  [ "$got" = "$KEY_FPR" ] || { echo "release key fingerprint mismatch: $got"; exit 1; }
  gpg --dearmor < /tmp/ou-release.asc > /usr/share/keyrings/ou-release-lab.gpg
  echo "deb [signed-by=/usr/share/keyrings/ou-release-lab.gpg] $REPO_URL $CHANNEL main" > /etc/apt/sources.list.d/office-unbound.list
  { for pv in $PINS; do echo "Package: ${pv%%=*}"; echo "Pin: version ${pv#*=}"; echo "Pin-Priority: 1001"; echo; done; } > /etc/apt/preferences.d/office-unbound-pins
  apt-get update -q >/dev/null
}

svc_stop() { for s in $SVCS_STOP php8.2-fpm; do systemctl stop $s 2>/dev/null || true; done; }
svc_start() { for s in $SVCS_START php8.2-fpm; do systemctl start $s; done; sleep 3; for s in $SVCS_START php8.2-fpm; do systemctl is-active -q $s || { echo "NOT ACTIVE: $s"; systemctl status $s --no-pager | tail -5; return 1; }; done; }

migrate() {
  BK=$(cat $BKROOT/LATEST); T0=$(t)
  [ -s "$BK/files.list" ] || { echo "run pre first"; exit 1; }
  log "apt source + pins"; apt_setup
  log "download the packages first (service stays up)"
  apt-get install -y -q --download-only --no-install-recommends -o Dpkg::Options::=--force-confold $PINS >/dev/null
  T1=$(t)
  log "stop services"; svc_stop
  log "data snapshot (services stopped, consistent): mysqldump + /var/lib/gromox"
  mysqldump --single-transaction --routines --triggers --events email > "$BK/db.sql"
  tar -C / -cf "$BK/var-lib-gromox.tar" var/lib/gromox; chmod 0600 "$BK"/db.sql "$BK"/var-lib-gromox.tar
  ( cd /var/lib/gromox && find . -type f | sort | xargs -d '\n' sha256sum | sha256sum | cut -c1-16 ) > "$BK/data.treehash" 2>/dev/null || true
  log "keep the lab application configs"; mkdir -p "$BK/cfg"
  for a in sync dav web; do cp -p /usr/share/grommunio-$a/config.php "$BK/cfg/$a.config.php"; done
  log "remove the source-built install (make uninstall for libhx/gromox, file list for the rest)"
  for d in libhx gromox; do ( cd /usr/src/ou/$d && make -n uninstall > "$BK/uninstall-$d.dryrun" 2>&1 || true; make uninstall >/dev/null 2>&1 || true ); done
  grep -v '^/usr/share/grommunio-\|^/usr/share/gromox/' "$BK/files.list" | xargs -d '\n' rm -f 2>/dev/null || true
  rm -f /usr/lib/x86_64-linux-gnu/libwmime* /usr/lib/x86_64-linux-gnu/pkgconfig/libwmime* 2>/dev/null || true
  for a in sync dav web; do mv /usr/share/grommunio-$a "$BK/old-tree-grommunio-$a"; done
  [ -d /usr/share/mapi-header-php ] && mv /usr/share/mapi-header-php "$BK/old-tree-mapi-header-php" || true
  [ -d /usr/share/gromox ] && mv /usr/share/gromox "$BK/old-tree-share-gromox" || true
  rm -rf /usr/libexec/gromox
  ldconfig
  log "install the signed packages (exact versions)"
  T2=$(t)
  apt-get install -y -q --no-install-recommends -o Dpkg::Options::=--force-confold -o Dpkg::Options::=--force-confdef $PINS 2>&1 | tail -15
  T3=$(t)
  log "restore lab configuration into the package conffiles"
  for a in sync dav web; do install -m 0644 "$BK/cfg/$a.config.php" /etc/grommunio-$a/config.php; done
  # the lab keeps its own php ini + conf.d links; the package ships cli/conf.d/mapi.ini: drop the package copies, keep the lab config (zcore socket)
  ls -la /etc/php/8.2/*/conf.d/ | grep -i mapi || true
  for f in /etc/php/8.2/cli/conf.d/mapi.ini /etc/php/8.2/fpm/conf.d/mapi.ini; do [ -f "$f" ] && [ ! -L "$f" ] && cmp -s "$f" /etc/php/8.2/mods-available/mapi.ini && rm -f "$f"; done || true
  grep -q "^bearer_issuer" /etc/gromox/gromox.cfg || printf 'bearer_issuer=%s\nbearer_audience=%s\n' "$BEARER_ISSUER" "$BEARER_AUDIENCE" >> /etc/gromox/gromox.cfg
  systemctl daemon-reload
  for s in $SVCS_START; do systemctl enable $s >/dev/null 2>&1 || true; done
  log "start"; svc_start
  T4=$(t)
  apt-mark hold $(for pv in $PINS; do echo "${pv%%=*}"; done) >/dev/null
  echo "TIMING download_s=$(python3 -c "print(round($T1-$T0,1))") downtime_s=$(python3 -c "print(round($T4-$T1,1))") (stop->started) install_only_s=$(python3 -c "print(round($T3-$T2,1))") total_s=$(el $T0)"
  echo "held: $(apt-mark showhold | tr '\n' ' ')"
  echo "leftovers not owned by a package:"; for f in /usr/libexec/gromox/* /usr/sbin/gromox-*; do dpkg -S "$f" >/dev/null 2>&1 || echo "  UNOWNED $f"; done | head
}

change() {   # upgrade / downgrade to exactly $PINS
  T0=$(t); apt_setup; T1=$(t)
  svc_stop
  apt-get install -y -q --no-install-recommends --allow-downgrades --allow-change-held-packages -o Dpkg::Options::=--force-confold $PINS 2>&1 | tail -8
  T2=$(t)
  systemctl daemon-reload; svc_start; T3=$(t)
  apt-mark hold $(for pv in $PINS; do echo "${pv%%=*}"; done) >/dev/null
  echo "TIMING index_update_s=$(python3 -c "print(round($T1-$T0,1))") package_swap_s=$(python3 -c "print(round($T2-$T1,1))") restart_s=$(python3 -c "print(round($T3-$T2,1))") total_downtime_s=$(python3 -c "print(round($T3-$T1,1))") total_s=$(el $T0)"
}

status() {
  dpkg-query -W -f='${Package} ${Version} ${db:Status-Abbrev}\n' 'ou-*' 2>/dev/null | sed 's/ ii $//'
  echo "held: $(apt-mark showhold | tr '\n' ' ')"
  for s in $SVCS_START php8.2-fpm nginx mariadb; do echo "$s=$(systemctl is-active $s)"; done | tr '\n' ' '; echo
  echo "imap binary sha256: $(sha256sum /usr/libexec/gromox/imap | cut -c1-16) owned by: $(dpkg -S /usr/libexec/gromox/imap 2>&1 | cut -d: -f1)"
}

case $PHASE in pre) pre;; migrate) migrate;; change) change;; status) status;; *) echo bad phase; exit 2;; esac
