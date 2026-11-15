#!/bin/bash
# Runs INSIDE the package test machine (ou-pkgtest1, fresh Debian 12). Driven by pkgtest.sh.
#   pkgtest-guest.sh setup <repo-url> <suite> <fingerprint>   add ONLY our signed repo (signed-by, key fingerprint verified)
#   pkgtest-guest.sh install <package...>                     apt install from it
#   pkgtest-guest.sh smoke                                    configure gromox with a test domain via the lab SQL path, run IMAP + EWS
#   pkgtest-guest.sh tamper                                   signature-enforcement experiments on file:// copies of the repo
set -uo pipefail
export DEBIAN_FRONTEND=noninteractive LC_ALL=C.UTF-8
PASS=0; FAIL=0
ok() { echo "PASS  $*"; PASS=$((PASS+1)); }
no() { echo "FAIL  $*"; FAIL=$((FAIL+1)); }
KEYRING=/usr/share/keyrings/ou-release-lab.gpg

setup() {
  url=$1; suite=$2; fpr=$3
  got=$(gpg --show-keys --with-colons /tmp/ou-release-lab.pub.asc | awk -F: '/^fpr/{print $10; exit}')
  [ "$got" = "$fpr" ] || { echo "key fingerprint mismatch: $got != $fpr"; exit 1; }
  gpg --dearmor < /tmp/ou-release-lab.pub.asc > $KEYRING
  cat > /etc/apt/sources.list <<EOF
deb http://deb.debian.org/debian bookworm main
deb http://deb.debian.org/debian bookworm-updates main
deb http://deb.debian.org/debian-security bookworm-security main
EOF
  echo "deb [signed-by=$KEYRING] $url $suite main" > /etc/apt/sources.list.d/office-unbound.list
  apt-get update -q 2>&1 | tail -3
  echo "--- sources in use:"; grep -h '^deb' /etc/apt/sources.list /etc/apt/sources.list.d/* | sed 's/^/    /'
  apt-cache policy ou-gromox | head -6
}

install_pkgs() {
  apt-get install -y -q --no-install-recommends "$@" 2>&1 | tail -4
  for p in "$@"; do dpkg -s "$p" 2>/dev/null | grep -E '^(Package|Version|Status)' | tr '\n' ' '; echo; done
}

smoke() {
  DOM=pkgtest.ou-lab.internal; U=smoke1; PW=$(openssl rand -hex 8); DBPASS=$(openssl rand -hex 12)
  apt-get install -y -q --no-install-recommends mariadb-server python3 sqlite3 openssl >/dev/null 2>&1
  grep -q "$DOM" /etc/hosts || echo "127.0.1.1 $(hostname) $DOM" >> /etc/hosts
  getent passwd gromox >/dev/null && echo 'gromox user created by package postinst' || echo 'MISSING gromox user'
  install -d -o gromox -g gromox -m 0770 /var/lib/gromox /var/lib/gromox/user /var/lib/gromox/domain /var/lib/gromox/queue /var/lib/gromox/queue/mess /var/lib/gromox/queue/save /var/lib/gromox/queue/cache /var/log/gromox
  install -d -o root -g gromoxcf -m 0750 /etc/gromox
  systemctl enable --now mariadb >/dev/null 2>&1
  mysql -e "CREATE DATABASE IF NOT EXISTS email CHARACTER SET utf8mb4;
   CREATE USER IF NOT EXISTS 'gromox'@'localhost' IDENTIFIED BY '$DBPASS'; GRANT ALL ON email.* TO 'gromox'@'localhost'; FLUSH PRIVILEGES;"
  cat > /etc/gromox/mysql_adaptor.cfg <<EOF
mysql_username=gromox
mysql_password=$DBPASS
mysql_dbname=email
mysql_host=localhost
schema_upgrade=host:$DOM
EOF
  cat > /etc/gromox/gromox.cfg <<EOF
host_id=$DOM
http_listen=127.0.0.1:10080
http_listen_tls=
lda_listen=127.0.0.1:24
lda_listen_tls=
imap_listen=127.0.0.1:143
imap_listen_tls=
EOF
  printf 'http_support_tls=false\nhttp_auth_basic=true\n' > /etc/gromox/http.cfg
  printf 'imap_support_tls=false\n' > /etc/gromox/imap.cfg
  chown root:gromoxcf /etc/gromox/*.cfg; chmod 0640 /etc/gromox/*.cfg
  gromox-dbop -C 2>&1 | tail -2
  # domain + user via the same SQL path as the lab (blueprints/lab/spike-groupware/lab-configure.sh)
  mysql email -e "INSERT IGNORE INTO orgs (id,name,description) VALUES (1,'lab','pkgtest');
   INSERT IGNORE INTO domains (org_id,domainname,homedir,max_user,title,end_day,domain_status) VALUES (1,'$DOM','/var/lib/gromox/domain/$DOM',0,'pkgtest','2099-01-01',0);"
  DID=$(mysql -N email -e "SELECT id FROM domains WHERE domainname='$DOM'")
  md=/var/lib/gromox/user/$U@$DOM; h=$(openssl passwd -6 "$PW")
  mysql email -e "INSERT IGNORE INTO users (username,password,domain_id,group_id,maildir,privilege_bits,address_status,lang,timezone)
    VALUES ('$U@$DOM','$h',$DID,0,'$md',15,0,'en','UTC');
    INSERT IGNORE INTO user_properties (user_id,proptag,propval_str) SELECT id,0x39050003,'0' FROM users WHERE username='$U@$DOM';
    INSERT IGNORE INTO user_properties (user_id,proptag,propval_str) SELECT id,0x3001001F,'Smoke One' FROM users WHERE username='$U@$DOM'"
  install -d -o gromox -g gromox -m 0770 $md $md/exmdb $md/tmp $md/tmp/imap.rfc822 $md/config $md/cid /var/lib/gromox/domain/$DOM
  gromox-mkprivate "$U@$DOM" 2>&1 | tail -1; gromox-mkmidb "$U@$DOM" 2>&1 | tail -1
  chown -R gromox:gromox /var/lib/gromox
  echo "--- gromox units shipped:"; systemctl list-unit-files 'gromox*' --no-legend | awk '{print "    "$1,$2}'
  for u in gromox-event gromox-timer gromox-midb gromox-zcore gromox-http gromox-delivery gromox-delivery-queue gromox-imap gromox-pop3 gromox-istore; do
    systemctl list-unit-files "$u.service" --no-legend | grep -q . || continue
    systemctl start "$u" 2>&1 | tail -1
  done
  sleep 6
  for u in gromox-event gromox-timer gromox-midb gromox-zcore gromox-http gromox-delivery gromox-imap; do
    systemctl list-unit-files "$u.service" --no-legend | grep -q . || continue
    if systemctl is-active --quiet "$u"; then ok "service $u active"; else no "service $u not active: $(systemctl status $u --no-pager -l 2>&1 | tail -4 | tr '\n' '|')"; fi
  done
  out=$(python3 - "$U@$DOM" "$PW" <<'PY'
import imaplib, sys, http.client, base64, time
user, pw = sys.argv[1:3]
try:
    m = imaplib.IMAP4("127.0.0.1", 143); print("IMAP greeting:", m.welcome.decode()[:60])
    m.login(user, pw); t, d = m.select("INBOX"); print("IMAP login+select INBOX:", t, d); m.logout(); print("PASS  IMAP login and SELECT INBOX")
except Exception as e:
    print("FAIL  IMAP:", e)
body = ('<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" '
        'xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">'
        '<soap:Header><t:RequestServerVersion Version="Exchange2013"/></soap:Header><soap:Body><m:GetFolder><m:FolderShape><t:BaseShape>Default</t:BaseShape></m:FolderShape>'
        '<m:FolderIds><t:DistinguishedFolderId Id="inbox"/></m:FolderIds></m:GetFolder></soap:Body></soap:Envelope>')
try:
    c = http.client.HTTPConnection("127.0.0.1", 10080, timeout=20)
    c.request("POST", "/EWS/Exchange.asmx", body, {"Content-Type": "text/xml", "Authorization": "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()})
    r = c.getresponse(); data = r.read().decode(errors="replace")
    ok = r.status == 200 and "NoError" in data
    print(("PASS  " if ok else "FAIL  ") + f"EWS GetFolder inbox: HTTP {r.status}, NoError={'NoError' in data}")
    if not ok: print(data[:300])
except Exception as e:
    print("FAIL  EWS:", e)
PY
)
  echo "$out"; PASS=$((PASS+$(echo "$out" | grep -c '^PASS'))); FAIL=$((FAIL+$(echo "$out" | grep -c '^FAIL')))
}

# ---------------- patch / content verification of the installed packages ----------------
verify() {
  A=/usr/share/grommunio-admin-api
  if [ -d $A ]; then
    [ "$(grep -c 'License user limit' $A/orm/users.py)" = 0 ] && ok "admin-api: user-cap checks removed from orm/users.py" || no "admin-api: user cap still present"
    ! grep -q 'portal.grommunio.com' $A/endpoints/system/misc.py && ok "admin-api: licence portal call-home removed" || no "admin-api: portal URL still present"
    out=$(cd $A && PYTHONPATH=/usr/lib/ou-admin-api/site-packages python3 -c "import tools.license as l; print(l.getLicense().users, l.getLicense().product)" 2>&1 | tail -1)
    [ "$out" = "0 Office Unbound" ] && ok "admin-api: default licence reports users=0 (unlimited), product 'Office Unbound'" || echo "INFO  admin-api python import check: $out"
  fi
  W=/usr/share/grommunio-web
  if [ -d $W ]; then
    grep -q "Office Unbound Web" $W/manifest.webmanifest && ok "web: manifest says Office Unbound Web" || no "web: manifest not rebranded"
    grep -q 'WEBAPP_TITLE", "Office Unbound Web"' /etc/grommunio-web/config.php && ok "web: default title rebranded" || no "web: title not rebranded"
    grep -q "Office Unbound" $W/client/resources/images/grommunio-logo.svg && ok "web: logo replaced" || no "web: logo not replaced"
    [ ! -e $W/client/resources/images/grommunio-logo.svg.gz ] && ok "web: no stale precompressed upstream logo" || no "web: stale .gz logo"
    n=$(grep -rl "grommunio Web" $W/server/language/*/LC_MESSAGES/*.po 2>/dev/null | wc -l)
    echo "INFO  web: .po catalogues still mentioning 'grommunio Web': $n (not shipped as .po? $(ls $W/server/language/en_GB/LC_MESSAGES 2>/dev/null | tr '\n' ' '))"
  fi
  for f in /etc/grommunio-sync/config.php /etc/grommunio-dav/config.php /etc/grommunio-web/config.php; do [ -e "$f" ] && grep -qx "$f" <(dpkg-query -W -f='${Conffiles}\n' 'ou-*' | awk '{print $1}') && ok "conffile registered: $f"; done
  echo "RESULT verify: pass=$PASS fail=$FAIL"
}

# ---------------- signature enforcement ----------------
apt_with() { # <dir> <args...>: apt using only the sources in <dir>/sources.list
  d=$1; shift
  apt-get -o Dir::Etc::sourcelist=$d/sources.list -o Dir::Etc::sourceparts=/dev/null -o Dir::State::lists=$d/lists \
    -o Dir::Cache=$d/cache -o Dir::State::status=/var/lib/dpkg/status -o Debug::NoLocking=1 -q "$@"
}
mkcase() { # <name>: fresh file:// copy of the good repo; echo dir
  d=/tmp/tamper/$1; rm -rf "$d"; mkdir -p "$d/lists/partial" "$d/cache/archives/partial"
  cp -a /tmp/ou-repo-good "$d/repo"
  echo "deb [signed-by=$KEYRING] file:$d/repo $SUITE main" > "$d/sources.list"
  echo "$d"
}
expect_fail() { # <desc> <dir> <cmd...>
  desc=$1; d=$2; shift 2
  out=$(apt_with "$d" "$@" 2>&1); rc=$?
  if [ $rc -ne 0 ]; then ok "$desc REFUSED (rc=$rc): $(echo "$out" | grep -E '^(E|W):|Err:' | head -2 | tr '\n' ' ' | cut -c1-230)"
  else no "$desc was ACCEPTED"; fi
}
tamper() {
  SUITE=${1:-dev}
  rm -rf /tmp/tamper
  d=$(mkcase good); out=$(apt_with "$d" update 2>&1); rc=$?
  [ $rc -eq 0 ] && ok "baseline: untouched repo copy verifies and updates" || { no "baseline failed: $out"; return; }
  d=$(mkcase tampered-inrelease)
  python3 - "$d/repo/dists/$SUITE/InRelease" <<'PY'
import sys; p=sys.argv[1]; s=open(p).read(); open(p,"w").write(s.replace("Origin: Office Unbound","Origin: Office Unbounds",1))
PY
  expect_fail "tampered InRelease (signed text modified)" "$d" update
  d=$(mkcase tampered-release-gpg)
  python3 - "$d/repo/dists/$SUITE/Release" <<'PY'
import sys; p=sys.argv[1]; s=open(p).read(); open(p,"w").write(s.replace("Office Unbound","Office Unbounde",1))
PY
  rm -f "$d/repo/dists/$SUITE/InRelease"
  expect_fail "tampered Release with original Release.gpg" "$d" update
  d=$(mkcase unsigned)
  rm -f "$d/repo/dists/$SUITE/InRelease" "$d/repo/dists/$SUITE/Release.gpg"
  expect_fail "unsigned repository (Release only)" "$d" update
  d=$(mkcase wrong-key)
  export GNUPGHOME=$(mktemp -d); gpg --batch --quiet --pinentry-mode loopback --passphrase '' --quick-generate-key "Attacker <a@example.invalid>" ed25519 sign 1d 2>/dev/null
  F=$(gpg --list-secret-keys --with-colons | awk -F: '/^fpr/{print $10; exit}')
  gpg --batch --yes --pinentry-mode loopback --passphrase '' --local-user "$F" --clearsign < "$d/repo/dists/$SUITE/Release" > "$d/repo/dists/$SUITE/InRelease"
  gpg --batch --yes --pinentry-mode loopback --passphrase '' --local-user "$F" --armor --detach-sign < "$d/repo/dists/$SUITE/Release" > "$d/repo/dists/$SUITE/Release.gpg"
  unset GNUPGHOME
  expect_fail "repository signed by a different (attacker) key" "$d" update
  d=$(mkcase tampered-packages)
  python3 - "$d/repo/dists/$SUITE/main/binary-amd64/Packages" <<'PY'
import sys,re; p=sys.argv[1]; s=open(p).read(); s=re.sub(r"(SHA256: )([0-9a-f])", lambda m: m.group(1)+("0" if m.group(2)!="0" else "1"), s, count=1); open(p,"w").write(s)
PY
  rm -f "$d/repo/dists/$SUITE/main/binary-amd64/Packages.gz"
  expect_fail "Packages index modified after signing" "$d" update
  d=$(mkcase tampered-deb)
  apt_with "$d" update >/dev/null 2>&1
  deb=$(ls "$d"/repo/pool/$SUITE/*/ou-libhx_*.deb 2>/dev/null | head -1)
  [ -n "$deb" ] || deb=$(ls "$d"/repo/pool/$SUITE/*/*.deb | head -1)
  printf 'X' >> "$deb"
  pk=$(basename "$deb" | cut -d_ -f1)
  expect_fail "package file modified after signing ($pk)" "$d" install --download-only --reinstall -y "$pk"
  d=$(mkcase rogue-deb)
  cp "$deb" "$d/repo/pool/$SUITE/rogue_1.0_amd64.deb" 2>/dev/null
  apt_with "$d" update >/dev/null 2>&1
  out=$(apt_with "$d" install --download-only -y rogue 2>&1); rc=$?
  [ $rc -ne 0 ] && ok "deb not listed in the signed index is not installable (rc=$rc)" || no "unlisted deb was installable"
  echo "RESULT tamper: pass=$PASS fail=$FAIL"
}

cmd=${1:-}; shift || true
case "$cmd" in
  setup) setup "$@" ;;
  install) install_pkgs "$@" ;;
  verify) verify ;;
  smoke) smoke; echo "RESULT smoke: pass=$PASS fail=$FAIL" ;;
  tamper) tamper "$@" ;;
  *) echo "usage: $0 setup|install|smoke|tamper" ;;
esac
[ "$FAIL" -eq 0 ]
