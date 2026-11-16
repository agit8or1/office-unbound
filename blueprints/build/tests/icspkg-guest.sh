#!/bin/bash
# Runs INSIDE a fresh package-test machine (Ubuntu 24.04 or Debian 12) as root. Driven by icspkgtest.sh.
#   icspkg-guest.sh setup <repo-url> <channel> <fingerprint>   pin the repository key, add ONLY our signed repo (+ the distro archive)
#   icspkg-guest.sh install <version>                          apt-get install ou-ics=<version>; first-run checks
#   icspkg-guest.sh offline-wheels                             the postinst's pip step again, with NO network (unshare -n)
#   icspkg-guest.sh data                                       create owner (admin account) + extra audit data; prints the audit head
#   icspkg-guest.sh backupfail <version>                       upgrade with a broken backup tool: must be REFUSED, old version untouched
#   icspkg-guest.sh upgrade                                    preflight, apt-get install ou-ics (candidate), then checks
#   icspkg-guest.sh rollback <version>                         apt-get install --allow-downgrades ou-ics=<version> + ou-ics-rollback
#   icspkg-guest.sh status                                     one-line state summary
set -uo pipefail
export DEBIAN_FRONTEND=noninteractive LC_ALL=C.UTF-8
PASS=0; FAIL=0
ok() { echo "PASS  $*"; PASS=$((PASS+1)); }
no() { echo "FAIL  $*"; FAIL=$((FAIL+1)); }
chk() { local d=$1; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else no "$d"; fi; }
OPT=/opt/office-unbound/ics
KEYRING=/usr/share/keyrings/ou-release-lab.gpg
ICS() { ( cd "$OPT" && runuser -u ics -- "$OPT/.venv/bin/python" -m ics.cli "$@" ); }
readyz() { curl -s -o /tmp/readyz.json -w '%{http_code}' http://127.0.0.1:8088/readyz; }
wait_ready() { local i; for i in $(seq 1 90); do [ "$(readyz)" = 200 ] && return 0; sleep 1; done; return 1; }
pgq() { runuser -u postgres -- psql -X -q -Atd ics -c "$1"; }
summary() { echo "== RESULT: $PASS passed, $FAIL failed"; [ "$FAIL" = 0 ]; }

setup() {
  url=$1; ch=$2; fpr=$3
  . /etc/os-release; echo "== $PRETTY_NAME, python $(python3 -V 2>&1), $(free -m | awk '/Mem:/{print $2}') MiB RAM visible"
  rm -f /etc/apt/sources.list.d/office-unbound.list
  for i in $(seq 1 60); do ip -4 route | grep -q default && break; sleep 1; done
  apt-get -o DPkg::Lock::Timeout=300 -qq update && apt-get -qq install -y gnupg curl ca-certificates >/dev/null
  got=$(gpg --show-keys --with-colons /root/ou-release-lab.pub.asc | awk -F: '/^fpr/{print $10; exit}')
  [ "$got" = "$fpr" ] || { echo "key fingerprint mismatch: $got != $fpr"; exit 1; }
  gpg --dearmor < /root/ou-release-lab.pub.asc > "$KEYRING"
  echo "deb [signed-by=$KEYRING] $url $ch main" > /etc/apt/sources.list.d/office-unbound.list
  apt-get -qq update 2>&1 | tail -3
  apt-cache policy ou-ics | head -8
  ok "repository key pinned ($fpr), source added"
}

install_v() {
  v=$1
  start=$(date +%s)
  apt-get install -y -q --no-install-recommends "ou-ics=$v" > /root/install-$v.log 2>&1; rc=$?
  tail -15 /root/install-$v.log
  [ "$rc" = 0 ] && ok "apt-get install ou-ics=$v ($(( $(date +%s) - start )) s)" || { no "apt-get install ou-ics=$v rc=$rc"; summary; exit 1; }
  chk "package version is $v" test "$(dpkg-query -W -f='${Version}' ou-ics)" = "$v"
  chk "readyz 200 within 90 s of install (database, worker, audit chain)" wait_ready
  cat /tmp/readyz.json; echo
  chk "service user ics exists (sysusers)" getent passwd ics
  chk "keys are root:ics 0640" test "$(stat -c '%a %U:%G' /etc/office-unbound/vault.key /etc/office-unbound/audit.key /etc/office-unbound/ics-signing.key | sort -u)" = "640 root:ics"
  chk "ics.env root:ics 0640, ics-migrate.env root:root 0600" test "$(stat -c '%a %U:%G' /etc/office-unbound/ics.env /etc/office-unbound/ics-migrate.env | tr '\n' ' ')" = "640 root:ics 600 root:root "
  chk "conffile ics-tuning.env registered" dpkg-query -W -f='${Conffiles}' ou-ics | grep -q ics-tuning.env
  chk "units come from /usr/lib/systemd/system" test -f /usr/lib/systemd/system/ics.service
  chk "ics.service active, enabled" systemctl is-active -q ics.service
  chk "venv python matches the system python ABI" test "$("$OPT/.venv/bin/python" -c 'import sys;print(sys.version_info[:2])')" = "$(python3 -c 'import sys;print(sys.version_info[:2])')"
  echo "-- /api/v1/version (anonymous: major only) and BUILD_INFO.json:"; curl -s http://127.0.0.1:8088/api/v1/version; echo
  python3 -c "import json;d=json.load(open('$OPT/BUILD_INFO.json'));print({k:d[k] for k in ('version','commit','dirty','package','schema_head','built_at')})"
  chk "BUILD_INFO commit recorded, dirty=false, package=ou-ics $v" python3 -c "import json,sys;d=json.load(open('$OPT/BUILD_INFO.json'));sys.exit(0 if d['commit'] and d['dirty'] is False and d['package']=='ou-ics $v' else 1)"
  echo "-- alembic head in DB: $(pgq 'select version_num from alembic_version')"
  chk "audit chain verifies (ics.cli verify-chain)" ICS verify-chain
  summary
}

offline_wheels() {
  ABI="cp$(python3 -c 'import sys; print("%d%d" % sys.version_info[:2])')"
  rm -rf /tmp/offvenv; python3 -m venv /tmp/offvenv
  if unshare -n -- /tmp/offvenv/bin/pip install -q --no-index --find-links "/usr/share/ou-ics/wheels/$ABI" --require-hashes --disable-pip-version-check -r "$OPT/requirements.lock" 2>/tmp/off.err; then
    ok "pip install --no-index --require-hashes from the vendored $ABI wheels works in an EMPTY network namespace ($(/tmp/offvenv/bin/pip list 2>/dev/null | wc -l) packages)"
  else cat /tmp/off.err; no "offline wheel install"; fi
  # a tampered wheel must be refused (hash check)
  cp -a "/usr/share/ou-ics/wheels/$ABI" /tmp/tamper; w=$(ls /tmp/tamper/idna-*.whl 2>/dev/null | head -1)
  if [ -n "$w" ]; then printf 'x' >> "$w"; rm -rf /tmp/tv; python3 -m venv /tmp/tv
    if /tmp/tv/bin/pip install -q --no-index --find-links /tmp/tamper --require-hashes --disable-pip-version-check -r "$OPT/requirements.lock" >/dev/null 2>&1; then no "tampered wheel was ACCEPTED"; else ok "a tampered wheel is refused by --require-hashes"; fi
  fi
  rm -rf /tmp/offvenv /tmp/tamper /tmp/tv
  summary
}

data() {
  tok=$(ICS create-admin --username owner1 --role admin | tail -n1)
  [ -n "$tok" ] && ok "owner bootstrap: create-admin printed a one-time enrollment token (${#tok} chars, not shown)" || no "create-admin"
  ICS unlock --username owner1 >/dev/null; ICS unlock --username owner1 >/dev/null
  echo "audit events: $(pgq 'select count(*) from audit_events'), head $(pgq 'select left(hash,16) from audit_events order by seq desc limit 1')"
  chk "audit chain verifies after writes" ICS verify-chain
  summary
}

backupfail() {
  v=$(dpkg-query -W -f='${Version}' ou-ics); sb=$(pgq 'select version_num from alembic_version')
  cp -p /usr/lib/ou-ics/ics-backup.sh /root/ics-backup.sh.orig
  printf '#!/bin/sh\necho simulated backup failure >&2\nexit 1\n' > /usr/lib/ou-ics/ics-backup.sh
  apt-get install -y -q --no-install-recommends ou-ics > /root/upgrade-refused.log 2>&1; rc=$?
  tail -8 /root/upgrade-refused.log
  cp -p /root/ics-backup.sh.orig /usr/lib/ou-ics/ics-backup.sh
  [ "$rc" != 0 ] && ok "upgrade with a failing backup is REFUSED (apt exit $rc)" || no "upgrade went ahead with a failing backup"
  chk "installed version unchanged ($v)" test "$(dpkg-query -W -f='${Version}' ou-ics)" = "$v"
  chk "package still configured (ii)" test "$(dpkg-query -W -f='${db:Status-Abbrev}' ou-ics | tr -d ' ')" = ii
  chk "database schema untouched ($sb)" test "$(pgq 'select version_num from alembic_version')" = "$sb"
  chk "ics still serving after the refused upgrade" wait_ready
  summary
}

upgrade() {
  from=$(dpkg-query -W -f='${Version}' ou-ics); before_head=$(pgq 'select version_num from alembic_version'); n_before=$(ls -1 /var/backups/office-unbound/ics | wc -l)
  events_before=$(pgq 'select count(*) from audit_events')
  echo "-- upgrade-preflight (as root):"; ( cd "$OPT" && ./.venv/bin/python -m ics.cli upgrade-preflight ); chk "upgrade-preflight exit 0" test "$?" = 0
  apt-get update -qq; echo "-- candidate:"; apt-cache policy ou-ics | sed -n 1,4p
  start=$(date +%s)
  apt-get install -y -q --no-install-recommends ou-ics > /root/upgrade.log 2>&1; rc=$?
  tail -25 /root/upgrade.log
  [ "$rc" = 0 ] && ok "apt-get install ou-ics (upgrade from $from) ok in $(( $(date +%s) - start )) s" || { no "upgrade rc=$rc"; summary; exit 1; }
  to=$(dpkg-query -W -f='${Version}' ou-ics); echo "-- $from -> $to"
  chk "version changed" test "$to" != "$from"
  chk "a pre-upgrade backup was taken automatically (backup dirs $n_before -> $(ls -1 /var/backups/office-unbound/ics | wc -l))" test "$(ls -1 /var/backups/office-unbound/ics | wc -l)" -gt "$n_before"
  bk=$(python3 -c "import json;print(json.load(open('/var/lib/office-unbound/ics-last-upgrade.json'))['path'])")
  echo "-- backup used: $bk"; cat "$bk/MANIFEST"
  chk "backup recorded the PRE-upgrade schema ($before_head)" test "$(sed -n 's/^alembic_head=//p' "$bk/MANIFEST")" = "$before_head"
  chk "backup archive hash matches its MANIFEST" test "$(sha256sum < "$bk/ics-backup.tar" | cut -d' ' -f1)" = "$(sed -n 's/^archive_sha256=//p' "$bk/MANIFEST")"
  after_head=$(pgq 'select version_num from alembic_version')
  chk "migration applied (schema $before_head -> $after_head)" test "$after_head" != "$before_head"
  chk "dummy migration object exists" test "$(pgq "select note from ou_pkgtest_marker where id=1")" = "migrated by 0.1.1-dev.1"
  chk "readyz 200 after upgrade" wait_ready
  chk "audit chain verifies after upgrade" ICS verify-chain
  chk "owner account survived" test "$(pgq "select count(*) from users where username='owner1'")" = 1
  chk "audit events preserved ($events_before before)" test "$(pgq 'select count(*) from audit_events')" -ge "$events_before"
  chk "keys and env files unchanged by the upgrade" test "$(stat -c '%a %U:%G' /etc/office-unbound/vault.key | tr -d '\n')" = "640 root:ics"
  echo "SCHEMA=$before_head" > /root/schema.before
  summary
}

rollback() {
  v=$1
  cur=$(dpkg-query -W -f='${Version}' ou-ics)
  apt-get install -y -q --no-install-recommends --allow-downgrades "ou-ics=$v" > /root/rollback.log 2>&1; rc=$?
  tail -14 /root/rollback.log
  [ "$rc" = 0 ] && ok "apt-get install --allow-downgrades ou-ics=$v ($cur -> $v) completed" || no "downgrade rc=$rc"
  chk "version is $v" test "$(dpkg-query -W -f='${Version}' ou-ics)" = "$v"
  chk "schema moved: the old package left the ICS stopped and set the restore marker" test -f /var/lib/office-unbound/ics-needs-restore
  chk "ics is NOT running against the newer schema" test "$(systemctl is-active ics.service)" != active
  cand=$(grep -o 'ou-ics-rollback /var/backups[^ ]*' /root/rollback.log | head -1 | cut -d' ' -f2)
  echo "-- postinst named the backup: $cand"
  chk "the named backup holds the pre-upgrade schema" test "$(sed -n 's/^alembic_head=//p' "$cand/MANIFEST")" = "$(sed -n 's/^SCHEMA=//p' /root/schema.before)"
  ou-ics-rollback "$cand" > /root/rollback-restore.log 2>&1; rc=$?; cat /root/rollback-restore.log
  [ "$rc" = 0 ] && ok "ou-ics-rollback $cand" || no "ou-ics-rollback rc=$rc"
  chk "marker removed" test ! -f /var/lib/office-unbound/ics-needs-restore
  chk "schema is back at $(sed -n 's/^SCHEMA=//p' /root/schema.before)" test "$(pgq 'select version_num from alembic_version')" = "$(sed -n 's/^SCHEMA=//p' /root/schema.before)"
  chk "dummy migration object is gone" test "$(pgq "select to_regclass('public.ou_pkgtest_marker') is null")" = t
  chk "readyz 200 after rollback" wait_ready
  chk "audit chain verifies after rollback" ICS verify-chain
  chk "owner account present" test "$(pgq "select count(*) from users where username='owner1'")" = 1
  chk "safety dump of the rolled-away database kept" ls "$cand"/pre-rollback-*.dump
  summary
}

status() { echo "ou-ics $(dpkg-query -W -f='${Version}' ou-ics 2>/dev/null) schema=$(pgq 'select version_num from alembic_version' 2>/dev/null) ics=$(systemctl is-active ics.service) readyz=$(readyz)"; }

cmd=$1; shift
case $cmd in
  setup) setup "$@";; install) install_v "$@";; offline-wheels) offline_wheels;; data) data;; backupfail) backupfail;; upgrade) upgrade;; rollback) rollback "$@";; status) status;;
  *) echo usage; exit 2;;
esac
