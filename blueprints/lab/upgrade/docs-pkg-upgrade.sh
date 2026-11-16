#!/bin/bash
# Document-tier upgrade drill driver (ICS host): ou-office1 tar-installed ou1 -> signed `ou-docs` package, upgrade, rollback, roll forward.
# Same pattern as gw-pkg-upgrade.sh (A21). Never touches the production ICS service or DB. Machine commands go through `systemd-run -M` (no ssh).
#   docs-pkg-upgrade.sh pre                 backup of config + hash inventory of the tar-installed engine (prints the backup dir)
#   docs-pkg-upgrade.sh migrate <version>   apt source/key/pin, download first, stop, install pinned+held (vendor coolwsd removed), unit, start
#   docs-pkg-upgrade.sh change <version>    pinned upgrade/downgrade of ou-docs (download first, stop, install, start); prints the timings
#   docs-pkg-upgrade.sh status
# env: REPO_URL (http://<ou-repo1 zone ip>:8077)  CHANNEL (dev)  DOCS_MACHINE (ou-office1)  PROBE_LOG (file for the external availability probe)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd); BUILD=$HERE/../../build
M=${DOCS_MACHINE:-ou-office1}; CHANNEL=${CHANNEL:-dev}; : "${REPO_URL:?REPO_URL=http://<repo ip>:8077}"
FPR=$(cat "$BUILD/keys/ou-release-$CHANNEL.FINGERPRINT")
run() { sudo systemd-run -M "$M" --wait --pipe -q /bin/bash -s -- "$@"; }
CA=${OU_CA_FILE:-}

probe_start() {  # external availability probe through nginx: one line "epoch_ms code" every ~0.2 s
  [ -n "${PROBE_LOG:-}" ] || return 0
  ( while :; do c=$(curl -s -o /dev/null -w '%{http_code}' --max-time 1 ${CA:+--cacert "$CA"} https://office.ou-lab.internal/hosting/capabilities || true); echo "$(date +%s%3N) $c"; sleep 0.2; done ) > "$PROBE_LOG" 2>/dev/null &
  PROBE_PID=$!
}
probe_stop() { sleep 6; [ -n "${PROBE_PID:-}" ] && { kill "$PROBE_PID" 2>/dev/null || true; wait "$PROBE_PID" 2>/dev/null || true; }
  [ -n "${PROBE_LOG:-}" ] && awk '{ if ($2!="200") { if(!s) s=$1; e=$1; n++ } else if (s) { printf "external probe: non-200 from %d ms to %d ms after the first failure = %.1f s (%d failed probes); ", s, e, (e-s)/1000, n; s=0 } } END { if (s) printf "still failing at end; " ; print "" }' "$PROBE_LOG" || true; }

inner_pre() {
  set -e; ts=$(date -u +%Y%m%dT%H%M%SZ); bk=/var/backups/ou-docs-drill/$ts; mkdir -p "$bk"; chmod 700 /var/backups/ou-docs-drill "$bk"
  tar -cpf "$bk/config.tar" /etc/coolwsd /etc/systemd/system/coolwsd.service /etc/nginx/sites-enabled /etc/apt/sources.list.d /etc/apt/preferences.d 2>/dev/null
  dpkg -l | grep -E 'coolwsd|collaboraoffice|code-brand|ou-docs' | awk '{print $1,$2,$3}' > "$bk/dpkg.txt"; apt-mark showhold > "$bk/holds.txt"
  ( cd /opt/officeunbound-office && find . -type f -print0 | sort -z | xargs -0 sha256sum ) > "$bk/engine.sha256"
  ( cd / && sha256sum usr/bin/cool* usr/bin/loolwsd* ) > "$bk/bin.sha256"; ( cd /usr/share/coolwsd && find . -type f -print0 | sort -z | xargs -0 sha256sum ) > "$bk/share.sha256"
  systemctl is-enabled coolwsd > "$bk/coolwsd.enabled"; systemctl is-active coolwsd > "$bk/coolwsd.active" || true
  echo "$bk  engine tree $(sha256sum < "$bk/engine.sha256" | cut -c1-16) files $(wc -l < "$bk/engine.sha256"); share tree $(sha256sum < "$bk/share.sha256" | cut -c1-16) files $(wc -l < "$bk/share.sha256")"
}

inner_migrate() {  # args: version
  set -e; v=$1; t0=$(date +%s.%N)
  curl -fsS "$REPO_URL/ou-release-$CHANNEL.pub.asc" -o /tmp/ou-release.asc
  got=$(gpg --show-keys --with-colons /tmp/ou-release.asc | awk -F: '/^fpr/{print $10; exit}'); [ "$got" = "$KEY_FPR" ] || { echo "release key fingerprint mismatch: $got"; exit 1; }
  gpg --dearmor < /tmp/ou-release.asc > /usr/share/keyrings/ou-release-$CHANNEL.gpg
  echo "deb [signed-by=/usr/share/keyrings/ou-release-$CHANNEL.gpg] $REPO_URL $CHANNEL main" > /etc/apt/sources.list.d/office-unbound.list
  printf 'Package: ou-docs\nPin: version %s\nPin-Priority: 1001\n' "$v" > /etc/apt/preferences.d/office-unbound-pins
  apt-get update -qq
  apt-mark unhold coolwsd code-brand >/dev/null 2>&1 || true     # the vendor holds (AF) would make the dependency solver fail; ou-docs Conflicts/Replaces coolwsd
  apt-get install -y -qq --download-only --allow-change-held-packages "ou-docs=$v" >/dev/null     # while the node is still serving
  t1=$(date +%s.%N); systemctl stop coolwsd
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq -o Dpkg::Options::=--force-confold --allow-change-held-packages "ou-docs=$v" 2>&1 | tail -15
  apt-mark hold ou-docs >/dev/null
  # lab unit (user cool, loopback, hardening) now uses the package's /opt/cool work dirs (the postinst rebuilds /opt/cool/systemplate from the installed engine)
  cp /root/coolwsd.service.new /etc/systemd/system/coolwsd.service; systemctl daemon-reload; chown -R cool:cool /opt/cool
  systemctl enable coolwsd >/dev/null 2>&1 || true; systemctl start coolwsd; t2=$(date +%s.%N)
  for i in $(seq 1 120); do curl -fs http://[::1]:9980/hosting/capabilities >/dev/null 2>&1 && break; sleep 0.5; done; t3=$(date +%s.%N)
  printf 'TIMING prepare(download) %.1f s | service stopped for %.1f s (stop to start) | to capabilities answering %.1f s | total %.1f s\n' "$(awk "BEGIN{print $t1-$t0}")" "$(awk "BEGIN{print $t2-$t1}")" "$(awk "BEGIN{print $t3-$t1}")" "$(awk "BEGIN{print $t3-$t0}")"
}

inner_change() {  # args: version
  set -e; v=$1; t0=$(date +%s.%N)
  printf 'Package: ou-docs\nPin: version %s\nPin-Priority: 1001\n' "$v" > /etc/apt/preferences.d/office-unbound-pins
  apt-get update -qq
  apt-get install -y -qq --download-only --allow-downgrades --allow-change-held-packages "ou-docs=$v" >/dev/null     # a failed download must not leave the node down
  t1=$(date +%s.%N); systemctl stop coolwsd
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --allow-downgrades --allow-change-held-packages -o Dpkg::Options::=--force-confold "ou-docs=$v" 2>&1 | tail -15
  apt-mark hold ou-docs >/dev/null; chown -R cool:cool /opt/cool; systemctl daemon-reload; systemctl start coolwsd; t2=$(date +%s.%N)
  for i in $(seq 1 120); do curl -fs http://[::1]:9980/hosting/capabilities >/dev/null 2>&1 && break; sleep 0.5; done; t3=$(date +%s.%N)
  printf 'TIMING prepare(download) %.1f s | service stopped for %.1f s (stop to start) | to capabilities answering %.1f s | total %.1f s\n' "$(awk "BEGIN{print $t1-$t0}")" "$(awk "BEGIN{print $t2-$t1}")" "$(awk "BEGIN{print $t3-$t1}")" "$(awk "BEGIN{print $t3-$t0}")"
}

inner_status() {
  dpkg -l ou-docs coolwsd 2>&1 | tail -3 | cut -c1-80; apt-mark showhold; systemctl is-active coolwsd; systemctl is-enabled coolwsd ou-docs 2>&1 | tr '\n' ' '; echo
  curl -s http://[::1]:9980/hosting/capabilities | grep -o '"productName":"[^"]*","productVersion":"[^"]*"'
  ( cd /opt/officeunbound-office && find . -type f -print0 | sort -z | xargs -0 sha256sum ) | sha256sum | cut -c1-16
}

case "${1:-}" in
  pre)     run < <(declare -f inner_pre; echo inner_pre) ;;
  migrate) probe_start; run < <(echo "REPO_URL=$REPO_URL CHANNEL=$CHANNEL KEY_FPR=$FPR"; echo "cat > /root/coolwsd.service.new <<'OUEOF'"; cat "$BUILD/collabora/deploy/coolwsd.service"; echo OUEOF
           declare -f inner_migrate; echo "inner_migrate $2") || true; probe_stop ;;
  change)  probe_start; run < <(declare -f inner_change; echo "inner_change $2") || true; probe_stop ;;
  status)  run < <(declare -f inner_status; echo inner_status) ;;
  *) sed -n 2,10p "$0"; exit 2 ;;
esac
