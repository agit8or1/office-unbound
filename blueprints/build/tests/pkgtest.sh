#!/bin/bash
# Install + signature-enforcement + smoke test of a channel of the signed Office Unbound repo on a FRESH machine.
#   pkgtest.sh <suite> <package...>     e.g. pkgtest.sh dev ou-gromox ou-gromox-php-mapi
# Creates ou-pkgtest1 (clone of the Debian 12 base, MemoryMax=2G, zone oulab) from scratch each run, adds ONLY our
# repo (signed-by, fingerprint-checked key), installs, runs tamper + smoke tests. The repo is served by repo.sh serve on the
# zone bridge address only. Writes the log to $STATE/out/pkgtest-<suite>.log and exits non-zero on any failure.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd); BUILD=$(cd "$HERE/.." && pwd)
# shellcheck disable=SC1091
. "$BUILD/tools.env"
STATE=${OU_PKG_STATE:-/var/lib/office-unbound/pkgbuild}
SUITE=$1; shift
PKGS="$*"
LOG=$STATE/out/pkgtest-$SUITE.log
FPR=$(cat "$BUILD/keys/ou-release-lab.FINGERPRINT")
exec > >(tee "$LOG") 2>&1
inm() { sudo systemd-run -M "$TESTER" --wait --pipe -q /bin/bash -c "$1"; }

echo "== pkgtest $(date -u +%FT%TZ) suite=$SUITE packages=$PKGS key=$FPR"
# fresh tester
sudo machinectl terminate "$TESTER" 2>/dev/null || true; sleep 2
sudo machinectl remove "$TESTER" 2>/dev/null || true
sudo machinectl clone "$BUILDER_BASE" "$TESTER"
printf '[Exec]\nBoot=yes\nPrivateUsers=pick\n[Network]\nZone=oulab\n' | sudo tee "/etc/systemd/nspawn/$TESTER.nspawn" >/dev/null
sudo machinectl start "$TESTER"; sudo systemctl set-property "systemd-nspawn@$TESTER.service" MemoryMax="$TESTER_MEM"
sleep 10
"$BUILD/repo/repo.sh" serve
IP=$(ip -4 -o addr show | awk '/vz-oulab/ && !/169\.254/ {split($4,a,"/"); print a[1]; exit}')
inm "apt-get update -q >/dev/null 2>&1; apt-get install -y -q --no-install-recommends gnupg ca-certificates curl python3 >/dev/null 2>&1; echo base ready"
# ship public key + guest script (tester never sees the private key)
tar -C "$BUILD/keys" -c ou-release-lab.pub.asc | sudo systemd-run -M "$TESTER" --wait --pipe -q /bin/bash -c 'tar -C /tmp -x'
tar -C "$HERE" -c pkgtest-guest.sh | sudo systemd-run -M "$TESTER" --wait --pipe -q /bin/bash -c 'tar -C /root -x'
echo "== 1. add only our signed repo, install"
inm "bash /root/pkgtest-guest.sh setup http://$IP:8077 $SUITE $FPR"
inm "bash /root/pkgtest-guest.sh install $PKGS"
echo "== 2. signature enforcement (file:// copies of the same repo, tampered)"
tar -C "$STATE/repo" -c . | sudo systemd-run -M "$TESTER" --wait --pipe -q /bin/bash -c 'rm -rf /tmp/ou-repo-good; mkdir -p /tmp/ou-repo-good; tar -C /tmp/ou-repo-good -x'
rc=0
inm "bash /root/pkgtest-guest.sh tamper $SUITE" || rc=1
echo "== 3. smoke test"
inm "bash /root/pkgtest-guest.sh smoke" || rc=1
echo "== done rc=$rc"
"$BUILD/repo/repo.sh" unserve || true
exit $rc
