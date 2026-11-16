#!/bin/bash
# A21 drill driver (ICS host): source-built groupware node -> signed packages, upgrade, rollback. Never touches the production ICS service or DB.
#   gw-pkg-upgrade.sh pre|migrate|status
#   gw-pkg-upgrade.sh change <gromox-version>        e.g. change 3.13-ou1  (rollback)  /  change 3.13-ou2  (roll forward)
# env: GW_MACHINE (ou-gw1)  REPO_URL (http://<ou-repo1 zone ip>:8077)  CHANNEL (stable)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd); BUILD=$HERE/../../build
M=${GW_MACHINE:-ou-gw1}; CHANNEL=${CHANNEL:-stable}; STATE=${OU_PKG_STATE:-/var/lib/office-unbound/pkgbuild}
: "${REPO_URL:?REPO_URL=http://<repo ip>:8077}"
FPR=$(cat "$BUILD/keys/ou-release-$CHANNEL.FINGERPRINT")
PKGS="ou-libhx ou-wmime ou-gromox ou-gromox-php-mapi ou-mapi-header-php ou-grommunio-sync ou-grommunio-dav ou-grommunio-web"
pin_versions() {   # latest version per package in the channel, gromox pair overridden by $1
  python3 - "$STATE/repo/dists/$CHANNEL/main/binary-amd64/Packages" "${1:-}" $PKGS <<'PY'
import re, sys, subprocess
txt, gv, pk = open(sys.argv[1]).read(), sys.argv[2], sys.argv[3:]
best = {}
for st in txt.split("\n\n"):
    d = dict(re.findall(r"^([A-Za-z-]+): (.*)$", st, re.M))
    if d.get("Package") in pk:
        v = d["Version"]
        if d["Package"] in ("ou-gromox", "ou-gromox-php-mapi") and gv:
            if v == gv:
                best[d["Package"]] = v
            continue
        if d["Package"] not in best or subprocess.run(["dpkg", "--compare-versions", v, "gt", best[d["Package"]]]).returncode == 0:
            best[d["Package"]] = v
print(" ".join("%s=%s" % (p, best[p]) for p in pk))
PY
}
BEARER_ISSUER=${BEARER_ISSUER:-https://auth.ou-lab.internal/realms/ou-lab}; BEARER_AUDIENCE=${BEARER_AUDIENCE:-ou-webmail}
run() { PINS=$1; phase=$2; sudo systemd-run -M "$M" --quiet --pipe --wait /bin/bash -c "export REPO_URL='$REPO_URL' CHANNEL='$CHANNEL' KEY_FPR='$FPR' PINS='$PINS' BEARER_ISSUER='$BEARER_ISSUER' BEARER_AUDIENCE='$BEARER_AUDIENCE'; bash -s $phase" < "$HERE/gw-pkg-inner.sh"; }
case "${1:-}" in
  pre) run "" pre ;;
  migrate) P=$(pin_versions); echo "pins: $P"; run "$P" migrate ;;
  change) P=$(pin_versions "${2:?gromox version}"); echo "pins: $P"; run "$P" change ;;
  status) run "" status ;;
  *) sed -n 2,6p "$0"; exit 2 ;;
esac
