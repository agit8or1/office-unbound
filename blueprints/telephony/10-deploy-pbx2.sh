#!/usr/bin/env bash
# Run on the ICS host after 00-create-pbx2.sh. Pushes the provisioner/softphone files and the lab secrets (read from ou-pbx1's filesystem, root only,
# never printed) into ou-pbx2 and runs 20-install-from-repo.sh there.
#   REPO_URL    signed apt repo, e.g. http://192.168.186.185:8077  (blueprints/build/repo/repo.sh serve; builder ou-pkg1 must be running)
#   REPO_SUITE  channel (default dev)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; SPIKE="$HERE/../lab/spike-pbx"; BUILD="$HERE/../build"
n=ou-pbx2; M=/var/lib/machines; : "${REPO_URL:?}"; SUITE=${REPO_SUITE:-dev}
inm() { sudo systemd-run -M "$n" --pipe --wait --quiet "$@"; }
inm mkdir -p /root/stage/secrets; inm rm -rf /root/stage/pbx /root/stage/phone; inm mkdir -p /root/stage/secrets /root/stage/phone /root/stage/pbx
tar -C "$HERE/pbx" -cz . | inm tar -xz -C /root/stage/pbx
tar -C "$SPIKE/phone" -cz static phone_app.py | inm tar -xz -C /root/stage/phone
tar -C "$BUILD/keys" -c ou-release-$SUITE.pub.asc ou-release-$SUITE.FINGERPRINT | inm tar -x -C /root/stage
for s in ldap-bind.pw; do sudo cat "$M/ou-pbx1/etc/ou-pbx/$s" | inm bash -c "umask 077; cat > /root/stage/secrets/$s"; done
cat /etc/office-unbound/lab/gw1-ca.crt | inm bash -c 'cat > /root/stage/secrets/gw1-ca.crt'
cat "$HERE/20-install-from-repo.sh" | inm bash -c 'cat > /root/stage/20-install-from-repo.sh'
sudo systemd-run -M "$n" --pipe --wait env REPO_URL="$REPO_URL" REPO_SUITE="$SUITE" bash /root/stage/20-install-from-repo.sh
