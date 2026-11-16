#!/bin/bash
# One-time (idempotent) setup of the artifact test runner programs (review 6 H1 / review 7 H-3 model: the runner makes the evidence itself). Run as root:
#   sudo bash install-oci-runner.sh        (needs blueprints/build/repo/install-signer.sh first: that creates the user ou-testrunner and its key)
#   * the fixed test program /usr/local/lib/ou-testrunner/oci-scan for kind `oci-scan` of ou-test-attest (branch fixes-r7 interface: `ou-test-attest run oci-scan <repo>@sha256:<hex>`,
#     sudoers rule of install-signer.sh; the caller names the artifact, the runner pulls it, makes the SBOM and the OSV scan itself and signs what it observed)
#   * syft and osv-scanner at the versions and sha256 pinned in blueprints/build/tools.env, installed root-owned in /usr/local/lib/ou-testrunner
#     (downloaded from github.com releases, authorized read-only source; checksum verified before install).
#   * /etc/office-unbound/oci-registry is written by install-oci-signer.sh (the registry host:port the runner pulls from).
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
HERE=$(cd "$(dirname "$0")" && pwd)
BUILDUSER=${BUILD_USER:-administrator}
. "$HERE/../../tools.env"
id ou-testrunner >/dev/null 2>&1 || { echo "no user ou-testrunner: run blueprints/build/repo/install-signer.sh first"; exit 1; }
install -d -m 0755 -o root -g root /usr/local/lib/ou-testrunner
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
if [ ! -x /usr/local/lib/ou-testrunner/syft ]; then
  curl -fsSL --proto '=https' --tlsv1.2 -o "$T/syft.tgz" "$SYFT_URL"
  echo "$SYFT_SHA256  $T/syft.tgz" | sha256sum -c - >/dev/null || { echo "REFUSED: syft checksum mismatch"; exit 4; }
  tar -xzf "$T/syft.tgz" -C "$T" syft; install -m 0755 -o root -g root "$T/syft" /usr/local/lib/ou-testrunner/syft
fi
if [ ! -x /usr/local/lib/ou-testrunner/osv-scanner ]; then
  curl -fsSL --proto '=https' --tlsv1.2 -o "$T/osv" "$OSV_URL"
  echo "$OSV_SHA256  $T/osv" | sha256sum -c - >/dev/null || { echo "REFUSED: osv-scanner checksum mismatch"; exit 4; }
  install -m 0755 -o root -g root "$T/osv" /usr/local/lib/ou-testrunner/osv-scanner
fi
# The runner program itself (fixes-r7 interface plus kind oci-scan): this branch contains the whole of it, so it simply replaces ou-test-attest
# (set OU_TEST_ATTEST_DST to install it beside an older one on a host that has not rolled out fixes-r7 yet).
ATTEST_DST=${OU_TEST_ATTEST_DST:-/usr/local/sbin/ou-test-attest}
install -m 0755 -o root -g root "$HERE/../../repo/ou-test-attest" "$ATTEST_DST"
{
  printf '%s ALL=(ou-testrunner) NOPASSWD: %s run oci-scan *\n' "$BUILDUSER" "$ATTEST_DST"
  printf '%s ALL=(ou-testrunner) NOPASSWD: %s run image-first-boot *\n' "$BUILDUSER" "$ATTEST_DST"
} > /etc/sudoers.d/ou-artifact-attest
chmod 0440 /etc/sudoers.d/ou-artifact-attest; visudo -cf /etc/sudoers.d/ou-artifact-attest >/dev/null
install -m 0755 -o root -g root "$HERE/../testrunner/oci-scan" /usr/local/lib/ou-testrunner/oci-scan      # fixed program of kind oci-scan of ou-test-attest
echo "installed: oci-scan test program, syft $SYFT_VERSION, osv-scanner $OSV_VERSION"
