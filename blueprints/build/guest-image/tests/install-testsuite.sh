#!/usr/bin/env bash
# Installs the independent image boot-test suite into the BOOT-TEST MACHINE (default the lab machine ou-img1, root-owned, NOT writable by the build user).
# Run as root on the ICS host from a reviewed checkout (never from the builder's output):
#   install-testsuite.sh [machine-root]     default /var/lib/machines/ou-img1   (a plain directory root; use "/" to install on the local system)
# The runner-side program `image-first-boot` (blueprints/build/guest-image/testrunner/, branch oci-signing) asks the root helper `image-boot-root` to boot the
# copy; that helper runs <machine>:/var/tmp/ou-guest-image/tests/image-boot-suite <image> and judges its exit status + SUMMARY line
# (docs/status/golden-image-prod-results.md "Integration with the attestor").
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
M=${1:-/var/lib/machines/ou-img1}
DST=$M/var/tmp/ou-guest-image/tests
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
install -d -m 0755 -o root -g root "$DST"
install -m 0644 -o root -g root "$HERE/icssim.py" "$HERE/staticchecks.py" "$HERE/tcprelay.py" "$DST/"
install -m 0755 -o root -g root "$HERE/image-boot-suite" "$DST/image-boot-suite"
(cd "$DST" && sha256sum image-boot-suite icssim.py staticchecks.py tcprelay.py)
echo "needed inside the machine: qemu-system-x86_64 qemu-img openssl e2fsprogs(debugfs) util-linux(sfdisk) python3-cryptography (checked by the suite itself: exit 2 if missing)"
