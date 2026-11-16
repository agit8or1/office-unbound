#!/bin/bash
# One-time (idempotent) setup of the dedicated golden-image signer. Run as root:  sudo bash install-image-signer.sh
#   system user `ou-imgsign` (nologin), state /var/lib/ou-imgsign (0700): ECDSA P-256 key protected by a random passphrase file (0400),
#   /usr/local/sbin/ou-image-sign (root:root 0755), root-owned trust/test-runner.pub (the pipeline test runner's public key, copied from the release
#   signer's trust directory: install blueprints/build/repo/install-signer.sh first), and a sudoers drop-in naming EXACTLY three commands (no `*`, security review 6 H1):
#       sign, record-test, pubkey   (record-test takes an attestation on stdin that only the ou-testrunner identity can produce)
# Lab arrangement (same limits as repo/install-signer.sh: while the build user keeps NOPASSWD ALL this is separation of duties on paper;
# production = offline host / HSM, and the public key pin below is then re-confirmed by the owner).
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
HERE=$(cd "$(dirname "$0")" && pwd)
ST=/var/lib/ou-imgsign
BUILDUSER=${BUILD_USER:-administrator}
RUNNER_PUB_FILE=${OU_RUNNER_PUB_FILE:-/var/lib/ou-release/trust/test-runner.pub}
[ -s "$RUNNER_PUB_FILE" ] || { echo "no test-runner public key at $RUNNER_PUB_FILE: run blueprints/build/repo/install-signer.sh first"; exit 1; }
id ou-imgsign >/dev/null 2>&1 || useradd --system --home-dir "$ST" --create-home --shell /usr/sbin/nologin --comment "Office Unbound image signer" ou-imgsign
install -d -m 0700 -o ou-imgsign -g ou-imgsign "$ST" "$ST/records"
install -d -m 0755 -o root -g root "$ST/trust"
install -m 0644 -o root -g root "$RUNNER_PUB_FILE" "$ST/trust/test-runner.pub"
install -m 0755 -o root -g root "$HERE/ou-image-sign" /usr/local/sbin/ou-image-sign
if [ ! -s "$ST/passphrase" ]; then
  ( umask 077; head -c 32 /dev/urandom | base64 > "$ST/passphrase" )
  chown ou-imgsign:ou-imgsign "$ST/passphrase"; chmod 0400 "$ST/passphrase"
fi
if [ ! -s "$ST/key.pem" ]; then
  runuser -u ou-imgsign -- sh -c "umask 077; openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -aes-256-cbc -pass file:$ST/passphrase -out $ST/key.pem"
fi
{
  printf '%s ALL=(ou-imgsign) NOPASSWD: /usr/local/sbin/ou-image-sign sign\n' "$BUILDUSER"
  printf '%s ALL=(ou-imgsign) NOPASSWD: /usr/local/sbin/ou-image-sign record-test\n' "$BUILDUSER"
  printf '%s ALL=(ou-imgsign) NOPASSWD: /usr/local/sbin/ou-image-sign pubkey\n' "$BUILDUSER"
} > /etc/sudoers.d/ou-image-sign
chmod 0440 /etc/sudoers.d/ou-image-sign
visudo -cf /etc/sudoers.d/ou-image-sign >/dev/null
echo "installed; public key + pin:"
runuser -u ou-imgsign -- /usr/local/sbin/ou-image-sign pubkey
