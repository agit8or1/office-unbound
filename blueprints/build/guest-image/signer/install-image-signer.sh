#!/bin/bash
# One-time (idempotent) setup of the dedicated golden-image signer. Run as root:  sudo bash install-image-signer.sh
#   system user `ou-imgsign` (nologin), state /var/lib/ou-imgsign (0700): ECDSA P-256 key protected by a random passphrase file (0400),
#   /usr/local/sbin/ou-image-sign (root:root 0755), sudoers drop-in allowing exactly `sudo -u ou-imgsign /usr/local/sbin/ou-image-sign *` to the build user.
# Lab arrangement (same limits as repo/install-signer.sh: while the build user keeps NOPASSWD ALL this is separation of duties on paper;
# production = offline host / HSM, and the public key pin below is then re-confirmed by the owner).
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
HERE=$(cd "$(dirname "$0")" && pwd)
ST=/var/lib/ou-imgsign
BUILDUSER=${BUILD_USER:-administrator}
id ou-imgsign >/dev/null 2>&1 || useradd --system --home-dir "$ST" --create-home --shell /usr/sbin/nologin --comment "Office Unbound image signer" ou-imgsign
install -d -m 0700 -o ou-imgsign -g ou-imgsign "$ST" "$ST/records"
install -m 0755 -o root -g root "$HERE/ou-image-sign" /usr/local/sbin/ou-image-sign
if [ ! -s "$ST/passphrase" ]; then
  ( umask 077; head -c 32 /dev/urandom | base64 > "$ST/passphrase" )
  chown ou-imgsign:ou-imgsign "$ST/passphrase"; chmod 0400 "$ST/passphrase"
fi
if [ ! -s "$ST/key.pem" ]; then
  runuser -u ou-imgsign -- sh -c "umask 077; openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -aes-256-cbc -pass file:$ST/passphrase -out $ST/key.pem"
fi
printf '%s ALL=(ou-imgsign) NOPASSWD: /usr/local/sbin/ou-image-sign *\n' "$BUILDUSER" > /etc/sudoers.d/ou-image-sign
chmod 0440 /etc/sudoers.d/ou-image-sign
visudo -cf /etc/sudoers.d/ou-image-sign >/dev/null
echo "installed; public key + pin:"
runuser -u ou-imgsign -- /usr/local/sbin/ou-image-sign pubkey
