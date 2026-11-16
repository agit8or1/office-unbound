#!/bin/bash
# One-time (idempotent) setup of the dedicated OCI image signer. Run as root:  sudo OU_OCI_REGISTRY=<host:port> bash install-oci-signer.sh
#   system user `ou-ocisign` (nologin), state /var/lib/ou-ocisign (0700): ECDSA P-256 key protected by a random passphrase file (0400); neither is readable
#   by the build user (administrator) except through the root escalation the lab still has (see the limits note below).
#   /usr/local/sbin/ou-oci-sign (root:root 0755); root-owned trust/ directory: test-runner.pub (copied from the release signer's trust dir),
#   ics-promotion.pub (copied from there when present: staging/stable signing needs it), registry (host:port as written in image references);
#   sudoers drop-in with EXACT commands (no `*`):  sign, pubkey dev|staging|stable. One signing key per channel.
# Install blueprints/build/repo/install-signer.sh first (creates the test runner and its key).
# Lab arrangement (same limits as the other signers): while the build user keeps NOPASSWD ALL, separation of duties is on paper; production = separate host / HSM.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
HERE=$(cd "$(dirname "$0")" && pwd)
ST=/var/lib/ou-ocisign
BUILDUSER=${BUILD_USER:-administrator}
REL=${OU_RELEASE_TRUST_DIR:-/var/lib/ou-release/trust}
REG=${OU_OCI_REGISTRY:-}
[ -s "$REL/test-runner.pub" ] || { echo "no $REL/test-runner.pub: run blueprints/build/repo/install-signer.sh first"; exit 1; }
if [ -z "$REG" ] && [ -s "$ST/trust/registry" ]; then REG=$(cat "$ST/trust/registry"); fi
[[ "$REG" =~ ^[A-Za-z0-9.-]+(:[0-9]{1,5})?$ ]] || { echo "set OU_OCI_REGISTRY=<host:port> of the image registry"; exit 1; }
id ou-ocisign >/dev/null 2>&1 || useradd --system --home-dir "$ST" --create-home --shell /usr/sbin/nologin --comment "Office Unbound OCI image signer" ou-ocisign
install -d -m 0700 -o ou-ocisign -g ou-ocisign "$ST" "$ST/records"
install -d -m 0755 -o root -g root "$ST/trust"
install -m 0644 -o root -g root "$REL/test-runner.pub" "$ST/trust/test-runner.pub"
[ ! -s "$REL/ics-promotion.pub" ] || install -m 0644 -o root -g root "$REL/ics-promotion.pub" "$ST/trust/ics-promotion.pub"
printf '%s\n' "$REG" > "$ST/trust/registry"; chown root:root "$ST/trust/registry"; chmod 0644 "$ST/trust/registry"
install -m 0755 -o root -g root "$HERE/ou-oci-sign" /usr/local/sbin/ou-oci-sign
for C in dev staging stable; do      # one key and one passphrase per channel (review 7): a dev signature never verifies on a staging/stable host
  if [ ! -s "$ST/passphrase-$C" ]; then
    ( umask 077; head -c 32 /dev/urandom | base64 > "$ST/passphrase-$C" )
    chown ou-ocisign:ou-ocisign "$ST/passphrase-$C"; chmod 0400 "$ST/passphrase-$C"
  fi
  if [ ! -s "$ST/key-$C.pem" ]; then
    runuser -u ou-ocisign -- sh -c "umask 077; openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -aes-256-cbc -pass file:$ST/passphrase-$C -out $ST/key-$C.pem"
  fi
done
install -d -m 0755 -o root -g root /etc/office-unbound
printf '%s\n' "$REG" > /etc/office-unbound/oci-registry; chmod 0644 /etc/office-unbound/oci-registry     # read by the test runner (ou-artifact-attest)
{
  printf '%s ALL=(ou-ocisign) NOPASSWD: /usr/local/sbin/ou-oci-sign sign\n' "$BUILDUSER"
  for C in dev staging stable; do printf '%s ALL=(ou-ocisign) NOPASSWD: /usr/local/sbin/ou-oci-sign pubkey %s\n' "$BUILDUSER" "$C"; done
} > /etc/sudoers.d/ou-oci-sign
chmod 0440 /etc/sudoers.d/ou-oci-sign
visudo -cf /etc/sudoers.d/ou-oci-sign >/dev/null
[ -s "$ST/trust/ics-promotion.pub" ] || echo "NOTE: no ICS promotion key in trust/: staging/stable signing is refused until install-signer.sh was run with OU_ICS_PROMOTION_PUB and this script re-run"
for C in dev staging stable; do echo "installed; $C public key + pin:"; runuser -u ou-ocisign -- /usr/local/sbin/ou-oci-sign pubkey $C; done
