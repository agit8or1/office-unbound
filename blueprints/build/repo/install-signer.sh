#!/bin/bash
# One-time (idempotent) setup of the dedicated release signer (security review 4, H2/M7/M8). Run as root:  sudo bash install-signer.sh
#   * system user `ou-release` (nologin, home /var/lib/ou-release)
#   * the existing lab release key (fingerprint stays 5D2750D022E0218361518491CE58A8B691F84C1B, public key unchanged) is MOVED from
#     /etc/office-unbound/release/gnupg (passphrase-less) into /var/lib/ou-release/gnupg and protected with a random passphrase kept in
#     /var/lib/ou-release/passphrase (0400 ou-release); the old home is shredded
#   * the revocation certificate is moved OUT of the key directory to /root/ou-release-revocation-<fpr>.asc (root 0600): the owner copies it offline
#   * /usr/local/sbin/ou-release-sign (root:root 0755, not writable by the build user) + sudoers drop-in allowing exactly that program, as user ou-release
#   * ledgers and test records are seeded ONCE from the pool that the previous (old key) signed, so the existing channels keep working
# Review 5 H1/H2: the signer rebuilds what it signs (no caller header), promotions need an ICS-signed manifest (trust/ics-promotion.pub, root-owned),
# test records need an attestation of the test runner (user ou-testrunner, program /usr/local/sbin/ou-test-attest, trust/test-runner.pub).
#   usage: sudo OU_ICS_PROMOTION_PUB=<file with the ICS signing public key, base64 raw> bash install-signer.sh   (re-run to re-install after every change of the programs)
#   the ICS public key is printed by `ics-cli signing-pubkey` (or: python -c from ics.agentclient.pub_b64); without it promotions stay refused.
# Limits (see docs/status/package-pipeline-results.md): while `administrator` keeps `NOPASSWD: ALL` sudo this is separation of duties on paper only
# (the same user can still `sudo -u ou-release gpg ...` or read the passphrase file). The sudoers drop-in is what remains once that rule is removed.
# Production signing must be offline / HSM / a separate host; this is the lab arrangement.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
HERE=$(cd "$(dirname "$0")" && pwd)
ST=/var/lib/ou-release; OLD=/etc/office-unbound/release/gnupg
BUILD_STATE=${OU_PKG_STATE:-/var/lib/office-unbound/pkgbuild}
id ou-release >/dev/null 2>&1 || useradd --system --home-dir "$ST" --create-home --shell /usr/sbin/nologin --comment "Office Unbound release signer" ou-release
install -d -m 0755 -o ou-release -g ou-release "$ST" "$ST/ledger" "$ST/records" "$ST/promotions"
install -d -m 0700 -o ou-release -g ou-release "$ST/gnupg"
install -m 0755 -o root -g root "$HERE/ou-release-sign" /usr/local/sbin/ou-release-sign
install -m 0755 -o root -g root "$HERE/ou-test-attest" /usr/local/sbin/ou-test-attest
id ou-testrunner >/dev/null 2>&1 || useradd --system --home-dir /var/lib/ou-testrunner --create-home --shell /usr/sbin/nologin --comment "Office Unbound pipeline test runner" ou-testrunner
install -d -m 0700 -o ou-testrunner -g ou-testrunner /var/lib/ou-testrunner
install -d -m 0755 -o root -g root "$ST/trust"          # public keys the signer trusts: root-owned, never writable by the signer or the build user
RUNNER_PUB=$(runuser -u ou-testrunner -- /usr/local/sbin/ou-test-attest keygen)
printf '%s\n' "$RUNNER_PUB" > "$ST/trust/test-runner.pub"; chown root:root "$ST/trust/test-runner.pub"; chmod 0644 "$ST/trust/test-runner.pub"
if [ -n "${OU_ICS_PROMOTION_PUB:-}" ]; then
  python3 -c 'import base64,sys; assert len(base64.b64decode(open(sys.argv[1]).read().strip(), validate=True))==32' "$OU_ICS_PROMOTION_PUB" || { echo "OU_ICS_PROMOTION_PUB is not a base64 raw ed25519 key"; exit 1; }
  install -m 0644 -o root -g root "$OU_ICS_PROMOTION_PUB" "$ST/trust/ics-promotion.pub"
fi
[ -s "$ST/trust/ics-promotion.pub" ] || echo "NOTE: no ICS promotion key installed yet: dev>staging>stable promotions are refused until OU_ICS_PROMOTION_PUB is given"
printf 'default-cache-ttl 1\nmax-cache-ttl 1\n' > "$ST/gnupg/gpg-agent.conf"; chown ou-release:ou-release "$ST/gnupg/gpg-agent.conf"
if [ ! -s "$ST/passphrase" ]; then umask 077; head -c 32 /dev/urandom | base64 > "$ST/passphrase"; chown ou-release:ou-release "$ST/passphrase"; chmod 0400 "$ST/passphrase"; fi
AS() { runuser -u ou-release -- env GNUPGHOME="$ST/gnupg" "$@"; }
if ! AS gpg --list-secret-keys --with-colons 2>/dev/null | grep -q '^sec'; then
  [ -d "$OLD" ] || { echo "no old key home and no key in $ST/gnupg"; exit 1; }
  FPR=$(gpg --homedir "$OLD" --list-secret-keys --with-colons | awk -F: '/^fpr/{print $10; exit}')
  gpg --homedir "$OLD" --batch --pinentry-mode loopback --passphrase '' --export-secret-keys "$FPR" | AS gpg --batch --pinentry-mode loopback --passphrase '' --import
  AS gpg --batch --yes --pinentry-mode loopback --passphrase-file "$ST/passphrase" --change-passphrase "$FPR"
  echo "$FPR" > "$ST/FINGERPRINT"; chown ou-release:ou-release "$ST/FINGERPRINT"
  echo "install-signer self-test" | AS gpg --batch --pinentry-mode loopback --passphrase-file "$ST/passphrase" --local-user "$FPR" --clearsign >/dev/null \
    || { echo "signing with the protected key FAILED: old key home kept"; exit 1; }
  # revocation certificate: out of the key directory, to the owner (offline copy), then shred the old key home
  REV=$(ls "$OLD"/openpgp-revocs.d/*.rev 2>/dev/null | head -1 || true)
  if [ -n "$REV" ]; then install -m 0600 "$REV" "/root/ou-release-revocation-$FPR.asc"; fi
  find "$OLD" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf "$OLD"
  AS find "$ST/gnupg/openpgp-revocs.d" -type f -name '*.rev' -delete 2>/dev/null || true
fi
FPR=$(cat "$ST/FINGERPRINT")
# the private key file must now be passphrase-protected
grep -qr 'protected-private-key' "$ST/gnupg/private-keys-v1.d" || { echo "key is NOT protected"; exit 1; }
# one-time seed of ledgers and test records from the existing (old-key-signed) pool and records
if [ ! -e "$ST/.seeded" ]; then
  for s in dev staging stable; do
    for f in "$BUILD_STATE"/repo/pool/$s/*/*; do [ -f "$f" ] && [ ! -L "$f" ] && echo "$(sha256sum "$f" | cut -d' ' -f1)  $(basename "$f")  seed"; done > "$ST/ledger/$s.sha256" 2>/dev/null || true
    chown ou-release:ou-release "$ST/ledger/$s.sha256"
  done
  python3 - "$BUILD_STATE/records/tests" "$ST/records" <<'PY'
import json, os, sys, shutil
src, dst = sys.argv[1:3]
for f in os.listdir(src) if os.path.isdir(src) else []:
    d = json.load(open(os.path.join(src, f)))
    json.dump({"sha256": d["sha256"], "results": d["results"], "seeded": True}, open(os.path.join(dst, f), "w"), indent=1)
PY
  chown -R ou-release:ou-release "$ST/records"; touch "$ST/.seeded"
fi
# sudoers: exactly one program, as exactly one user
cat > /etc/sudoers.d/ou-release <<'E'
# Office Unbound release signer: the build user may run the signing program as ou-release, nothing else as that user
administrator ALL=(ou-release) NOPASSWD: /usr/local/sbin/ou-release-sign
administrator ALL=(ou-testrunner) NOPASSWD: /usr/local/sbin/ou-test-attest
E
chmod 0440 /etc/sudoers.d/ou-release; visudo -cf /etc/sudoers.d/ou-release
echo "signer ready: key $FPR, state $ST"
