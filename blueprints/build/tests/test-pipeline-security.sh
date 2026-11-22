#!/bin/bash
# Regression tests for security review 4 pipeline findings H1, H2, M7, M8 (artifact checks, signer program, promotion gate, Valid-Until).
# Self-contained sandbox: temp state/repo, own throw-away signing key WITH passphrase, no sudo, no builder, nothing outside the temp dir is touched.
#   tests/test-pipeline-security.sh        -> prints PASS/FAIL per check, exit 1 on any FAIL
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd); BUILD=$(cd "$HERE/.." && pwd)
T=$(mktemp -d); trap 'for g in "$T"/gh "$T"/signer/gnupg; do gpgconf --homedir "$g" --kill all 2>/dev/null; done; rm -rf "$T"' EXIT
export OU_PKG_STATE=$T/state OU_REPO_DIR=$T/state/repo OU_RELEASE_STATE=$T/signer GNUPGHOME=$T/gh
export OU_RELEASE_CMD="python3 -I $BUILD/repo/ou-release-sign"
export OU_TESTRUNNER_STATE=$T/runner OU_RELEASE_SANDBOX=1 OU_ATTEST_CMD="python3 -I $BUILD/repo/ou-test-attest"
MF="python3 $HERE/sandbox-manifest.py"
mkdir -p "$T/state/out/libhx/artifacts" "$T/state/repo" "$OU_RELEASE_STATE"/{ledger,records,promotions} "$T/gh" "$OU_RELEASE_STATE/gnupg"; chmod 700 "$T/gh" "$OU_RELEASE_STATE/gnupg"
fails=0; n=0
ok() { n=$((n+1)); echo "PASS $1"; }
bad() { n=$((n+1)); fails=$((fails+1)); echo "FAIL $1"; }
expect_refuse() { name=$1; shift; if "$@" >"$T/out.txt" 2>&1; then bad "$name (was accepted)"; sed 's/^/    /' "$T/out.txt" | head -3; else ok "$name"; fi; }
expect_ok() { name=$1; shift; if "$@" >"$T/out.txt" 2>&1; then ok "$name"; else bad "$name"; sed 's/^/    /' "$T/out.txt" | head -5; fi; }
CHK="python3 -I $BUILD/lib/artifact-check.py"
R=$BUILD/repo/repo.sh

# signer key with a passphrase (what install-signer.sh produces)
echo 'sandbox-passphrase' > "$OU_RELEASE_STATE/passphrase"; chmod 400 "$OU_RELEASE_STATE/passphrase"
printf 'default-cache-ttl 1\nmax-cache-ttl 1\n' > "$OU_RELEASE_STATE/gnupg/gpg-agent.conf"
GNUPGHOME=$OU_RELEASE_STATE/gnupg gpg --batch --pinentry-mode loopback --passphrase-file "$OU_RELEASE_STATE/passphrase" --quick-generate-key "Sandbox Signer <s@s>" ed25519 sign 1d >/dev/null 2>&1
FPR=$(GNUPGHOME=$OU_RELEASE_STATE/gnupg gpg --list-secret-keys --with-colons | awk -F: '/^fpr/{print $10; exit}'); echo "$FPR" > "$OU_RELEASE_STATE/FINGERPRINT"
GNUPGHOME=$OU_RELEASE_STATE/gnupg gpg --armor --export "$FPR" > "$T/pub.asc"
# review 5 H2: the signer trusts the ICS promotion key and the test runner key (root-owned in production; the sandbox is its own owner)
mkdir -p "$OU_RELEASE_STATE/trust"; chmod 755 "$OU_RELEASE_STATE/trust"
$MF init "$T/ics.key" "$OU_RELEASE_STATE/trust/ics-promotion.pub"
python3 -I "$BUILD/repo/ou-test-attest" keygen > "$OU_RELEASE_STATE/trust/test-runner.pub"; chmod 644 "$OU_RELEASE_STATE/trust/"*.pub
export GNUPGHOME=$OU_RELEASE_STATE/gnupg

# a minimal real .deb that satisfies the libhx recipe (Package ou-libhx, Version 4.28-ou1)
mkpkg() {  # name version outfile
  d=$(mktemp -d -p "$T"); mkdir -p "$d/DEBIAN" "$d/usr/share/doc/$1"; echo "${4:-hi}" > "$d/usr/share/doc/$1/x"
  printf 'Package: %s\nVersion: %s\nArchitecture: amd64\nMaintainer: t <t@t>\nDescription: t\n' "$1" "$2" > "$d/DEBIAN/control"
  dpkg-deb --root-owner-group -Znone --build "$d" "$3" >/dev/null
}
A=$T/state/out/libhx/artifacts
mkpkg ou-libhx 4.28-ou1 "$A/ou-libhx_4.28-ou1_amd64.deb"

echo "== H1: builder output is hostile"
expect_ok "clean artifact set accepted" $CHK verify "$A" libhx "$BUILD"
ln -s /etc/hostname "$A/x.deb"
expect_refuse "H1 verify: planted x.deb symlink to a host file" $CHK verify "$A" libhx "$BUILD"
expect_refuse "H1 publish: planted symlink never reaches the pool" $R publish libhx
[ -z "$(ls "$T/state/repo/pool/dev/libhx" 2>/dev/null | grep x.deb)" ] && ok "H1 publish: nothing from the symlink was copied" || bad "H1 publish: symlink target copied into the pool"
rm "$A/x.deb"
ln "$A/ou-libhx_4.28-ou1_amd64.deb" "$T/second-name.deb"
expect_refuse "H1 verify: hard-linked artifact (link count 2)" $CHK verify "$A" libhx "$BUILD"
rm "$T/second-name.deb"
printf 'not a deb' > "$A/junk.deb"
expect_refuse "H1 verify: file named .deb that dpkg-deb cannot parse" $CHK verify "$A" libhx "$BUILD"
rm "$A/junk.deb"
mkpkg ou-evil 4.28-ou1 "$A/ou-evil_4.28-ou1_amd64.deb"
expect_refuse "H1 verify: .deb whose Package is not in the recipe" $CHK verify "$A" libhx "$BUILD"
rm "$A/ou-evil_4.28-ou1_amd64.deb"
mkpkg ou-libhx 9.9-ou1 "$A/ou-libhx_9.9-ou1_amd64.deb"
expect_refuse "H1 verify: .deb with unexpected Version" $CHK verify "$A" libhx "$BUILD"
rm "$A/ou-libhx_9.9-ou1_amd64.deb"
# tar stream attacks against `extract`
X=$T/x; mkdir -p "$X"; ( cd "$X" && ln -s /etc/hostname evil.deb && tar -c evil.deb ) > "$T/sym.tar"
expect_refuse "H1 extract: tar with a symlink member" bash -c "$CHK extract $T/ex1 libhx $BUILD < $T/sym.tar"
( cd "$X" && rm evil.deb && mkdir sub && cp "$A/ou-libhx_4.28-ou1_amd64.deb" sub/ && tar -c sub/ou-libhx_4.28-ou1_amd64.deb ) > "$T/nest.tar"
expect_refuse "H1 extract: tar with a nested path" bash -c "$CHK extract $T/ex2 libhx $BUILD < $T/nest.tar"
( cd "$X" && tar -c --transform='s,^,../,' sub/ou-libhx_4.28-ou1_amd64.deb ) > "$T/dotdot.tar" 2>/dev/null
expect_refuse "H1 extract: tar with a .. path" bash -c "$CHK extract $T/ex3 libhx $BUILD < $T/dotdot.tar"
( cd "$A" && tar -c ./ou-libhx_4.28-ou1_amd64.deb ) > "$T/good.tar"
expect_ok "H1 extract: honest tar accepted" bash -c "$CHK extract $T/ex4 libhx $BUILD < $T/good.tar"
[ ! -e "$T/ex1" ] && ok "H1 extract: rejected extraction leaves no directory behind" || bad "H1 extract: leftovers"

echo "== M7/H2/M8: signer, ledger, promotion gate, Valid-Until"
expect_ok "publish of the clean set (admit to dev ledger, sign dev)" $R publish libhx
D=$T/state/repo/dists/dev
if GNUPGHOME=$T/verify bash -c "mkdir -m700 $T/verify; gpg --batch --import $T/pub.asc 2>/dev/null; gpg --batch --verify $D/InRelease 2>&1 | grep -q 'Good signature'"; then ok "InRelease verifies against the signer's public key"; else bad "InRelease does not verify"; fi
vu=$(sed -n 's/^Valid-Until: //p' "$D/Release"); [ -n "$vu" ] && ok "M8 Release carries Valid-Until ($vu)" || bad "M8 Release has no Valid-Until"
python3 - "$vu" <<'PY' && ok "M8 Valid-Until is about 14 days ahead" || bad "M8 Valid-Until not ~14 days ahead"
import sys, datetime
t = datetime.datetime.strptime(sys.argv[1], "%a, %d %b %Y %H:%M:%S UTC")
d = (t - datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)).total_seconds() / 86400
sys.exit(0 if 13 < d < 15 else 1)
PY
grep -q 'protected-private-key' "$OU_RELEASE_STATE"/gnupg/private-keys-v1.d/*.key && ok "H2 signing key file is passphrase-protected" || bad "H2 key is unprotected"
mv "$OU_RELEASE_STATE/passphrase" "$OU_RELEASE_STATE/passphrase.good"; echo wrong > "$OU_RELEASE_STATE/passphrase"; sleep 2
expect_refuse "H2 signing with a wrong passphrase fails" $R index dev
mv "$OU_RELEASE_STATE/passphrase.good" "$OU_RELEASE_STATE/passphrase"

mf() { $MF make "$T/ics.key" "$1" "$2" libhx "$T/state/repo/pool/$1/libhx" "$OU_RELEASE_STATE" "$3" requester-id > "$T/m.json"; }
expect_refuse "H2 the old CLI promote path (typed approver name) is gone" $R promote dev staging libhx --approved-by "Somebody"
mf dev staging ap1
expect_refuse "M7 promote without any test record" $R promote-manifest "$T/m.json"
H=$(sha256sum "$T/state/repo/pool/dev/libhx/ou-libhx_4.28-ou1_amd64.deb" | cut -d' ' -f1)
echo log > "$T/log.txt"
expect_ok "record a FAILED test" $R record-test libhx install-smoke fail "$T/log.txt"
mf dev staging ap1
expect_refuse "M7 promote after a recorded failure" $R promote-manifest "$T/m.json"
expect_ok "record a passing test" $R record-test libhx install-smoke pass "$T/log.txt"
mf dev staging requester-id
expect_refuse "H2 the requester cannot be the approver" $R promote-manifest "$T/m.json"
mf dev staging ap1
expect_ok "promote dev>staging with a passing record and an ICS-signed manifest" $R promote-manifest "$T/m.json"
expect_refuse "H2 a manifest is single use (replay)" $R promote-manifest "$T/m.json"
mf staging stable ap1
expect_refuse "M7 promote to stable with ONE approver" $R promote-manifest "$T/m.json"
mf staging stable ap1,ap2
expect_ok "promote staging>stable with two ICS approvers" $R promote-manifest "$T/m.json"
ls "$OU_RELEASE_STATE/promotions"/*.asc >/dev/null 2>&1 && ok "M7 signed promotion records written" || bad "M7 no signed promotion record"
# unadmitted file dropped straight into a pool, then the index is signed
mkdir -p "$T/state/repo/pool/stable/rogue"; mkpkg ou-rogue 1 "$T/state/repo/pool/stable/rogue/ou-rogue_1_amd64.deb"
expect_refuse "M7 index refuses a pool file that was never promoted (cp into the pool + index)" $R index stable
rm -rf "$T/state/repo/pool/stable/rogue"; expect_ok "index works again without the rogue file" $R index stable
# swap content of an admitted file (same name, different bytes) in the dev pool: promotion must notice (ledger is by hash)
cp "$T/state/repo/pool/dev/libhx/ou-libhx_4.28-ou1_amd64.deb" "$T/orig.deb"
mkpkg ou-libhx 4.28-ou1 "$T/state/repo/pool/dev/libhx/ou-libhx_4.28-ou1_amd64.deb" "different content"
mf dev staging ap1
expect_refuse "M7 swapped .deb content (TOCTOU / tamper in the pool) is not promotable" $R promote-manifest "$T/m.json"
echo
echo "== $((n - fails)) PASS, $fails FAIL of $n"
[ "$fails" = 0 ]
