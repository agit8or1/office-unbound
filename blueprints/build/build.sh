#!/bin/bash
# Office Unbound package builder (ADR-0008). Run on the ICS host as the operator user (uses sudo for machinectl/systemd-run).
#   build.sh <component|all>        fetch+verify -> licence check -> build in the clean builder -> SBOM -> vuln scan
#   build.sh prepare                create/refresh the builder machine (ou-pkg1)
#   build.sh fetch|license|compile|sbom|scan <component>   single stages
# State: $OU_PKG_STATE (default /var/lib/office-unbound/pkgbuild): src/ (clones), in/ (orig tarballs), out/<component>/ (results)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091
. "$HERE/tools.env"
STATE=${OU_PKG_STATE:-/var/lib/office-unbound/pkgbuild}
ORDER="libhx wmime gromox mapi-header-php grommunio-sync grommunio-dav grommunio-web admin-api asterisk"
mkdir -p "$STATE"/{src,in,out,tools,dl}

log() { echo "[$(date +%T)] $*"; }
inb() { sudo systemd-run -M "$BUILDER" --wait --pipe -q /bin/bash -c "$1"; }   # run a command inside the builder
rv() { python3 -I "$HERE/lib/recipe.py" "$@"; }

ensure_builder() {
  if ! sudo machinectl show "$BUILDER" >/dev/null 2>&1; then
    if [ ! -d "/var/lib/machines/$BUILDER" ]; then sudo machinectl clone "$BUILDER_BASE" "$BUILDER"; fi
    printf '[Exec]\nBoot=yes\nPrivateUsers=pick\n[Network]\nZone=oulab\n' | sudo tee "/etc/systemd/nspawn/$BUILDER.nspawn" >/dev/null
    sudo machinectl start "$BUILDER"; sleep 8
  fi
  sudo systemctl set-property "systemd-nspawn@$BUILDER.service" MemoryMax="$BUILDER_MEM"
}

prepare() {
  ensure_builder
  tar -C "$HERE/lib" -c builder-inner.sh | sudo systemd-run -M "$BUILDER" --wait --pipe -q /bin/bash -c 'mkdir -p /build && tar -C /build -x'
  inb "export NODESOURCE_KEY_URL='$NODESOURCE_KEY_URL' NODESOURCE_KEY_FPR='$NODESOURCE_KEY_FPR' NODE_PKG_VERSION='$NODE_PKG_VERSION'; bash /build/builder-inner.sh prepare"
  inb 'cat /build/builder-manifest.txt' > "$STATE/out/builder-manifest.txt"
}

fetch_tarball() {  # upstream release tarball: sha256 pin + detached OpenPGP signature verified against a pinned key fingerprint
  c=$1; d=$STATE/src/$SRC_NAME; dl=$STATE/dl/$c; mkdir -p "$dl"
  tb=$dl/$(basename "$TARBALL_URL"); sg=$dl/$(basename "$SIG_URL")
  [ -f "$tb" ] || curl -fsSL --max-time 600 -o "$tb" "$TARBALL_URL"
  [ -f "$sg" ] || curl -fsSL --max-time 120 -o "$sg" "$SIG_URL"
  got=$(sha256sum "$tb" | cut -d' ' -f1)
  [ "$got" = "$TARBALL_SHA256" ] || { echo "FETCH FAIL $c: tarball sha256 $got != pinned $TARBALL_SHA256"; exit 1; }
  gh=$(mktemp -d); chmod 700 "$gh"
  gpg --homedir "$gh" --batch --quiet --import "$HERE/$SIGNING_KEY" 2>/dev/null
  have=$(gpg --homedir "$gh" --with-colons --list-keys | awk -F: '/^fpr/{print $10}' | tr '\n' ' ')
  case " $have" in *" $SIGFPR "*) ;; *) echo "FETCH FAIL $c: pinned key file does not contain fingerprint $SIGFPR (has: $have)"; rm -rf "$gh"; exit 1;; esac
  raw=$(gpg --homedir "$gh" --batch --status-fd 1 --verify "$sg" "$tb" 2>/dev/null || true); rm -rf "$gh"
  echo "$raw" | grep -q '^\[GNUPG:\] GOODSIG' || { echo "FETCH FAIL $c: signature not GOOD: $raw"; exit 1; }
  echo "$raw" | grep -q "^\[GNUPG:\] VALIDSIG $SIGFPR " || { echo "FETCH FAIL $c: not made by the pinned primary key $SIGFPR: $raw"; exit 1; }
  SDE=$(echo "$raw" | awk '/VALIDSIG/{print $5}')       # signature creation time = SOURCE_DATE_EPOCH
  rm -rf "$d"; mkdir -p "$d"; tar -xzf "$tb" -C "$d" --strip-components=1
  mkdir -p "$STATE/in/$c" "$STATE/out/$c"
  gzip -dc "$tb" | xz -9e -T1 -c > "$STATE/in/$c/orig.tar.xz"   # same content, deterministic container
  { echo "component=$c"; echo "repo=$REPO"; echo "tag=$TAG"; echo "commit=$COMMIT"; echo "source_date_epoch=$SDE"
    echo "signature=valid OpenPGP (GOODSIG+VALIDSIG, primary key $SIGFPR) over the release tarball; sha256 pin ok"
    echo "tarball_sha256=$got"; echo "orig_sha256=$(sha256sum "$STATE/in/$c/orig.tar.xz" | cut -d' ' -f1)"; } > "$STATE/out/$c/source.info"
  log "fetch $c: tarball sha256 ok, OpenPGP signature valid (key $SIGFPR), SDE=$SDE"
}

fetch() {  # clone pinned tag, verify tag object + commit SHA + signature, export deterministic orig tarball
  c=$1; eval "$(rv vars "$c")"
  if [ "$SRC_KIND" = tarball ]; then fetch_tarball "$c"; return; fi
  d=$STATE/src/$SRC_NAME
  [ -d "$d/.git" ] || git clone -q --branch "$TAG" "$REPO" "$d" 2>/dev/null
  git -C "$d" fetch -q --tags origin 2>/dev/null || true
  got=$(git -C "$d" rev-parse "refs/tags/$TAG^{commit}")
  [ "$got" = "$COMMIT" ] || { echo "FETCH FAIL $c: tag $TAG resolves to $got, recipe pins $COMMIT"; exit 1; }
  if [ -n "$TAG_OBJECT" ]; then
    obj=$(git -C "$d" rev-parse "refs/tags/$TAG")
    [ "$obj" = "$TAG_OBJECT" ] || { echo "FETCH FAIL $c: tag object $obj != pinned $TAG_OBJECT"; exit 1; }
  fi
  sig=none
  if [ "$VERKIND" = pgp-tag ]; then
    raw=$(git -C "$d" verify-tag --raw "refs/tags/$TAG" 2>&1 || true)
    keyid=$(echo "$raw" | awk '/ERRSIG|VALIDSIG/ {for(i=1;i<=NF;i++) if ($i ~ /^[0-9A-F]{16}$/ || $i ~ /^[0-9A-F]{40}$/) {print $i; exit}}')
    case "$SIGFPR" in *"$keyid") ;; *) echo "FETCH FAIL $c: tag signed by key '${keyid:-none}', pinned signer $SIGFPR"; exit 1;; esac
    if echo "$raw" | grep -q GOODSIG; then sig="valid (key in keyring)"; else sig="signed by pinned key id $keyid (signature NOT cryptographically verified: public key not available from an authorized endpoint)"; fi
  fi
  SDE=$(git -C "$d" log -1 --format=%ct "$COMMIT")
  mkdir -p "$STATE/in/$c"
  git -C "$d" archive --format=tar --prefix="$SRC_NAME-$UPSTREAM_VERSION/" "$COMMIT" | xz -9e -T1 -c > "$STATE/in/$c/orig.tar.xz"
  mkdir -p "$STATE/out/$c"
  { echo "component=$c"; echo "repo=$REPO"; echo "tag=$TAG"; echo "commit=$COMMIT"; echo "source_date_epoch=$SDE"
    echo "signature=$sig"; echo "orig_sha256=$(sha256sum "$STATE/in/$c/orig.tar.xz" | cut -d' ' -f1)"; } > "$STATE/out/$c/source.info"
  log "fetch $c: commit $COMMIT ok, signature: $sig, SDE=$SDE"
}

bundled_sources() {  # statically bundled third-party source tarballs (recipe bundled_sources): sha256-verified, unpacked into the scan tree
  c=$1
  python3 -I "$HERE/lib/recipe.py" bundled "$c" | while read -r name url sha; do
    f=$STATE/dl/$c/$(basename "$url"); mkdir -p "$STATE/dl/$c"; [ -f "$f" ] || curl -fsSL --max-time 300 -o "$f" "$url"
    [ "$(sha256sum "$f" | cut -d' ' -f1)" = "$sha" ] || { echo "BUNDLED SOURCE sha256 mismatch: $name"; exit 1; }
    mkdir -p "$STATE/src/$SRC_NAME/_bundled/$name"; tar -xf "$f" -C "$STATE/src/$SRC_NAME/_bundled/$name" --strip-components=1
  done
}

licensecheck() {
  c=$1; eval "$(rv vars "$c")"
  bundled_sources "$c"
  python3 -I "$HERE/lib/licensecheck.py" "$c" "$STATE/src/$SRC_NAME" "$STATE/out/$c/license-report.json"
}

compile() {
  c=$1; eval "$(rv vars "$c")"
  SDE=$(sed -n 's/^source_date_epoch=//p' "$STATE/out/$c/source.info")
  DEBV="$UPSTREAM_VERSION-$OU_REVISION"
  stage=$STATE/in/$c; rm -rf "$stage/debian" "$stage/patches"
  cp -a "$HERE/$c/debian" "$stage/debian"; [ -d "$HERE/$c/patches" ] && cp -a "$HERE/$c/patches" "$stage/patches" || true
  {
    echo "COMPONENT=$c"; echo "SRC_NAME=$SRC_NAME"; echo "DEB_VERSION=$DEBV"; echo "UPSTREAM_VERSION=$UPSTREAM_VERSION"
    echo "SOURCE_DATE_EPOCH=$SDE"; echo "JOBS=$BUILDER_JOBS"; printf 'PREFETCH=%q\n' "$PREFETCH"
  } > "$stage/build.env"
  ensure_builder
  tar -C "$HERE/lib" -c builder-inner.sh | sudo systemd-run -M "$BUILDER" --wait --pipe -q /bin/bash -c 'mkdir -p /build && tar -C /build -x'
  inb "rm -rf /build/in/$c; mkdir -p /build/in/$c"
  tar -C "$stage" -c . | sudo systemd-run -M "$BUILDER" --wait --pipe -q /bin/bash -c "tar -C /build/in/$c -x"
  log "build $c $DEBV in $BUILDER (JOBS=$BUILDER_JOBS, MemoryMax=$BUILDER_MEM, network-less compile)"
  inb "bash /build/builder-inner.sh build $c" | tee "$STATE/out/$c/build-summary.txt"
  rm -rf "$STATE/out/$c/artifacts"; mkdir -p "$STATE/out/$c/artifacts"
  inb "tar -C /build/out/$c -c ." | tar -C "$STATE/out/$c/artifacts" -x
  log "build $c done: $(ls "$STATE/out/$c/artifacts"/*.deb | xargs -n1 basename | tr '\n' ' ')"
}

sbom() { python3 -I "$HERE/lib/sbom.py" "$1" "$STATE" "$HERE"; }
scan() { python3 -I "$HERE/lib/vulnscan.py" "$1" "$STATE" "$HERE"; }

do_one() {
  c=$1
  fetch "$c"; licensecheck "$c"; compile "$c"; sbom "$c"; scan "$c"
}

case "${1:-}" in
  prepare) prepare ;;
  fetch|license|compile|sbom|scan) cmd=$1; shift
    for c in $([ "${1:-}" = all ] && echo "$ORDER" || echo "$@"); do
      case $cmd in license) licensecheck "$c";; *) "$cmd" "$c";; esac; done ;;
  all) for c in $ORDER; do do_one "$c"; done ;;
  "" ) sed -n 2,8p "$0"; exit 2 ;;
  *) do_one "$1" ;;
esac
