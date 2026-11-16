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
ORDER="libhx wmime gromox libexmdbpp mapi-header-php grommunio-sync grommunio-dav grommunio-web admin-api admin-web"   # collabora (prebuilt-stage) is separate: build.sh collabora; the ICS itself is built from a release tag: OU_ICS_TAG=vX.Y.Z build.sh ics
mkdir -p "$STATE"/{src,in,out,tools}

log() { echo "[$(date +%T)] $*"; }
inb() { sudo systemd-run -M "$BUILDER" --wait --pipe -q /bin/bash -c "$1"; }   # run a command inside the builder
rv() { python3 -I "$HERE/lib/recipe.py" "$@"; }

# M9: the builder is EPHEMERAL. `prepare` builds the golden image $BUILDER_GOLDEN once (tooling only); every compile starts from a fresh clone of it and
# the clone is thrown away afterwards, so nothing a build (or its dependencies) did survives into the next build.
start_machine() {
  printf '[Exec]\nBoot=yes\nPrivateUsers=pick\n[Network]\nZone=oulab\n' | sudo tee "/etc/systemd/nspawn/$1.nspawn" >/dev/null
  sudo machinectl start "$1"; sleep 8
  sudo systemctl set-property "systemd-nspawn@$1.service" MemoryMax="$BUILDER_MEM"
}
drop_machine() { sudo machinectl terminate "$1" 2>/dev/null || true; sleep 3; sudo machinectl remove "$1" 2>/dev/null || true; }
ensure_builder() {   # a clean builder: fresh clone of the golden image, with the earlier, verified OU packages as its internal build-dep repo
  [ -d "/var/lib/machines/$BUILDER_GOLDEN" ] || sudo test -d "/var/lib/machines/$BUILDER_GOLDEN" || { echo "no golden builder image: run build.sh prepare"; exit 1; }
  drop_machine "$BUILDER"
  sudo machinectl clone "$BUILDER_GOLDEN" "$BUILDER"
  start_machine "$BUILDER"
  inb 'mkdir -p /build/localrepo'
  for d in "$STATE"/out/*/artifacts; do   # build-deps (ou-libhx-dev, ...) of components that were built and verified earlier
    [ -d "$d" ] || continue
    case "$d" in */collabora/*) continue;; esac     # the Ubuntu prebuilt package is not a build-dep of anything
    ( cd "$d" && for f in $(ls ./*.deb 2>/dev/null | grep -v -- '-dbgsym_'); do [ -f "$f" ] && [ ! -L "$f" ] && echo "$f"; done ) | tar -C "$d" -c -T - 2>/dev/null \
      | sudo systemd-run -M "$BUILDER" --wait --pipe -q /bin/bash -c 'tar -C /build/localrepo -x --no-same-owner' || true
  done
}

prepare() {
  drop_machine "$BUILDER"; drop_machine "$BUILDER_GOLDEN"
  sudo machinectl clone "$BUILDER_BASE" "$BUILDER"
  start_machine "$BUILDER"
  tar -C "$HERE/lib" -c builder-inner.sh | sudo systemd-run -M "$BUILDER" --wait --pipe -q /bin/bash -c 'mkdir -p /build && tar -C /build -x'
  inb "export NODESOURCE_KEY_URL='$NODESOURCE_KEY_URL' NODESOURCE_KEY_FPR='$NODESOURCE_KEY_FPR' NODE_PKG_VERSION='$NODE_PKG_VERSION'; bash /build/builder-inner.sh prepare"
  inb 'cat /build/builder-manifest.txt' > "$STATE/out/builder-manifest.txt"
  sudo machinectl poweroff "$BUILDER"; sleep 8
  sudo machinectl clone "$BUILDER" "$BUILDER_GOLDEN"; sudo machinectl remove "$BUILDER"
  echo "golden builder image $BUILDER_GOLDEN ready (manifest sha256 $(sha256sum < "$STATE/out/builder-manifest.txt" | cut -c1-16))"
}

fetch() {  # clone pinned tag, verify tag object + commit SHA + signature, export deterministic orig tarball
  c=$1; eval "$(rv vars "$c")"
  d=$STATE/src/$SRC_NAME
  [ -d "$d/.git" ] || git clone -q --branch "$TAG" "$REPO" "$d" 2>/dev/null
  git -C "$d" fetch -q --tags origin 2>/dev/null || true
  got=$(git -C "$d" rev-parse "refs/tags/$TAG^{commit}")
  if [ "$DYNAMIC" = 1 ]; then   # release-tag build of this repository (ou-ics): the operator names the tag; the commit is recorded, optionally pinned
    [ -z "$COMMIT" ] || [ "$got" = "$COMMIT" ] || { echo "FETCH FAIL $c: tag $TAG resolves to $got, OU_ICS_COMMIT pins $COMMIT"; exit 1; }
    [ "$(git -C "$d" cat-file -t "refs/tags/$TAG")" = tag ] || { echo "FETCH FAIL $c: $TAG is a lightweight tag; releases use annotated tags (ADR-0011)"; exit 1; }
    [ "$(git -C "$d" show "$got:VERSION")" = "${TAG#v}" ] || { echo "FETCH FAIL $c: VERSION at $TAG is '$(git -C "$d" show "$got:VERSION")', not '${TAG#v}'"; exit 1; }
    COMMIT=$got; TAG_OBJECT=$(git -C "$d" rev-parse "refs/tags/$TAG")
    if git -C "$d" verify-tag "refs/tags/$TAG" >/dev/null 2>&1; then DYN_SIG="valid"
    elif [ "${OU_ICS_REQUIRE_SIGNED:-0}" = 1 ]; then echo "FETCH FAIL $c: tag $TAG is not validly signed and OU_ICS_REQUIRE_SIGNED=1"; exit 1
    else DYN_SIG="UNSIGNED (annotated tag only; no signing key configured, docs/RELEASING.md step 7)"; fi
  else
    [ "$got" = "$COMMIT" ] || { echo "FETCH FAIL $c: tag $TAG resolves to $got, recipe pins $COMMIT"; exit 1; }
  fi
  if [ -n "$TAG_OBJECT" ]; then
    obj=$(git -C "$d" rev-parse "refs/tags/$TAG")
    [ "$obj" = "$TAG_OBJECT" ] || { echo "FETCH FAIL $c: tag object $obj != pinned $TAG_OBJECT"; exit 1; }
  fi
  sig=none; [ "$DYNAMIC" != 1 ] || sig=$DYN_SIG
  if [ "$VERKIND" = pgp-tag ]; then
    raw=$(git -C "$d" verify-tag --raw "refs/tags/$TAG" 2>&1 || true)
    keyid=$(echo "$raw" | awk '/ERRSIG|VALIDSIG/ {for(i=1;i<=NF;i++) if ($i ~ /^[0-9A-F]{16}$/ || $i ~ /^[0-9A-F]{40}$/) {print $i; exit}}')
    case "$SIGFPR" in *"$keyid") ;; *) echo "FETCH FAIL $c: tag signed by key '${keyid:-none}', pinned signer $SIGFPR"; exit 1;; esac
    if echo "$raw" | grep -q GOODSIG; then sig="valid (key in keyring)"; else sig="signed by pinned key id $keyid (signature NOT cryptographically verified: public key not available from an authorized endpoint)"; fi
  fi
  SDE=$(git -C "$d" log -1 --format=%ct "$COMMIT")
  mkdir -p "$STATE/in/$c"
  mkdir -p "$STATE/in/$c" "$STATE/out/$c"
  if [ "$DYNAMIC" = 1 ]; then   # no .git in the archive: carry the commit in the tree so BUILD_INFO.json can record it
    printf '%s\n' "$COMMIT" > "$STATE/in/$c/.ou-source-commit"
    git -C "$d" archive --format=tar --prefix="$SRC_NAME-$UPSTREAM_VERSION/" --add-file="$STATE/in/$c/.ou-source-commit" "$COMMIT" | xz -9e -T1 -c > "$STATE/in/$c/orig.tar.xz"
  else
    git -C "$d" archive --format=tar --prefix="$SRC_NAME-$UPSTREAM_VERSION/" "$COMMIT" | xz -9e -T1 -c > "$STATE/in/$c/orig.tar.xz"
  fi
  { echo "component=$c"; echo "repo=$REPO"; echo "tag=$TAG"; echo "commit=$COMMIT"; echo "source_date_epoch=$SDE"
    echo "signature=$sig"; echo "tag_object=$TAG_OBJECT"; echo "deb_upstream_version=$UPSTREAM_VERSION"; echo "orig_sha256=$(sha256sum "$STATE/in/$c/orig.tar.xz" | cut -d' ' -f1)"; } > "$STATE/out/$c/source.info"
  log "fetch $c: commit $COMMIT ok, signature: $sig, SDE=$SDE"
}

licensecheck() {
  c=$1; eval "$(rv vars "$c")"
  python3 -I "$HERE/lib/licensecheck.py" "$c" "$STATE/src/$SRC_NAME" "$STATE/out/$c/license-report.json"
}

compile() {
  c=$1; eval "$(rv vars "$c")"
  SDE=$(sed -n 's/^source_date_epoch=//p' "$STATE/out/$c/source.info")
  DEBV="$UPSTREAM_VERSION-${OU_REVISION_C:-$OU_REVISION}"   # per-recipe ou_revision overrides tools.env
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
  # H1: the builder's output is hostile. Only regular files of the artifact name set are written (O_EXCL|O_NOFOLLOW), then every .deb/.dsc is parsed.
  inb "tar -C /build/out/$c --no-recursion -c -- \$(cd /build/out/$c && ls)" | python3 -I "$HERE/lib/artifact-check.py" extract "$STATE/out/$c/artifacts" "$c" "$HERE"
  drop_machine "$BUILDER"      # ephemeral: the build machine is destroyed once its artifacts are out
  log "build $c done: $(ls "$STATE/out/$c/artifacts"/*.deb | xargs -n1 basename | tr '\n' ' ')"
}

# ---- prebuilt-stage components (Collabora / Office Unbound Docs): the .deb is assembled from a staged DESTDIR tree on the machine that built it ----
package_prebuilt() {
  c=$1; eval "$(rv vars "$c")"
  mach=$(rv field "$c" stage.machine); tree=$(rv field "$c" stage.tree); tarf=$(rv field "$c" stage.tar)
  # the pins in recipe.yaml must equal the ones in the build script
  for pin in "TAG=$TAG" "TAG_OBJECT=$TAG_OBJECT" "COMMIT=$COMMIT"; do
    grep -q "^$pin\b" "$HERE/$c/recipe.sh" || { echo "PACKAGE FAIL $c: pin $pin of recipe.yaml not found in $c/recipe.sh"; exit 1; }
  done
  SDE=$(sed -n 's/^export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-\([0-9]*\)}.*/\1/p' "$HERE/$c/recipe.sh")
  DEBV="$UPSTREAM_VERSION-${OU_REVISION_C:-$OU_REVISION}"
  mkdir -p "$STATE/out/$c"
  sudo systemd-run -M "$mach" --wait --pipe -q /bin/bash -c "sha256sum '$tarf'" | cut -d' ' -f1 > "$STATE/out/$c/stage-tar.sha256"
  { echo "component=$c"; echo "repo=$REPO"; echo "tag=$TAG"; echo "commit=$COMMIT"; echo "source_date_epoch=$SDE"; echo "signature=none (annotated tag, sha-pinned)"
    echo "stage_machine=$mach"; echo "stage_tar=$tarf"; echo "stage_tar_sha256=$(cat "$STATE/out/$c/stage-tar.sha256")"
    echo "orig_sha256=$(cat "$STATE/out/$c/stage-tar.sha256")"; echo "recipe_sh_sha256=$(sha256sum "$HERE/$c/recipe.sh" | cut -d' ' -f1)"; echo "reproducible=NOT PROVEN (engine not rebuilt by the pipeline)"; } > "$STATE/out/$c/source.info"
  tar -C "$HERE/lib" -c package-prebuilt-inner.sh | sudo systemd-run -M "$mach" --wait --pipe -q /bin/bash -c 'mkdir -p /root/build && tar -C /root/build -x'
  log "package $c $DEBV from $mach:$tree"
  sudo systemd-run -M "$mach" --wait --pipe -q /bin/bash -c "bash /root/build/package-prebuilt-inner.sh '$SRC_NAME' '$DEBV' '$tree' /root/build/pkg-out '$SDE'" | tee "$STATE/out/$c/build-summary.txt"
  sudo systemd-run -M "$mach" --wait --pipe -q /bin/bash -c 'cd /root/build/pkg-out && tar --no-recursion -c -- $(ls)' | python3 -I "$HERE/lib/artifact-check.py" extract "$STATE/out/$c/artifacts" "$c" "$HERE"
  printf '%s\n' "dpkg-query -W -f='"'${Package} ${Version}'"\\n' | sort" | sudo systemd-run -M "$mach" --wait --pipe -q /bin/bash -s > "$STATE/out/$c/artifacts/build-env.txt"
  log "package $c done: $(ls "$STATE/out/$c/artifacts"/*.deb | xargs -n1 basename | tr '\n' ' ')"
}

sbom() { python3 -I "$HERE/lib/sbom.py" "$1" "$STATE" "$HERE"; }
scan() { python3 -I "$HERE/lib/vulnscan.py" "$1" "$STATE" "$HERE"; }

do_one() {
  c=$1
  if [ "$(rv field "$c" kind 2>/dev/null || echo debian)" = prebuilt-stage ]; then
    package_prebuilt "$c"; sbom "$c"; scan "$c"; return
  fi
  fetch "$c"; licensecheck "$c"; compile "$c"
  # vendored wheels exist only after the build's prefetch step: their licences are checked from the METADATA the builder recorded, before sbom/scan
  if [ -f "$STATE/out/$c/artifacts/wheel-licenses.json" ]; then
    OU_WHEELS_JSON="$STATE/out/$c/artifacts/wheel-licenses.json" python3 -I "$HERE/lib/licensecheck.py" "$c" "$STATE/src/$SRC_NAME" "$STATE/out/$c/license-report.json"
  fi
  sbom "$c"; scan "$c"
}

case "${1:-}" in
  prepare) prepare ;;
  fetch|license|compile|sbom|scan|package-prebuilt) cmd=$1; shift
    for c in $([ "${1:-}" = all ] && echo "$ORDER" || echo "$@"); do
      case $cmd in license) licensecheck "$c";; package-prebuilt) package_prebuilt "$c";; *) "$cmd" "$c";; esac; done ;;
  all) for c in $ORDER; do do_one "$c"; done ;;
  "" ) sed -n 2,8p "$0"; exit 2 ;;
  *) do_one "$1" ;;
esac
