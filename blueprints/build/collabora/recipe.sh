#!/usr/bin/env bash
# Office Unbound Docs (Collabora Online source build) - ADR-0008 recipe #1.
# Re-runnable. Run INSIDE the builder (Ubuntu 24.04 noble nspawn, ou-build1) as root:
#   recipe.sh deps | fetch | patch | engine | online | install | all
# Inputs are pinned below. Outputs: $OUT/instdir (DESTDIR tree) and $OUT/ou-docs-*.tar.
set -euo pipefail

# ---- pinned inputs -------------------------------------------------------
REPO=https://github.com/CollaboraOnline/online.mirror.git
TAG=cp-26.04.6-1
TAG_OBJECT=494e0e0b4d73b473aabe880e96900f9ecf9119bb   # annotated tag object
COMMIT=febe91b27107ff458ddb8dcdf8c0c6d521483033        # peeled commit
BRAND_NAME="Office Unbound Docs"
VENDOR="Office Unbound"
INFO_URL="https://officeunbound.com"
MAXCONN=100000
MAXDOCS=100000

HERE=$(cd "$(dirname "$0")" && pwd)
WORK=${WORK:-/root/build}
SRC=$WORK/online
OUT=$WORK/out
JOBS=${JOBS:-8}
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-1794700000}
mkdir -p "$WORK" "$OUT"

do_deps() {
  export DEBIAN_FRONTEND=noninteractive
  sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/ubuntu.sources
  apt-get update
  # engine (LibreOffice-derived) build deps from the distro's own libreoffice source package
  apt-get build-dep -y libreoffice
  # online + misc (per upstream codeql workflow / install_deps.sh / docker from-source)
  apt-get install -y git build-essential zip ccache libunwind-dev libcap-dev python3-polib npm \
    libpng-dev python3-lxml libpam-dev libzstd-dev libssl-dev libcppunit-dev wget cmake nasm gperf \
    default-jdk-headless ant libkrb5-dev libcups2-dev libfontconfig1-dev libxslt1-dev xsltproc \
    libxml2-utils libxrandr-dev bison flex autoconf automake libtool pkg-config python3-dev \
    python3-venv meson ninja-build curl ca-certificates fonts-wqy-zenhei fonts-wqy-microhei fonts-droid-fallback fonts-noto-cjk \
    libpoco-dev- 2>&1 | tail -3
  # meson/ninja (bundled harfbuzz) ignores make's -j and spawns nproc+2 compilers -> OOM in an 8G machine; cap it
  printf '#!/bin/sh\nexec /usr/bin/ninja -j${NINJA_JOBS:-4} "$@"\n' > /usr/local/bin/ninja
  chmod +x /usr/local/bin/ninja
}

do_fetch() {
  if [ ! -d "$SRC/.git" ]; then
    git init -q "$SRC"; git -C "$SRC" remote add origin "$REPO"
  fi
  git -C "$SRC" fetch --depth 1 origin "refs/tags/$TAG:refs/tags/$TAG"
  [ "$(git -C "$SRC" rev-parse "$TAG^{commit}")" = "$COMMIT" ] || { echo "PIN MISMATCH"; exit 1; }
  git -C "$SRC" checkout -qf "$TAG"
  git -C "$SRC" clean -fdxq
}

do_patch() {
  cd "$SRC"
  for p in "$HERE"/patches/*.patch; do
    echo "applying $p"; git apply --whitespace=nowarn "$p"
  done
  # new binary-free asset files that patches reference are in patches/assets
  if [ -d "$HERE/patches/assets" ]; then cp -a "$HERE"/patches/assets/. "$SRC"/; fi
}

do_engine() {
  cd "$SRC/engine"
  ./autogen.sh --with-distro=OfficeUnbound-LOKit --disable-epm --without-package-format --disable-symbols \
     --with-parallelism=$JOBS
  make -j"$JOBS" 2>&1
}

do_online() {
  cd "$SRC"
  ./autogen.sh
  # NOTE: no --with-welcome-url, no --with-support-public-key, no --with-infobar-url, no --with-feedback-url
  ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --disable-tests \
     --with-lokit-path="$SRC/engine/include" --with-lo-path=/opt/officeunbound-office \
     --with-vendor="$VENDOR" --with-app-name="$BRAND_NAME" --with-info-url="$INFO_URL" \
     --with-max-connections=$MAXCONN --with-max-documents=$MAXDOCS \
     --disable-branding
  make -j"$JOBS"
}

do_install() {
  rm -rf "$OUT/instdir"; mkdir -p "$OUT/instdir/opt"
  cp -a "$SRC/engine/instdir" "$OUT/instdir/opt/officeunbound-office"
  (cd "$SRC" && DESTDIR="$OUT/instdir" make install)
  tar -C "$OUT/instdir" --sort=name --owner=0 --group=0 --numeric-owner -cf "$OUT/ou-docs-$TAG.tar" .
  ls -l "$OUT"/ou-docs-*.tar
}

case "${1:-all}" in
  deps) do_deps;; fetch) do_fetch;; patch) do_patch;; engine) do_engine;; online) do_online;; install) do_install;;
  all) do_deps; do_fetch; do_patch; do_engine; do_online; do_install;;
  *) echo "usage: $0 deps|fetch|patch|engine|online|install|all"; exit 2;;
esac
