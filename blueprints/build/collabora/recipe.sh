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
    python3-venv rsync meson ninja-build curl ca-certificates fonts-wqy-zenhei fonts-wqy-microhei fonts-droid-fallback fonts-noto-cjk \
    libpoco-dev- 2>&1 | tail -3
  # meson/ninja (bundled harfbuzz) ignores make's -j and spawns nproc+2 compilers -> OOM in an 8G machine; cap it
  printf '#!/bin/sh\nexec /usr/bin/ninja -j${NINJA_JOBS:-4} "$@"\n' > /usr/local/bin/ninja
  chmod +x /usr/local/bin/ninja
  # online configure needs node >= 20; noble ships 18 -> pinned official tarball
  NODE_VER=v22.21.1; NODE_SHA=680d3f30b24a7ff24b98db5e96f294c0070f8f9078df658da1bce1b9c9873c88
  if ! /usr/local/bin/node --version 2>/dev/null | grep -q "$NODE_VER"; then
    curl -fsSL -o /tmp/node.tar.xz "https://nodejs.org/dist/$NODE_VER/node-$NODE_VER-linux-x64.tar.xz"
    echo "$NODE_SHA  /tmp/node.tar.xz" | sha256sum -c -
    tar -C /usr/local --strip-components=1 -xJf /tmp/node.tar.xz
  fi
}

do_fetch() {
  if [ ! -d "$SRC/.git" ]; then
    git init -q "$SRC"; git -C "$SRC" remote add origin "$REPO"
  fi
  git -C "$SRC" fetch --depth 1 origin "refs/tags/$TAG:refs/tags/$TAG"
  [ "$(git -C "$SRC" rev-parse "$TAG^{commit}")" = "$COMMIT" ] || { echo "PIN MISMATCH"; exit 1; }
  # incremental-friendly: a fresh checkout is cleaned; an existing one at the pin keeps its build products
  if [ "$(git -C "$SRC" rev-parse HEAD 2>/dev/null)" = "$COMMIT" ]; then
    echo "already at pinned commit; keeping build products (rm -rf $SRC for a pristine rebuild)"
  else
    git -C "$SRC" checkout -qf "$TAG"; git -C "$SRC" clean -fdxq
  fi
}

do_patch() {
  cd "$SRC"
  for p in "$HERE"/patches/*.patch; do
    if git apply --reverse --check "$p" >/dev/null 2>&1; then echo "already applied: $p"; continue; fi
    echo "applying $p"; git apply --whitespace=nowarn "$p"
  done
}

do_engine() {
  cd "$SRC/engine"
  # --with-product-name: engine PRODUCTNAME (PDF Producer, bootstraprc ProductKey, registry ooName, ...); the first build (2026-11-15)
  # omitted it and kept "Collabora Office". Pass PRODUCT_NAME="" to reproduce that.
  PN=(); [ "${PRODUCT_NAME-x}" = "" ] || PN=(--with-product-name="$BRAND_NAME")
  ./autogen.sh --with-distro=OfficeUnbound-LOKit --disable-epm --without-package-format --disable-symbols \
     "${PN[@]}" --with-parallelism=$JOBS
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
     --enable-branding=CODE   # theme dir patched to Office Unbound (patch 0001)
  make -j"$JOBS"
}

do_install() {
  rm -rf "$OUT/instdir"; mkdir -p "$OUT/instdir/opt"
  cp -a "$SRC/engine/instdir" "$OUT/instdir/opt/officeunbound-office"
  (cd "$SRC" && DESTDIR="$OUT/instdir" make install)
  # engine InfoURL (share/registry/main.xcd) is a plain-XML value fixed by the engine configure; the engine is not rebuilt for a URL: set it here,
  # failing unless exactly one occurrence is replaced (ou3, agent BK). Copyright/licence texts naming the upstream project are NOT touched.
  XCD="$OUT/instdir/opt/officeunbound-office/share/registry/main.xcd"
  if grep -q '<prop oor:name="InfoURL"' "$XCD"; then
    n=$(grep -o '<prop oor:name="InfoURL" oor:type="xs:string"><value>[^<]*' "$XCD" | wc -l)
    [ "$n" = 1 ] || { echo "main.xcd: $n InfoURL values (want 1)"; exit 1; }
    sed -i "s#\(<prop oor:name=\"InfoURL\" oor:type=\"xs:string\"><value>\)[^<]*#\1$INFO_URL#" "$XCD"
    grep -o '<prop oor:name="InfoURL" oor:type="xs:string"><value>[^<]*' "$XCD"
  fi
  tar -C "$OUT/instdir" --sort=name --owner=0 --group=0 --numeric-owner -cf "$OUT/ou-docs-$TAG.tar" .
  ls -l "$OUT"/ou-docs-*.tar
}

case "${1:-all}" in
  deps) do_deps;; fetch) do_fetch;; patch) do_patch;; engine) do_engine;; online) do_online;; install) do_install;;
  all) do_deps; do_fetch; do_patch; do_engine; do_online; do_install;;
  *) echo "usage: $0 deps|fetch|patch|engine|online|install|all"; exit 2;;
esac
