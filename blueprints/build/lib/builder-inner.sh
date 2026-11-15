#!/bin/bash
# Runs INSIDE the builder machine (ou-pkg1, Debian 12) as root. Driven by build.sh; not for manual use.
#   builder-inner.sh prepare            one-time/idempotent builder preparation
#   builder-inner.sh build <component>  build one component from /build/in/<component>/
# Inputs in /build/in/<component>/: build.env, orig.tar.xz, debian/, patches/ (optional)
# Outputs in /build/out/<component>/.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive LC_ALL=C.UTF-8 TZ=UTC
umask 022
BUILD=/build

prepare() {
  cat > /etc/apt/sources.list <<'EOF'
deb http://deb.debian.org/debian bookworm main
deb http://deb.debian.org/debian bookworm-updates main
deb http://deb.debian.org/debian-security bookworm-security main
EOF
  apt-get update -q
  apt-get install -y -q --no-install-recommends build-essential debhelper dpkg-dev fakeroot quilt devscripts equivs \
    git xz-utils ca-certificates curl gnupg lintian autoconf automake libtool pkg-config python3 composer >/dev/null
  # Node.js 22 (nodesource, authorized endpoint) for grommunio-web; repo key pinned by fingerprint
  if [ -n "${NODESOURCE_KEY_FPR:-}" ]; then
    curl -fsSL "$NODESOURCE_KEY_URL" -o /tmp/nodesource.key
    got=$(gpg --show-keys --with-colons /tmp/nodesource.key | awk -F: '/^fpr/{print $10; exit}')
    [ "$got" = "$NODESOURCE_KEY_FPR" ] || { echo "nodesource key fingerprint mismatch: $got"; exit 1; }
    gpg --dearmor < /tmp/nodesource.key > /usr/share/keyrings/nodesource.gpg
    echo "deb [signed-by=/usr/share/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main" > /etc/apt/sources.list.d/nodesource.list
    apt-get update -q >/dev/null
    apt-get install -y -q --no-install-recommends "nodejs=$NODE_PKG_VERSION" >/dev/null
  fi
  # unprivileged user for the network-enabled dependency fetch (npm/yarn/composer/pip run upstream-controlled code: never as root, M9)
  id obuild >/dev/null 2>&1 || useradd --system --create-home --home-dir /home/obuild --shell /bin/bash --uid 1500 obuild
  mkdir -p $BUILD/in $BUILD/out $BUILD/localrepo
  dpkg-query -W -f='${Package} ${Version} ${Architecture}\n' | sort > $BUILD/builder-manifest.txt
  echo "builder ready: $(wc -l < $BUILD/builder-manifest.txt) packages, manifest sha256 $(sha256sum < $BUILD/builder-manifest.txt | cut -c1-16)"
}

refresh_localrepo() {
  # Flat, builder-internal repo of previously built OU packages (build-deps like ou-libhx-dev). Never published.
  mkdir -p $BUILD/localrepo
  ( cd $BUILD/localrepo && dpkg-scanpackages -m . /dev/null 2>/dev/null | gzip -9n > Packages.gz )
  echo "deb [trusted=yes] file:$BUILD/localrepo ./" > /etc/apt/sources.list.d/ou-local.list
  apt-get update -q >/dev/null
}

build() {
  c=$1; IN=$BUILD/in/$c; OUT=$BUILD/out/$c
  # shellcheck disable=SC1091
  . "$IN/build.env"    # COMPONENT SRC_NAME DEB_VERSION UPSTREAM_VERSION SOURCE_DATE_EPOCH JOBS PREFETCH(optional)
  export SOURCE_DATE_EPOCH
  rm -rf "$OUT" "$BUILD/work/$c"; mkdir -p "$OUT" "$BUILD/work/$c"
  # fixed build path => no path-dependent differences between builds
  W=$BUILD/work/$c; D=$W/$SRC_NAME-$UPSTREAM_VERSION
  cp "$IN/orig.tar.xz" "$W/${SRC_NAME}_${UPSTREAM_VERSION}.orig.tar.xz"
  mkdir -p "$D"; tar -xJf "$IN/orig.tar.xz" -C "$D" --strip-components=1
  cp -a "$IN/debian" "$D/debian"
  if [ -d "$IN/patches" ] && ls "$IN"/patches/*.patch >/dev/null 2>&1; then
    mkdir -p "$D/debian/patches"; : > "$D/debian/patches/series"
    for p in "$IN"/patches/*.patch; do cp "$p" "$D/debian/patches/"; basename "$p" >> "$D/debian/patches/series"; done
  fi
  cat > "$D/debian/changelog" <<EOF
$SRC_NAME ($DEB_VERSION) bookworm; urgency=medium

  * Office Unbound build of upstream $UPSTREAM_VERSION (see blueprints/build/$COMPONENT/recipe.yaml).

 -- Office Unbound Build <build@officeunbound.com>  $(date -u -R -d "@$SOURCE_DATE_EPOCH")
EOF
  refresh_localrepo
  ( cd "$D" && apt-get build-dep -y -q --no-install-recommends ./ >/dev/null )
  # record the exact build environment (versions of everything installed)
  dpkg-query -W -f='${Package} ${Version}\n' | sort > "$OUT/build-env.txt"
  # source package first, from the pristine tree (prefetch below adds untracked dependency trees)
  ( cd "$D" && dpkg-source -b . > "$OUT/dpkg-source.log" 2>&1 ) || { cat "$OUT/dpkg-source.log"; exit 1; }
  if [ -n "${PREFETCH:-}" ]; then   # network allowed ONLY here (lockfile-pinned npm/composer fetch)
    # unprivileged user, own HOME, no root; npm/yarn run with --ignore-scripts (see the recipes). The tree is handed back to root afterwards.
    chown -R obuild:obuild "$D"
    printf '%s\n' "$PREFETCH" > "$W/prefetch.sh"; chmod 0644 "$W/prefetch.sh"
    su obuild -s /bin/bash -c "cd '$D' && export HOME=/home/obuild COMPOSER_HOME=/home/obuild/.composer SOURCE_DATE_EPOCH='$SOURCE_DATE_EPOCH' && bash -e '$W/prefetch.sh'" > "$OUT/prefetch.log" 2>&1 \
      || { tail -30 "$OUT/prefetch.log"; exit 1; }
  fi
  # binary build runs with NO network (own empty network namespace)
  ( cd "$D" && DEB_BUILD_OPTIONS="parallel=$JOBS" unshare -n -- \
      dpkg-buildpackage -us -uc -b -j"$JOBS" > "$OUT/build.log" 2>&1 ) \
    || { tail -40 "$OUT/build.log"; echo "BUILD FAILED $c"; exit 1; }
  cp "$W"/*.deb "$W"/*.dsc "$W"/*.buildinfo "$W"/*.changes "$W"/*.tar.* "$OUT/" 2>/dev/null || true
  cp "$W"/*.deb "$BUILD/localrepo/" 2>/dev/null || true
  ( cd "$OUT" && lintian --no-tag-display-limit -I ./*.changes > lintian.txt 2>&1 || true )
  ( cd "$OUT" && sha256sum ./*.deb ./*.dsc ./*.tar.* > SHA256SUMS )
  cat "$OUT/SHA256SUMS"
}

case "${1:-}" in
  prepare) prepare ;;
  build) build "$2" ;;
  *) echo "usage: $0 prepare|build <component>" >&2; exit 2 ;;
esac
