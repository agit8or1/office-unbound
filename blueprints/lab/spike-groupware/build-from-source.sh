#!/bin/sh
# Office Unbound groupware lab: build Gromox + deps from pinned source tags.
# Runs INSIDE the lab machine (Debian 12 bookworm, systemd-nspawn ou-gw1), as root.
# Usage: sh build-from-source.sh [stage...]   stages: deps libhx wmime gromox sync dav web
set -eu
SRC=${SRC:-/usr/src/ou}
JOBS=${JOBS:-6}   # nspawn MemoryMax=6G: -j$(nproc) (48) OOM-killed wmime
LIBHX_TAG=v4.28; WMIME_TAG=wmime-1.2.0; GROMOX_TAG=gromox-3.13
WEB_TAG=grommunio-web-5.2; SYNC_TAG=2.7; DAV_TAG=1.9; MAPIHDR_TAG=2.4
export DEBIAN_FRONTEND=noninteractive
mkdir -p "$SRC"; cd "$SRC"
clone() { # url tag dir
  [ -d "$3" ] || git clone -q --depth 1 --branch "$2" "$1" "$3"
  echo "PIN $3 $2 $(git -C "$3" rev-parse HEAD)"
}
stage_deps() {
  apt-get update -q
  apt-get install -y -q --no-install-recommends ca-certificates git build-essential autoconf automake libtool \
    pkg-config cmake make m4 perl libfmt-dev libjsoncpp-dev libxml2-dev libzstd-dev libmariadb-dev \
    libldap-dev libssl-dev libsqlite3-dev libtinyxml2-dev zlib1g-dev php-dev php-cli libcurl4-openssl-dev \
    libpam0g-dev libxxhash-dev libc-ares-dev libkrb5-dev libgsasl-dev libgnutls28-dev libidn2-dev \
    curl unzip xz-utils sqlite3 zstd gettext
}
stage_libhx() {
  clone https://github.com/jengelh/libhx "$LIBHX_TAG" libhx
  cd libhx; [ -x configure ] || autoreconf -fi
  ./configure --prefix=/usr --libdir=/usr/lib/x86_64-linux-gnu >/dev/null && make -j"$JOBS" >/dev/null && make install >/dev/null
  ldconfig; pkg-config --modversion libHX; cd "$SRC"
}
stage_wmime() {
  clone https://github.com/grommunio/wmime "$WMIME_TAG" wmime
  cd wmime; mkdir -p build; cd build
  cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_INSTALL_LIBDIR=lib/x86_64-linux-gnu \
    -DVMIME_HAVE_MESSAGING_PROTO_SENDMAIL=OFF -DVMIME_BUILD_TESTS=OFF -DVMIME_BUILD_DOCUMENTATION=OFF -DVMIME_BUILD_SAMPLES=OFF >/dev/null
  make -j"$JOBS" >/dev/null && make install >/dev/null; ldconfig; pkg-config --modversion wmime; cd "$SRC"
}
stage_gromox() {
  clone https://github.com/grommunio/gromox "$GROMOX_TAG" gromox
  cd gromox; [ -x configure ] || autoreconf -fi
  ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --libdir=/usr/lib/x86_64-linux-gnu >/dev/null
  make -j"$JOBS" >/dev/null && make install >/dev/null; ldconfig; cd "$SRC"
}
stage_mapihdr() {
  clone https://github.com/grommunio/mapi-header-php "$MAPIHDR_TAG" mapi-header-php
  make -C mapi-header-php install >/dev/null; ls /usr/share/php-mapi | wc -l
}
stage_sync() {
  apt-get install -y -q --no-install-recommends redis-server php-redis php-soap php-intl >/dev/null
  clone https://github.com/grommunio/grommunio-sync "$SYNC_TAG" grommunio-sync
  rm -rf /usr/share/grommunio-sync; cp -a grommunio-sync /usr/share/grommunio-sync; rm -rf /usr/share/grommunio-sync/.git
  sed "s/__VERSION__/$SYNC_TAG/" grommunio-sync/build/version.php.in > /usr/share/grommunio-sync/version.php
  (cd /usr/share/grommunio-sync && HOME=/root COMPOSER_HOME=/root/.composer COMPOSER_ALLOW_SUPERUSER=1 composer install --no-dev -a --no-interaction 2>&1 | tail -3)
}
stage_dav() {
  clone https://github.com/grommunio/grommunio-dav "$DAV_TAG" grommunio-dav
  rm -rf /usr/share/grommunio-dav; cp -a grommunio-dav /usr/share/grommunio-dav; rm -rf /usr/share/grommunio-dav/.git
  (cd /usr/share/grommunio-dav && HOME=/root COMPOSER_HOME=/root/.composer COMPOSER_ALLOW_SUPERUSER=1 composer install --no-dev -a --no-interaction 2>&1 | tail -3)
}
stage_web() {
  # Debian 12 nodejs 18 is too old for grommunio-web 5.2 deps (EBADENGINE, esm failure) -> official Node 22 tarball
  NODEV=22.23.5
  if [ ! -x /opt/node/bin/node ]; then
    curl -fsSLO https://nodejs.org/dist/v$NODEV/node-v$NODEV-linux-x64.tar.xz
    curl -fsSL https://nodejs.org/dist/v$NODEV/SHASUMS256.txt | grep " node-v$NODEV-linux-x64.tar.xz\$" | sha256sum -c -
    mkdir -p /opt/node && tar -xJf node-v$NODEV-linux-x64.tar.xz -C /opt/node --strip-components=1
  fi
  export PATH=/opt/node/bin:$PATH
  node --version; npm --version
  clone https://github.com/grommunio/grommunio-web "$WEB_TAG" grommunio-web
  cd grommunio-web
  # git describe (WEBAPPVERSION in Makefile) needs the tag: shallow clone by tag has it
  HOME=/root npm ci --no-audit --no-fund 2>&1 | tail -3
  HOME=/root make -j2 2>&1 | tail -5
  rm -rf /usr/share/grommunio-web; cp -a deploy /usr/share/grommunio-web; cd "$SRC"
}
for s in ${*:-deps libhx wmime gromox mapihdr sync dav web}; do echo "=== stage $s $(date +%T)"; "stage_$s"; done
