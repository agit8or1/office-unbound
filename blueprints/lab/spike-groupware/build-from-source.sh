#!/bin/sh
# Office Unbound groupware lab: build Gromox + deps from pinned source tags.
# Runs INSIDE the lab machine (Debian 12 bookworm, systemd-nspawn ou-gw1), as root.
# Usage: sh build-from-source.sh [stage...]   stages: deps libhx wmime gromox sync dav web
set -eu
SRC=${SRC:-/usr/src/ou}
LIBHX_TAG=v4.28; WMIME_TAG=wmime-1.2.0; GROMOX_TAG=gromox-3.13
SYNC_TAG=2.7; DAV_TAG=1.9; MAPIHDR_TAG=2.4
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
  ./configure --prefix=/usr --libdir=/usr/lib/x86_64-linux-gnu >/dev/null && make -j"$(nproc)" >/dev/null && make install >/dev/null
  ldconfig; pkg-config --modversion libHX; cd "$SRC"
}
stage_wmime() {
  clone https://github.com/grommunio/wmime "$WMIME_TAG" wmime
  cd wmime; mkdir -p build; cd build
  cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_INSTALL_LIBDIR=lib/x86_64-linux-gnu \
    -DVMIME_BUILD_TESTS=OFF -DVMIME_BUILD_DOCUMENTATION=OFF -DVMIME_BUILD_SAMPLES=OFF >/dev/null
  make -j"$(nproc)" >/dev/null && make install >/dev/null; ldconfig; pkg-config --modversion wmime; cd "$SRC"
}
stage_gromox() {
  clone https://github.com/grommunio/gromox "$GROMOX_TAG" gromox
  cd gromox; [ -x configure ] || autoreconf -fi
  ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --libdir=/usr/lib/x86_64-linux-gnu >/dev/null
  make -j"$(nproc)" >/dev/null && make install >/dev/null; ldconfig; cd "$SRC"
}
for s in ${*:-deps libhx wmime gromox}; do echo "=== stage $s $(date +%T)"; "stage_$s"; done
