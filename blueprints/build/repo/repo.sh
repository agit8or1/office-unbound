#!/bin/bash
# Office Unbound signed apt repository (ADR-0008 steps 8-9). Run on the ICS host as the operator user. The signing key is NOT reachable from here:
# everything that needs it goes through the fixed program /usr/local/sbin/ou-release-sign as user `ou-release` (install-signer.sh; security review 4).
#   repo.sh publish <component>             verify the built artifacts (regular files only, dpkg-deb parsed), add to channel `dev`, admit + sign dev
#   repo.sh record-test <component> <suite-name> pass|fail <logfile>   record a test result for every .deb of the component's dev pool (operator-supplied;
#                                           tests/pkgtest.sh records what it really installed on its own)
#   repo.sh record-installed <suite> <name> pass|fail <logfile> <pkg_version>...   record for exactly the named pool .debs (used by pkgtest.sh)
#   repo.sh promote <from> <to> <component> [--approved-by NAME]       dev->staging->stable; ENFORCED by ou-release-sign (test records + approver + ledger)
#   repo.sh index <suite>                   regenerate metadata of a suite and have it signed (Valid-Until set by the signer)
#   repo.sh resign-all                      re-index + re-sign every suite (run from the timer: Valid-Until must never lapse)
#   repo.sh serve|unserve                   push the public tree to the DEDICATED read-only repo machine (not the builder) on the oulab zone
# Channels are separate suites with separate pools; the same .deb (same sha256) may exist in several channels.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
BUILD=$(cd "$HERE/.." && pwd)
STATE=${OU_PKG_STATE:-/var/lib/office-unbound/pkgbuild}
REPO=${OU_REPO_DIR:-$STATE/repo}             # served tree (public)
SIGN=${OU_RELEASE_CMD:-sudo -n -u ou-release /usr/local/sbin/ou-release-sign}   # tests point this at a sandbox signer
SUITES="dev staging stable"
ARCH=amd64
mkdir -p "$REPO"

# every pool file set is verified before it is handed on: only regular, unlinked files directly in the directory
strict_dir() {
  d=$1
  [ -d "$d" ] && [ ! -L "$d" ] || { echo "REFUSED: $d is not a plain directory"; exit 3; }
  bad=$(find "$d" -mindepth 1 \( ! -type f -o -links +1 \) -print -quit)
  [ -z "$bad" ] || { echo "REFUSED: $bad is not a regular, unlinked file"; exit 3; }
}

pkgfiles() {  # <component> -> deb/dsc/tarball files built (no dbgsym); strict: regular files only
  a="$STATE/out/$1/artifacts"; strict_dir "$a"
  find "$a" -maxdepth 1 -type f \( -name '*.deb' -o -name '*.dsc' -o -name '*.tar.*' \) ! -name '*-dbgsym_*' | sort
}

tar_dir() { strict_dir "$1"; tar -C "$1" --no-recursion --owner=0 --group=0 --numeric-owner --mtime=@0 --sort=name -c -- $(cd "$1" && ls); }

index() {
  s=$1; cd "$REPO"
  mkdir -p "pool/$s" "dists/$s/main/binary-$ARCH" "dists/$s/main/source"
  apt-ftparchive packages "pool/$s" 2>/dev/null > "dists/$s/main/binary-$ARCH/Packages"
  gzip -9nc "dists/$s/main/binary-$ARCH/Packages" > "dists/$s/main/binary-$ARCH/Packages.gz"
  apt-ftparchive sources "pool/$s" 2>/dev/null > "dists/$s/main/source/Sources"
  gzip -9nc "dists/$s/main/source/Sources" > "dists/$s/main/source/Sources.gz"
  apt-ftparchive \
    -o APT::FTPArchive::Release::Origin="Office Unbound" -o APT::FTPArchive::Release::Label="Office Unbound ($s)" \
    -o APT::FTPArchive::Release::Suite="$s" -o APT::FTPArchive::Release::Codename="$s" \
    -o APT::FTPArchive::Release::Architectures="$ARCH" -o APT::FTPArchive::Release::Components="main" \
    -o APT::FTPArchive::Release::Description="Office Unbound lab channel $s (Debian 12)" \
    release "dists/$s" 2>/dev/null > "dists/$s/Release.new"
  mv "dists/$s/Release.new" "dists/$s/Release"
  tmp=$(mktemp -d); trap 'rm -rf "$tmp"' RETURN
  # the signer re-verifies the hashes, refuses unadmitted pool files, sets Date + Valid-Until and signs
  ( cd "dists/$s" && tar --owner=0 --group=0 --numeric-owner --mtime=@0 --sort=name -c Release main ) | $SIGN sign "$s" > "$tmp/signed.tar"
  tar -x -C "$tmp" -f "$tmp/signed.tar" --no-same-owner
  for f in Release InRelease Release.gpg; do [ -f "$tmp/$f" ] && [ ! -L "$tmp/$f" ] || { echo "signer returned no $f"; exit 1; }; mv "$tmp/$f" "dists/$s/$f.new"; mv "dists/$s/$f.new" "dists/$s/$f"; done
  cp "$BUILD/keys/ou-release-lab.pub.asc" "$REPO/ou-release-lab.pub.asc"
  echo "indexed+signed suite $s: $(grep -c '^Package:' "dists/$s/main/binary-$ARCH/Packages") binary packages, $(grep '^Valid-Until' "dists/$s/Release")"
}

publish() {
  c=$1; d="$REPO/pool/dev/$c"
  python3 -I "$BUILD/lib/artifact-check.py" verify "$STATE/out/$c/artifacts" "$c" "$BUILD" >/dev/null   # names, regular files, dpkg-deb control fields
  rm -rf "$d"; mkdir -p "$d"                                                                               # a rebuilt component replaces its previous dev files
  for f in $(pkgfiles "$c"); do
    [ -f "$f" ] && [ ! -L "$f" ] || { echo "REFUSED: $f is not a regular file"; exit 3; }
    cp --no-dereference -p "$f" "$d/"
    [ "$(sha256sum < "$f")" = "$(sha256sum < "$d/$(basename "$f")")" ] || { echo "copy of $f differs"; exit 3; }
  done
  tar_dir "$d" | $SIGN admit dev
  index dev
}

record_test() {
  c=$1; name=$2; res=$3; log=$4
  [ "$res" = pass ] || [ "$res" = fail ] || { echo "result must be pass|fail"; exit 2; }
  for f in "$REPO/pool/dev/$c"/*.deb; do
    $SIGN record-test "$(sha256sum "$f" | cut -d' ' -f1)" "$name" "$res" "$(sha256sum "$log" | cut -d' ' -f1)"
  done
  echo "recorded $name=$res for $c"
}

record_installed() {  # <suite> <name> <res> <log> <package_version>... -> only the pool .debs whose Package_Version was really installed by the test
  s=$1; name=$2; res=$3; log=$4; shift 4; n=0
  for pv in "$@"; do
    for f in "$REPO"/pool/"$s"/*/"${pv}"_*.deb; do
      [ -f "$f" ] && [ ! -L "$f" ] || continue
      $SIGN record-test "$(sha256sum "$f" | cut -d' ' -f1)" "$name" "$res" "$(sha256sum "$log" | cut -d' ' -f1)"; n=$((n+1))
    done
  done
  echo "recorded $name=$res for $n installed packages of suite $s"
}

promote() {
  from=$1; to=$2; c=$3; shift 3; approver=""
  [ "${1:-}" = "--approved-by" ] && approver=${2:-}
  case "$from>$to" in "dev>staging"|"staging>stable") ;; *) echo "only dev>staging or staging>stable"; exit 2;; esac
  src="$REPO/pool/$from/$c"; [ -d "$src" ] || { echo "REFUSED: $c is not in $from"; exit 3; }
  tmp=$(mktemp -d); trap 'rm -rf "$tmp"' RETURN
  tar_dir "$src" > "$tmp/set.tar"                      # ONE tar: the signer approves exactly these bytes and exactly these bytes are copied
  $SIGN promote "$from" "$to" "$approver" < "$tmp/set.tar" || { echo "promotion refused by the signer"; exit 3; }
  # earlier promoted versions stay in the target pool (rollback = pinned downgrade to a version that is still in the channel); only dev is replaced
  mkdir -p "$REPO/pool/$to/$c"; tar -x -C "$REPO/pool/$to/$c" -f "$tmp/set.tar" --no-same-owner --no-same-permissions
  echo "{\"component\":\"$c\",\"from\":\"$from\",\"to\":\"$to\",\"approved_by\":\"$approver\",\"at\":\"$(date -u +%FT%TZ)\",\"set_sha256\":\"$(sha256sum < "$tmp/set.tar" | cut -c1-16)\"}" >> "$STATE/records-promotions.log"
  index "$to"
}

resign_all() { for s in $SUITES; do index "$s"; done; }

serve() {
  # The ICS host firewall (nspawn zone rules) drops zone -> host traffic, so the repo is served from a zone member. M8: NOT the builder (which runs
  # untrusted build code) but a dedicated machine ou-repo1 that runs nothing else: read-only tree owned by root, python http.server as a dynamic user.
  . "$BUILD/tools.env"
  sudo machinectl show "$REPO_MACHINE" >/dev/null 2>&1 || {
    [ -d "/var/lib/machines/$REPO_MACHINE" ] || sudo machinectl clone "$BUILDER_BASE" "$REPO_MACHINE"
    printf '[Exec]\nBoot=yes\nPrivateUsers=pick\n[Network]\nZone=oulab\n' | sudo tee "/etc/systemd/nspawn/$REPO_MACHINE.nspawn" >/dev/null
    sudo machinectl start "$REPO_MACHINE"; sleep 8
    sudo systemctl set-property "systemd-nspawn@$REPO_MACHINE.service" MemoryMax=512M
  }
  tar -C "$REPO" -c . | sudo systemd-run -M "$REPO_MACHINE" --wait --pipe -q /bin/bash -c 'systemctl stop ou-pkgrepo.service 2>/dev/null; rm -rf /srv/ou-repo; mkdir -p /srv/ou-repo; tar -C /srv/ou-repo -x --no-same-owner; chown -R root:root /srv/ou-repo; chmod -R go-w /srv/ou-repo'
  ip=$(sudo systemd-run -M "$REPO_MACHINE" --wait --pipe -q /bin/bash -c "ip -4 -o addr show host0 | awk '{split(\$4,a,\"/\"); print a[1]; exit}'")
  sudo systemd-run -M "$REPO_MACHINE" --wait --pipe -q /bin/bash -c "systemctl stop ou-pkgrepo.service 2>/dev/null; systemd-run --unit=ou-pkgrepo -p DynamicUser=yes -p ProtectSystem=strict -p ProtectHome=yes -p PrivateTmp=yes -p NoNewPrivileges=yes -p ReadOnlyPaths=/srv/ou-repo -q /usr/bin/python3 -m http.server 8077 --bind $ip --directory /srv/ou-repo"
  echo "serving the repo on http://$ip:8077/ (zone oulab, from $REPO_MACHINE); apt line: deb [signed-by=/usr/share/keyrings/ou-release-lab.gpg] http://$ip:8077 <channel> main"
}
unserve() { . "$BUILD/tools.env"; sudo systemd-run -M "$REPO_MACHINE" --wait --pipe -q /bin/bash -c 'systemctl stop ou-pkgrepo.service'; }

case "${1:-}" in
  keygen) echo "the signing key is managed by install-signer.sh (run as root); see the header of that file"; exit 2 ;;
  publish) publish "$2" ;;
  record-test) shift; record_test "$@" ;;
  record-installed) shift; record_installed "$@" ;;
  promote) shift; promote "$@" ;;
  index) index "$2" ;;
  resign-all) resign_all ;;
  serve) serve ;;
  unserve) unserve ;;
  *) sed -n 2,14p "$0"; exit 2 ;;
esac
