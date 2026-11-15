#!/bin/bash
# Office Unbound signed apt repository (ADR-0008 steps 8-9). Run on the ICS host as the operator user (sudo for signing).
#   repo.sh keygen                          create the lab release signing key (root-only, /etc/office-unbound/release); idempotent
#   repo.sh publish <component>             add the component's built packages to channel `dev`, rebuild + sign dev
#   repo.sh record-test <component> <suite-name> pass|fail <logfile>   record a test result for every package of the component
#   repo.sh promote <from> <to> <component> [--approved-by NAME]       dev->staging->stable; ONLY if all tests passed
#   repo.sh index <suite>                   regenerate + sign metadata of a suite
#   repo.sh serve|unserve                   serve the repo read-only to the oulab zone only, from a zone member (never the LAN)
# Channels are separate suites with separate pools; the same .deb (same sha256) may exist in several channels.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
BUILD=$(cd "$HERE/.." && pwd)
STATE=${OU_PKG_STATE:-/var/lib/office-unbound/pkgbuild}
REPO=${OU_REPO_DIR:-$STATE/repo}             # served tree (public)
REC=$STATE/records                           # NOT served: test + promotion records
KEYDIR=${OU_RELEASE_KEYDIR:-/etc/office-unbound/release}
GNUPG=$KEYDIR/gnupg
SUITES="dev staging stable"
ARCH=amd64
mkdir -p "$REPO" "$REC/tests" "$REC/promotions"

sg() { sudo gpg --homedir "$GNUPG" --batch --yes "$@"; }
fpr() { sg --list-secret-keys --with-colons 2>/dev/null | awk -F: '/^fpr/{print $10; exit}'; }

keygen() {
  sudo install -d -m 0700 -o root -g root "$KEYDIR" "$GNUPG"
  if [ -n "$(fpr)" ]; then echo "release key exists: $(fpr)"; else
    sg --pinentry-mode loopback --passphrase '' --quick-generate-key \
      "Office Unbound Lab Release Signing <release@officeunbound.com>" ed25519 sign 2y
    echo "created key $(fpr)"
  fi
  F=$(fpr)
  mkdir -p "$BUILD/keys"
  sg --armor --export "$F" > "$BUILD/keys/ou-release-lab.pub.asc"
  echo "$F" > "$BUILD/keys/ou-release-lab.FINGERPRINT"
  sudo chmod -R go-rwx "$KEYDIR"
  echo "public key: $BUILD/keys/ou-release-lab.pub.asc  fingerprint $F"
}

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
  F=$(fpr); [ -n "$F" ] || { echo "no release key: run keygen"; exit 1; }
  sg --local-user "$F" --pinentry-mode loopback --passphrase '' --clearsign < "dists/$s/Release" > "dists/$s/InRelease.new"
  sg --local-user "$F" --pinentry-mode loopback --passphrase '' --armor --detach-sign < "dists/$s/Release" > "dists/$s/Release.gpg.new"
  mv "dists/$s/InRelease.new" "dists/$s/InRelease"; mv "dists/$s/Release.gpg.new" "dists/$s/Release.gpg"
  cp "$BUILD/keys/ou-release-lab.pub.asc" "$REPO/ou-release-lab.pub.asc"
  echo "indexed+signed suite $s with $F: $(grep -c '^Package:' "dists/$s/main/binary-$ARCH/Packages") binary packages"
}

pkgfiles() {  # <component> -> deb/dsc/tarball files built (no dbgsym)
  ls "$STATE/out/$1/artifacts/"*.deb "$STATE/out/$1/artifacts/"*.dsc "$STATE/out/$1/artifacts/"*.tar.* 2>/dev/null | grep -v -- '-dbgsym_' || true
}

publish() {
  c=$1; d="$REPO/pool/dev/$c"; rm -rf "$d"; mkdir -p "$d"   # a rebuilt component replaces its previous files
  for f in $(pkgfiles "$c"); do cp -p "$f" "$d/"; done
  index dev
}

record_test() {
  c=$1; name=$2; res=$3; log=$4
  [ "$res" = pass ] || [ "$res" = fail ] || { echo "result must be pass|fail"; exit 2; }
  for f in $(pkgfiles "$c" | grep '\.deb$'); do
    h=$(sha256sum "$f" | cut -d' ' -f1)
    python3 - "$REC/tests/$h.json" "$(basename "$f")" "$h" "$name" "$res" "$(sha256sum "$log" | cut -d' ' -f1)" <<'PY'
import json, sys, os, time
fn, deb, h, name, res, logsha = sys.argv[1:7]
d = json.load(open(fn)) if os.path.exists(fn) else {"deb": deb, "sha256": h, "results": {}}
d["results"][name] = {"result": res, "log_sha256": logsha, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
json.dump(d, open(fn, "w"), indent=1)
PY
  done
  echo "recorded $name=$res for $c"
}

promote() {
  from=$1; to=$2; c=$3; shift 3; approver=""
  [ "${1:-}" = "--approved-by" ] && approver=${2:-}
  case "$from>$to" in "dev>staging"|"staging>stable") ;; *) echo "only dev>staging or staging>stable"; exit 2;; esac
  [ "$to" != stable ] || [ -n "$approver" ] || { echo "REFUSED: promotion to stable needs --approved-by (stands in for the ICS approval record)"; exit 3; }
  src="$REPO/pool/$from/$c"; [ -d "$src" ] || { echo "REFUSED: $c is not in $from"; exit 3; }
  req=${OU_REQUIRED_TESTS:-install-smoke}
  for f in "$src"/*.deb; do
    h=$(sha256sum "$f" | cut -d' ' -f1); rf="$REC/tests/$h.json"
    for t in $req; do
      ok=$(python3 -c "import json,sys;d=json.load(open('$rf'));print(d['results'].get('$t',{}).get('result',''))" 2>/dev/null || true)
      [ "$ok" = pass ] || { echo "REFUSED: $(basename "$f") has no passing '$t' test record (got '${ok:-none}')"; exit 3; }
    done
  done
  rm -rf "$REPO/pool/$to/$c"; mkdir -p "$REPO/pool/$to/$c"; cp -p "$src"/* "$REPO/pool/$to/$c/"
  echo "{\"component\":\"$c\",\"from\":\"$from\",\"to\":\"$to\",\"approved_by\":\"$approver\",\"at\":\"$(date -u +%FT%TZ)\",\"files\":\"$(cd "$src" && sha256sum ./* | sha256sum | cut -c1-16)\"}" >> "$REC/promotions/log.jsonl"
  index "$to"
}

serve() {
  # The ICS host firewall (nspawn zone rules) drops zone -> host traffic, so the repo is served from a zone member:
  # a copy of the public tree is pushed to the builder machine and served on its zone address only (never the LAN).
  . "$BUILD/tools.env"
  tar -C "$REPO" -c . | sudo systemd-run -M "$BUILDER" --wait --pipe -q /bin/bash -c 'rm -rf /srv/ou-repo; mkdir -p /srv/ou-repo; tar -C /srv/ou-repo -x'
  ip=$(sudo systemd-run -M "$BUILDER" --wait --pipe -q /bin/bash -c "ip -4 -o addr show host0 | awk '{split(\$4,a,\"/\"); print a[1]; exit}'")
  sudo systemd-run -M "$BUILDER" --wait --pipe -q /bin/bash -c "systemctl stop ou-pkgrepo.service 2>/dev/null; systemd-run --unit=ou-pkgrepo -p DynamicUser=yes -p ProtectSystem=strict -p NoNewPrivileges=yes -q /usr/bin/python3 -m http.server 8077 --bind $ip --directory /srv/ou-repo"
  echo "serving the repo on http://$ip:8077/ (zone oulab, from $BUILDER); apt line: deb [signed-by=/usr/share/keyrings/ou-release-lab.gpg] http://$ip:8077 <channel> main"
}
unserve() { . "$BUILD/tools.env"; sudo systemd-run -M "$BUILDER" --wait --pipe -q /bin/bash -c 'systemctl stop ou-pkgrepo.service'; }

case "${1:-}" in
  keygen) keygen ;;
  publish) publish "$2" ;;
  record-test) shift; record_test "$@" ;;
  promote) shift; promote "$@" ;;
  index) index "$2" ;;
  serve) serve ;;
  unserve) unserve ;;
  *) sed -n 2,11p "$0"; exit 2 ;;
esac
