#!/usr/bin/env bash
# Admit the agent deb into the `dev` ledger of the dedicated release signer and have the repository metadata signed (security review 4: the build user
# never touches the key; everything goes through /usr/local/sbin/ou-release-sign as user ou-release). Usage: publish-dev.sh <deb> <repo-dir>
# The resulting tree (<repo>/pool/dev/*.deb, <repo>/dists/dev/{Release,InRelease,Release.gpg}) is what recipe.sh installs from (file: or http:).
set -euo pipefail
DEB=${1:?usage: publish-dev.sh <deb> <repo-dir>}; REPO=${2:?}
SIGN=${OU_RELEASE_CMD:-sudo -n -u ou-release /usr/local/sbin/ou-release-sign}
S=dev; N=$(basename "$DEB")
[ -f "$DEB" ] && [ ! -L "$DEB" ] || { echo "REFUSED: $DEB is not a regular file"; exit 3; }
mkdir -p "$REPO/pool/$S" "$REPO/dists/$S/main/binary-amd64" "$REPO/dists/$S/main/source"
cp "$DEB" "$REPO/pool/$S/$N"
( cd "$REPO/pool/$S" && tar --owner=0 --group=0 --numeric-owner --mtime=@0 --sort=name -c "$N" ) | $SIGN admit dev
cd "$REPO"
apt-ftparchive packages "pool/$S" > "dists/$S/main/binary-amd64/Packages" 2>/dev/null
gzip -9nc "dists/$S/main/binary-amd64/Packages" > "dists/$S/main/binary-amd64/Packages.gz"
: > "dists/$S/main/source/Sources"; gzip -9nc "dists/$S/main/source/Sources" > "dists/$S/main/source/Sources.gz"
apt-ftparchive -o APT::FTPArchive::Release::Origin="Office Unbound" -o APT::FTPArchive::Release::Label="Office Unbound ($S)" -o APT::FTPArchive::Release::Suite="$S" \
  -o APT::FTPArchive::Release::Codename="$S" -o APT::FTPArchive::Release::Architectures="amd64" -o APT::FTPArchive::Release::Components="main" release "dists/$S" > "dists/$S/Release.new" 2>/dev/null
mv "dists/$S/Release.new" "dists/$S/Release"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
( cd "dists/$S" && tar --owner=0 --group=0 --numeric-owner --mtime=@0 --sort=name -c Release main ) | $SIGN sign "$S" > "$T/signed.tar"
tar -x -C "$T" -f "$T/signed.tar" --no-same-owner
for f in Release InRelease Release.gpg; do [ -f "$T/$f" ] && [ ! -L "$T/$f" ] || { echo "signer returned no $f"; exit 1; }; mv "$T/$f" "dists/$S/$f"; done
echo "published $N to suite $S: $(grep '^Valid-Until' dists/$S/Release)"
