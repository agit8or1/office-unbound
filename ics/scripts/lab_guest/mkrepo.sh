#!/bin/sh
# lab-only: tiny signed apt repo (file:///srv/ou-repo) standing in for the Office Unbound repo
set -eu
apt-get install -y -qq apt-utils gnupg >/dev/null 2>&1
export GNUPGHOME=/root/lab/gnupg; mkdir -p $GNUPGHOME; chmod 700 $GNUPGHOME
[ -f /root/lab/repo.asc ] || {
  gpg --batch --passphrase '' --quick-generate-key "OU Lab Repo <lab@ou.invalid>" ed25519 sign never
  gpg --armor --export "OU Lab Repo" > /root/lab/repo.asc
}
gpg --with-colons --show-keys /root/lab/repo.asc | awk -F: '/^fpr:/{print $10; exit}' > /root/lab/repo.fpr
R=/srv/ou-repo; rm -rf $R /tmp/pk; mkdir -p $R/pool $R/dists/noble/main/binary-amd64 /tmp/pk/DEBIAN /tmp/pk/usr/share/ou-hello
cat > /tmp/pk/DEBIAN/control <<E
Package: ou-hello
Version: 1.0-1
Architecture: all
Maintainer: OU Lab <lab@ou.invalid>
Description: lab test package
E
echo hello > /tmp/pk/usr/share/ou-hello/README
dpkg-deb --build /tmp/pk $R/pool/ou-hello_1.0-1_all.deb >/dev/null
sed -i 's/1.0-1/2.0-1/' /tmp/pk/DEBIAN/control
dpkg-deb --build /tmp/pk $R/pool/ou-hello_2.0-1_all.deb >/dev/null
cd $R
apt-ftparchive packages pool > dists/noble/main/binary-amd64/Packages
gzip -kf dists/noble/main/binary-amd64/Packages
apt-ftparchive -o APT::FTPArchive::Release::Suite=noble -o APT::FTPArchive::Release::Codename=noble -o APT::FTPArchive::Release::Architectures=amd64 -o APT::FTPArchive::Release::Components=main release dists/noble > /tmp/Release
mv /tmp/Release dists/noble/Release
gpg --batch --yes --armor --detach-sign -o dists/noble/Release.gpg dists/noble/Release
gpg --batch --yes --clearsign -o dists/noble/InRelease dists/noble/Release
cat /root/lab/repo.fpr
