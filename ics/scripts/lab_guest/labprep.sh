#!/bin/sh
# lab-only tooling inside ou-guest1: local registry on 127.0.0.1:5000, lab signing keys, signed / unsigned / wrong-key images
set -eu
cat > /etc/docker/registry/config.yml <<'E'
version: 0.1
storage:
  filesystem:
    rootdirectory: /var/lib/docker-registry
  delete:
    enabled: true
http:
  addr: 127.0.0.1:5000
E
systemctl restart docker-registry; sleep 2
mkdir -p /root/lab && cd /root/lab
umask 077
echo labpass-not-secret > pass.txt
[ -f ou-sign.private ] || skopeo generate-sigstore-key --output-prefix ou-sign --passphrase-file pass.txt
[ -f other.private ] || skopeo generate-sigstore-key --output-prefix other --passphrase-file pass.txt
python3 /root/mkimg.py signed-oci "hello from the signed ou image" > signed.digest
python3 /root/mkimg.py unsigned-oci "unsigned image" > unsigned.digest
python3 /root/mkimg.py wrongkey-oci "image signed by another.private" > wrongkey.digest
skopeo copy --dest-tls-verify=false --sign-by-sigstore-private-key ou-sign.private --sign-passphrase-file pass.txt oci:signed-oci docker://127.0.0.1:5000/ou/whoami:1
skopeo copy --dest-tls-verify=false oci:unsigned-oci docker://127.0.0.1:5000/ou/unsigned:1
skopeo copy --dest-tls-verify=false --sign-by-sigstore-private-key other.private --sign-passphrase-file pass.txt oci:wrongkey-oci docker://127.0.0.1:5000/ou/wrongkey:1
cat signed.digest unsigned.digest wrongkey.digest
