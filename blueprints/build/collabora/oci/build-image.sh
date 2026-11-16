#!/bin/bash
# Build + lab-sign the Office Unbound Docs OCI image inside the builder (ou-build1). Lab only: nothing leaves the host.
# Run as root; the build itself runs ROOTLESS as user imgbuild (subuid 20000:40000, vfs storage: nspawn has no overlay).
# usage: build-image.sh <artifact.tar> <oci-dir-with-Containerfile-and-scripts>
set -euo pipefail
TAR=${1:?artifact tar}; SRC=${2:?dir with Containerfile entrypoint.sh healthcheck.sh}
VER=${OU_DOCS_VERSION:-26.04.6-ou2}
CTX=/home/imgbuild/ctx
KEYDIR=/home/imgbuild/ou-lab-image-key              # PRIVATE lab signing key lives only here (mode 700, never in the repo)
REG=127.0.0.1:5000
rm -rf "$CTX"; install -d -o imgbuild -g imgbuild "$CTX" "$CTX/rootfs"
# extracted as imgbuild (not root): files map to container root inside the user namespace, ownership is not restorable anyway
su - imgbuild -c "tar -xpf - -C $CTX/rootfs" < "$TAR"
cp "$SRC"/Containerfile "$SRC"/entrypoint.sh "$SRC"/healthcheck.sh "$CTX"/
chown -R imgbuild:imgbuild "$CTX"
# reproducibility aid: clamp file mtimes in the context to a fixed epoch (2025-11-12, arbitrary) so layer content does not depend on the build time
find "$CTX" -exec touch -h -d @1763000000 {} + 2>/dev/null || true
su - imgbuild -c "cd $CTX && buildah bud --isolation chroot --storage-driver vfs --format docker --build-arg OU_VERSION=$VER --timestamp 1763000000 -t ou-docs:$VER ."
# record package versions of the image (helper script: nested quoting through su -c is not worth it)
cat > /home/imgbuild/dpkgl.sh <<'EOS'
#!/bin/bash
c=$(buildah --storage-driver vfs from localhost/ou-docs:__VER__)
buildah --storage-driver vfs run --isolation chroot $c -- dpkg-query -W -f "\${Package} \${Version}\n"
buildah --storage-driver vfs rm $c >/dev/null
EOS
sed -i "s/__VER__/$VER/" /home/imgbuild/dpkgl.sh
chmod +x /home/imgbuild/dpkgl.sh; chown imgbuild /home/imgbuild/dpkgl.sh
su - imgbuild -c /home/imgbuild/dpkgl.sh > /root/ou-docs-image-dpkg.txt || true
# lab key (generated once) + local registry for signature attachments
if [ ! -f "$KEYDIR/ou-sign.private" ]; then
  install -d -m 700 -o imgbuild -g imgbuild "$KEYDIR"; head -c 24 /dev/urandom | base64 > "$KEYDIR/pass.txt"; chown imgbuild:imgbuild "$KEYDIR/pass.txt"; chmod 600 "$KEYDIR/pass.txt"
  su - imgbuild -c "cd $KEYDIR && skopeo generate-sigstore-key --output-prefix ou-sign --passphrase-file pass.txt"
fi
# lab registry: loopback only, no auth, signatures stored as attachments (same shape as ics/scripts/lab_guest/labprep.sh)
if ! curl -fsS "http://$REG/v2/" >/dev/null 2>&1; then
  sed -i '/^auth:/,/^    path:.*/d' /etc/docker/registry/config.yml; sed -i 's/addr: :5000/addr: 127.0.0.1:5000/' /etc/docker/registry/config.yml
  systemctl restart docker-registry; sleep 2
fi
curl -fsS "http://$REG/v2/" >/dev/null
# push + sign as imgbuild inside `buildah unshare` (skopeo cannot read rootless storage without a user namespace); signature = cosign-format attachment
install -d -o imgbuild /home/imgbuild/run /home/imgbuild/.config/containers/registries.d
printf 'docker:\n  %s:\n    use-sigstore-attachments: true\n' "$REG" > /home/imgbuild/.config/containers/registries.d/ou-lab.yaml
chown imgbuild /home/imgbuild/.config/containers/registries.d/ou-lab.yaml
cat > /home/imgbuild/pushsign.sh <<EOS
#!/bin/bash
set -e
skopeo copy --dest-tls-verify=false --sign-by-sigstore-private-key $KEYDIR/ou-sign.private --sign-passphrase-file $KEYDIR/pass.txt containers-storage:[vfs@/home/imgbuild/.local/share/containers/storage+/home/imgbuild/run]localhost/ou-docs:$VER docker://$REG/ou/office:$VER
EOS
chmod +x /home/imgbuild/pushsign.sh; chown imgbuild /home/imgbuild/pushsign.sh
su - imgbuild -c "buildah unshare /home/imgbuild/pushsign.sh"
skopeo inspect --tls-verify=false --format '{{.Digest}}' "docker://$REG/ou/office:$VER"
