#!/bin/bash
# Build the collaboration OCI images in the builder (ou-build1), UNSIGNED. Lab only: images go to the loopback registry in the builder (127.0.0.1:5000).
# Input tree (/root/collab/src): this directory as collab/, plus lab/ (blueprints/lab) and element/ (release tarball + .asc). Run as root.
# Signing is deliberately NOT done here: the OCI signing path is not a hardened signer yet (ou-image-sign only signs golden qcow2 images).
# usage: build.sh <image|all>   images: synapse element-web meet-token softphone pbx-helper
set -euo pipefail
SRC=/root/collab/src; OUT=/root/collab/out; REG=127.0.0.1:5000; BASE=localhost/ou-base-noble:latest
ELEMENT_V=1.12.35; ELEMENT_SHA=5aaff32e348eba976aea8da11cd50f9ca7f824f235aa66e24d1176f829e6bba5
ELEMENT_FPR=712BFBEE92DCA45252DB17D7C7BE97EFA179B100
mkdir -p "$OUT"
IB() { su - imgbuild -c "$*"; }
BUD="buildah bud --isolation chroot --storage-driver vfs --format docker"

make_base() {
  IB "buildah --storage-driver vfs images -q $BASE" | grep -q . && return 0
  rm -rf /root/collab/base && debootstrap --variant=minbase --components=main,universe noble /root/collab/base http://archive.ubuntu.com/ubuntu >/root/collab/debootstrap.log 2>&1
  sha256sum /root/collab/base/var/lib/apt/lists/*noble_InRelease > "$OUT/base-InRelease.sha256" 2>/dev/null || true
  tar --numeric-owner -C /root/collab/base -cf /root/collab/base.tar . && sha256sum /root/collab/base.tar > "$OUT/base.tar.sha256"
  install -m 644 -o imgbuild /root/collab/base.tar /home/imgbuild/base.tar
  IB "buildah --storage-driver vfs import --os linux /home/imgbuild/base.tar 2>/dev/null || podman --storage-driver vfs import /home/imgbuild/base.tar $BASE"
}

stage() { # $1 = name; assembles /home/imgbuild/ctx-$1
  local n=$1 c=/home/imgbuild/ctx-$1
  rm -rf "$c"; mkdir -p "$c"; cp -a "$SRC/collab/$n/." "$c/"; cp "$SRC/collab/healthcheck.py" "$c/"
  case $n in
    element-web)
      cd "$SRC/element"
      echo "$ELEMENT_SHA  element-v$ELEMENT_V.tar.gz" | sha256sum -c -
      GNUPGHOME=/root/collab/gnupg gpg --status-fd 1 --verify "element-v$ELEMENT_V.tar.gz.asc" "element-v$ELEMENT_V.tar.gz" 2>/dev/null | grep -q "VALIDSIG .* $ELEMENT_FPR\$" || { echo "element signature not valid for pinned primary key"; exit 1; }
      mkdir -p "$c/webroot"; tar -xzf "element-v$ELEMENT_V.tar.gz" -C "$c/webroot" --strip-components=1
      rm -f "$c/webroot/config.sample.json"; [ -f "$c/webroot/index.html" ] ;;
    meet-token) mkdir -p "$c/app"; cp "$SRC/lab/spike-collab/meet-token/app.py" "$c/app/" ;;
    softphone) mkdir -p "$c/app"; cp "$SRC/lab/spike-pbx/phone/phone_app.py" "$c/app/"; cp -a "$SRC/lab/spike-pbx/phone/static" "$c/app/static" ;;
    pbx-helper) mkdir -p "$c/app"; cp "$SRC/lab/spike-pbx/pbx/ou_pbx.py" "$SRC/lab/spike-pbx/pbx/ou_pbx_helper.py" "$c/app/"; cp -a "$SRC/lab/spike-pbx/pbx/templates" "$c/app/templates" 2>/dev/null || true ;;
  esac
  chown -R imgbuild:imgbuild "$c"
}

build() { # $1 name  $2 repo path  $3 tag
  local n=$1 repo=$2 tag=$3
  stage "$n"
  IB "cd /home/imgbuild/ctx-$n && $BUD --build-arg BASE=$BASE -t ou-$n:$tag ." >"$OUT/$n.build.log" 2>&1 || { tail -30 "$OUT/$n.build.log"; return 1; }
  cat > /home/imgbuild/push-$n.sh <<EOS
#!/bin/bash
set -e
skopeo copy --dest-tls-verify=false containers-storage:[vfs@/home/imgbuild/.local/share/containers/storage+/home/imgbuild/run]localhost/ou-$n:$tag docker://$REG/$repo:$tag
EOS
  chmod +x /home/imgbuild/push-$n.sh; chown imgbuild /home/imgbuild/push-$n.sh
  IB "buildah unshare /home/imgbuild/push-$n.sh" >>"$OUT/$n.build.log" 2>&1
  local d; d=$(skopeo inspect --tls-verify=false --format '{{.Digest}}' "docker://$REG/$repo:$tag")
  echo "$n $repo:$tag $d" | tee -a "$OUT/digests.txt"
  # SBOM (syft, CycloneDX) from the pushed image, so the SBOM describes exactly the digest
  rm -rf "/root/collab/oci-$n"; skopeo copy --src-tls-verify=false "docker://$REG/$repo@$d" "oci:/root/collab/oci-$n:x" >/dev/null
  syft "oci-dir:/root/collab/oci-$n" -o cyclonedx-json="$OUT/$n.sbom.cdx.json" -q
  python3 -c "import json,sys; b=json.load(open('$OUT/$n.sbom.cdx.json')); print('$n sbom components:', len(b['components']))"
}

[ -f "$OUT/digests.txt" ] || : > "$OUT/digests.txt"
curl -fsS "http://$REG/v2/" >/dev/null 2>&1 || { systemctl start docker-registry; sleep 2; curl -fsS "http://$REG/v2/" >/dev/null; }
make_base
T=${1:-all}
for n in synapse element-web meet-token softphone pbx-helper; do
  [ "$T" = all ] || [ "$T" = "$n" ] || continue
  case $n in
    synapse) build synapse ou/synapse 1.165.0 ;;
    element-web) build element-web ou/element-web 1.12.35-ou2 ;;   # ou2: config under /ou-element (was /etc/ou-element: refused as a mount)
    meet-token) build meet-token ou/meet-token-service 0.1.0-ou1 ;;
    softphone) build softphone ou/ou-softphone 0.1.0-ou1 ;;
    pbx-helper) build pbx-helper ou/ou-pbx 0.1.0-ou1 ;;
  esac
done
