#!/bin/bash
# Build the MAS and Jitsi OCI images in the builder (ou-build1), UNSIGNED, and push them to the lab registry (127.0.0.1:5000 inside the builder, 192.168.186.235:5000 in the zone).
# Prerequisites: mas/01-prepare.sh + mas/02-compile.sh (outputs in /home/imgbuild/mas/out), jitsi/01-fetch-verify.sh (debs in /home/imgbuild/jitsi/debs),
# the lab base image localhost/ou-base-noble (blueprints/build/collab/build.sh make_base). Signing is NOT done here: ou-oci-sign signs, on the ICS host.
# usage (root): build-images.sh <mas|jitsi-web|prosody|jicofo|jvb|all>      source tree: /root/oci-oci/src = this directory (blueprints/build/oci)
set -euo pipefail
SRC=${SRC:-/root/oci/src}; OUT=/root/oci/out; REG=127.0.0.1:5000; BASE=localhost/ou-base-noble:latest
JW=/home/imgbuild/jitsi; MO=/home/imgbuild/mas/out
mkdir -p "$OUT"
IB() { su - imgbuild -c "$*"; }
BUD="buildah bud --isolation chroot --storage-driver vfs --format docker"

harden_web() {  # config.js from the jitsi-meet-web-config deb with third-party traffic switched off
  python3 - "$1" "$2" <<'PY'
import re, sys
s = open(sys.argv[1]).read()
s = s.replace("// disableThirdPartyRequests: false,", "disableThirdPartyRequests: true,")
s = re.sub(r"analytics:\s*\{", "analytics: {\n        disabled: true,", s, count=1)
s = re.sub(r"\{\s*urls:\s*'stun:meet-jit-si-turnrelay\.jitsi\.net:443'\s*\},?", "", s)         # Jitsi's public STUN relay
open(sys.argv[2], "w").write(s)
left = [m for m in re.findall(r"^[^/\n]*(?:jitsi\.net|8x8\.vc|amplitude|callstats|googleapis)[^\n]*$", s, re.M)]
print("third-party references left in config.js (uncommented):", left)
PY
}

stage() {
  local n=$1 c=/home/imgbuild/ctx-oci-$1
  rm -rf "$c"; mkdir -p "$c"
  case $n in
    mas) cp -a "$SRC/mas/Containerfile" "$SRC/mas/entrypoint.sh" "$c/"; cp "$MO/mas-cli" "$c/"; cp -a "$MO/share" "$c/share" ;;
    jitsi-web) cp -a "$SRC/jitsi/web/." "$c/"; mkdir -p "$c/webroot"; cp -a "$JW/x/jitsi-meet-web/usr/share/jitsi-meet/." "$c/webroot/"
               harden_web "$JW/x/jitsi-meet-web-config/usr/share/jitsi-meet-web-config/config.js" "$c/config.js" ;;
    prosody) cp -a "$SRC/jitsi/prosody/." "$c/"; mkdir -p "$c/prosody-plugins"; cp -a "$JW/x/jitsi-meet-prosody/usr/share/jitsi-meet/prosody-plugins/." "$c/prosody-plugins/" ;;
    jicofo) cp -a "$SRC/jitsi/jicofo/." "$c/"; mkdir -p "$c/jicofo"; cp -a "$JW/x/jicofo/usr/share/jicofo/." "$c/jicofo/"; cp "$JW/x/jicofo/etc/jitsi/jicofo/logging.properties" "$c/" ;;
    jvb) cp -a "$SRC/jitsi/jvb/." "$c/"; mkdir -p "$c/jitsi-videobridge"; cp -a "$JW/x/jitsi-videobridge2/usr/share/jitsi-videobridge/." "$c/jitsi-videobridge/"
         cp "$JW/x/jitsi-videobridge2/etc/jitsi/videobridge/logging.properties" "$c/" ;;
  esac
  chown -R imgbuild:imgbuild "$c"
}

build() { # $1 name  $2 repo  $3 tag
  local n=$1 repo=$2 tag=$3
  stage "$n"
  IB "cd /home/imgbuild/ctx-oci-$n && $BUD --build-arg BASE=$BASE -t ou-$n:$tag ." >"$OUT/$n.build.log" 2>&1 || { tail -30 "$OUT/$n.build.log"; return 1; }
  cat > /home/imgbuild/push-oci-$n.sh <<EOS
#!/bin/bash
set -e
skopeo copy --dest-tls-verify=false containers-storage:[vfs@/home/imgbuild/.local/share/containers/storage+/home/imgbuild/run]localhost/ou-$n:$tag docker://$REG/$repo:$tag
EOS
  chmod +x /home/imgbuild/push-oci-$n.sh; chown imgbuild /home/imgbuild/push-oci-$n.sh
  IB "buildah unshare /home/imgbuild/push-oci-$n.sh" >>"$OUT/$n.build.log" 2>&1
  local d; d=$(skopeo inspect --tls-verify=false --format '{{.Digest}}' "docker://$REG/$repo:$tag")
  echo "$n $repo:$tag $d" | tee -a "$OUT/digests.txt"
}

T=${1:-all}
for n in mas jitsi-web prosody jicofo jvb; do
  [ "$T" = all ] || [ "$T" = "$n" ] || continue
  case $n in
    mas) build mas ou/matrix-authentication-service 1.29.0 ;;      # repo names and tags are the ones the catalog (blueprints/catalog/components) uses
    jitsi-web) build jitsi-web ou/jitsi-web 1.0.9442 ;;
    prosody) build prosody ou/jitsi-prosody 0.12.4 ;;
    jicofo) build jicofo ou/jicofo 1.0.1205 ;;
    jvb) build jvb ou/jitsi-videobridge 2.3.318 ;;
  esac
done
