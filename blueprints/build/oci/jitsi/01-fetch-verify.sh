#!/bin/bash
# Jitsi server components, step 1 (root, builder ou-build1): fetch the .debs from download.jitsi.org and verify the whole chain.
# CHOICE (justified in docs/status/oci-signing-results.md): signed .debs from Jitsi's apt repo, NOT a Maven source build. Reasons: jicofo/jvb are Kotlin/Java
# with ~300 Maven artifacts incl. Jitsi's own libraries that are published on their own maven repo (jitsi-maven-repository, not authorized); jitsi-meet-web is
# a webpack bundle only Jitsi's release process builds reproducibly. What we do instead: the trust chain is pinned end to end --
#   key fingerprint (2 independent sources, compared by this script) -> InRelease signature (VALIDSIG by the pinned key) -> Packages.xz sha256 (in InRelease)
#   -> .deb sha256 (in Packages AND pinned below) -> content extracted with dpkg-deb -x (no maintainer scripts are ever run) -> our own minimal images.
# Prosody comes from the Ubuntu archive (signed by the distro), not from this repo.
set -euo pipefail
W=${W:-/home/imgbuild/jitsi}; D=$W/debs
KEY_FPR=FFD65A0DA2BEBDEB73D44C8BB4D2D216F1FD7806          # "Jitsi <dev@jitsi.org>" primary key
BASE=https://download.jitsi.org
# exact release set (jitsi-meet 2.0.11248-1 depends on these jicofo/web/prosody versions); sha256 as listed in the signed Packages file on 2026-11-16
declare -A SHA=(
  [jicofo_1.0-1205-1_all.deb]=0c37e9ea3e2e3ecd12b57b0363a41421a558616a9b5b0732d4abd612611644e4
  [jitsi-videobridge2_2.3-318-gbf271b11f-1_all.deb]=650a38bd1b1da7585d69f662c2cb17730e3956766e10273ac020b74a22e0253c
  [jitsi-meet-web_1.0.9442-1_all.deb]=c2991fd93bd7f5a382b5168ad6e284fd9593cd1fff41220d54f1d21404a3a447
  [jitsi-meet-web-config_1.0.9442-1_all.deb]=2c290db91cddf937cf5b67cb3371a08cb5cf06e559dad1b8c35a2971e36616a9
  [jitsi-meet-prosody_1.0.9442-1_all.deb]=18021462ec88d7475fc4053dad2871bba583de7d855d64a755bfe1b8d0386731
  [jitsi-meet-tokens_1.0.9442-1_all.deb]=3f370dccbb7cda5002168696c82fe9c320fc6b0b0b0adacae8153a46b1f90c64
)
mkdir -p "$D" "$W/gnupg"; chmod 700 "$W/gnupg"; cd "$W"
export GNUPGHOME=$W/gnupg
curl -fsSL --proto '=https' -o jitsi-key.asc "$BASE/jitsi-key.gpg.key"
curl -fsSL --proto '=https' -o keyserver.asc "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x$KEY_FPR"
fpr() { gpg --batch --show-keys --with-colons "$1" | awk -F: '/^fpr/{print $10; exit}'; }
[ "$(fpr jitsi-key.asc)" = "$KEY_FPR" ] || { echo "REFUSED: key from download.jitsi.org is not $KEY_FPR" >&2; exit 4; }
[ "$(fpr keyserver.asc)" = "$KEY_FPR" ] || { echo "REFUSED: key from keyserver.ubuntu.com is not $KEY_FPR" >&2; exit 4; }
echo "key $KEY_FPR confirmed by 2 sources (download.jitsi.org, keyserver.ubuntu.com)"
gpg --batch --import jitsi-key.asc 2>/dev/null
curl -fsSL --proto '=https' -o InRelease "$BASE/stable/InRelease"
gpg --batch --status-fd 1 --verify InRelease 2>/dev/null | grep -q "^\[GNUPG:\] VALIDSIG $KEY_FPR " || { echo "REFUSED: InRelease is not signed by the pinned key" >&2; exit 4; }
grep -E '^(Date|Suite|Codename):' InRelease
curl -fsSL --proto '=https' -o Packages.xz "$BASE/stable/Packages.xz"
want=$(awk '/^SHA256:/{f=1;next} f&&$3=="Packages.xz"{print $1;exit}' InRelease)
[ "$(sha256sum Packages.xz | awk '{print $1}')" = "$want" ] || { echo "REFUSED: Packages.xz does not match InRelease" >&2; exit 4; }
xz -dc Packages.xz > Packages
for f in "${!SHA[@]}"; do
  curl -fsSL --proto '=https' -o "$D/$f" "$BASE/stable/$f"
  have=$(sha256sum "$D/$f" | awk '{print $1}')
  listed=$(awk -v fn="stable/$f" '$1=="Filename:"{c=($2==fn)} c&&$1=="SHA256:"{print $2;exit}' Packages)
  [ "$have" = "${SHA[$f]}" ] && [ "$have" = "$listed" ] || { echo "REFUSED: $f sha256 $have differs from the pin ${SHA[$f]} / the signed Packages entry $listed" >&2; exit 4; }
  echo "ok $f $have"
done
( cd "$D" && sha256sum *.deb ) > "$W/debs.sha256"
chown -R imgbuild:imgbuild "$W"
