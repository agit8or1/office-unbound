#!/bin/bash
# Keycloak 26.8.2 and OpenCloud 9.1.0 release artifacts for the identity/files OCI images (root, builder ou-build1). Endpoints: github.com releases, repo1.maven.org (authorized).
#   Keycloak: the GitHub release tarball and the Maven Central keycloak-quarkus-dist tarball are the SAME bytes; both publish a sha1 (GitHub: .sha1 file, Maven: .sha1 and .sha256);
#             the build requires the two sha1 values to agree, the Maven .sha256 to match the bytes and then pins the sha256.
#   OpenCloud: release asset opencloud-9.1.0-linux-amd64; the .sha256 file next to it and the sha256 digest GitHub's API reports for the asset must both match the bytes.
set -euo pipefail
W=${W:-/home/imgbuild/idfiles}; mkdir -p "$W"; cd "$W"
KC=26.8.2; OC=9.1.0
curl -fsSL -o kc.tgz "https://repo1.maven.org/maven2/org/keycloak/keycloak-quarkus-dist/$KC/keycloak-quarkus-dist-$KC.tar.gz"
m256=$(curl -fsSL "https://repo1.maven.org/maven2/org/keycloak/keycloak-quarkus-dist/$KC/keycloak-quarkus-dist-$KC.tar.gz.sha256" | tr -d ' \n')
m1=$(curl -fsSL "https://repo1.maven.org/maven2/org/keycloak/keycloak-quarkus-dist/$KC/keycloak-quarkus-dist-$KC.tar.gz.sha1" | tr -d ' \n')
g1=$(curl -fsSL "https://github.com/keycloak/keycloak/releases/download/$KC/keycloak-$KC.tar.gz.sha1" | awk '{print $1}')
have256=$(sha256sum kc.tgz | awk '{print $1}'); have1=$(sha1sum kc.tgz | awk '{print $1}')
[ "$m256" = "$have256" ] && [ "$m1" = "$have1" ] && [ "$g1" = "$have1" ] || { echo "REFUSED: keycloak checksums disagree (maven256=$m256 maven1=$m1 github1=$g1 have=$have256/$have1)" >&2; exit 4; }
echo "keycloak-$KC.tar.gz sha256 $have256 (Maven Central sha256 + sha1 and GitHub release sha1 agree)"
curl -fsSL -o opencloud "https://github.com/opencloud-eu/opencloud/releases/download/v$OC/opencloud-$OC-linux-amd64"
o256=$(curl -fsSL "https://github.com/opencloud-eu/opencloud/releases/download/v$OC/opencloud-$OC-linux-amd64.sha256" | awk '{print $1}')
api=$(curl -fsSL "https://api.github.com/repos/opencloud-eu/opencloud/releases/tags/v$OC" | python3 -c "import json,sys;print([a['digest'] for a in json.load(sys.stdin)['assets'] if a['name']=='opencloud-$OC-linux-amd64'][0].split(':')[1])")
oh=$(sha256sum opencloud | awk '{print $1}')
[ "$o256" = "$oh" ] && [ "$api" = "$oh" ] || { echo "REFUSED: opencloud checksums disagree (file=$o256 api=$api have=$oh)" >&2; exit 4; }
echo "opencloud-$OC-linux-amd64 sha256 $oh (release .sha256 file and the GitHub asset digest agree)"
mkdir -p kc && tar -xzf kc.tgz -C kc --strip-components=1
chmod 0755 opencloud
chown -R imgbuild:imgbuild "$W"
