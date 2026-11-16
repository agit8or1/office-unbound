#!/bin/bash
# MAS 1.29.0 from source, step 1 (root, in the builder ou-build1): toolchain from the Ubuntu archive, source tree, tag verification, OPA.
# Endpoints: github.com (public repo + release asset), archive.ubuntu.com. crates.io / npm registry come in step 2.
set -euo pipefail
V=1.29.0; TAG=v$V; W=/home/imgbuild/mas; REPO=https://github.com/element-hq/matrix-authentication-service.git
OPA_V=1.21.4
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -qq rustc-1.97 cargo-1.97 build-essential pkg-config libssl-dev ca-certificates curl >/dev/null
install -d -o imgbuild -g imgbuild "$W"
[ -d "$W/src/.git" ] || su - imgbuild -c "cd $W && git clone -q $REPO src"
git config --global --add safe.directory "$W/src"
cd "$W/src"
# --- tag verification. The upstream tag is not GPG-signed, so the commit is cross-checked against a fresh ls-remote and the release page.
c_local=$(git rev-parse "refs/tags/$TAG^{commit}")
c_remote=$(git ls-remote "$REPO" "refs/tags/$TAG" "refs/tags/$TAG^{}" | awk '{print $1}' | tail -1)
c_rel=$(curl -fsSL "https://github.com/element-hq/matrix-authentication-service/releases/tag/$TAG" | grep -oE '/commit/[0-9a-f]{40}' | head -1 | cut -d/ -f3 || true)
echo "tag $TAG: local=$c_local remote=$c_remote release-page=${c_rel:-n/a}"
[ "$c_local" = "$c_remote" ] || { echo "REFUSED: tag commit differs between clone and fresh ls-remote" >&2; exit 4; }
[ -z "$c_rel" ] || [ "$c_rel" = "$c_local" ] || { echo "REFUSED: release page names another commit" >&2; exit 4; }
git merge-base --is-ancestor "$c_local" origin/main && echo "commit is on origin/main"
git -c advice.detachedHead=false checkout -q "$TAG"
echo "$c_local" > "$W/TAG_COMMIT"
# --- OPA (policy.wasm compiler): release binary + the sha256 file published next to it
cd "$W"
curl -fsSLo opa "https://github.com/open-policy-agent/opa/releases/download/v$OPA_V/opa_linux_amd64_static"
curl -fsSLo opa.sha256 "https://github.com/open-policy-agent/opa/releases/download/v$OPA_V/opa_linux_amd64_static.sha256"
want=$(awk '{print $1}' opa.sha256); have=$(sha256sum opa | awk '{print $1}')
[ "$want" = "$have" ] || { echo "REFUSED: opa checksum mismatch" >&2; exit 4; }
install -m 0755 opa /usr/local/bin/opa; echo "opa $OPA_V sha256 $have"
chown -R imgbuild:imgbuild "$W"
