#!/bin/bash
# MAS 1.29.0 step 2 (user imgbuild, builder ou-build1; run it as a transient unit, MemoryMax 7G):
#   crates: `cargo vendor --locked` (every crate is fetched from crates.io and verified by cargo against the checksum in Cargo.lock), then the compile
#           runs from the vendored tree with --frozen --offline, so what is built is exactly what was vendored; the vendor listing is kept as evidence.
#   frontend: pnpm (version AND sha512 pinned by package.json `packageManager`, verified by corepack) install --frozen-lockfile (lockfile integrity hashes).
#   policy: OPA (pinned release binary, step 1) compiles policies/ to policy.wasm.
# Output: /home/imgbuild/mas/out/{mas-cli,share/...,vendor.sha256,Cargo.lock.sha256}
set -euo pipefail
W=/home/imgbuild/mas; S=$W/src; O=$W/out
export PATH=/usr/lib/rust-1.97/bin:$PATH CARGO_HOME=$W/cargo SQLX_OFFLINE=true CARGO_TERM_COLOR=never COREPACK_HOME=$W/corepack CI=true
export VERGEN_GIT_DESCRIBE=v1.29.0 NPM_CONFIG_UPDATE_NOTIFIER=false
export CARGO_BUILD_JOBS=${JOBS:-4}
mkdir -p "$O" "$CARGO_HOME"
cd "$S"
rustc --version; cargo --version
# 1. vendor
mkdir -p .cargo
cargo vendor --locked --versioned-dirs "$W/vendor" > .cargo/config.toml.new
grep -q 'git' Cargo.lock && grep -n 'source = "git' Cargo.lock && echo "WARNING git sources present" || echo "no git sources in Cargo.lock (registry crates only)"
sha256sum Cargo.lock > "$O/Cargo.lock.sha256"
( cd "$W/vendor" && find . -type f -name .cargo-checksum.json | sort | xargs sha256sum ) > "$O/vendor.sha256"
echo "vendored crates: $(ls "$W/vendor" | wc -l)"
mv .cargo/config.toml.new .cargo/config.toml
# 2. build, offline from the vendor tree
cargo build --frozen --offline --locked --release --bin mas-cli --no-default-features --features docker
install -m 0755 target/release/mas-cli "$O/mas-cli"
# 3. frontend
mkdir -p "$W/bin"; corepack enable --install-directory "$W/bin"
export PATH=$W/bin:$PATH
pnpm --version
pnpm install --frozen-lockfile
pnpm --filter mas-frontend run build
mkdir -p "$O/share/assets"
cp frontend/dist/manifest.json "$O/share/manifest.json"
rm -f frontend/dist/index.html* frontend/dist/manifest.json*
cp -r frontend/dist/* "$O/share/assets/"
# 4. policy
( cd policies && make -B && chmod a+r policy.wasm && cp policy.wasm "$O/share/policy.wasm" )
cp -r templates translations "$O/share/"
cp LICENSE LICENSE-COMMERCIAL "$O/share/"
sha256sum "$O/mas-cli" "$O/share/policy.wasm" > "$O/artifacts.sha256"
ldd "$O/mas-cli" | tee "$O/ldd.txt"
echo DONE
