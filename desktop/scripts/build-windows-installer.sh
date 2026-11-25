#!/usr/bin/env bash
# Cross-builds the Windows x64 NSIS installer on Linux (GNU ABI, mingw-w64). Unsigned alpha build.
# Output: app/src-tauri/target-dir .../bundle/nsis/Office Unbound_<version>_x64-setup.exe and its SHA-256.
# The release build should come from the Windows CI job (MSVC ABI) once it exists; this script is for development.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
. "$here/scripts/xwin-env.sh"
T=x86_64-pc-windows-gnu
cd "$here"
nice -n 15 cargo build --release --locked --target "$T" -p ou-agent
mkdir -p app/src-tauri/binaries
cp "target/$T/release/ou-agent.exe" "app/src-tauri/binaries/ou-agent-$T.exe"
cd app
npm ci --ignore-scripts --no-audit --no-fund
# tauri-cli on a Linux host probes for an appindicator library when the tray feature is on (Linux-only concern); skip it.
export TAURI_LINUX_AYATANA_APPINDICATOR=true
PATH="$here/scripts/shim:$PATH" nice -n 15 npx tauri build --target "$T" --bundles nsis -- --locked
out="$(ls -1 "$here/target/$T/release/bundle/nsis/"*-setup.exe | head -1)"
sha256sum "$out"
