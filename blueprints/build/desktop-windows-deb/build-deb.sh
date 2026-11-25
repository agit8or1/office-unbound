#!/usr/bin/env bash
# Builds `ou-desktop-windows_<ver>-ou<N>_all.deb`: the Office Unbound Desktop for Windows installer plus manifest.json under
# /usr/share/ou-desktop/windows/, so the portal (/download/windows) and the ICS console serve the installer from our own servers (owner
# 2026-11-25: "the app needs to be able to be directly downloaded from the ui"). Reaches a deployment like every other pinned package: the
# catalog pins it in blueprints/catalog/components/portal.yaml, it is admitted + signed with publish-dev.sh (OU_COMPONENT=ou-desktop-windows)
# and served by the artifact service (ADR-0015). Steps: docs/desktop/download.md.
# Usage: build-deb.sh <installer.exe|.msi> <expected sha256> <version> <outdir>
#   version = the app's version (e.g. 0.1.0 or 0.1.0-alpha.1); OU_REVISION (default ou1); OU_SIGNED=1 when the installer is code-signed.
# Refuses an installer whose sha256 is not the expected one (the value the winci GitHub Actions run printed). Reproducible (fixed mtimes).
set -euo pipefail
SRC=${1:?usage: build-deb.sh <installer> <sha256> <version> <outdir>}; WANT=${2:?}; APPVER=${3:?}; OUTDIR=${4:?}
REV=${OU_REVISION:-ou1}
[ -f "$SRC" ] && [ ! -L "$SRC" ] || { echo "REFUSED: $SRC is not a regular file" >&2; exit 3; }
[[ $WANT =~ ^[0-9a-f]{64}$ ]] || { echo "REFUSED: expected sha256 must be 64 lower-case hex digits" >&2; exit 3; }
[[ $APPVER =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.]{1,40})?$ ]] || { echo "REFUSED: version $APPVER is not X.Y.Z[-pre]" >&2; exit 3; }
[[ $REV =~ ^ou[0-9]{1,4}$ ]] || { echo "REFUSED: OU_REVISION must be ou<N>" >&2; exit 3; }
EXT=${SRC##*.}; EXT=${EXT,,}
[ "$EXT" = exe ] || [ "$EXT" = msi ] || { echo "REFUSED: installer must be .exe or .msi" >&2; exit 3; }
GOT=$(sha256sum "$SRC" | cut -d' ' -f1)
[ "$GOT" = "$WANT" ] || { echo "REFUSED: sha256 of $SRC is $GOT, expected $WANT" >&2; exit 4; }
SIZE=$(stat -c %s "$SRC")
[ "$SIZE" -gt 0 ] || { echo "REFUSED: empty installer" >&2; exit 3; }
FILE="OfficeUnbound-Desktop-${APPVER}-x64-setup.${EXT}"
UNSIGNED=true; [ "${OU_SIGNED:-0}" = 1 ] && UNSIGNED=false
STAGE=alpha; case "$APPVER" in *beta*) STAGE=beta;; esac
VER="${APPVER//-/\~}-$REV"   # 0.1.0-alpha.1 -> 0.1.0~alpha.1-ou1 (a pre-release sorts before the release)
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-1763200000}
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
R=$T/root; D=$R/usr/share/ou-desktop/windows
install -d -m 0755 "$D" "$R/DEBIAN" "$R/usr/share/doc/ou-desktop-windows"
install -m 0644 "$SRC" "$D/$FILE"
python3 -I - "$D/manifest.json" "$APPVER" "$FILE" "$WANT" "$SIZE" "$UNSIGNED" "$STAGE" <<'PY'
import json, sys
p, ver, f, sha, size, unsigned, stage = sys.argv[1:]
m = {"schema": 1, "product": "Office Unbound Desktop", "platform": "windows-x64", "version": ver, "file": f, "sha256": sha,
     "size": int(size), "unsigned": unsigned == "true", "stage": stage}
open(p, "w").write(json.dumps(m, indent=1, sort_keys=True) + "\n")
PY
chmod 0644 "$D/manifest.json"
printf 'Office Unbound Desktop: see the licence of the Office Unbound source tree.\n' > "$R/usr/share/doc/ou-desktop-windows/copyright"
cat > "$R/DEBIAN/control" <<CTL
Package: ou-desktop-windows
Version: $VER
Architecture: all
Maintainer: Office Unbound <packages@office-unbound.invalid>
Section: misc
Priority: optional
Description: Office Unbound Desktop for Windows (installer served to users)
 The Windows installer of Office Unbound Desktop $APPVER and its manifest (version, sha256, size). Nothing runs on
 this machine: the user portal offers the file at /download/windows after checking its sha256.
CTL
find "$R" -type d -exec chmod 0755 {} +
find "$R" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
mkdir -p "$OUTDIR"
dpkg-deb --root-owner-group -Zxz --build "$R" "$OUTDIR/ou-desktop-windows_${VER}_all.deb" >/dev/null
sha256sum "$OUTDIR/ou-desktop-windows_${VER}_all.deb"
