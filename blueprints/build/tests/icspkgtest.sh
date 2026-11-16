#!/bin/bash
# Host-side driver for the ou-ics package proof (docs/status/ics-package-results.md). Run as the operator user (uses sudo for machinectl/systemd-run).
#   icspkgtest.sh create <machine> <base-image>      fresh clone, zone oulab, MemoryMax=1500M, key + guest script pushed
#   icspkgtest.sh run <machine> <guest-args...>      run icspkg-guest.sh inside (output is the evidence)
#   icspkgtest.sh destroy <machine>
# The repository is the signed dev channel served by ou-repo1 (repo.sh serve); the key is pinned by FINGERPRINT.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
BUILD=$(cd "$HERE/.." && pwd)
cmd=$1; shift
inm() { sudo systemd-run -M "$M" --wait --pipe -q /bin/bash -c "$1"; }
case $cmd in
  create)
    M=$1; BASE=$2
    free_gb=$(free -g | awk '/^Mem:/{print $7}')
    [ "$free_gb" -ge 2 ] || { echo "only ${free_gb} GiB available: refusing to start another machine"; exit 1; }
    sudo machinectl show-image "$M" >/dev/null 2>&1 && { echo "refusing: $M exists"; exit 3; }
    sudo machinectl clone "$BASE" "$M"
    printf '[Exec]\nBoot=yes\nPrivateUsers=pick\n[Network]\nZone=oulab\n' | sudo tee "/etc/systemd/nspawn/$M.nspawn" >/dev/null
    sudo machinectl start "$M"; sleep 8
    sudo systemctl set-property "systemd-nspawn@$M.service" MemoryMax=1500M
    for i in $(seq 1 30); do sudo systemd-run -M "$M" --wait -q -P /bin/true 2>/dev/null && break; sleep 1; done
    R=/var/lib/machines/$M
    echo "127.0.0.1 $(sudo cat "$R/etc/hostname")" | sudo tee -a "$R/etc/hosts" >/dev/null
    CROOT=$(sudo stat -c %u "$R/root")
    # the repository key the guest pins (out-of-band fingerprint is passed to `setup`). Default: the lab key committed in keys/; the host's signer may have
    # moved to per-channel keys (/var/lib/ou-release/FINGERPRINT-<channel>): then point OU_PKG_KEYFILE at that channel's public key.
    sudo install -m 0644 -o "$CROOT" -g "$CROOT" "${OU_PKG_KEYFILE:-$BUILD/keys/ou-release-lab.pub.asc}" "$R/root/ou-release-lab.pub.asc"
    sudo install -m 0755 -o "$CROOT" -g "$CROOT" "$HERE/icspkg-guest.sh" "$R/root/icspkg-guest.sh"
    echo "machine $M ready (MemoryMax=1500M, $(sudo cat "$R/etc/os-release" | sed -n 's/^PRETTY_NAME=//p'))" ;;
  run) M=$1; shift; inm "bash /root/icspkg-guest.sh $*" ;;
  destroy) M=$1; sudo machinectl terminate "$M" 2>/dev/null || true; sleep 3; sudo machinectl remove "$M" 2>/dev/null || true; sudo rm -f "/etc/systemd/nspawn/$M.nspawn" ;;
  *) sed -n 2,7p "$0"; exit 2 ;;
esac
