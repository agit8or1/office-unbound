#!/usr/bin/env bash
# HOST side (sudo): create one lab nspawn machine from a base image, exactly as the lab machines were made.
#   sudo create-machine.sh <name> <ou-base-noble|ou-base-bookworm> <static-ip|dhcp> <MemoryMax e.g. 2G> [start]
# Zone oulab (isolated by ou-lab-fw), Boot=yes, PrivateUsers=pick, static address via 05-static.network
# (the 80-host0 DHCP file is removed so the address is stable and matches lab-local.env).
# Added by the A22 clean-room run: machine creation was only ever done by hand and documented in host-changes.md.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
[ $# -ge 4 ] || { echo "usage: $0 <name> <base> <ip|dhcp> <MemoryMax> [start]" >&2; exit 2; }
NAME="$1"; BASE="$2"; IP="$3"; MEM="$4"
[ -d "/var/lib/machines/${BASE}" ] || { echo "no base image ${BASE}" >&2; exit 1; }
[ ! -e "/var/lib/machines/${NAME}" ] || { echo "${NAME} already exists" >&2; exit 1; }
avail_kb="$(awk '/MemAvailable/{print $2}' /proc/meminfo)"
[ "${avail_kb}" -ge $((2*1024*1024)) ] || { echo "host MemAvailable < 2 GiB, refusing" >&2; exit 1; }
machinectl clone "${BASE}" "${NAME}"
cat > "/etc/systemd/nspawn/${NAME}.nspawn" <<N
[Exec]
Boot=yes
PrivateUsers=pick

[Network]
Zone=oulab
N
systemctl set-property "systemd-nspawn@${NAME}" "MemoryMax=${MEM}"
R="/var/lib/machines/${NAME}"
echo "${NAME}" > "${R}/etc/hostname"   # clone would otherwise keep the base hostname (sudo/hosts warnings)
if [ "${IP}" != dhcp ]; then
  rm -f "${R}/etc/systemd/network/80-host0.network"
  cat > "${R}/etc/systemd/network/05-static.network" <<N
[Match]
Name=host0
[Network]
Address=${IP}/24
Gateway=192.168.186.1
DNS=192.168.22.1
N
fi
[ "${5:-}" = start ] && machinectl start "${NAME}"
echo "machine ${NAME} created (${BASE}, ${IP}, MemoryMax=${MEM})"
