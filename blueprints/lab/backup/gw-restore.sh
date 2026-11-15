#!/usr/bin/env bash
# Office Unbound lab: restore a groupware backup (gw-backup.sh) onto a NEW nspawn machine built from pinned source.
# Usage (sudo):
#   gw-restore.sh create  <backup_dir> <new_machine> [base_image]   clone base, start, MemoryMax=3G, own /etc/hosts, start the source build DETACHED
#   gw-restore.sh restore <backup_dir> <machine>                    after the build finished OK: config + DB + stores + mailbox import + services
#   gw-restore.sh all     <backup_dir> <new_machine> [base_image]   create, poll the build every 30 s, restore
# Binaries are never restored from backup: the node is rebuilt by spike-groupware/build-from-source.sh (pinned tags, SHAs compared with the
# MANIFEST). Refuses an existing machine (create) / an already restored machine (restore). The restored node answers for gw1/mail names ITSELF
# (own /etc/hosts); it is tested by IP and must not be given the production names in DNS until a cut-over is intended.
set -euo pipefail
CMD="${1:?create|restore|all}"; B="${2:?backup dir}"; M="${3:?machine}"; BASE="${4:-ou-base-bookworm}"
HERE="$(cd "$(dirname "$0")" && pwd)"; LAB="$(cd "$HERE/.." && pwd)"
ROOTFS="/var/lib/machines/$M"; JOBS="${JOBS:-3}"
[ -f "$B/MANIFEST" ] && [ -f "$B/groupware.tar" ] || { echo "not a backup dir: $B" >&2; exit 2; }
get() { sed -n "s/^$1=//p" "$B/MANIFEST"; }
[ "$(sha256sum "$B/groupware.tar" | cut -d' ' -f1)" = "$(get archive_sha256)" ] || { echo "archive checksum mismatch" >&2; exit 4; }
in_m() { systemd-run -M "$M" --wait -q -P --pipe /bin/bash -c "$1"; }
build_ok() { grep -q '^EXIT=0$' "$ROOTFS/root/build.log" 2>/dev/null; }
croot() { stat -c %u "$ROOTFS/root"; }   # PrivateUsers=pick: container root = shifted host uid (files dropped into the rootfs must be chowned)

do_create() {
  machinectl show-image "$M" >/dev/null 2>&1 && { echo "refusing: machine $M already exists" >&2; exit 3; }
  machinectl clone "$BASE" "$M"
  printf '[Exec]\nBoot=yes\nPrivateUsers=pick\n[Network]\nZone=oulab\n' > "/etc/systemd/nspawn/$M.nspawn"
  machinectl start "$M"; systemctl set-property "systemd-nspawn@$M" MemoryMax=3G
  for i in $(seq 1 30); do systemd-run -M "$M" --wait -q -P /bin/true 2>/dev/null && break; sleep 1; done
  # own name resolution (::1 localhost is REQUIRED: the exmdb provider binds [::1]:5000 and the clients resolve "localhost"): gw1/mail names -> this node; the directory (LDAP) name -> the real directory node. (the base image ships no /etc/hosts)
  { echo "127.0.0.1 localhost"; echo "::1 localhost ip6-localhost ip6-loopback"; echo "127.0.1.1 gw1.ou-lab.internal ou-lab mail.ou-lab.internal autodiscover.gw1.ou-lab.internal"
    sed -n '/# ou-lab hosts/,/^$/p' /etc/hosts | grep -E 'ldap\.ou-lab|auth\.ou-lab'; } > "$ROOTFS/etc/hosts"
  local C; C="$(croot)"; install -d -o "$C" -g "$C" "$ROOTFS/root/lab"
  tar -C "$LAB" -c --exclude=__pycache__ common spike-groupware backup | tar -x -C "$ROOTFS/root/lab" --no-same-owner; chown -R "$C:$C" "$ROOTFS/root/lab"
  # long build runs detached inside the machine (survives this shell), logs to /root/build.log
  systemd-run -M "$M" --unit=ou-build --collect -p StandardOutput=file:/root/build.log -p StandardError=file:/root/build.log \
    /bin/sh -c "date +%s > /root/build.start; JOBS=$JOBS sh /root/lab/spike-groupware/build-from-source.sh ${GW_STAGES:-}; echo EXIT=\$?; date +%s > /root/build.end" >/dev/null
  echo "machine $M created, build started (log: $ROOTFS/root/build.log)"
}
do_restore() {
  build_ok || { echo "source build of $M not finished OK (no EXIT=0 in /root/build.log)" >&2; exit 5; }
  [ ! -e "$ROOTFS/root/ou-restore.done" ] || { echo "refusing: $M was already restored" >&2; exit 3; }
  local C; C="$(croot)"
  install -m 0600 -o "$C" -g "$C" "$B/groupware.tar" "$ROOTFS/root/ou-restore.tar"
  install -m 0600 -o "$C" -g "$C" "$B/MANIFEST" "$ROOTFS/root/ou-restore.MANIFEST"
  install -m 0755 -o "$C" -g "$C" "$LAB/spike-groupware/gw-ldap-sync.py" "$ROOTFS/root/gw-ldap-sync.py"
  install -m 0700 -o "$C" -g "$C" "$HERE/gw-restore-inner.sh" "$ROOTFS/root/gw-restore-inner.sh"
  local rc=0; systemd-run -M "$M" --wait -q -P --pipe /root/gw-restore-inner.sh || rc=$?
  rm -f "$ROOTFS/root/gw-restore-inner.sh" "$ROOTFS/root/ou-restore.tar"
  [ "$rc" = 0 ] || { echo "restore FAILED (rc=$rc)" >&2; exit "$rc"; }
  echo "restored $M from $B; IP: $(machinectl list --no-legend | awk -v m="$M" '$1==m{print $NF}')"
  echo "cgroup memory peak so far: $(( $(cat /sys/fs/cgroup/machine.slice/systemd-nspawn@$M.service/memory.peak) / 1048576 )) MiB"
}
case "$CMD" in
  create)  do_create;;
  restore) do_restore;;
  all)     do_create; until build_ok; do
             grep -q '^EXIT=[1-9]' "$ROOTFS/root/build.log" && { echo "build failed, see $ROOTFS/root/build.log" >&2; exit 5; }
             echo "[$(date +%T)] building: $(grep '^=== stage' "$ROOTFS/root/build.log" | tail -1)"; sleep 30; done; do_restore;;
  *) echo "unknown command $CMD" >&2; exit 2;;
esac
