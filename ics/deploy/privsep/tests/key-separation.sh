#!/usr/bin/env bash
# Key separation check (privilege separation, Priority 0-E). Run as root on the ICS host or in a scratch machine:
#   sudo key-separation.sh [--build-user administrator] [--manifest keys.manifest]
# 1. FILES: for every key/secret in the manifest, which of the identities {build user, ics, ou-release, ou-imgsign, ou-testrunner, nobody} can read it,
#    compared with the expected reader list. Any unexpected reader is a violation. Missing files are reported as SKIP (not a pass).
# 2. SUDO: as the build user, `sudo -n` must refuse an arbitrary command, a root shell, the key files via the signer users, a host command through the
#    lab shims (-M .host, ou-base-* as target, host paths), and must still allow the intended narrow operations.
# Exit 0 only when no violation was found. Prints a summary with the counts (SKIP is not PASS).
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
BUILD=administrator
MANIFEST=$HERE/keys.manifest
while [ $# -gt 0 ]; do
  case $1 in
    --build-user) BUILD=${2:?}; shift ;;
    --manifest) MANIFEST=${2:?}; shift ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
  shift
done
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }
IDS=("$BUILD" ics ou-release ou-imgsign ou-testrunner nobody)
pass=0; fail=0; skip=0
can_read() { # identity path
  # shellcheck disable=SC2016  # $1 is meant to expand in the inner shell
  runuser -u "$1" -- bash -c 'if [ -d "$1" ]; then ls "$1" >/dev/null 2>&1; else head -c1 "$1" >/dev/null 2>&1; fi' _ "$2" 2>/dev/null
}
echo "== 1. who can read which key (build user: $BUILD)"
while IFS='|' read -r pattern readers desc; do
  case $pattern in ''|'#'*) continue ;; esac
  # shellcheck disable=SC2086  # the manifest patterns may contain globs on purpose
  files=$(compgen -G "$pattern" || true)
  if [ -z "$files" ]; then printf 'SKIP  %-52s (not present here)  %s\n' "$pattern" "$desc"; skip=$((skip+1)); continue; fi
  for f in $files; do
    got=""
    for id in "${IDS[@]}"; do id "$id" >/dev/null 2>&1 || continue; can_read "$id" "$f" && got="$got $id"; done
    bad=""
    for id in $got; do
      case ",$readers," in *",$id,"*) ;; *) bad="$bad $id" ;; esac
    done
    # the build user stands in for "any unprivileged account": it may never be listed as an expected reader
    if [ -n "$bad" ]; then printf 'FAIL  %-52s readable by:%s (expected: %s)  %s\n' "$f" "$bad" "${readers:-root only}" "$desc"; fail=$((fail+1))
    else printf 'PASS  %-52s readers:%s  %s\n' "$f" "${got:- root only}" "$desc"; pass=$((pass+1)); fi
  done
done < "$MANIFEST"

echo "== 2. what the build user can do through sudo"
chk() { # label expected(0=must succeed,1=must fail) cmd...
  local label=$1 want=$2; shift 2
  runuser -u "$BUILD" -- "$@" >/dev/null 2>&1; local rc=$?
  if { [ "$want" = 0 ] && [ $rc = 0 ]; } || { [ "$want" = 1 ] && [ $rc != 0 ]; }; then printf 'PASS  %s\n' "$label"; pass=$((pass+1))
  else printf 'FAIL  %s (rc=%s)\n' "$label" "$rc"; fail=$((fail+1)); fi
}
# Harmless probes only (id, true, cat of a non-secret, tee to /dev/null): on a host that still has the old rules they succeed without doing damage.
# (`sudo -l CMD` is no usable test: with any NOPASSWD entry present sudo lists the password-protected rules without asking.)
chk "arbitrary root command (true) is refused" 1 sudo -n /usr/bin/true
chk "root shell (bash -c true) is refused" 1 sudo -n /usr/bin/bash -c true
chk "run as ou-release (id) is refused" 1 sudo -n -u ou-release /usr/bin/id
chk "run as ou-imgsign (id) is refused" 1 sudo -n -u ou-imgsign /usr/bin/id
chk "run as ics, the service identity (id) is refused" 1 sudo -n -u ics /usr/bin/id
chk "run as postgres (id) is refused" 1 sudo -n -u postgres /usr/bin/id
chk "root read of a file (cat /etc/hostname) is refused" 1 sudo -n /usr/bin/cat /etc/hostname
chk "root systemctl (--version) is refused" 1 sudo -n /usr/bin/systemctl --version
chk "root tee (/dev/null) is refused" 1 sudo -n /usr/bin/tee /dev/null
chk "lab shim: systemd-run -M .host is refused" 1 sudo -n /usr/local/lib/ou-priv/bin/systemd-run -M .host id
chk "lab shim: systemd-run without -M is refused" 1 sudo -n /usr/local/lib/ou-priv/bin/systemd-run id
chk "lab shim: second -M is refused" 1 sudo -n /usr/local/lib/ou-priv/bin/systemd-run -M ou-x -M .host id
chk "lab shim: --host is refused" 1 sudo -n /usr/local/lib/ou-priv/bin/systemd-run -M ou-x --host=root@y id
chk "lab shim: remove base image refused" 1 sudo -n /usr/local/lib/ou-priv/bin/machinectl remove ou-base-noble
chk "lab shim: clone onto a base image refused" 1 sudo -n /usr/local/lib/ou-priv/bin/machinectl clone ou-x ou-base-noble
chk "lab shim: machine name with path chars refused" 1 sudo -n /usr/local/lib/ou-priv/bin/machinectl start '../etc'
chk "lab shim: systemctl restart ics refused" 1 sudo -n /usr/local/lib/ou-priv/bin/systemctl restart ics
chk "lab shim: tee of an arbitrary file refused" 1 sudo -n /usr/local/lib/ou-priv/bin/tee /etc/passwd
chk "lab shim: test -e /etc/shadow refused" 1 sudo -n /usr/local/lib/ou-priv/bin/test -e /etc/shadow
chk "lab shim: machinectl list is allowed" 0 sudo -n /usr/local/lib/ou-priv/bin/machinectl list
chk "lab shim: test -e /var/lib/machines/ou-x is allowed" 0 sudo -n /usr/local/lib/ou-priv/bin/test -e /var/lib/machines/ou-x
if [ -x /usr/local/sbin/ou-release-sign ]; then
  chk "signer: sudo -u ou-release ou-release-sign status is allowed" 0 sudo -n -u ou-release /usr/local/sbin/ou-release-sign status
  chk "signer: unlisted subcommand (promote dev stable) is refused by sudo" 1 sudo -n -u ou-release /usr/local/sbin/ou-release-sign promote dev stable
  chk "signer: the signer program as root is refused" 1 sudo -n /usr/local/sbin/ou-release-sign status
fi
nopass_all=$(sudo -l -U "$BUILD" 2>/dev/null | grep -Ec 'NOPASSWD:[[:space:]]*ALL[[:space:]]*$')
if [ "$nopass_all" = 0 ]; then echo "PASS  sudo -l -U $BUILD lists no NOPASSWD ALL"; pass=$((pass+1)); else echo "FAIL  sudo -l -U $BUILD lists NOPASSWD ALL ($nopass_all)"; fail=$((fail+1)); fi
echo "== summary: pass=$pass fail=$fail skip=$skip"
[ "$fail" = 0 ]
