#!/usr/bin/env bash
# Undo apply-privsep.sh from its backup: restores the original sudoers files (including the NOPASSWD ALL rules), removes everything the apply installed
# (rules, shims, polkit/ssh files, unit drop-ins) and restores drop-in directories that existed before. Dry run by default.
#   sudo revert-privsep.sh [--apply] [--backup /root/sudoers-backup-<ts>]      (default backup: the one recorded in /var/lib/ou-priv/last-backup)
# Run from a root shell. Nothing is restarted.
set -euo pipefail
export LC_ALL=C
APPLY=0
BACKUP=""
while [ $# -gt 0 ]; do
  case $1 in
    --apply) APPLY=1 ;;
    --dry-run) APPLY=0 ;;
    --backup) BACKUP=${2:?--backup needs a directory}; shift ;;
    -h|--help) sed -n '2,6p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
  shift
done
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "run as root"
SUDOERS_DIR=${PRIVSEP_SUDOERS_DIR:-/etc/sudoers.d}
POLKIT_DIR=${PRIVSEP_POLKIT_DIR:-/etc/polkit-1/rules.d}
SYSD_DIR=${PRIVSEP_SYSTEMD_DIR:-/etc/systemd/system}
[ -n "$BACKUP" ] || BACKUP=$(cat /var/lib/ou-priv/last-backup 2>/dev/null || true)
[ -d "$BACKUP/sudoers.d" ] || die "no backup directory (give --backup /root/sudoers-backup-<ts>)"
echo "== revert from $BACKUP ($([ "$APPLY" = 1 ] && echo APPLY || echo DRY RUN))"
run() { if [ "$APPLY" = 1 ]; then echo "  + $*"; "$@"; else echo "  would: $*"; fi; }

# sudoers first, validated: the original files come back, ours go away
TMP=$(mktemp -d /run/ou-revert.XXXXXX)
trap 'rm -rf "$TMP"' EXIT
for f in "$BACKUP"/sudoers.d/*; do
  b=${f##*/}
  case $b in README) continue ;; esac
  if [ -f "$f" ]; then visudo -cf "$f" >/dev/null || die "backup file $b does not validate: not restoring"; fi
done
for f in "$BACKUP"/sudoers.d/*; do
  b=${f##*/}
  [ -f "$f" ] && run install -m 0440 -o root -g root "$f" "$SUDOERS_DIR/$b"
done
for n in ou-priv-signers ou-priv-lab ou-priv-testrunner; do
  [ -e "$BACKUP/sudoers.d/$n" ] || run rm -f "$SUDOERS_DIR/$n" "$SUDOERS_DIR/$n.new"
done
[ -e "$BACKUP/sudoers" ] && run install -m 0440 -o root -g root "$BACKUP/sudoers" /etc/sudoers
if [ "$APPLY" = 1 ]; then visudo -c >/dev/null || die "restored sudoers does not validate: inspect $BACKUP by hand"; echo "ok  sudoers restored and valid"; fi

run rm -f "$POLKIT_DIR/50-ou-privsep.rules" /etc/ssh/sshd_config.d/60-ou-privsep.conf
for u in ics.service ics-bootstrap.service ics-migrate.service ics-admin-fw.service ou-lab-fw.service ou-rb-backup@.service ou-repo-resign.service nginx.service postgresql@.service; do
  if [ -d "$BACKUP/dropins/$u.d" ] && [ -e "$BACKUP/dropins/$u.d/10-privsep.conf" ]; then
    run install -m 0644 "$BACKUP/dropins/$u.d/10-privsep.conf" "$SYSD_DIR/$u.d/10-privsep.conf"
  else
    run rm -f "$SYSD_DIR/$u.d/10-privsep.conf"
    [ -d "$SYSD_DIR/$u.d" ] && [ "$APPLY" = 1 ] && rmdir --ignore-fail-on-non-empty "$SYSD_DIR/$u.d"
  fi
done
run rm -rf /usr/local/lib/ou-priv
run systemctl daemon-reload
echo "NOTE: running units keep the sandbox they were started with until restarted."
[ "$APPLY" = 1 ] || echo "DRY RUN finished: nothing changed."
