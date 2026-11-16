#!/usr/bin/env bash
# Office Unbound privilege separation, OWNER-RUN (Priority 0-E). Replaces the blanket `NOPASSWD: ALL` rules of the operator account by exact,
# argument-validated rules, installs polkit/ssh/systemd hardening, and keeps a backup so revert-privsep.sh can undo everything.
#
#   sudo ics/deploy/privsep/apply-privsep.sh              dry run (default): validates, prints every action, changes nothing
#   sudo ics/deploy/privsep/apply-privsep.sh --apply      do it
# options: --operator NAME   the account that loses NOPASSWD ALL (default: administrator)
#          --with-ssh        also install sshd PermitRootLogin no (validated with sshd -t; sshd is NOT reloaded)
#          --restart-services  after the change, offer to restart the units whose sandbox changed (asks you to type a confirmation per run)
#
# RUN IT FROM A ROOT SHELL THAT DOES NOT DEPEND ON THE RULES BEING REMOVED (console, or `su -`; keep a second root shell open until you tested
# `sudo -l` as the operator). The script refuses to continue when the operator has no password or is in neither group `sudo` nor `admin` (lockout).
# Nothing is restarted by default; the production ics/nginx/postgresql units keep running their old sandbox until you restart them.
set -euo pipefail
export LC_ALL=C
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
OPERATOR=administrator
APPLY=0
WITH_SSH=0
RESTART=0
while [ $# -gt 0 ]; do
  case $1 in
    --apply) APPLY=1 ;;
    --dry-run) APPLY=0 ;;
    --operator) OPERATOR=${2:?--operator needs a name}; shift ;;
    --with-ssh) WITH_SSH=1 ;;
    --restart-services) RESTART=1 ;;
    -h|--help) sed -n '2,15p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
  shift
done

SUDOERS_DIR=${PRIVSEP_SUDOERS_DIR:-/etc/sudoers.d}
POLKIT_DIR=${PRIVSEP_POLKIT_DIR:-/etc/polkit-1/rules.d}
SYSD_DIR=${PRIVSEP_SYSTEMD_DIR:-/etc/systemd/system}
LIBDIR=/usr/local/lib/ou-priv
STATE=/var/lib/ou-priv
TS=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP=/root/sudoers-backup-$TS
LEGACY=(90-cloud-init-users 90-claude-administrator ou-release ou-image-sign)
NEW_SUDOERS=(ou-priv-signers ou-priv-lab ou-priv-testrunner)
SHIMS=(machinectl systemd-run systemctl tee test)
UNITS=(ics.service ics-bootstrap.service ics-migrate.service ics-admin-fw.service ou-lab-fw.service ou-rb-backup@.service ou-repo-resign.service nginx.service postgresql@.service)
RESTART_UNITS=(ics.service ics-bootstrap.service nginx.service postgresql@16-main.service)

say() { printf '%s\n' "$*"; }
act() { if [ "$APPLY" = 1 ]; then printf '  + %s\n' "$*"; else printf '  would: %s\n' "$*"; fi; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root (console or su -), not through the rules this script removes"
command -v visudo >/dev/null || die "visudo missing"
id "$OPERATOR" >/dev/null 2>&1 || die "no such account: $OPERATOR"

say "== privilege separation for account '$OPERATOR' ($([ "$APPLY" = 1 ] && echo APPLY || echo DRY RUN))"

# --- 1. lockout checks
pw=$(passwd -S "$OPERATOR" | awk '{print $2}')
[ "$pw" = P ] || die "$OPERATOR has no usable password (passwd -S says '$pw'); set one first (passwd $OPERATOR), otherwise nobody can use sudo afterwards"
id -nG "$OPERATOR" | tr ' ' '\n' | grep -qx -e sudo -e admin || die "$OPERATOR is in neither group sudo nor admin: no password-protected sudo rule would apply"
grep -Eq '^%(sudo|admin)[[:space:]]' /etc/sudoers || die "/etc/sudoers has no %sudo/%admin rule: the owner would lose all sudo"
say "ok  operator has a password and the password-protected group rule exists (it stays: interactive sudo for the owner)"

# --- 2. render + validate the new rules BEFORE anything is touched
WORK=$(mktemp -d /run/ou-privsep.XXXXXX)
trap 'rm -rf "$WORK"' EXIT
for f in "${NEW_SUDOERS[@]}"; do
  sed "s/@OPERATOR@/$OPERATOR/g" "$HERE/sudoers/$f" > "$WORK/$f"
  chmod 0440 "$WORK/$f"
  visudo -cf "$WORK/$f" >/dev/null || die "rendered $f does not validate (visudo -cf)"
  grep -Eq 'NOPASSWD:[[:space:]]*ALL([[:space:]]|$)' "$WORK/$f" && die "rendered $f contains NOPASSWD: ALL"
  say "ok  visudo -cf $f"
done
if [ -d "$POLKIT_DIR" ]; then
  [ -s "$HERE/polkit/50-ou-privsep.rules" ] || die "polkit rule missing from the package"
fi
python3 -I -c 'import ast,sys; ast.parse(open(sys.argv[1]).read())' "$HERE/lib/ou-lab-policy" || die "policy program does not parse"
say "ok  lab policy program parses"

# --- 3. what exists today
say "-- current rules of $OPERATOR (before):"
sudo -l -U "$OPERATOR" 2>/dev/null | sed -n '/may run/,$p' | sed 's/^/     /' || true
for f in "${LEGACY[@]}"; do [ -e "$SUDOERS_DIR/$f" ] && say "   legacy rule file present: $SUDOERS_DIR/$f"; done

# --- 4. the plan
act "back up $SUDOERS_DIR, /etc/sudoers, $POLKIT_DIR, ssh drop-ins and the touched unit drop-in dirs to $BACKUP/"
act "install $LIBDIR (ou-lab-policy + 5 shims: ${SHIMS[*]})"
for f in "${NEW_SUDOERS[@]}"; do act "install $SUDOERS_DIR/$f (staged as $f.new, validated, then moved)"; done
for f in "${LEGACY[@]}"; do [ -e "$SUDOERS_DIR/$f" ] && act "move $SUDOERS_DIR/$f to $BACKUP/ (only after the new rules validated together)"; done
[ -d "$POLKIT_DIR" ] && act "install $POLKIT_DIR/50-ou-privsep.rules"
[ "$WITH_SSH" = 1 ] && act "install /etc/ssh/sshd_config.d/60-ou-privsep.conf (PermitRootLogin no), sshd -t; sshd NOT reloaded"
unit_exists() { systemctl cat "$1" >/dev/null 2>&1 || [ -e "$SYSD_DIR/$1" ] || [ -e "/usr/lib/systemd/system/$1" ]; }
for u in "${UNITS[@]}"; do
  if unit_exists "$u"; then act "install $SYSD_DIR/$u.d/10-privsep.conf"; else say "  skip $u (unit not installed on this host)"; fi
done
act "systemctl daemon-reload (no unit is restarted)"
act "verify: sudo -l -U $OPERATOR lists no NOPASSWD ALL; on failure restore everything from $BACKUP automatically"

if [ "$APPLY" != 1 ]; then
  say ""; say "DRY RUN finished: nothing was changed. Re-run with --apply."
  exit 0
fi

# --- 5. backup
install -d -m 0700 "$BACKUP" "$STATE"
cp -a /etc/sudoers "$BACKUP/sudoers"
mkdir -p "$BACKUP/sudoers.d" "$BACKUP/polkit" "$BACKUP/dropins"
cp -a "$SUDOERS_DIR/." "$BACKUP/sudoers.d/"
[ -d "$POLKIT_DIR" ] && cp -a "$POLKIT_DIR/." "$BACKUP/polkit/"
: > "$BACKUP/installed.list"
{ for f in "${NEW_SUDOERS[@]}"; do echo "$SUDOERS_DIR/$f"; done; echo "$POLKIT_DIR/50-ou-privsep.rules"; echo /etc/ssh/sshd_config.d/60-ou-privsep.conf; } >> "$BACKUP/installed.list"
for u in "${UNITS[@]}"; do echo "$SYSD_DIR/$u.d/10-privsep.conf" >> "$BACKUP/installed.list"
  [ -d "$SYSD_DIR/$u.d" ] && { mkdir -p "$BACKUP/dropins/$u.d"; cp -a "$SYSD_DIR/$u.d/." "$BACKUP/dropins/$u.d/"; }; done
printf '%s\n' "$BACKUP" > "$STATE/last-backup"
say "ok  backup in $BACKUP"

rollback() {
  say "!! rolling back from $BACKUP"
  bash "$HERE/revert-privsep.sh" --apply --backup "$BACKUP" || say "!! automatic rollback failed: restore by hand: cp -a $BACKUP/sudoers.d/. $SUDOERS_DIR/"
}

# --- 6. install helpers and rules (new rules first, legacy removal last)
install -d -m 0755 -o root -g root /usr/local/lib/ou-priv "$LIBDIR/bin"
install -m 0755 -o root -g root "$HERE/lib/ou-lab-policy" "$LIBDIR/ou-lab-policy"
for s in "${SHIMS[@]}"; do install -m 0755 -o root -g root "$HERE/lib/shim" "$LIBDIR/bin/$s"; done
echo "$LIBDIR" >> "$BACKUP/installed.list"
for f in "${NEW_SUDOERS[@]}"; do
  install -m 0440 -o root -g root "$WORK/$f" "$SUDOERS_DIR/$f.new"
  visudo -cf "$SUDOERS_DIR/$f.new" >/dev/null || { rm -f "$SUDOERS_DIR/$f.new"; rollback; die "$f.new failed validation"; }
  mv "$SUDOERS_DIR/$f.new" "$SUDOERS_DIR/$f"
done
visudo -c >/dev/null || { rollback; die "combined sudoers does not validate with the new rules"; }
say "ok  new sudoers rules installed and the combined configuration validates"
for f in "${LEGACY[@]}"; do [ -e "$SUDOERS_DIR/$f" ] && mv "$SUDOERS_DIR/$f" "$BACKUP/removed-$f"; done
visudo -c >/dev/null || { rollback; die "sudoers invalid after removing legacy rules"; }

# --- 7. verify
after=$(sudo -l -U "$OPERATOR" 2>&1) || { rollback; die "sudo -l failed"; }
if printf '%s\n' "$after" | grep -Eq 'NOPASSWD:[[:space:]]*ALL[[:space:]]*$'; then
  printf '%s\n' "$after" >&2; rollback; die "$OPERATOR still has NOPASSWD ALL (another rule grants it): rolled back"
fi
say "ok  sudo -l -U $OPERATOR shows no NOPASSWD ALL:"
printf '%s\n' "$after" | sed -n '/may run/,$p' | sed 's/^/     /'

# --- 8. polkit, ssh, systemd
if [ -d "$POLKIT_DIR" ]; then install -m 0644 -o root -g root "$HERE/polkit/50-ou-privsep.rules" "$POLKIT_DIR/50-ou-privsep.rules"; say "ok  polkit rule installed"; fi
if [ "$WITH_SSH" = 1 ]; then
  install -d -m 0755 /etc/ssh/sshd_config.d
  install -m 0644 -o root -g root "$HERE/sshd/60-ou-privsep.conf" /etc/ssh/sshd_config.d/60-ou-privsep.conf
  if sshd -t; then say "ok  sshd config valid; reload ssh yourself: systemctl reload ssh"; else rm -f /etc/ssh/sshd_config.d/60-ou-privsep.conf; say "!! sshd -t failed: ssh drop-in removed"; fi
fi
for u in "${UNITS[@]}"; do
  if unit_exists "$u"; then install -d -m 0755 "$SYSD_DIR/$u.d"; install -m 0644 -o root -g root "$HERE/systemd/$u.d/10-privsep.conf" "$SYSD_DIR/$u.d/10-privsep.conf"; fi
done
systemctl daemon-reload
say "ok  unit drop-ins installed, daemon reloaded (no unit restarted)"

# --- 9. restarts (never silent)
say ""
say "Units whose running sandbox is still the OLD one until restarted:"
for u in "${RESTART_UNITS[@]}"; do systemctl is-active --quiet "$u" 2>/dev/null && say "   $u  (active)  -> systemctl restart $u"; done
if [ "$RESTART" = 1 ]; then
  say "These are PRODUCTION services (console, reverse proxy, database). A restart interrupts users for a few seconds."
  printf 'Type "restart production" to restart them now (anything else skips): '
  read -r ans || ans=
  if [ "$ans" = "restart production" ]; then
    for u in ics-migrate.service postgresql@16-main.service ics.service ics-bootstrap.service nginx.service; do
      systemctl is-active --quiet "$u" 2>/dev/null || continue
      if systemctl restart "$u"; then say "   restarted $u"; else say "!! $u failed to restart: journalctl -u $u; revert with revert-privsep.sh"; fi
    done
  else say "skipped"; fi
fi
say ""
say "DONE. Test now from the operator account (a second shell): sudo -n true must FAIL, sudo -n /usr/local/sbin/ou-release-sign status must work."
say "Undo: sudo $HERE/revert-privsep.sh --apply   (backup: $BACKUP)"
