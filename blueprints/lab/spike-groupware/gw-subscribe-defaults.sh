#!/bin/bash
# One-time migration for mailboxes that existed BEFORE Gromox patch 0005 (midb subscribes the special-use folders by default):
# subscribe Drafts (0x0e), Sent Items (0x0a), Deleted Items (0x0b) and Junk Email (0x17) once, so clients that list only subscribed
# folders (Thunderbird) see the server's own folders instead of creating duplicate "Sent"/"Trash". New mailboxes get this from midb itself.
# Runs INSIDE the groupware node as root. Idempotent through a marker file: it never runs a second time, so a user's later
# unsubscribe is respected. Usage: gw-subscribe-defaults.sh [--force]
set -eu
MARK=/var/lib/gromox/.ou-default-subscriptions-done
[ "${1:-}" = "--force" ] || { [ ! -e "$MARK" ] || { echo "gw-subscribe-defaults: already done ($MARK)"; exit 0; }; }
command -v sqlite3 >/dev/null || apt-get install -y -q --no-install-recommends sqlite3 >/dev/null
n=0
for db in /var/lib/gromox/user/*/exmdb/midb.sqlite3; do
  [ -f "$db" ] || continue
  # the midb file is owned by gromox; write as that user so WAL side files keep their owner
  if runuser -u gromox -- sqlite3 "$db" "UPDATE folders SET unsub=0 WHERE folder_id IN (10,11,14,23) AND unsub=1" 2>/dev/null; then n=$((n+1)); fi
done
touch "$MARK"
# midb re-reads its files after a restart; gromox-imap must reconnect to midb too (it answers "fail to communicate with MIDB" otherwise)
if systemctl is-active --quiet gromox-midb; then systemctl restart gromox-midb; systemctl is-active --quiet gromox-imap && systemctl restart gromox-imap; fi
echo "gw-subscribe-defaults: $n mailbox(es) processed"
