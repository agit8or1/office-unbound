#!/bin/sh
# Run every gw_* lab test in order against gw1 and print a summary. Usage: gw_run_all.sh [seed|verify-only]
cd "$(dirname "$0")" || exit 2
rc=0
for t in gw_01_smtp_imap gw_02_ews_mapi_autodiscover gw_03_activesync gw_04_dav gw_05_shared_mailbox gw_08_web gw_07_backup_restore; do
  ${OU_PYTHON:-python3} $t.py || rc=1; echo
done
exit $rc
