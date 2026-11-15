#!/usr/bin/env bash
# Run all automated acceptance tests; print a summary; exit nonzero if any FAILED.
# Usage: ./run_all.sh [files|groupware|all]     (default: all)
# Needs OU_CA_FILE + OU_PASSWORD_* in the environment (see lab-test.env.example).
set -u
cd "$(dirname "$0")"
which="${1:-all}"
files=(t01_oidc.py t02_files_webdav.py t03_office_roundtrip.py t04_wopi.py t05_versions.py t06_disable_user.py)
groupware=(t10_smtp_imap.py t11_caldav.py t12_carddav.py t13_ews.py t14_activesync.py t15_autodiscover.py t16_mapihttp.py)
case "$which" in files) list=("${files[@]}");; groupware) list=("${groupware[@]}");; all) list=("${files[@]}" "${groupware[@]}");; *) echo "usage: $0 [files|groupware|all]"; exit 2;; esac
rc=0; summary=()
for t in "${list[@]}"; do
  "${OU_PYTHON:-python3}" -I "$t"; c=$?   # -I: isolated mode; each test adds its own dir to sys.path
  summary+=("$t exit=$c"); [ "$c" -ne 0 ] && rc=1
  echo
done
echo "==== summary ===="; printf '%s\n' "${summary[@]}"
echo "(exit 77 = skipped under OU_STRICT_SKIP). Manual tests still required: see MANUAL-CHECKLIST.md"
exit "$rc"
