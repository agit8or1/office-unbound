#!/usr/bin/env bash
# Gate: the ICS, agent, portal and migration trees must stay valid on Python 3.11 (Debian 12).
# With python3.11 installed: byte-compile with it (compileall). Otherwise (dev host): token/AST check of every 3.12-only form (scripts/check_py311.py).
set -euo pipefail
cd "$(dirname "$0")/.."
TREES=(ics/ics ics/agent ics/migrations ics/tests portal migration scripts)
if command -v python3.11 >/dev/null 2>&1; then
  echo "python3.11 found: byte-compiling"
  python3.11 -m compileall -q -d . "${TREES[@]}" >/dev/null
  echo "compileall OK (python3.11)"
else
  echo "python3.11 not installed: static 3.12-syntax check"
  python3 -I scripts/check_py311.py "${TREES[@]}"
fi
