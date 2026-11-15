#!/bin/sh
# Re-runnable UI verification: ics/e2e/run.sh <checkout_dir> [playwright args...]
#  - copies <checkout>/ics (read-only use of the checkout) to $E2E_ROOT/work/app, builds the frontend there,
#  - starts a real backend on 127.0.0.1:8108 against DB ics_test_h (env file /etc/office-unbound/ics-test-h.env, override E2E_ENV_FILE),
#  - seeds through the real API/CLI, runs the Playwright specs, stops the backend.
# Never touches the production ics service, deploy/install.sh or ports other than 8108.
# Env: E2E_ROOT (browsers/cache/work; default scratchpad ui-h), E2E_PY (python with the ICS requirements; default
#      <checkout>/ics/.venv or the main checkout venv), SHOT_DIR (screenshots; default <repo>/docs/screenshots/e2e).
set -eu
CHECKOUT=$(cd "${1:?usage: run.sh <checkout_dir> [playwright args]}" && pwd); shift
HERE=$(cd "$(dirname "$0")" && pwd)
E2E_ROOT=${E2E_ROOT:-/tmp/claude-1000/-home-administrator/a1d917f8-7438-424e-a57a-793b46deb95e/scratchpad/ui-h}
WORK=$E2E_ROOT/work; APP=$WORK/app
PY=${E2E_PY:-}
[ -z "$PY" ] && [ -x "$CHECKOUT/ics/.venv/bin/python" ] && PY=$CHECKOUT/ics/.venv/bin/python
[ -z "$PY" ] && PY=/home/administrator/office-unbound/ics/.venv/bin/python
mkdir -p "$WORK" "$E2E_ROOT/cache"

echo "[e2e] copying $CHECKOUT/ics -> $APP"
mkdir -p "$APP"
rsync -a --delete --exclude .venv --exclude node_modules --exclude e2e --exclude static --exclude __pycache__ "$CHECKOUT/ics/" "$APP/"

echo "[e2e] building frontend"
LOCK=$(sha256sum "$APP/frontend/package-lock.json" | cut -c1-16)
NM=$E2E_ROOT/cache/nm-$LOCK
if [ ! -d "$NM" ]; then
  (cd "$APP/frontend" && npm ci --no-audit --no-fund >/dev/null && mv node_modules "$NM")
fi
rm -rf "$APP/frontend/node_modules"; cp -al "$NM" "$APP/frontend/node_modules"  # hardlink copy (symlinks break module resolution)
(cd "$APP/frontend" && npx vite build >"$WORK/build.log" 2>&1) || { tail -20 "$WORK/build.log"; exit 1; }

echo "[e2e] starting backend + seed (database ics_test_h, port 8108)"
rm -f "$WORK/state.json"
"$PY" "$HERE/harness/launcher.py" --app-dir "$APP" --work "$WORK" --env-file "${E2E_ENV_FILE:-/etc/office-unbound/ics-test-h.env}" >"$WORK/launcher.log" 2>&1 &
LPID=$!
trap 'kill $LPID 2>/dev/null; wait $LPID 2>/dev/null || true' EXIT INT TERM
i=0
while [ ! -f "$WORK/state.json" ]; do
  kill -0 $LPID 2>/dev/null || { echo "[e2e] launcher died:"; tail -20 "$WORK/launcher.log"; tail -20 "$WORK/server.log" 2>/dev/null; exit 1; }
  i=$((i+1)); [ $i -gt 240 ] && { echo "[e2e] seed timeout"; exit 1; }
  sleep 1
done

echo "[e2e] running specs"
cd "$HERE"
[ -d node_modules ] || npm ci --no-audit --no-fund >/dev/null
rm -rf results; mkdir -p results
export E2E_STATE="$WORK/state.json" PLAYWRIGHT_BROWSERS_PATH="$E2E_ROOT/browsers"
export SHOT_DIR=${SHOT_DIR:-$HERE/../../docs/screenshots/e2e}
[ -d "$PLAYWRIGHT_BROWSERS_PATH" ] || npx playwright install chromium
# Chromium needs a few shared libraries that this host lacks; fetch the .debs (no root, no install) and extract them under E2E_ROOT.
SL=$E2E_ROOT/syslibs; SHELLBIN=$(ls "$PLAYWRIGHT_BROWSERS_PATH"/chromium_headless_shell-*/chrome-headless-shell-linux64/chrome-headless-shell | head -1)
if LD_LIBRARY_PATH="$SL/root/usr/lib/x86_64-linux-gnu" ldd "$SHELLBIN" | grep -q "not found" && [ ! -d "$SL/debs" ]; then
  mkdir -p "$SL/debs"
  (cd "$SL/debs" && apt-get download libatk1.0-0t64 libatk-bridge2.0-0t64 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 libasound2t64 libatspi2.0-0t64 libxrender1 libxi6 >/dev/null 2>&1 && for f in *.deb; do dpkg -x "$f" "$SL/root"; done)
fi
export LD_LIBRARY_PATH="$SL/root/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
rc=0
if [ $# -gt 0 ]; then
  npx playwright test "$@" || rc=$?   # custom selection: single invocation (add --project=setup if auth files are missing)
else
  npx playwright test --project=desktop --project=tablet --project=mobile || rc=$?
  npx playwright test --project=flows || rc=$?
fi
node scripts/findings-summary.mjs || true
exit $rc
