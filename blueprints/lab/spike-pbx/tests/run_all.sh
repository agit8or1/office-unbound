#!/usr/bin/env bash
# Run from the ICS host. Needs a venv with playwright + ldap3 (python3 -m venv v; v/bin/pip install playwright ldap3 requests) and
# `export PY=<venv>/bin/python`; see ../README.md for the environment variables used by pbx_lib.py.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; PY="${PY:-python3}"; rc=0
for t in p01_webrtc_call p02_native_tls p03_voicemail p05_provisioning_endpoint p04_deprovision; do
  "$PY" "$HERE/$t.py" 2>&1 | grep -v '^   | [A-Za-z0-9+/ ]*$' || true; [ "${PIPESTATUS[0]}" -eq 0 ] || rc=1
done; exit $rc
