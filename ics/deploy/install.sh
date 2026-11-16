#!/bin/sh
# Install/refresh the service. Run as root:  sudo sh deploy/install.sh
# Code and venv are copied to /opt/office-unbound/ics, owned by root and read-only to the service user, so neither the service
# account nor the interactive user can alter what runs as root (migrations) or as ics. Re-run after code changes.
set -eu
SRC="$(cd "$(dirname "$0")/.." && pwd)"
DST=/opt/office-unbound/ics
getent passwd ics >/dev/null || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin ics
install -d -o root -g root -m 0755 /opt/office-unbound "$DST"
rsync -a --delete --exclude .venv --exclude __pycache__ --exclude .pytest_cache --exclude tests --exclude node_modules "$SRC"/ "$DST"/
[ -x "$DST/.venv/bin/python" ] || python3 -m venv "$DST/.venv"
"$DST/.venv/bin/pip" install -q --require-hashes -r "$DST/requirements.lock"
# build metadata is computed here (install time), never by the running service (ADR-0011)
python3 "$SRC/deploy/write_build_info.py" "$SRC/.." "$DST/BUILD_INFO.json"
chown -R root:root "$DST"; chmod -R go-w "$DST"
# Deployment catalog (blueprints/catalog) — read by ics.deploy.catalog at /opt/office-unbound/blueprints/catalog.
# Found in production 2026-11-15: it was never installed (tests run from the checkout, where it sits next to the code) -> /catalog/* 500.
CAT_SRC="$SRC/../blueprints/catalog"
CAT_DST=/opt/office-unbound/blueprints/catalog
[ -d "$CAT_SRC" ] || { echo "install.sh: deployment catalog missing at $CAT_SRC" >&2; exit 1; }
install -d -m 0755 /opt/office-unbound/blueprints
rsync -a --delete "$CAT_SRC"/ "$CAT_DST"/
chown -R root:root /opt/office-unbound/blueprints; chmod -R go-w,a+rX /opt/office-unbound/blueprints
install -m 0644 "$DST/deploy/ics.service" "$DST/deploy/ics-migrate.service" "$DST/deploy/ics-bootstrap.service" /etc/systemd/system/
rm -f /etc/systemd/system/ics-callback.service   # renamed to ics-bootstrap.service
systemctl daemon-reload
systemctl enable ics-migrate.service ics.service ics-bootstrap.service
systemctl restart ics-migrate.service ics.service
# the guest-bootstrap listener only runs once /etc/office-unbound/callback.env exists (ConditionPathExists; written by bootstrap.sh --callback-listen)
if [ -f /etc/office-unbound/callback.env ]; then systemctl restart ics-bootstrap.service; else systemctl stop ics-bootstrap.service 2>/dev/null || true; fi
