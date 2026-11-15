#!/bin/sh
# Install/refresh the service. Run as root:  sudo sh deploy/install.sh
# Code and venv are copied to /opt/office-unbound/ics, owned by root and read-only to the service user, so neither the service
# account nor the interactive user can alter what runs as root (migrations) or as ics. Re-run after code changes.
set -eu
SRC="$(cd "$(dirname "$0")/.." && pwd)"
DST=/opt/office-unbound/ics
getent passwd ics >/dev/null || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin ics
install -d -o root -g root -m 0755 /opt/office-unbound "$DST"
rsync -a --delete --exclude .venv --exclude __pycache__ --exclude .pytest_cache --exclude tests "$SRC"/ "$DST"/
[ -x "$DST/.venv/bin/python" ] || python3 -m venv "$DST/.venv"
"$DST/.venv/bin/pip" install -q --require-hashes -r "$DST/requirements.lock"
chown -R root:root "$DST"; chmod -R go-w "$DST"
install -m 0644 "$DST/deploy/ics.service" "$DST/deploy/ics-migrate.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable ics-migrate.service ics.service
systemctl restart ics-migrate.service ics.service
