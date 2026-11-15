#!/bin/sh
# Install the node agent inside a node (run as root ON the node). Usage: sh install-agent.sh <bind-address> <hostname>
# Expects ./ou_agent/, ./agent.json, ./ou-agent.service, ./render_polkit.py next to this script. Prints the enrollment
# token and the two fingerprints ONCE on the console; hand them to the ICS operator out of band.
set -eu
ADDR="$1"; HOST="$2"; D="$(cd "$(dirname "$0")" && pwd)"
export DEBIAN_FRONTEND=noninteractive
dpkg -s python3-cryptography >/dev/null 2>&1 || apt-get install -y -qq python3-cryptography
dpkg -s polkitd >/dev/null 2>&1 || apt-get install -y -qq polkitd
getent passwd ou-agent >/dev/null || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin ou-agent
install -d -o root -g root -m 0755 /opt/ou-agent /etc/ou-agent
rm -rf /opt/ou-agent/ou_agent && cp -r "$D/ou_agent" /opt/ou-agent/ou_agent && chown -R root:root /opt/ou-agent && chmod -R go-w /opt/ou-agent
find /opt/ou-agent -name __pycache__ -prune -exec rm -rf {} +
python3 - "$D/agent.json" "$ADDR" > /etc/ou-agent/agent.json <<'PY'
import json, sys
c = json.load(open(sys.argv[1])); c["listen"]["address"] = sys.argv[2]; print(json.dumps(c, indent=2))
PY
chown root:root /etc/ou-agent/agent.json; chmod 0644 /etc/ou-agent/agent.json
python3 "$D/render_polkit.py" /etc/ou-agent/agent.json > /etc/polkit-1/rules.d/50-ou-agent.rules
chmod 0644 /etc/polkit-1/rules.d/50-ou-agent.rules
install -d -o ou-agent -g ou-agent -m 0700 /var/lib/ou-agent
install -m 0644 "$D/ou-agent.service" /etc/systemd/system/ou-agent.service
systemctl daemon-reload
systemctl restart polkit 2>/dev/null || true
if [ ! -f /var/lib/ou-agent/agent_key.pem ]; then
  setpriv --reuid=ou-agent --regid=ou-agent --clear-groups env PYTHONPATH=/opt/ou-agent PYTHONDONTWRITEBYTECODE=1 \
    python3 -m ou_agent init --hostname "$HOST"
fi
systemctl enable --now ou-agent.service
