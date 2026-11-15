#!/usr/bin/env bash
# Office Unbound lab: run a node agent for the backup RUNNER on this host (the host is the only place that can reach the nspawn machines).
# A SECOND, separate agent instance - not the production ICS and not any lab node's agent: own state dir, own port, own allowlist (backup.* only).
# Usage: sudo lab-agent-setup.sh <ics-repo-root> <bind-address> [port=18443] [handshake_out=/var/lib/ou-agent-bkplab/handshake.json]
# Prints nothing secret. The handshake file (0644) holds the one-time enrollment token of a LAB agent that only enrolls into a throwaway test ICS.
set -euo pipefail
R="${1:?ics repo root}"; ADDR="${2:?bind address (e.g. the oulab bridge IP)}"; PORT="${3:-18443}"; ST=/var/lib/ou-agent-bkplab; HS="${4:-$ST/handshake.json}"
rm -rf /opt/ou-agent-bkplab; install -d -m 0755 /opt/ou-agent-bkplab /etc/ou-agent-bkplab
cp -r "$R/ics/agent/ou_agent" /opt/ou-agent-bkplab/ou_agent; chown -R root:root /opt/ou-agent-bkplab; find /opt/ou-agent-bkplab -name __pycache__ -prune -exec rm -rf {} +
python3 - "$R/ics/agent/deploy/agent-backup.json" "$ADDR" "$PORT" > /etc/ou-agent-bkplab/agent.json <<'PY'
import json, sys
c = json.load(open(sys.argv[1])); c["listen"] = {"address": sys.argv[2], "port": int(sys.argv[3])}
c["runbooks"] = {k: v for k, v in c["runbooks"].items() if k.startswith("backup.")}
print(json.dumps(c, indent=2))
PY
chmod 0644 /etc/ou-agent-bkplab/agent.json
install -m 0644 "$R/ics/agent/deploy/runbooks/ou-rb-backup@.service" /etc/systemd/system/ou-rb-backup@.service
systemctl daemon-reload
systemctl stop ou-agent-bkplab 2>/dev/null || true
rm -rf "$ST"; install -d -m 0700 "$ST"
OUT="$(cd /opt/ou-agent-bkplab && PYTHONPATH=/opt/ou-agent-bkplab PYTHONDONTWRITEBYTECODE=1 python3 -m ou_agent --state "$ST" --config /etc/ou-agent-bkplab/agent.json init --hostname ou-bkp-runner)"
TOKEN="$(printf '%s\n' "$OUT" | sed -n 's/^ENROLLMENT TOKEN.*: //p')"
TLS="$(printf '%s\n' "$OUT" | sed -n 's/^tls_fingerprint_sha256=//p')"; KEY="$(printf '%s\n' "$OUT" | sed -n 's/^agent_key_fingerprint_sha256=//p')"
systemd-run --quiet --unit=ou-agent-bkplab --collect -p RuntimeDirectory=ou-agent-spool -p RuntimeDirectoryMode=0755 -p UMask=0077 \
  -E PYTHONPATH=/opt/ou-agent-bkplab -E PYTHONDONTWRITEBYTECODE=1 python3 -m ou_agent --state "$ST" --config /etc/ou-agent-bkplab/agent.json serve
umask 022
printf '{"address":"%s","port":%s,"token":"%s","tls_fingerprint_sha256":"%s","agent_key_fingerprint_sha256":"%s"}\n' "$ADDR" "$PORT" "$TOKEN" "$TLS" "$KEY" > "$HS"
echo "lab backup agent listening on $ADDR:$PORT (unit ou-agent-bkplab); handshake $HS"
