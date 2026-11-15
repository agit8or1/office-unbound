#!/bin/sh
# LAB ONLY. Run as root ON a lab node that already runs the production ou-agent. Starts a SECOND agent instance ("sidecar", port 8444) with its own state dir,
# its own keys and its own trust (so a development ICS instance can be enrolled without touching the trust of the real ICS). It uses the same code
# (/opt/ou-agent), the same unprivileged user and therefore the same polkit rule / template units as the main agent; its allowlist is a copy of the main
# agent's /etc/ou-agent/agent.json, so deploy the main agent first (install-agent.sh) and re-run this script after changing the allowlist.
# usage: lab_agent_sidecar.sh [arm]      "arm" prints a fresh enrollment token and the two fingerprints (needed for node.enroll)
set -eu
STATE=/var/lib/ou-agent-ac; CFGDIR=/etc/ou-agent-ac; PORT=8444
ADDR=$(python3 -c 'import json;print(json.load(open("/etc/ou-agent/agent.json"))["listen"]["address"])')
install -d -o root -g root -m 0755 "$CFGDIR"
python3 - "$ADDR" "$PORT" > "$CFGDIR/agent.json" <<'PY'
import json, sys
c = json.load(open("/etc/ou-agent/agent.json")); c["listen"] = {"address": sys.argv[1], "port": int(sys.argv[2])}; print(json.dumps(c, indent=2))
PY
chmod 0644 "$CFGDIR/agent.json"
install -d -o ou-agent -g ou-agent -m 0700 "$STATE"
sed -e "s#/var/lib/ou-agent#$STATE#g" -e 's#-m ou_agent serve#-m ou_agent --state '"$STATE"' --config '"$CFGDIR"'/agent.json serve#' \
    -e 's#RuntimeDirectory=ou-agent-spool#RuntimeDirectory=ou-agent-ac-spool#' -e 's#^Description=.*#Description=Office Unbound node agent (lab sidecar for a development ICS)#' \
    /etc/systemd/system/ou-agent.service > /etc/systemd/system/ou-agent-ac.service
systemctl daemon-reload
RUN="setpriv --reuid=ou-agent --regid=ou-agent --clear-groups env PYTHONPATH=/opt/ou-agent PYTHONDONTWRITEBYTECODE=1 python3 -m ou_agent --state $STATE --config $CFGDIR/agent.json"
if [ ! -f "$STATE/agent_key.pem" ]; then $RUN init --hostname "$(hostname)"; elif [ "${1:-}" = arm ]; then rm -f "$STATE/trust.json"; $RUN arm-enroll; fi
systemctl enable ou-agent-ac.service >/dev/null 2>&1
systemctl restart ou-agent-ac.service
sleep 1
systemctl is-active ou-agent-ac.service
