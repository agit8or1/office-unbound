#!/usr/bin/env bash
# Run on the ICS host after 10-deploy-pbx2.sh. Installs the Office Unbound node agent (ics/agent) into ou-pbx2 with the telephony runbooks
# (agent-pbx.json: pbx.sync_extensions, pbx.kick_user, pbx.user_state, pbx.issue_credential). The agent is then enrolled by `ics/scripts/lab_telephony.py setup`
# (arm-enroll -> node.enroll plan with two approvers).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; AG="$HERE/../../ics/agent"; n=ou-pbx2
inm() { sudo systemd-run -M "$n" --pipe --wait --quiet "$@"; }
inm rm -rf /root/agent-stage; inm mkdir -p /root/agent-stage
tar -C "$AG" -c ou_agent | inm tar -x -C /root/agent-stage
tar -C "$AG/deploy" -c . | inm tar -x -C /root/agent-stage
inm bash -c 'cd /root/agent-stage && sh install-agent.sh 192.168.186.248 ou-pbx2 agent-pbx.json' 2>&1 | grep -v -i "token\|fingerprint" | tail -5
inm systemctl is-active ou-agent
