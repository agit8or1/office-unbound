#!/bin/bash
# LAB driver (runs INSIDE a guest prepared by the ICS cloud-init renderer, as root): executes one guest runbook through the same fixed path the node agent
# uses after it has verified an ICS-signed request: spool the params, start the template unit ou-rb-<family>@<rid>.service (User=ou-svc for podman.*, root for
# pkg.install_pinned), read /run/ou-rb-<family>/<rid>.json. The helper re-validates the params against the root-owned /etc/ou-agent/agent.json itself, so
# nothing here bypasses a check. NOT covered: the ICS signature/approval hop (agent + plan), which has its own tests (test_guest_bootstrap.py, lab_guest_flow.py).
# usage: rb-drive.sh <action> '<json params>'
set -eu
ACTION=$1; PARAMS=$2
case $ACTION in pkg.install_pinned) FAM=pkg;; podman.*|guest.facts) FAM=podman;; *) echo "unknown action" >&2; exit 2;; esac
RID=r$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')
install -d -m 0755 -o ou-agent -g ou-agent /run/ou-agent-spool
python3 -I - "$ACTION" "$PARAMS" "$RID" <<'PY'
import json, os, sys
a, p, rid = sys.argv[1:4]
fd = os.open(f"/run/ou-agent-spool/{rid}.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
os.write(fd, json.dumps({"action": a, "params": json.loads(p)}).encode()); os.close(fd)
PY
chown ou-agent /run/ou-agent-spool/$RID.json
systemctl start --wait "ou-rb-$FAM@$RID.service" || true
cat "/run/ou-rb-$FAM/$RID.json"; echo
rm -f /run/ou-agent-spool/$RID.json
