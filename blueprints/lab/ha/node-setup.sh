#!/bin/bash
# LAB ONLY, runs INSIDE ou-ha-node1 (as root) from /root/src: the agent node + the central recorder (docs/status/ha-partition-results.md).
#   bash /root/src/blueprints/lab/ha/node-setup.sh <node-ip>
# Installs the real node agent (with the exec log), a STUB of the backup helper (/usr/local/sbin/ou-backup: records every backup.* run the agent admits),
# and the recorder as the systemd unit ha-recorder (fake PVE + webhook + control API).
set -euo pipefail
IP="${1:?node ip}"
S=/root/src
rm -rf /root/agentpkg && mkdir -p /root/agentpkg
cp -r $S/ics/agent/deploy/. /root/agentpkg/
cp -r $S/ics/agent/ou_agent /root/agentpkg/ou_agent
cat > /root/agentpkg/node-agent.json <<'EOF'
{
  "listen": {"address": "0.0.0.0", "port": 8443},
  "runbooks": {
    "service.status": {"units": ["ou-agent", "systemd-networkd"]},
    "disk.usage": {"paths": ["/"]},
    "backup.run": {"tiers": ["files"], "customers": ["c-0000000000000000000000000000a001"]},
    "backup.verify": {"tiers": ["files"], "customers": ["c-0000000000000000000000000000a001"]},
    "backup.prune": {"tiers": ["files"], "customers": ["c-0000000000000000000000000000a001"]}
  }
}
EOF
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -qq python3-cryptography python3-httpx >/dev/null 2>&1 || apt-get install -y -qq python3-cryptography
(cd /root/agentpkg && sh install-agent.sh "$IP" ou-ha-node1 node-agent.json) > /root/agent-install.log 2>&1 || { cat /root/agent-install.log; exit 1; }
# backup helper STUB: what the real root helper would do is irrelevant here; what matters is that a run is RECORDED when (and only when) the agent admitted it
install -d -m 0755 /var/lib/ha-recorder
cat > /usr/local/sbin/ou-backup <<'EOF'
#!/usr/bin/python3
import json, os, sys, time
rid = sys.argv[1]
spool = json.load(open(f"/run/ou-agent-spool/{rid}.json"))
with open("/var/lib/ha-recorder/backup.jsonl", "a") as f:
    f.write(json.dumps({"ts": round(time.time(), 3), "rid": rid, "action": spool["action"], "tier": spool["params"].get("tier")}) + "\n")
os.makedirs("/run/ou-rb-backup", exist_ok=True)
json.dump({"rid": rid, "result": {"stub": True, "snapshot_id": "00000000", "bytes_added": 0, "bytes_processed": 0, "repo_bytes": 0, "duration_seconds": 0}},
          open(f"/run/ou-rb-backup/{rid}.json", "w"))
EOF
chmod 0755 /usr/local/sbin/ou-backup
install -m 0644 $S/ics/agent/deploy/runbooks/ou-rb-backup@.service /etc/systemd/system/
systemctl daemon-reload
cat > /etc/systemd/system/ha-recorder.service <<EOF
[Unit]
Description=HA proof recorder (lab only)
After=network.target
[Service]
ExecStart=/usr/bin/python3 /root/src/blueprints/lab/ha/recorder.py --src /root/src/ics --bind $IP
Restart=on-failure
EOF
systemctl daemon-reload
systemctl enable --now ha-recorder.service
sleep 3
systemctl is-active ou-agent ha-recorder
journalctl -u ha-recorder -n 3 --no-pager | tail -3
grep -i "token\|fingerprint" /root/agent-install.log | sed 's/^/agent: /'
