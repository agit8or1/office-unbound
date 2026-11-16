#!/bin/sh
# LAB ONLY (agent BE, mailbox administration). Run as root ON a lab node (ou-gw1 / ou-files1) that already runs the production ou-agent.
# Starts a SECOND agent instance ("ou-agent-be", port 8446) with its own state dir, keys and trust, so a development ICS can be enrolled without
# touching the trust of the real ICS (nor of other sidecars). Code: a COPY of this branch's agent in /opt/ou-agent-be (the production /opt/ou-agent
# is never modified). Allowlist: a copy of the main agent's /etc/ou-agent/agent.json plus the mailbox runbooks (gromox.set_aliases ... mail_usage).
# On a Gromox node it also installs the template unit ou-rb-gromox-mbx@.service (PYTHONPATH=/opt/ou-agent-be) and the polkit rule
# /etc/polkit-1/rules.d/49-ou-agent-be.rules that lets user ou-agent START exactly that template (rule 50 denies everything else and would win otherwise).
# usage: lab_agent_sidecar_be.sh <dir-with-ou_agent-and-runbooks> [arm]     ("arm" prints a fresh enrollment token + the two fingerprints)
set -eu
SRC="$1"; STATE=/var/lib/ou-agent-be; CFGDIR=/etc/ou-agent-be; PORT=8446; CODE=/opt/ou-agent-be
install -d -o root -g root -m 0755 "$CODE" "$CFGDIR"
rm -rf "$CODE/ou_agent"; cp -r "$SRC/ou_agent" "$CODE/ou_agent"; chown -R root:root "$CODE"; chmod -R go-w "$CODE"; find "$CODE" -name __pycache__ -prune -exec rm -rf {} +
ADDR=$(python3 -c 'import json;print(json.load(open("/etc/ou-agent/agent.json"))["listen"]["address"])')
python3 - "$ADDR" "$PORT" "$SRC" > "$CFGDIR/agent.json" <<'PY'
import json, sys
sys.path.insert(0, sys.argv[3])
from ou_agent import guestspec, mbxspec, runbooks
known = set(runbooks.RUNBOOKS) | set(runbooks.USER_RUNBOOKS) | set(guestspec.GUEST_RUNBOOKS) | set(mbxspec.MBX_RUNBOOKS)
c = json.load(open("/etc/ou-agent/agent.json")); c["listen"] = {"address": sys.argv[1], "port": int(sys.argv[2])}
c["runbooks"] = {k: v for k, v in c["runbooks"].items() if k in known}      # the production allowlist may name runbooks this code does not have
if any(k.startswith("gromox.") for k in c["runbooks"]):
    for r in ("set_aliases", "shared_create", "shared_delete", "shared_access", "shared_state", "set_quota", "mail_usage"):
        c["runbooks"]["gromox." + r] = {"enabled": True}
print(json.dumps(c, indent=2))
PY
chmod 0644 "$CFGDIR/agent.json"
if grep -q '"gromox\.set_aliases' "$CFGDIR/agent.json"; then
  sed -e "s#/opt/ou-agent #/opt/ou-agent-be #; s#^Environment=PYTHONPATH=/opt/ou-agent #Environment=PYTHONPATH=$CODE #" "$SRC/runbooks/ou-rb-gromox-mbx@.service" > /etc/systemd/system/ou-rb-gromox-mbx@.service
  sed -i "s#PYTHONPATH=/opt/ou-agent #PYTHONPATH=$CODE #" /etc/systemd/system/ou-rb-gromox-mbx@.service
  cat > /etc/polkit-1/rules.d/49-ou-agent-be.rules <<'EOF'
// lab sidecar (agent BE): user ou-agent may START exactly the mailbox-administration template unit, nothing else
polkit.addRule(function(action, subject) {
  if (subject.user != "ou-agent" || action.id != "org.freedesktop.systemd1.manage-units" || action.lookup("verb") != "start") return polkit.Result.NOT_HANDLED;
  if (/^ou-rb-gromox-mbx@r[0-9a-f]{16}\.service$/.test(action.lookup("unit") || "")) return polkit.Result.YES;
  return polkit.Result.NOT_HANDLED;
});
EOF
  chmod 0644 /etc/polkit-1/rules.d/49-ou-agent-be.rules
fi
install -d -o ou-agent -g ou-agent -m 0700 "$STATE"
sed -e "s#/var/lib/ou-agent#$STATE#g" -e "s#PYTHONPATH=/opt/ou-agent #PYTHONPATH=$CODE #" -e 's#-m ou_agent serve#-m ou_agent --state '"$STATE"' --config '"$CFGDIR"'/agent.json serve#' \
    -e 's#RuntimeDirectory=ou-agent-spool#RuntimeDirectory=ou-agent-be-spool#' -e "s#^Description=.*#Description=Office Unbound node agent (lab sidecar BE for a development ICS)#" \
    /etc/systemd/system/ou-agent.service > /etc/systemd/system/ou-agent-be.service
sed -i "/^UMask=/a Environment=OU_AGENT_SPOOL=/run/ou-agent-be-spool" /etc/systemd/system/ou-agent-be.service
systemctl daemon-reload
systemctl restart polkit 2>/dev/null || true
RUN="setpriv --reuid=ou-agent --regid=ou-agent --clear-groups env PYTHONPATH=$CODE PYTHONDONTWRITEBYTECODE=1 python3 -m ou_agent --state $STATE --config $CFGDIR/agent.json"
if [ ! -f "$STATE/agent_key.pem" ]; then $RUN init --hostname "$(hostname)"; elif [ "${2:-}" = arm ]; then rm -f "$STATE/trust.json"; $RUN arm-enroll; fi
systemctl enable ou-agent-be.service >/dev/null 2>&1
systemctl restart ou-agent-be.service
sleep 1
systemctl is-active ou-agent-be.service
