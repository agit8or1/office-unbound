#!/bin/sh
# Install the node agent inside a node (run as root ON the node). Usage: sh install-agent.sh <bind-address> <hostname> [config.json]
# [config.json] defaults to ./agent.json (Gromox node); use agent-files.json for the OpenCloud node. Identity runbook helpers in ./runbooks/ are installed
# when the config enables a gromox.* / opencloud.* runbook. Re-running upgrades code, allowlist and polkit rule and restarts the agent (enrollment is kept).
# Cloud-init path: OU_ENROLL_TOKEN_SHA256=<hex> arms enrollment with the ICS-generated token's HASH (plaintext never on the node; nothing printed).
# Expects ./ou_agent/, ./agent.json, ./ou-agent.service, ./render_polkit.py next to this script. Prints the enrollment
# token and the two fingerprints ONCE on the console; hand them to the ICS operator out of band.
set -eu
ADDR="$1"; HOST="$2"; CFGSRC="${3:-agent.json}"; D="$(cd "$(dirname "$0")" && pwd)"
export DEBIAN_FRONTEND=noninteractive
dpkg -s python3-cryptography >/dev/null 2>&1 || apt-get install -y -qq python3-cryptography
dpkg -s polkitd >/dev/null 2>&1 || apt-get install -y -qq polkitd
getent passwd ou-agent >/dev/null || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin ou-agent
install -d -o root -g root -m 0755 /opt/ou-agent /etc/ou-agent
rm -rf /opt/ou-agent/ou_agent && cp -r "$D/ou_agent" /opt/ou-agent/ou_agent && chown -R root:root /opt/ou-agent && chmod -R go-w /opt/ou-agent
find /opt/ou-agent -name __pycache__ -prune -exec rm -rf {} +
python3 - "$D/$CFGSRC" "$ADDR" > /etc/ou-agent/agent.json <<'PY'
import json, sys
c = json.load(open(sys.argv[1])); c["listen"]["address"] = sys.argv[2]; print(json.dumps(c, indent=2))
PY
chown root:root /etc/ou-agent/agent.json; chmod 0644 /etc/ou-agent/agent.json
GUEST=0; grep -q '"podman\.\|"guest\.\|"pkg\.' /etc/ou-agent/agent.json && GUEST=1
if [ "$GUEST" = 1 ]; then
  # guest runbooks (ADR-0009 s5): podman family runs as the rootless service user ou-svc (created by cloud-init), pkg as root
  grep -q '"pkg\.' /etc/ou-agent/agent.json && install -m 0644 "$D/runbooks/ou-rb-pkg@.service" /etc/systemd/system/
  if grep -q '"podman\.\|"guest\.' /etc/ou-agent/agent.json; then
    getent passwd ou-svc >/dev/null || { echo "user ou-svc missing (cloud-init creates it)" >&2; exit 1; }
    install -m 0644 "$D/runbooks/ou-rb-podman@.service" /etc/systemd/system/
  fi
  if grep -q '"podman\.pull_verified\|"podman\.deploy_unit' /etc/ou-agent/agent.json; then
    [ -s /etc/ou-agent/image-signing.pub ] || { echo "/etc/ou-agent/image-signing.pub missing" >&2; exit 1; }
    python3 "$D/render_image_policy.py" /etc/ou-agent/agent.json /etc/ou-agent/image-signing.pub policy > /etc/ou-agent/image-policy.json
    install -d -m 0755 /etc/containers/registries.d
    python3 "$D/render_image_policy.py" /etc/ou-agent/agent.json /etc/ou-agent/image-signing.pub registries > /etc/containers/registries.d/ou-agent.yaml
    python3 "$D/render_image_policy.py" /etc/ou-agent/agent.json /etc/ou-agent/image-signing.pub pullonly > /etc/ou-agent/image-policy-pullonly.json
    chmod 0644 /etc/ou-agent/image-policy.json /etc/ou-agent/image-policy-pullonly.json /etc/ou-agent/image-signing.pub /etc/containers/registries.d/ou-agent.yaml
  fi
fi
if grep -q '"gromox\.\|"opencloud\.' /etc/ou-agent/agent.json; then
  install -d -o root -g root -m 0755 /etc/ou-rb
  for fam in gromox opencloud; do
    grep -q "\"$fam\\." /etc/ou-agent/agent.json && for f in "$D"/runbooks/ou-rb-$fam-*@.service; do install -m 0644 "$f" /etc/systemd/system/; done
  done
  grep -q '"gromox\.' /etc/ou-agent/agent.json && install -m 0755 -o root -g root "$D/runbooks/ou-gw-user" /usr/local/sbin/ou-gw-user
  grep -q '"opencloud\.' /etc/ou-agent/agent.json && install -m 0755 -o root -g root "$D/runbooks/ou-oc-check" /usr/local/sbin/ou-oc-check
  grep -q '"opencloud\.' /etc/ou-agent/agent.json && install -m 0755 -o root -g root "$D/runbooks/ou-oc-revoke" /usr/local/sbin/ou-oc-revoke
  if grep -q '"gromox\.wipe_devices' /etc/ou-agent/agent.json; then   # grommunio-sync wipe contract (runbooks/ou-wipe-api); its DB account is created by the operator
    install -m 0755 -o root -g root "$D/runbooks/ou-wipe-api" /usr/local/sbin/ou-wipe-api
    install -m 0644 "$D/runbooks/ou-wipe-api.service" /etc/systemd/system/ou-wipe-api.service
  fi
  [ -n "${OU_MAIL_DOMAIN:-}" ] && printf '{"mail_domain": "%s"}\n' "$OU_MAIL_DOMAIN" > /etc/ou-rb/gromox.json
fi
if grep -q '"backup\.' /etc/ou-agent/agent.json; then   # backup product (ADR-0010): fixed template unit + root helper; tier configs /etc/ou-backup/<tier>.json are provisioned separately
  install -m 0644 "$D/runbooks/ou-rb-backup@.service" /etc/systemd/system/
  install -m 0755 -o root -g root "$D/runbooks/ou-backup" /usr/local/sbin/ou-backup
  install -m 0755 -o root -g root "$D/runbooks/ou-backup-canary.py" /usr/local/sbin/ou-backup-canary.py
fi
if grep -q '"pbx\.' /etc/ou-agent/agent.json; then
  for f in "$D"/runbooks/ou-rb-pbx-*@.service; do install -m 0644 "$f" /etc/systemd/system/; done
  install -m 0755 -o root -g root "$D/runbooks/ou-pbx-user" /usr/local/sbin/ou-pbx-user
fi
python3 "$D/render_polkit.py" /etc/ou-agent/agent.json > /etc/polkit-1/rules.d/50-ou-agent.rules
chmod 0644 /etc/polkit-1/rules.d/50-ou-agent.rules
install -d -o ou-agent -g ou-agent -m 0700 /var/lib/ou-agent
install -m 0644 "$D/ou-agent.service" /etc/systemd/system/ou-agent.service
systemctl daemon-reload
systemctl restart polkit 2>/dev/null || true
if [ ! -f /var/lib/ou-agent/agent_key.pem ]; then
  setpriv --reuid=ou-agent --regid=ou-agent --clear-groups env PYTHONPATH=/opt/ou-agent PYTHONDONTWRITEBYTECODE=1 \
    python3 -m ou_agent init --hostname "$HOST" ${OU_ENROLL_TOKEN_SHA256:+--token-sha256 "$OU_ENROLL_TOKEN_SHA256" --ttl "${OU_ENROLL_TTL:-86400}"}
fi
systemctl enable --now ou-agent.service
systemctl restart ou-agent.service
