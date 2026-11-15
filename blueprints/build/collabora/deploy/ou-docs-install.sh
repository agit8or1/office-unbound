#!/bin/bash
# One-pass runtime install of the Office Unbound Docs artifact (own Collabora Online build) on an office machine
# that already ran blueprints/lab/spike-identity-files/office/install-office.sh (nginx + lab TLS + vendor CODE).
# Root, INSIDE the machine. Idempotent. Replaces the vendor coolwsd (stopped + disabled, packages kept).
#   ou-docs-install.sh <artifact.tar> <wopi-host-url e.g. https://cloud.cr.ou-lab.internal:443> [ca-file=/etc/ou-lab/tls/ca.crt]
# Written by the A22 clean-room run from the manual steps of docs/status/docengine-rollout-results.md section 1
# (those were never scripted as one pass; the runtime apt packages came from oci/Containerfile).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TAR="${1:?artifact tar}"; WOPI="${2:?wopi host url}"; CA="${3:-/etc/ou-lab/tls/ca.crt}"
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends ca-certificates curl cpio fontconfig fonts-droid-fallback libcap2-bin \
  libpng16-16t64 libxcb-render0 libxcb-shm0 libxext6 libxrender1 libunwind8 libcurl4t64 libsqlite3-0 openssl
systemctl disable --now coolwsd 2>/dev/null || true       # vendor unit; same unit name is shadowed below
if [ ! -x /usr/bin/coolwsd ] || [ ! -d /opt/officeunbound-office ]; then
  tar -xf "${TAR}" -C /
fi
# coolwsd.xml: the artifact ships the patched default; keep an existing, already configured file (idempotent)
[ -s /etc/coolwsd/coolwsd.xml ] || { echo "artifact did not provide /etc/coolwsd/coolwsd.xml" >&2; exit 1; }
if ! grep -q "<host allow=\"true\">${WOPI}</host>" /etc/coolwsd/coolwsd.xml; then
  python3 "${HERE}/ou-docs-configure.py" "${WOPI}" "${CA}"
fi
bash "${HERE}/ou-docs-setup.sh"
install -m 0644 "${HERE}/coolwsd.service" /etc/systemd/system/coolwsd.service
systemctl daemon-reload
systemctl enable coolwsd
systemctl restart coolwsd
for i in $(seq 1 40); do curl -fsS http://[::1]:9980/hosting/discovery >/dev/null 2>&1 && { echo "Office Unbound Docs discovery OK"; exit 0; }; sleep 3; done
echo "no discovery: journalctl -u coolwsd" >&2; exit 1
