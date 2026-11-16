#!/bin/bash
# Client side of the OCI signing path (runs as the build user on the ICS/release host; holds no keys, makes no trust decision):
#   1. resolve <repo>:<tag> to its digest in the lab registry (the signer re-checks everything),
#   2. ask the test runner (ou-artifact-attest scan, user ou-testrunner) to pull that digest and build the SBOM + OSV scan itself,
#   3. hand request + SBOM + scan attestation (+ the ICS promotion manifest for staging/stable) to ou-oci-sign (user ou-ocisign),
#   4. store the returned signature as a cosign-style attachment in the registry (oci-publish-sig.py).
# usage: oci-sign.sh <dev|staging|stable> <repo e.g. ou/synapse> <tag> [promotion-manifest.json]       env: OU_OCI_REGISTRY_ADDR (default: /etc/office-unbound/oci-registry)
set -euo pipefail
CH=${1:?channel}; REPO=${2:?repo}; TAG=${3:?tag}; MAN=${4:-}
REG=${OU_OCI_REGISTRY_ADDR:-$(cat /etc/office-unbound/oci-registry)}
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
DIGEST=$(curl -fsSI -H 'Accept: application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json' "http://$REG/v2/$REPO/manifests/$TAG" | awk 'tolower($1)=="docker-content-digest:"{print $2}' | tr -d '\r')
[[ "$DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "cannot resolve $REPO:$TAG in $REG" >&2; exit 1; }
echo "$REPO:$TAG -> $DIGEST"
printf '{"repo":"%s","digest":"%s"}' "$REPO" "$DIGEST" | sudo -n -u ou-testrunner /usr/local/sbin/ou-artifact-attest scan > "$W/bundle.json"
python3 -I - "$W" "$REPO" "$TAG" "$DIGEST" "$CH" "$MAN" <<'PY'
import io, json, sys, tarfile
w, repo, tag, digest, ch, man = sys.argv[1:7]
b = json.load(open(w + "/bundle.json"))
print("scan attestation:", {k: b["attestation"][k] for k in ("result", "vuln_ids", "max_cvss", "sbom_components")})
files = {"request.json": json.dumps({"repo": repo, "tag": tag, "digest": digest, "channel": ch}).encode(), "sbom.cdx.json": b["sbom"].encode(),
         "scan.attestation.json": json.dumps({"attestation": b["attestation"], "sig": b["sig"]}).encode()}
if man:
    files["promotion-manifest.json"] = open(man, "rb").read()
with tarfile.open(w + "/req.tar", "w") as tf:
    for n, d in files.items():
        ti = tarfile.TarInfo(n)
        ti.size = len(d)
        tf.addfile(ti, io.BytesIO(d))
PY
sudo -n -u ou-ocisign /usr/local/sbin/ou-oci-sign sign < "$W/req.tar" > "$W/signed.tar"
python3 -I "$HERE/signer/oci-publish-sig.py" "http://$REG" "$REPO" "$DIGEST" "$W/signed.tar"
