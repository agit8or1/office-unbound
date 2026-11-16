# LAB host-side helper: render the cloud-init user-data of the proof machine with the ICS renderer. usage (cwd ics/, PYTHONPATH=.): art-render-userdata.py <outdir> <dev-oci-pubkey.pem> <dev-release-key.asc> <fingerprint>
import base64, hashlib, os, secrets, sys
from cryptography.hazmat.primitives import serialization
from ics.guest import cloudinit as ci
out, pub, asc, fpr = sys.argv[1:5]
os.makedirs(out, exist_ok=True)
token = secrets.token_urlsafe(32)
fd = os.open(os.path.join(out, "enroll-token"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600); os.write(fd, token.encode()); os.close(fd)
pem = open(pub).read()
der = serialization.load_pem_public_key(pem.encode()).public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
bundle = ci.build_agent_bundle("/home/administrator/office-unbound/.claude/worktrees/agent-abcd3d5ce99565c37/ics/agent")
spec = ci.GuestSpec(
    hostname="ou-art1", domain="ou-lab.internal", mgmt_sources=["192.168.186.1/32"], agent_address="192.168.186.248",
    enroll_token_sha256=hashlib.sha256(token.encode()).hexdigest(),
    agent_bundle_b64=base64.b64encode(bundle).decode(), agent_bundle_sha256=hashlib.sha256(bundle).hexdigest(),
    image_registries=["192.168.186.235:5000"], insecure_registries=["192.168.186.235:5000"],
    image_signing_pubkey_pem=pem, image_signing_key_sha256=hashlib.sha256(der).hexdigest(),
    ou_repo=ci.OuRepo(url="file:///srv/ou-repo", suite="dev", key_armored=open(asc).read(), key_fingerprint=fpr),
    pkg_allowlist=["slapd", "ldap-utils", "postgresql-16", "nginx", "openssl", "ca-certificates", "inotify-tools"],
    declared_ports=[ci.Port(port=443, sources=["192.168.186.0/24"]), ci.Port(port=636, sources=["192.168.186.0/24"])],
    subid_start=20000, subid_count=40000,
)
open(os.path.join(out, "user-data"), "w").write(ci.render(spec))
print("rendered", len(ci.render(spec)), "key sha256", spec.image_signing_key_sha256)
