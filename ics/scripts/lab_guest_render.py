#!/usr/bin/env python3
"""Lab: render cloud-init user-data for the nspawn guest ou-guest1 (the same renderer a Proxmox VM would use).
usage: lab_guest_render.py <outdir> <signing-pub.pem> <repo-key.asc> <repo-fingerprint> <guest-ip>
Writes <outdir>/user-data and <outdir>/enroll-token (mode 0600; the PLAINTEXT stays with the ICS side, user-data holds only its SHA-256)."""
import base64
import hashlib
import os
import secrets
import sys

from cryptography.hazmat.primitives import serialization

from ics.guest import cloudinit as ci

out, pub, asc, fpr, ip = sys.argv[1:6]
os.makedirs(out, exist_ok=True)
token = secrets.token_urlsafe(32)
fd = os.open(os.path.join(out, "enroll-token"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
os.write(fd, token.encode())
os.close(fd)
pem = open(pub).read()
der = serialization.load_pem_public_key(pem.encode()).public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
bundle = ci.build_agent_bundle(os.path.join(os.path.dirname(__file__), "..", "agent"))
spec = ci.GuestSpec(
    hostname="ou-guest1", domain="ou-lab.internal", mgmt_sources=["192.168.186.1/32"], agent_address=ip,
    enroll_token_sha256=hashlib.sha256(token.encode()).hexdigest(),
    agent_bundle_b64=base64.b64encode(bundle).decode(), agent_bundle_sha256=hashlib.sha256(bundle).hexdigest(),
    image_registries=["127.0.0.1:5000"], image_signing_pubkey_pem=pem, image_signing_key_sha256=hashlib.sha256(der).hexdigest(),
    ou_repo=ci.OuRepo(url="file:///srv/ou-repo", suite="noble", key_armored=open(asc).read(), key_fingerprint=fpr),
    pkg_allowlist=["ou-hello"], declared_ports=[ci.Port(port=8080, sources=["192.168.186.0/24"])],
    subid_start=20000, subid_count=40000,   # inside the 65536-id range an nspawn PrivateUsers=pick machine owns
)
open(os.path.join(out, "user-data"), "w").write(ci.render(spec))
print("rendered", len(ci.render(spec)), "bytes; image key sha256", spec.image_signing_key_sha256)
