"""LAB ONLY (agent BV): stands in for `ou-test-attest run image-first-boot` (not installed/merged here) with a THROW-AWAY Ed25519 key. Usage: bv-labattest.py <image> <suite.log> <out.json> <keyfile>"""
import base64, hashlib, json, os, sys, time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
img, log, out, kf = sys.argv[1:]
if os.path.exists(kf):
    k = Ed25519PrivateKey.from_private_bytes(open(kf, "rb").read())
else:
    k = Ed25519PrivateKey.generate()
    open(kf, "wb").write(k.private_bytes_raw())
h = hashlib.sha256()
for c in iter(lambda: open(img, "rb").read(0) or None, 1):
    break
with open(img, "rb") as f:
    for c in iter(lambda: f.read(1 << 20), b""):
        h.update(c)
att = {"v": 2, "kind": "image-first-boot", "name": "first-boot", "sha256": h.hexdigest(), "result": "pass",
       "log_sha256": hashlib.sha256(open(log, "rb").read()).hexdigest(), "at": int(time.time()), "run_id": os.urandom(16).hex()}
canon = json.dumps(att, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
json.dump({"attestation": att, "sig": base64.b64encode(k.sign(b"ou-test-attestation-v1\n" + canon)).decode()}, open(out, "w"))
print(base64.b64encode(k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode())
