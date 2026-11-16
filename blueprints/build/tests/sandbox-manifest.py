#!/usr/bin/env python3
"""Test helper for test-pipeline-security.sh (sandbox only): stands in for the ICS when it signs a promotion manifest.
  sandbox-manifest.py init <key-file> <pub-file>
  sandbox-manifest.py make <key-file> <from> <to> <component> <pool-dir> <state-dir> <approvers,comma> <requester-id> -> manifest JSON on stdout"""
import base64
import hashlib
import json
import os
import subprocess
import sys
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PREFIX = b"ou-release-promotion-v1\n"


def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def main():
    a = sys.argv[1:]
    if a[0] == "init":
        k = Ed25519PrivateKey.generate()
        open(a[1], "wb").write(k.private_bytes_raw())
        open(a[2], "w").write(base64.b64encode(k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode() + "\n")
        return
    key = Ed25519PrivateKey.from_private_bytes(open(a[1], "rb").read())
    frm, to, comp, pool, state, approvers, requester = a[2:9]
    pk, ev = [], []
    for fn in sorted(os.listdir(pool)):
        b = open(os.path.join(pool, fn), "rb").read()
        h = hashlib.sha256(b).hexdigest()
        e = {"file": fn, "sha256": h, "name": None, "version": None}
        if fn.endswith(".deb"):
            f = dict(ln.split(": ", 1) for ln in subprocess.run(["dpkg-deb", "-f", os.path.join(pool, fn)], capture_output=True, text=True).stdout.splitlines() if ": " in ln)
            e["name"], e["version"] = f["Package"], f["Version"]
            try:
                rec = json.load(open(os.path.join(state, "records", h + ".json")))["results"]["install-smoke"]
                ev.append({"sha256": h, "attestation_sha256": rec["attestation_sha256"]})
            except (OSError, KeyError, ValueError):
                pass
        pk.append(e)
    now = int(time.time())
    m = {"v": 1, "plan_id": "sandbox", "from": frm, "to": to, "component": comp, "requested_by_id": requester,
         "approvers": [{"id": x, "username": x} for x in approvers.split(",") if x], "approvals_required": 2 if to == "stable" else 1,
         "packages": pk, "evidence": ev, "nonce": base64.urlsafe_b64encode(os.urandom(18)).decode().rstrip("="), "issued_at": now, "expires_at": now + 600}
    print(json.dumps({"manifest": m, "sig": base64.b64encode(key.sign(PREFIX + canon(m))).decode()}))


main()
