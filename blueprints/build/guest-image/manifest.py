#!/usr/bin/env python3
"""Golden image manifest v2: builder side (stdlib only). The ICS side (verification) is ics/guest/golden.py `verify_release`; both must agree on SCHEMA.

  provenance --os O --epoch N --recipe-dir D --lock F --inrelease F --commit C --tool name=ver ...    prints provenance.json
  build --image F --sbom F --packages F --provenance F --attestation F --version N                    prints the UNSIGNED manifest.json (canonical JSON)
  lab-sign --manifest F --key KEY.pem                                                                 prints base64 DER ECDSA-P256/SHA-256 signature of the
                                                                                                      manifest bytes (LAB ONLY: the production signer is
                                                                                                      signer/ou-image-sign and holds the real key)

manifest.json (canonical: sorted keys, no whitespace, ASCII; the signature covers exactly these bytes):
  schema        "ou-golden-manifest-v2"
  name          "ou-golden-<os>-<YYYYMMDD>.qcow2"       image file name (also the key under which the ICS pins the release)
  os            "debian-12" | "ubuntu-24.04"
  version       integer, strictly monotonic per os (rollback floor in the ICS database)
  created_at    unix seconds == provenance.source_date_epoch
  image         {file, sha256, size}
  packages      {file, sha256, count}                    exact name=version list of the image (reproducibility input)
  sbom          {file, sha256}                           CycloneDX
  provenance    {file, sha256, ...}                      recipe hash, epoch, archive InRelease hashes, tool versions (the full provenance.json is
                                                         also shipped; its sha256 is bound here)
  boot_test     {attestation, sig, attestation_sha256}   the ou-test-attest v2 attestation (kind image-first-boot) for THIS image sha256, verbatim
"""
import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys

SCHEMA = "ou-golden-manifest-v2"
IMAGE_RE = re.compile(r"^ou-golden-(debian-12|ubuntu-24\.04)-(\d{8})\.qcow2$")


def canon(o) -> bytes:
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def sha256_file(p: str) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def cmd_provenance(a):
    rd = a.recipe_dir
    files = []
    for root, _dirs, fs in os.walk(rd):
        rel = os.path.relpath(root, rd)
        if rel.split(os.sep)[0] in ("bootproof", "signer", "tests", "__pycache__"):
            continue
        for f in fs:
            if f.endswith(".lock"):
                continue
            files.append(os.path.normpath(os.path.join(rel, f)))
    h = hashlib.sha256()
    for f in sorted(files):
        h.update(("%s  %s\n" % (sha256_file(os.path.join(rd, f)), f)).encode())
    inr = {}
    for line in open(a.inrelease).read().splitlines():
        if line.strip():
            d, n = line.split(None, 1)
            inr[n.strip()] = d
    tools = dict(t.split("=", 1) for t in a.tool)
    print(json.dumps({"os": a.os, "source_date_epoch": a.epoch, "recipe_sha256": h.hexdigest(), "recipe_commit": a.commit,
                      "package_lock_sha256": sha256_file(a.lock), "archive_inrelease_sha256": inr, "tools": tools}, sort_keys=True, indent=1))


def cmd_build(a):
    m = IMAGE_RE.match(os.path.basename(a.image))
    if not m:
        sys.exit("image name must be ou-golden-<os>-<YYYYMMDD>.qcow2")
    if a.version < 1:
        sys.exit("version must be a positive integer")
    prov = json.load(open(a.provenance))
    att = json.load(open(a.attestation))
    isha = sha256_file(a.image)
    if att["attestation"].get("sha256") != isha or att["attestation"].get("kind") != "image-first-boot" or att["attestation"].get("result") != "pass":
        sys.exit("the attestation is not a passing image-first-boot attestation of THIS image sha256")
    count = sum(1 for _ in open(a.packages) if _.strip())
    man = {"schema": SCHEMA, "name": os.path.basename(a.image), "os": m.group(1), "version": a.version, "created_at": prov["source_date_epoch"],
           "image": {"file": os.path.basename(a.image), "sha256": isha, "size": os.path.getsize(a.image)},
           "packages": {"file": os.path.basename(a.packages), "sha256": sha256_file(a.packages), "count": count},
           "sbom": {"file": os.path.basename(a.sbom), "sha256": sha256_file(a.sbom)},
           "provenance": {"file": os.path.basename(a.provenance), "sha256": sha256_file(a.provenance), "source_date_epoch": prov["source_date_epoch"],
                          "recipe_sha256": prov["recipe_sha256"], "package_lock_sha256": prov["package_lock_sha256"]},
           "boot_test": {"attestation": att["attestation"], "sig": att["sig"], "attestation_sha256": hashlib.sha256(canon(att["attestation"])).hexdigest()}}
    sys.stdout.buffer.write(canon(man) + b"\n")


def cmd_lab_sign(a):
    data = open(a.manifest, "rb").read()
    p = subprocess.run(["openssl", "dgst", "-sha256", "-sign", a.key], input=data, capture_output=True, check=True)
    sys.stdout.write(base64.b64encode(p.stdout).decode())


def main():
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="cmd", required=True)
    p = sp.add_parser("provenance")
    p.add_argument("--os", required=True)
    p.add_argument("--epoch", type=int, required=True)
    p.add_argument("--recipe-dir", required=True)
    p.add_argument("--lock", required=True)
    p.add_argument("--inrelease", required=True)
    p.add_argument("--commit", default="unknown")
    p.add_argument("--tool", action="append", default=[])
    p.set_defaults(f=cmd_provenance)
    b = sp.add_parser("build")
    for n in ("image", "sbom", "packages", "provenance", "attestation"):
        b.add_argument("--" + n, required=True)
    b.add_argument("--version", type=int, required=True)
    b.set_defaults(f=cmd_build)
    s = sp.add_parser("lab-sign")
    s.add_argument("--manifest", required=True)
    s.add_argument("--key", required=True)
    s.set_defaults(f=cmd_lab_sign)
    a = ap.parse_args()
    a.f(a)


main()
