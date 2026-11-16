#!/usr/bin/env python3
"""Lab: render the bootstrap configuration a golden-image guest receives for the artifact service (ADR-0015) and optionally apply the TRUST part of it.

  render  --base HOST:PORT --ca CA.pem --keys DIR --fprs dev=..,stable=.. --image-pub PEM --channels dev[,stable] --pkgs ou-libhx > conf.json
  apply   conf.json                      run ON THE CLIENT: ou_agent.firstboot.validate_config + apply_trust (the code the golden image runs at first boot)

`render` uses the same ArtifactMap / GuestSpec / callback_config code path as the ICS (agentport._artifact_fields), so what the client gets here is
byte-for-byte what a deployed VM would be told. `apply` needs ics/agent on PYTHONPATH (copied to /opt/ou-agent on the client)."""
import argparse
import base64
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(HERE, "..", "agent"))


def render(a):
    from cryptography.hazmat.primitives import serialization

    from ics import artifacts
    from ics.guest import cloudinit as ci
    amap = artifacts.load_map({"OU_ARTIFACT_BASE": a.base, "OU_ARTIFACT_CA_FILE": a.ca, "OU_ARTIFACT_CA_SHA256": artifacts.ca_sha256(open(a.ca).read()),
                               "OU_ARTIFACT_KEYS_DIR": a.keys, "OU_ARTIFACT_CHANNEL_FPRS": a.fprs,
                               "OU_ARTIFACT_SIGNED_REGISTRY": a.signed_registry or ""})
    pem = open(a.image_pub).read()
    der = serialization.load_pem_public_key(pem.encode()).public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    repos = []
    for ch in a.channels.split(","):
        k = amap.key(ch)
        repos.append({"url": amap.apt_url, "suite": ch, "components": ["main"], "key_armored": k[0], "key_fingerprint": k[1]})
    raw = b"golden-image"
    spec = ci.GuestSpec(hostname="ou-dist-client1", os="ubuntu-24.04", mgmt_sources=["192.168.186.1/32"], image_registries=[amap.registry_host],
                        image_signing_pubkey_pem=pem, image_signing_key_sha256=hashlib.sha256(der).hexdigest(), ou_repos=repos,
                        pkg_allowlist=a.pkgs.split(","), artifact_ca_pem=amap.ca_pem, artifact_ca_sha256=amap.ca_sha256,
                        artifact_tls_hosts=sorted({amap.apt_host, amap.registry_host}),
                        signed_registry=amap.signed_registry, image_repos=a.repos.split(",") if amap.signed_registry else [], enroll_token_sha256="0" * 64,
                        agent_bundle_b64=base64.b64encode(raw).decode(), agent_bundle_sha256=hashlib.sha256(raw).hexdigest())
    json.dump(ci.callback_config(spec, "ou-dist-client1", 8443, ["192.168.186.1/32"], []), sys.stdout, indent=1)


def apply(a):
    from ou_agent import firstboot
    conf = firstboot.validate_config(json.load(open(a.conf)))
    firstboot.apply_trust(firstboot.Guest("/"), conf)
    print("applied: repos=%s registries=%s ca_hosts=%s" % ([r["suite"] for r in conf["ou_repos"]], conf["image_registries"], conf["artifact_tls_hosts"]))


ap = argparse.ArgumentParser()
sp = ap.add_subparsers(dest="cmd", required=True)
r = sp.add_parser("render")
for k in ("base", "ca", "keys", "fprs", "image-pub", "channels", "pkgs"):
    r.add_argument("--" + k, required=True)
r.add_argument("--signed-registry", default=None)
r.add_argument("--repos", default="")
x = sp.add_parser("apply")
x.add_argument("conf")
args = ap.parse_args()
{"render": render, "apply": apply}[args.cmd](args)
