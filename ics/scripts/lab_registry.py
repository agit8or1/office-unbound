#!/usr/bin/env python3
"""LAB TOOL (not part of the ICS): builds, signs and serves a tiny container image without a container engine, for the first real deployment test.

  lab_registry.py keygen <dir>                      ECDSA P-256 key pair (cosign-compatible: PEM private + public), prints the pin (sha256 of the DER SPKI)
  lab_registry.py build  <dir> <host:port/repo>     builds the busybox "echo" image, signs it (cosign simple-signing, registry attachment `sha256-<hex>.sig`),
                                                    stores it under <dir>/registry and prints  image=<host:port/repo>@sha256:<digest>
  lab_registry.py serve  <dir> <bind-address> <port>  read-only OCI distribution endpoint (GET/HEAD manifests and blobs) over plain HTTP

The registry transport is plain HTTP on the lab LAN ON PURPOSE: image integrity rests on the digest pin + the signature checked against the pinned
public key (guest policy `sigstoreSigned`), never on the transport. The private key never leaves <dir> (0600)."""
import argparse
import base64
import gzip
import hashlib
import http.server
import io
import json
import os
import sys
import tarfile

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

# a minimal SMTP-style responder (greeting 220, 250 to everything, 221 on QUIT): enough for the ICS `smtp_banner` check (greeting + EHLO)
SCRIPT = 'echo "220 ou-echo ESMTP ready"; while read l; do case "$l" in QUIT*) echo "221 bye"; exit 0;; *) echo "250 ou-echo";; esac; done'
CMD = ["/bin/busybox", "nc", "-ll", "-p", "2525", "-e", "/bin/busybox", "sh", "-c", SCRIPT]
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
SIG_MIME = "application/vnd.dev.cosign.simplesigning.v1+json"


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def keygen(d: str) -> None:
    os.makedirs(d, mode=0o700, exist_ok=True)
    k = ec.generate_private_key(ec.SECP256R1())
    fd = os.open(os.path.join(d, "sign.key"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    pem = k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    open(os.path.join(d, "sign.pub"), "wb").write(pem)
    der = k.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    print("pubkey=" + os.path.join(d, "sign.pub"))
    print("pin_sha256=" + sha(der))


def build(d: str, repo_ref: str) -> None:
    reg = os.path.join(d, "registry")
    os.makedirs(os.path.join(reg, "blobs"), exist_ok=True)
    key = serialization.load_pem_private_key(open(os.path.join(d, "sign.key"), "rb").read(), None)
    store = {}

    def put(data: bytes) -> str:
        h = sha(data)
        open(os.path.join(reg, "blobs", h), "wb").write(data)
        return h

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for name in ("bin",):
            ti = tarfile.TarInfo(name)
            ti.type, ti.mode, ti.mtime = tarfile.DIRTYPE, 0o755, 0
            t.addfile(ti)
        data = open("/usr/bin/busybox", "rb").read()
        ti = tarfile.TarInfo("bin/busybox")
        ti.size, ti.mode, ti.mtime = len(data), 0o755, 0
        t.addfile(ti, io.BytesIO(data))
    layer = gzip.compress(buf.getvalue(), mtime=0)
    lh = put(layer)
    cfg = {"architecture": "amd64", "os": "linux", "config": {"Cmd": CMD, "User": "1000", "ExposedPorts": {"2525/tcp": {}}},
           "rootfs": {"type": "layers", "diff_ids": ["sha256:" + sha(buf.getvalue())]}}
    ch = put(json.dumps(cfg, sort_keys=True).encode())
    man = {"schemaVersion": 2, "mediaType": OCI_MANIFEST,
           "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": "sha256:" + ch, "size": len(json.dumps(cfg, sort_keys=True))},
           "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "sha256:" + lh, "size": len(layer)}]}
    mb = json.dumps(man, sort_keys=True).encode()
    mh = put(mb)
    store["sha256:" + mh] = OCI_MANIFEST
    # cosign-format signature, attached as the tag sha256-<manifest hex>.sig
    payload = json.dumps({"critical": {"identity": {"docker-reference": repo_ref}, "image": {"docker-manifest-digest": "sha256:" + mh},
                                       "type": "cosign container image signature"}, "optional": None}, sort_keys=True, separators=(",", ":")).encode()
    sig = base64.b64encode(key.sign(payload, ec.ECDSA(hashes.SHA256()))).decode()
    ph = put(payload)
    empty = put(b"{}")
    sman = {"schemaVersion": 2, "mediaType": OCI_MANIFEST,
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": "sha256:" + empty, "size": 2},
            "layers": [{"mediaType": SIG_MIME, "digest": "sha256:" + ph, "size": len(payload), "annotations": {"dev.cosignproject.cosign/signature": sig}}]}
    sb = json.dumps(sman, sort_keys=True).encode()
    sh = put(sb)
    store["sha256:" + sh] = OCI_MANIFEST
    repo = repo_ref.partition("/")[2]
    idx = {"repo": repo, "manifests": store, "tags": {"1.0.0": "sha256:" + mh, f"sha256-{mh}.sig": "sha256:" + sh}}
    json.dump(idx, open(os.path.join(reg, "index.json"), "w"), indent=1)
    print(f"image={repo_ref}@sha256:{mh}")


def serve(d: str, addr: str, port: int) -> None:
    reg = os.path.join(d, "registry")
    idx = json.load(open(os.path.join(reg, "index.json")))
    repo = idx["repo"]

    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *a):
            sys.stderr.write("registry %s %s\n" % (self.client_address[0], fmt % a))

        def _send(self, code, body=b"", ctype="application/json", digest=None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Docker-Distribution-API-Version", "registry/2.0")
            if digest:
                self.send_header("Docker-Content-Digest", digest)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def do_GET(self):
            p = self.path.split("?")[0]
            if p in ("/v2/", "/v2"):
                return self._send(200, b"{}")
            pre = f"/v2/{repo}/"
            if not p.startswith(pre):
                return self._send(404, b'{"errors":[{"code":"NAME_UNKNOWN"}]}')
            kind, _, ref = p[len(pre):].partition("/")
            if kind == "manifests":
                dg = idx["tags"].get(ref, ref)
                if dg in idx["manifests"]:
                    b = open(os.path.join(reg, "blobs", dg.split(":")[1]), "rb").read()
                    return self._send(200, b, idx["manifests"][dg], dg)
            elif kind == "blobs" and ref.startswith("sha256:") and len(ref) == 71 and all(c in "0123456789abcdef" for c in ref[7:]):
                f = os.path.join(reg, "blobs", ref[7:])
                if os.path.isfile(f):
                    return self._send(200, open(f, "rb").read(), "application/octet-stream", ref)
            return self._send(404, b'{"errors":[{"code":"MANIFEST_UNKNOWN"}]}')

        do_HEAD = do_GET

    http.server.ThreadingHTTPServer((addr, port), H).serve_forever()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="cmd", required=True)
    a = sp.add_parser("keygen")
    a.add_argument("dir")
    b = sp.add_parser("build")
    b.add_argument("dir")
    b.add_argument("repo_ref")
    c = sp.add_parser("serve")
    c.add_argument("dir")
    c.add_argument("addr")
    c.add_argument("port", type=int)
    n = ap.parse_args()
    keygen(n.dir) if n.cmd == "keygen" else build(n.dir, n.repo_ref) if n.cmd == "build" else serve(n.dir, n.addr, n.port)
