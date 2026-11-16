#!/usr/bin/env python3
"""oci-publish-sig.py: store a signature made by ou-oci-sign next to its image in the registry, as a cosign-style attachment (tag sha256-<hex>.sig, OCI image
manifest, one layer = the simple-signing payload with the base64 signature in the annotation dev.cosignproject.cosign/signature), which is what
containers/image reads with `use-sigstore-attachments: true`. This program holds no trust: whoever may write to the registry may write junk here, and clients
only accept an attachment whose signature verifies against the pinned public key.
usage: oci-publish-sig.py <registry-http-base e.g. http://192.168.186.235:5000> <repo> <digest> <signed.tar from ou-oci-sign sign>"""
import hashlib
import io
import json
import sys
import tarfile
import urllib.request


def put(url, data, ctype, method="PUT"):
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": ctype})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.status, r.headers


def push_blob(base, repo, data):
    d = "sha256:" + hashlib.sha256(data).hexdigest()
    req = urllib.request.Request("%s/v2/%s/blobs/%s" % (base, repo, d), method="HEAD")
    try:
        urllib.request.urlopen(req, timeout=30)
        return d
    except Exception:  # noqa: BLE001
        pass
    r = urllib.request.urlopen(urllib.request.Request("%s/v2/%s/blobs/uploads/" % (base, repo), data=b"", method="POST"), timeout=30)
    loc = r.headers["Location"]
    loc = loc if loc.startswith("http") else base + loc
    put(loc + ("&" if "?" in loc else "?") + "digest=" + d, data, "application/octet-stream")
    return d


def main():
    base, repo, digest, tarf = sys.argv[1:5]
    files = {}
    with tarfile.open(tarf) as tf:
        for m in tf:
            files[m.name] = tf.extractfile(m).read()
    payload, sig = files["payload.json"], files["signature.b64"].decode()
    pj = json.loads(payload)
    assert pj["critical"]["image"]["docker-manifest-digest"] == digest, "payload names another digest"
    cfg = json.dumps({"architecture": "", "os": "", "config": {}, "rootfs": {"type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(payload).hexdigest()]}}, separators=(",", ":")).encode()
    cd, ld = push_blob(base, repo, cfg), push_blob(base, repo, payload)
    man = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                      "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": cd, "size": len(cfg)},
                      "layers": [{"mediaType": "application/vnd.dev.cosign.simplesigning.v1+json", "digest": ld, "size": len(payload),
                                  "annotations": {"dev.cosignproject.cosign/signature": sig}}]}, separators=(",", ":")).encode()
    tag = "sha256-" + digest.split(":")[1] + ".sig"
    st, _ = put("%s/v2/%s/manifests/%s" % (base, repo, tag), man, "application/vnd.oci.image.manifest.v1+json")
    print("published %s:%s (HTTP %s)" % (repo, tag, st))


main()
