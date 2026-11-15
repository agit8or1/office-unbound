#!/usr/bin/python3
"""Lab-only: build a tiny OCI image layout (busybox httpd) without a container engine. usage: mkimg.py <outdir> <page-text>"""
import gzip, hashlib, io, json, os, sys, tarfile

out, page = sys.argv[1], sys.argv[2]
os.makedirs(out + "/blobs/sha256", exist_ok=True)
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w") as t:
    def add(name, data=b"", mode=0o644, type_=tarfile.REGTYPE, link=""):
        ti = tarfile.TarInfo(name); ti.size = len(data); ti.mode = mode; ti.type = type_; ti.linkname = link; ti.mtime = 0
        t.addfile(ti, io.BytesIO(data) if type_ == tarfile.REGTYPE else None)
    for d in ("bin", "www"):
        add(d, type_=tarfile.DIRTYPE, mode=0o755)
    add("bin/busybox", open("/usr/bin/busybox", "rb").read(), 0o755)
    add("www/index.html", (page + "\n").encode())
layer = gzip.compress(buf.getvalue(), mtime=0)
diff_id = hashlib.sha256(buf.getvalue()).hexdigest()


def blob(data):
    h = hashlib.sha256(data).hexdigest()
    open(f"{out}/blobs/sha256/{h}", "wb").write(data)
    return h, len(data)


lh, ls = blob(layer)
cfg = {"architecture": "amd64", "os": "linux", "config": {"Cmd": ["/bin/busybox", "httpd", "-f", "-p", "8080", "-h", "/www"], "User": "1000",
       "ExposedPorts": {"8080/tcp": {}}}, "rootfs": {"type": "layers", "diff_ids": ["sha256:" + diff_id]}}
ch, cs = blob(json.dumps(cfg).encode())
man = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
       "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": "sha256:" + ch, "size": cs},
       "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "sha256:" + lh, "size": ls}]}
mh, ms = blob(json.dumps(man).encode())
open(out + "/oci-layout", "w").write('{"imageLayoutVersion":"1.0.0"}')
json.dump({"schemaVersion": 2, "manifests": [{"mediaType": man["mediaType"], "digest": "sha256:" + mh, "size": ms}]}, open(out + "/index.json", "w"))
print("sha256:" + mh)
