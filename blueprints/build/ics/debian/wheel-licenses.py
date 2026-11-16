"""wheel-licenses.json writer: read METADATA of every wheel in a directory. usage: wl.py <wheel-dir> <out.json>"""
import email
import glob
import json
import sys
import zipfile

out = []
for w in sorted(glob.glob(sys.argv[1] + "/*.whl")):
    z = zipfile.ZipFile(w)
    n = [x for x in z.namelist() if x.endswith(".dist-info/METADATA")][0]
    m = email.message_from_bytes(z.read(n))
    out.append({"name": m["Name"], "version": m["Version"], "license_expression": m.get("License-Expression"), "license": m.get("License"),
                "classifiers": [c.split(" :: ")[-1] for c in (m.get_all("Classifier") or []) if c.startswith("License :: ")]})
json.dump(out, open(sys.argv[2], "w"), indent=1)
