#!/usr/bin/env python3
"""ADR-0008 step 6: vulnerability scan of the SBOMs with osv-scanner (pinned, checksum-verified; queries the OSV
database, an authorized endpoint). Results are RECORDED, they do not fail the build (triage happens in the release gate).
  vulnscan.py <component> <state-dir> <build-dir>   -> <state>/out/<component>/vuln/"""
import hashlib
import json
import os
import subprocess
import sys
import urllib.request

comp, state, bdir = sys.argv[1:4]
out = os.path.join(state, "out", comp)
env = {}
for l in open(os.path.join(bdir, "tools.env")):
    if "=" in l and not l.startswith("#"):
        k, v = l.strip().split("=", 1)
        env[k] = v
tool = os.path.join(state, "tools", "osv-scanner_linux_amd64")
if not os.path.exists(tool):
    urllib.request.urlretrieve(env["OSV_URL"], tool)
if hashlib.sha256(open(tool, "rb").read()).hexdigest() != env["OSV_SHA256"]:
    sys.exit("CHECKSUM MISMATCH osv-scanner")
os.chmod(tool, 0o755)
vd = os.path.join(out, "vuln")
os.makedirs(vd, exist_ok=True)
summary = []
sbdir = os.path.join(out, "sbom")
for f in sorted(os.listdir(sbdir)):
    if not f.endswith(".spdx.json") or ".syft." in f:
        continue
    o = os.path.join(vd, f.replace(".spdx.json", ".osv.json"))
    r = subprocess.run([tool, "scan", "source", "-L", os.path.join(sbdir, f), "--format", "json",
                        "--output-file", o], capture_output=True, text=True)
    ids, pkgs = set(), 0
    import re
    m = re.search(r"found (\d+) packages", r.stdout + r.stderr)
    scanned = int(m.group(1)) if m else None
    try:
        d = json.load(open(o))
        for res in d.get("results", []):
            for p in res.get("packages", []):
                pkgs += 1
                for v in p.get("vulnerabilities", []):
                    ids.add((p["package"]["name"], p["package"]["version"], v["id"]))
    except Exception as e:  # noqa
        summary.append({"sbom": f, "error": f"rc={r.returncode} {r.stderr[-300:]} {e}"})
        print("vuln scan error", f, r.returncode, r.stderr[-300:])
        continue
    summary.append({"sbom": f, "packages_scanned": scanned, "vulnerable_packages": pkgs, "osv_scanner": env["OSV_VERSION"],
                    "advisories": sorted(f"{a}@{b} {c}" for a, b, c in ids)})
    print(f"vuln {f}: scanned {scanned} packages, {len(ids)} advisories across {pkgs} vulnerable packages")
json.dump(summary, open(os.path.join(vd, "summary.json"), "w"), indent=1)
