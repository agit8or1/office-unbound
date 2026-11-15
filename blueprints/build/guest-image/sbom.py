#!/usr/bin/python3
"""CycloneDX 1.5 SBOM of the packages inside the image (run in the image at build time; ADR-0008 step 5). usage: sbom.py <os-id>"""
import json
import subprocess
import sys

os_id = sys.argv[1] if len(sys.argv) > 1 else "unknown"
out = subprocess.run(["dpkg-query", "-W", "-f", "${Package}\t${Version}\t${Architecture}\t${Status}\n"], capture_output=True, text=True, check=True).stdout
comps = []
for line in sorted(out.splitlines()):
    f = line.split("\t")
    if len(f) == 4 and f[3].endswith("installed"):
        comps.append({"type": "library", "name": f[0], "version": f[1], "purl": f"pkg:deb/{os_id.split('-')[0]}/{f[0]}@{f[1]}?arch={f[2]}"})
print(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                  "metadata": {"component": {"type": "operating-system", "name": f"ou-golden-{os_id}"}}, "components": comps}, indent=1))
