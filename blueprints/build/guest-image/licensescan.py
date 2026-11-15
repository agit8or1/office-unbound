#!/usr/bin/env python3
"""Licence scan + SBOM finalisation for the golden image (ADR-0007 gate, ADR-0008 steps 3 and 5).
usage: licensescan.py <syft-cyclonedx.json> <license-policy.yaml> <os-id> <out-sbom.json> <out-report.json>

Input is the syft (pinned) CycloneDX SBOM of the final image tree. Every declared licence of every component is classified:
  allowed  - an SPDX id in the policy `allowed` list (a trailing '+' / '-or-later' spelling is normalised; `WITH <exception>` needs an `allowed_exceptions` entry)
  denied   - matches the denied patterns (proprietary / non-commercial / source-available): the build FAILS
  review   - anything else (unknown id, free text, LicenseRef, no licence information): listed in the report, not silently accepted; the owner reviews it
Exit 5 on `denied`. The finalised SBOM gets metadata (image name, os, summary counts) so the signed manifest covers the licence summary."""
import json
import re
import sys

DENY = re.compile(r"(proprietary|non-?commercial|CC-BY-NC|SSPL|BUSL|Elastic-2|Commons-Clause|non-free|Confluent|Sleepycat-proprietary)", re.I)


def policy(path):
    allowed, exc, cur = set(), set(), None
    for ln in open(path):
        s = ln.split("#")[0].rstrip()
        if re.match(r"^allowed:", s):
            cur = allowed
        elif re.match(r"^allowed_exceptions:", s):
            cur = exc
        elif re.match(r"^\S", s):
            cur = None
        m = re.match(r"^\s+-\s+(.+?)\s*$", s)
        if m and cur is not None:
            cur.add(m.group(1))
    return allowed, exc


ALIAS = {"expat": "MIT", "mit/x11": "MIT", "x11": "MIT", "public-domain": "CC0-1.0", "gpl": "", "lgpl": "", "isc": "ISC", "zlib/libpng": "Zlib",
         "bsd": "", "bsd-2-clause": "BSD-2-Clause", "bsd-3-clause": "BSD-3-Clause", "apache-2.0": "Apache-2.0", "mpl-2.0": "MPL-2.0", "mit": "MIT",
         "gpl-2": "GPL-2.0-only", "gpl-3": "GPL-3.0-only", "gpl-2+": "GPL-2.0-or-later", "gpl-3+": "GPL-3.0-or-later", "lgpl-2+": "LGPL-2.0-or-later",
         "lgpl-2.1": "LGPL-2.1-only", "lgpl-2.1+": "LGPL-2.1-or-later", "lgpl-3": "LGPL-3.0-only", "lgpl-3+": "LGPL-3.0-or-later", "gpl-2.0+": "GPL-2.0-or-later"}


def norm(i):
    i = i.strip().strip("()")
    if i.lower() in ALIAS:     # Debian copyright short names: "Expat" is MIT; "public-domain" is treated as CC0-equivalent for the allow decision (reported as an alias)
        i = ALIAS[i.lower()]
    i = re.sub(r"^(GPL|LGPL|AGPL)-(\d(?:\.\d)?)\+$", r"\1-\2-or-later", i)
    i = re.sub(r"^(GPL|LGPL|AGPL)-(\d(?:\.\d)?)$", r"\1-\2-only", i)
    return i


def classify(expr, allowed, exc):
    if DENY.search(expr):
        return "denied"
    if not expr.strip():
        return "review"
    # an expression is acceptable if EVERY AND-operand has at least one acceptable OR-alternative
    for conj in re.split(r"\s+AND\s+", expr):
        alts = re.split(r"\s+OR\s+", conj.strip().strip("()"))
        ok = False
        for a in alts:
            w = re.split(r"\s+WITH\s+", a.strip().strip("()"))
            if norm(w[0]) in allowed and (len(w) == 1 or w[1].strip() in exc):
                ok = True
        if not ok:
            return "review"
    return "allowed"


def main():
    sbom_in, pol, os_id, sbom_out, rep_out = sys.argv[1:6]
    allowed, exc = policy(pol)
    bom = json.load(open(sbom_in))
    # only packages count: file hashes (13k entries) and per-module kernel entries (covered by the linux-image package) are dropped from the SBOM
    comps = [c for c in bom.get("components", []) if c.get("type") != "file" and not any(p.get("value") == "linux-kernel-module" for p in c.get("properties", []))]
    bom["components"] = comps
    rep = {"allowed": 0, "review": {}, "denied": {}}
    for c in comps:
        exprs = []
        for l in c.get("licenses", []):
            exprs.append(l.get("expression") or (l.get("license") or {}).get("id") or (l.get("license") or {}).get("name") or "")
        expr = " AND ".join(e for e in exprs if e)
        r = classify(expr, allowed, exc)
        key = "%s@%s" % (c.get("name"), c.get("version"))
        if r == "allowed":
            rep["allowed"] += 1
        else:
            rep[r][key] = expr or "(no licence information)"
    summary = {"components": len(comps), "allowed": rep["allowed"], "review": len(rep["review"]), "denied": len(rep["denied"])}
    md = bom.setdefault("metadata", {})
    md["component"] = {"type": "operating-system", "name": "ou-golden-" + os_id, "bom-ref": "ou-golden-" + os_id}
    md.setdefault("properties", []).extend([{"name": "ou:licence-scan:" + k, "value": str(v)} for k, v in summary.items()])
    json.dump(bom, open(sbom_out, "w"), indent=1, sort_keys=True)
    json.dump({"summary": summary, "review": rep["review"], "denied": rep["denied"]}, open(rep_out, "w"), indent=1, sort_keys=True)
    print("licence scan: %s" % summary)
    if rep["denied"]:
        print("DENIED licences: %s" % rep["denied"], file=sys.stderr)
        sys.exit(5)


main()
