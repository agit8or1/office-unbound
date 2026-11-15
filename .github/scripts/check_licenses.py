#!/usr/bin/env python3
"""License allowlist check for Python (installed distributions) and npm (package-lock.json) dependencies.

Fails (exit 1) on any license that is not on the allowlist, and on any package whose license cannot be determined
("unknown") or is proprietary/copyleft-strong. An SPDX expression passes if every AND-operand passes and at least one
OR-alternative of each group is allowed.

Usage:  check_licenses.py python            (checks the distributions installed in the running interpreter)
        check_licenses.py npm <package-lock.json>
"""
import json
import re
import sys
from importlib import metadata

ALLOWED = {
    "MIT", "MIT-0", "BSD-2-CLAUSE", "BSD-3-CLAUSE", "BSD", "0BSD", "APACHE-2.0", "ISC", "PSF-2.0", "PYTHON-2.0", "MPL-2.0",
    "UNLICENSE", "CC0-1.0", "CC-BY-4.0", "BLUEOAK-1.0.0", "ZLIB", "HPND",
    # weak copyleft, used only as unmodified, dynamically linked libraries (psycopg, ldap3)
    "LGPL-2.1", "LGPL-2.1-ONLY", "LGPL-2.1-OR-LATER", "LGPL-3.0", "LGPL-3.0-ONLY", "LGPL-3.0-OR-LATER",
}
# Python metadata is free text: map common phrases/classifiers to SPDX ids.
FREE_TEXT = [
    (r"apache", "APACHE-2.0"), (r"\bmit\b", "MIT"), (r"bsd", "BSD-3-CLAUSE"), (r"\bisc\b", "ISC"),
    (r"python software foundation|\bpsf\b", "PSF-2.0"), (r"mozilla public license", "MPL-2.0"),
    (r"lesser general public license|\blgpl", "LGPL-3.0"), (r"the unlicense|public domain", "UNLICENSE"),
]
DENY_HINT = re.compile(r"proprietary|commercial|all rights reserved|\bagpl\b|\bsspl\b|\bbusl\b|cc-by-nc|^gpl|(?<!lesser )general public license", re.I)


def _norm(s: str) -> str:
    return s.strip().strip("()").upper().replace(" ", "-")


def spdx_ok(expr: str) -> bool:
    expr = expr.strip()
    if not expr or DENY_HINT.search(expr):
        return False
    for group in re.split(r"\s+AND\s+", expr.replace("(", " ").replace(")", " "), flags=re.I):
        alts = re.split(r"\s+OR\s+", group.strip(), flags=re.I)
        if not any(_norm(a) in ALLOWED for a in alts if a.strip()):
            return False
    return True


def py_license(dist) -> str:
    md = dist.metadata
    expr = md.get("License-Expression")
    if expr:
        return expr
    classifiers = [c.split("::")[-1].strip() for c in md.get_all("Classifier") or [] if c.startswith("License ::")]
    lic = (md.get("License") or "").strip()
    cand = ([lic] if lic and len(lic) < 100 and "\n" not in lic else []) + classifiers
    ids = []
    for c in cand:
        if DENY_HINT.search(c):
            return c
        if _norm(c) in ALLOWED:
            ids.append(c)
            continue
        for pat, spdx in FREE_TEXT:
            if re.search(pat, c, re.I):
                ids.append(spdx)
                break
    return " AND ".join(dict.fromkeys(ids)) if ids else ""


def check_python() -> list[str]:
    bad = []
    for d in sorted(metadata.distributions(), key=lambda x: (x.metadata["Name"] or "").lower()):
        lic = py_license(d)
        if not spdx_ok(lic):
            bad.append(f"python {d.metadata['Name']}=={d.version}: license {lic or 'UNKNOWN'!r}")
    return bad


def check_npm(lock_path: str) -> list[str]:
    with open(lock_path) as f:
        lock = json.load(f)
    bad = []
    for path, pkg in sorted(lock.get("packages", {}).items()):
        if not path:
            continue
        lic = pkg.get("license")
        if isinstance(lic, dict):
            lic = lic.get("type")
        if isinstance(lic, list):
            lic = " OR ".join(x.get("type", "") if isinstance(x, dict) else str(x) for x in lic)
        if not lic or not spdx_ok(str(lic)):
            bad.append(f"npm {path}@{pkg.get('version')}: license {lic or 'UNKNOWN'!r}")
    return bad


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in ("python", "npm"):
        sys.exit(__doc__)
    problems = check_python() if sys.argv[1] == "python" else check_npm(sys.argv[2])
    for p in problems:
        print("LICENSE NOT ALLOWED:", p)
    print(f"{sys.argv[1]}: {'FAIL' if problems else 'ok'} ({len(problems)} problem(s))")
    sys.exit(1 if problems else 0)
