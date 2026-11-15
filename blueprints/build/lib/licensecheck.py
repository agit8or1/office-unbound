#!/usr/bin/env python3
"""ADR-0008 step 3: licence scan of a source tree + diff against the policy and docs/status/third-party-inventory.md.
  licensecheck.py <component> <source-dir> <report.json>
Exit 1 on: licence id not in policy (unknown), component missing from the inventory, bundled lock-file package
without a licence (unless excepted in the recipe). Declared-vs-found differences are recorded as warnings."""
import json
import os
import re
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.join(HERE, "..")
INVENTORY = os.path.join(BASE, "..", "..", "docs", "status", "third-party-inventory.md")
SPDX_RE = re.compile(rb"SPDX-License-Identifier:\s*([^\n\r*]*?)\s*(?:\*/|-->|--\}\}|\?>|$)", re.M)
SKIP_DIRS = {".git", "node_modules", "vendor"}
# plain-text licence files -> id (a fallback for trees without SPDX headers)
LICENSE_FILE_HINTS = [
    (re.compile(r"GNU AFFERO GENERAL PUBLIC LICENSE\s+Version 3", re.I), "AGPL-3.0-only"),
    (re.compile(r"GNU LESSER GENERAL PUBLIC LICENSE\s+Version 3", re.I), "LGPL-3.0-only"),
    (re.compile(r"GNU LESSER GENERAL PUBLIC LICENSE\s+Version 2\.1", re.I), "LGPL-2.1-only"),
    (re.compile(r"GNU GENERAL PUBLIC LICENSE\s+Version 3", re.I), "GPL-3.0-only"),
    (re.compile(r"GNU GENERAL PUBLIC LICENSE\s+Version 2", re.I), "GPL-2.0-only"),
]


DEPRECATED = re.compile(r"^(A?L?GPL-[0-9.]+)(\+)?$")


def canon(i):
    """map deprecated SPDX forms: GPL-2.0+ -> GPL-2.0-or-later, GPL-3.0 -> GPL-3.0-only"""
    i = i.strip().rstrip(".")
    m = DEPRECATED.match(i)
    if m:
        return m.group(1) + ("-or-later" if m.group(2) else "-only")
    return i


def split_expr(expr):
    expr = expr.replace(",", " ")
    expr = re.sub(r"(\d)\s+or-later", r"\1", expr)          # upstream typo form "CC-BY-SA-4.0 or-later"
    expr = re.sub(r";\s*SPDX-FileCopyrightText.*", "", expr)
    expr = re.sub(r"<.*", "", expr)
    toks = re.split(r"\s+(?:AND|OR)\s+|[()]", expr.strip(), flags=re.I)
    ids = set()
    for t in map(canon, toks):
        t = t.strip()
        if not t:
            continue
        m = re.match(r"(.+?)\s+WITH\s+(.+)", t, re.I)
        if m:
            ids.add(canon(m.group(1)))
            ids.add(m.group(2).strip())
        else:
            ids.add(t)
    return ids


def scan_tree(root):
    found, files = {}, 0
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in SKIP_DIRS]
        for f in fn:
            p = os.path.join(dp, f)
            try:
                if os.path.islink(p) or os.path.getsize(p) > 3_000_000:
                    continue
                with open(p, "rb") as fh:
                    data = fh.read()
            except OSError:
                continue
            files += 1
            for m in SPDX_RE.finditer(data[:20000]):
                for i in split_expr(m.group(1).decode("utf8", "replace")):
                    found.setdefault(i, 0)
                    found[i] += 1
            if re.match(r"(?i)^(copying|licen[cs]e)([._-][A-Za-z0-9._-]*)?$", f) and dp == root:
                txt = data[:20000].decode("utf8", "replace")
                for rx, lid in LICENSE_FILE_HINTS:
                    if rx.search(txt):
                        found.setdefault("file:" + lid, 0)
                        found["file:" + lid] += 1
    return found, files


YARN_ENTRY = re.compile(r'^"?(@?[^@\s"]+)@[^\n]*:\n  version "([^"]+)"', re.M)


def yarn_lock_packages(p, root):
    txt = open(p, encoding="utf8").read()
    return [("npm-yarn", n, v, [], os.path.relpath(p, root)) for n, v in sorted(set(YARN_ENTRY.findall(txt)))]


def lock_packages(root):
    """Bundled third-party packages from lock files: [(ecosystem, name, version, [licences])]."""
    out = []
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in (".git", "node_modules")]
        for f in fn:
            p = os.path.join(dp, f)
            if f == "package-lock.json":
                d = json.load(open(p))
                for k, v in (d.get("packages") or {}).items():
                    if not k:
                        continue
                    name = v.get("name") or k.split("node_modules/")[-1]
                    lic = v.get("license")
                    if isinstance(lic, dict):
                        lic = lic.get("type")
                    out.append(("npm", name, v.get("version", ""), [lic] if lic else [], os.path.relpath(p, root)))
            elif f == "yarn.lock":      # yarn classic: names + versions only, NO licence data (see the warning in main())
                out.extend(yarn_lock_packages(p, root))
            elif f == "composer.lock":
                d = json.load(open(p))
                for sec in ("packages", "packages-dev"):
                    if sec == "packages-dev":
                        continue  # dev packages are not shipped
                    for v in d.get(sec, []):
                        out.append(("composer", v["name"], v.get("version", ""), v.get("license") or [], os.path.relpath(p, root)))
    return out


def main():
    comp, root, report = sys.argv[1:4]
    recipe = yaml.safe_load(open(os.path.join(BASE, comp, "recipe.yaml")))
    policy = yaml.safe_load(open(os.path.join(BASE, "license-policy.yaml")))
    allowed = set(policy["allowed"]) | set(policy.get("allowed_exceptions", []))
    declared = set(recipe.get("licenses", []))
    excepted = recipe.get("license_exceptions", {}) or {}
    problems, warnings = [], []

    inv = open(INVENTORY, encoding="utf8").read().lower()
    key = recipe.get("inventory_match", comp).lower()
    in_inventory = key in inv
    if not in_inventory:
        problems.append(f"component '{key}' not found in docs/status/third-party-inventory.md")

    found, nfiles = scan_tree(root)
    for i in sorted(found):
        base = i[5:] if i.startswith("file:") else i
        if base not in allowed and base not in excepted:
            problems.append(f"licence id not in policy (unknown): {base} ({found[i]} files)")
        elif base not in declared and base not in excepted:
            warnings.append(f"found but not declared in recipe: {base} ({found[i]} files)")
    for d in sorted(declared):
        if d not in allowed:
            problems.append(f"recipe declares licence not in policy: {d}")

    bundled = lock_packages(root)
    seen = {}
    ny = sum(1 for b in bundled if b[0] == "npm-yarn")
    if ny:
        warnings.append(f"{ny} yarn.lock packages: the lock file has no licence data, per-package licences NOT scanned (open point)")
    for eco, name, ver, lics, src in bundled:
        if eco == "npm-yarn":
            continue
        if not lics:
            if name in excepted:
                continue
            problems.append(f"bundled {eco} package without licence metadata: {name} {ver} ({src})")
            continue
        for l in lics:
            for i in split_expr(l):
                if i not in allowed and name not in excepted and i not in excepted:
                    problems.append(f"bundled {eco} package {name} {ver}: licence not in policy: {i}")
                seen[i] = seen.get(i, 0) + 1
    rep = {"component": comp, "files_scanned": nfiles, "in_inventory": in_inventory, "spdx_found": found,
           "bundled_packages": len(bundled), "bundled_licences": seen, "warnings": warnings,
           "problems": problems, "result": "FAIL" if problems else "PASS"}
    json.dump(rep, open(report, "w"), indent=1, sort_keys=True)
    print(f"licence check {comp}: {rep['result']} files={nfiles} spdx_ids={len(found)} bundled={len(bundled)} "
          f"warnings={len(warnings)} problems={len(problems)}")
    for p in problems[:30]:
        print("  PROBLEM", p)
    sys.exit(1 if problems else 0)


main()
