#!/usr/bin/env python3
"""Check docs/status/SECURITY-REMEDIATION.md against the repository.

What it verifies (CI friendly: prints one line per mismatch, exit 1 when there is any error):
  * every `path:line` token (optionally `sha:path:line`) names a file that exists (at HEAD/working tree, or at that commit) and a line inside it;
  * every `path::test_name` token (optionally `sha:`-prefixed) names a `def test_name` in that file;
  * every status is in the vocabulary; every row not "Fixed on main" has a non-empty remaining-risk/plan cell;
    every "Fixed ..." row has at least one fix location and a regression-test cell;
  * the severity x status count table at the top equals the counts recomputed from the findings table.
Commits that are not present in this clone (branch-only work) are warnings; --strict makes them errors.

Usage: python3 scripts/security_remediation_check.py [--strict] [--doc PATH]
"""
import argparse
import collections
import os
import re
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CATS = ["Fixed on main", "Fixed on branch (pending merge)", "Partial", "Open", "Accepted risk", "Owner action"]
LOC = re.compile(r"^(?:([0-9a-f]{7,40}):)?([^:\s]+):(\d+)$")
TST = re.compile(r"^(?:([0-9a-f]{7,40}):)?([^:\s]+)::([A-Za-z_]\w*)$")


def git(*a):
    r = subprocess.run(["git", "-C", ROOT, *a], capture_output=True)
    return r.returncode, r.stdout


_cache: dict = {}


def content(ref, path):
    """file text at ref (None = working tree), or None when absent. Returns 'NOREF' when the commit is not in this clone."""
    key = (ref, path)
    if key in _cache:
        return _cache[key]
    if ref is None:
        p = os.path.join(ROOT, path)
        val = open(p, encoding="utf-8", errors="replace").read() if os.path.isfile(p) else None
    else:
        rc, _ = git("cat-file", "-e", ref + "^{commit}")
        if rc != 0:
            val = "NOREF"
        else:
            rc, out = git("show", f"{ref}:{path}")
            val = out.decode("utf-8", "replace") if rc == 0 else None
    _cache[key] = val
    return val


def category(status):
    for pre, c in (("Fixed on main", CATS[0]), ("Fixed on branch", CATS[1]), ("Partial", CATS[2]), ("Open", CATS[3]),
                   ("Accepted risk", CATS[4]), ("Owner action", CATS[5])):
        if status.startswith(pre):
            return c
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--strict", action="store_true", help="treat commits missing from this clone as errors")
    ap.add_argument("--doc", default=os.path.join(ROOT, "docs/status/SECURITY-REMEDIATION.md"))
    a = ap.parse_args()
    text = open(a.doc, encoding="utf-8").read()
    errors, warns = [], []
    rows, summary = [], {}
    in_table = False
    for ln in text.splitlines():
        if ln.startswith("## Findings table"):
            in_table = True
            continue
        if in_table and ln.startswith("## "):
            in_table = False
        m = re.match(r"^\| (Critical|High|Medium|Low) \| (\d+) \| (\d+) \| (\d+) \| (\d+) \| (\d+) \| (\d+) \| (\d+) \|$", ln)
        if m:
            summary[m.group(1)] = [int(x) for x in m.groups()[1:]]
        if in_table and ln.startswith("| ") and not ln.startswith("| ID ") and not ln.startswith("|---"):
            cells = [c.strip() for c in re.split(r"(?<!\\)\|", ln.strip().strip("|"))]
            if len(cells) != 8:
                errors.append(f"malformed row (expected 8 cells, got {len(cells)}): {ln[:80]}")
                continue
            rows.append(dict(zip(("id", "sev", "title", "status", "loc", "test", "indep", "remain"), cells)))
    if not rows:
        errors.append("no findings table found")
    seen = set()
    cnt = collections.Counter()
    for r in rows:
        rid = r["id"]
        if rid in seen:
            errors.append(f"{rid}: duplicate ID")
        seen.add(rid)
        cat = category(r["status"])
        if cat is None:
            errors.append(f"{rid}: status not in vocabulary: {r['status'][:60]}")
            continue
        sev = r["sev"].split("/")[0]
        sev = "Low" if sev == "Info" else sev
        if not rid.startswith("OA-"):
            cnt[(sev, cat)] += 1
        if cat != "Fixed on main" and (r["remain"] in ("", "-")):
            errors.append(f"{rid}: status '{cat}' needs a remaining-risk / plan entry")
        toks_loc = re.findall(r"`([^`]+)`", r["loc"])
        toks_tst = re.findall(r"`([^`]+)`", r["test"])
        if cat.startswith("Fixed") and not any(LOC.match(t) for t in toks_loc):
            errors.append(f"{rid}: fixed row without a file:line fix location")
        if cat.startswith("Fixed") and not r["test"]:
            errors.append(f"{rid}: fixed row with an empty regression-test cell (write 'none: <reason>')")
        for t in toks_loc + toks_tst:
            mt, ml = TST.match(t), LOC.match(t)
            if mt:
                ref, path, name = mt.groups()
                body = content(ref, path)
                if body == "NOREF":
                    (errors if a.strict else warns).append(f"{rid}: commit {ref} not in this clone ({t})")
                elif body is None:
                    errors.append(f"{rid}: test file missing{' at ' + ref if ref else ''}: {path}")
                elif not re.search(r"\bdef\s+" + re.escape(name) + r"\b", body):
                    errors.append(f"{rid}: test '{name}' is not defined in {path}{' at ' + ref if ref else ''}")
            elif ml:
                ref, path, line = ml.groups()
                body = content(ref, path)
                if body == "NOREF":
                    (errors if a.strict else warns).append(f"{rid}: commit {ref} not in this clone ({t})")
                elif body is None:
                    errors.append(f"{rid}: file missing{' at ' + ref if ref else ''}: {path}")
                elif int(line) > max(1, len(body.splitlines())):
                    errors.append(f"{rid}: {path} has only {len(body.splitlines())} lines, cited line {line}{' at ' + ref if ref else ''}")
    # summary counts
    for sev in ("Critical", "High", "Medium", "Low"):
        want = [cnt[(sev, c)] for c in CATS]
        want.append(sum(want))
        got = summary.get(sev)
        if got is None:
            errors.append(f"summary row for {sev} missing")
        elif got != want:
            errors.append(f"summary counts for {sev} are {got}, table says {want}")
    for w in warns:
        print("WARN  " + w)
    for e in errors:
        print("ERROR " + e)
    print(f"{len(rows)} rows checked, {len(errors)} errors, {len(warns)} warnings; by category: " +
          ", ".join(f"{c}={sum(v for (s, k), v in cnt.items() if k == c)}" for c in CATS))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
