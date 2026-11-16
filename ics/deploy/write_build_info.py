#!/usr/bin/env python3
"""Write BUILD_INFO.json at install time (ADR-0011). stdlib only; run by deploy/install.sh from the source checkout.

    write_build_info.py <repo-root> <output-file>

git is consulted HERE, once, while building/installing from a checkout - never by the running service. Outside a git
checkout (tarball) commit/dirty are recorded as null rather than guessed. Honors SOURCE_DATE_EPOCH for reproducible builds.
"""
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def git(root: Path, *args: str) -> str | None:
    try:
        r = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, timeout=20, check=True)
        return r.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def schema_head(versions: Path) -> str | None:
    revs, downs = {}, set()
    for f in versions.glob("*.py"):
        t = f.read_text()
        m = re.search(r"^revision\s*(?::\s*\w+)?\s*=\s*['\"]([^'\"]+)['\"]", t, re.M)
        d = re.search(r"^down_revision\s*(?::[^=]+)?=\s*(?:['\"]([^'\"]+)['\"]|None)", t, re.M)
        if m:
            revs[m.group(1)] = f.name
            if d and d.group(1):
                downs.add(d.group(1))
    heads = sorted(set(revs) - downs)
    return heads[0] if len(heads) == 1 else None


def main(root: Path, out: Path) -> None:
    j = lambda p: json.loads((root / p).read_text()) if (root / p).is_file() else {}
    vs, prog = j("VERSIONS.json"), j("docs/progress.json")
    dirty = git(root, "status", "--porcelain", "--untracked-files=no")
    commit = git(root, "rev-parse", "HEAD")
    # package build: the tree is a `git archive` of a release tag (no .git). The pipeline drops the tag's commit next to VERSION; it is clean by construction.
    pinned = root / ".ou-source-commit"
    if pinned.is_file() and commit is None:
        commit, dirty = pinned.read_text().strip() or None, ""
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    now = datetime.fromtimestamp(int(epoch), timezone.utc) if epoch else datetime.now(timezone.utc)
    info = {
        "product": "Office Unbound",
        "version": (root / "VERSION").read_text().strip(),
        "commit": commit,
        "dirty": None if dirty is None else bool(dirty),
        "package": f"ou-ics {os.environ['OU_PACKAGE_VERSION']}" if os.environ.get("OU_PACKAGE_VERSION") else None,
        "built_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "schema_head": schema_head(root / "ics" / "migrations" / "versions"),
        "components": vs.get("components", {}),
        "interfaces": vs.get("interfaces", {}),
        "releases": prog.get("releases", []),
    }
    out.write_text(json.dumps(info, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(Path(sys.argv[1]), Path(sys.argv[2]))
