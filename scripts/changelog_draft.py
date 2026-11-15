#!/usr/bin/env python3
"""Draft CHANGELOG "Unreleased" entries from commit subjects since the last tag. Local git only; no network.

    changelog_draft.py                 # commits since the latest tag (or all commits when there is no tag)
    changelog_draft.py --since v0.1.0  # explicit base
    changelog_draft.py --all           # also list docs/test/ci/chore commits (skipped by default)

Understands conventional-ish subjects ("feat(portal): ...", "fix: ...", "security: ...") and falls back to the first word
("Add ...", "Fix ...") for the free-form subjects this repository mostly uses. The output is a DRAFT for a human to edit:
add the evidence link to every entry before pasting it under "## [Unreleased]" in CHANGELOG.md (ADR-0011).
"""
import argparse
import re
import subprocess
import sys

SECTIONS = ("Added", "Changed", "Deprecated", "Removed", "Fixed", "Security")
CONV = re.compile(r"^(?P<type>[a-z]+)(?:\((?P<scope>[^)]*)\))?(?P<bang>!)?:\s*(?P<text>.+)$", re.I)
TYPE_MAP = {"feat": "Added", "feature": "Added", "add": "Added", "fix": "Fixed", "bug": "Fixed", "security": "Security", "sec": "Security",
            "change": "Changed", "refactor": "Changed", "perf": "Changed", "remove": "Removed", "deprecate": "Deprecated"}
SKIP_TYPES = {"docs", "doc", "test", "tests", "ci", "chore", "build", "style", "wip", "progress", "merge"}
WORD_MAP = {"add": "Added", "added": "Added", "implement": "Added", "introduce": "Added", "fix": "Fixed", "fixed": "Fixed", "remove": "Removed",
            "deprecate": "Deprecated", "harden": "Security", "remediate": "Security"}


def classify(subject: str) -> tuple[str | None, str]:
    """-> (section or None to skip, cleaned text)."""
    s = subject.strip()
    if not s or s.startswith("Merge ") or s.lower().startswith(("wip", "fixup!", "squash!", "revert \"")):
        return None, s
    m = CONV.match(s)
    if m:
        t = m["type"].lower()
        text = (f"**{m['scope']}**: " if m["scope"] else "") + m["text"].strip()
        if m["bang"]:
            return "Changed", "**BREAKING** " + text
        if t in SKIP_TYPES:
            return None, text
        if t in TYPE_MAP:
            return TYPE_MAP[t], text
    first = re.split(r"\W+", s, maxsplit=1)[0].lower()
    if re.search(r"\b(security|vulnerab|cve-)", s, re.I):
        return "Security", s
    if first in WORD_MAP:
        return WORD_MAP[first], s
    if re.match(r"^(docs?|tests?|progress|ci|host-changes|status)\b[:\s]", s, re.I):
        return None, s
    return "Changed", s


def draft(subjects: list[str], include_all: bool = False) -> str:
    buckets: dict[str, list[str]] = {k: [] for k in SECTIONS}
    skipped = 0
    for subj in subjects:
        sec, text = classify(subj)
        if sec is None:
            skipped += 1
            if include_all and text:
                buckets["Changed"].append(f"{text} (maintenance)")
            continue
        text = text[:1].upper() + text[1:] if text else text
        if len(text) > 240:
            text = text[:237].rstrip() + "..."
        if text not in buckets[sec]:
            buckets[sec].append(text)
    out = ["## [Unreleased]", ""]
    for k in SECTIONS:
        if buckets[k]:
            out += [f"### {k}"] + [f"- {t}. <!-- TODO: add evidence link -->" if not t.endswith(".") else f"- {t} <!-- TODO: add evidence link -->" for t in buckets[k]] + [""]
    if len(out) == 2:
        out += ["_No user-visible commits since the base._", ""]
    out.append(f"<!-- drafted from {len(subjects)} commit(s); {skipped} skipped (merges, docs, tests, ci, chore) -->")
    return "\n".join(out) + "\n"


def git(*args: str, repo: str) -> str:
    return subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True, check=True).stdout


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--since", help="base revision (default: latest tag)")
    ap.add_argument("--repo", default=".")
    ap.add_argument("--all", action="store_true", help="include maintenance commits")
    a = ap.parse_args(argv)
    base = a.since
    if base is None:
        try:
            base = git("describe", "--tags", "--abbrev=0", repo=a.repo).strip()
        except subprocess.CalledProcessError:
            base = None  # no tag yet: everything
    rng = [f"{base}..HEAD"] if base else ["HEAD"]
    try:
        subjects = [s for s in git("log", "--no-merges", "--format=%s", *rng, repo=a.repo).splitlines() if s]
    except subprocess.CalledProcessError as e:
        print(f"git failed: {e.stderr.strip()}", file=sys.stderr)
        return 2
    sys.stdout.write(draft(subjects, a.all))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
