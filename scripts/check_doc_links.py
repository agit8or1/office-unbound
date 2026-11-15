#!/usr/bin/env python3
"""Check the administrator documentation: every relative link, every cited repository path and every cited
`ics.cli` sub-command must exist. Exit 1 on any problem.

    python3 scripts/check_doc_links.py            # docs/admin, docs/runbooks, docs/RELEASING.md
    python3 scripts/check_doc_links.py FILE...    # specific files

What is checked, per Markdown file:
  * `[text](relative/path.md#anchor)`: the file exists and the anchor matches a heading (GitHub-style slug).
    External (http/https/mailto) links are not fetched.
  * Backtick spans that start with a known top-level repository folder (ics/, docs/, blueprints/, scripts/, ...)
    or a top-level file name: the path (first word of the span) must exist. Globs (`*`) must match something.
    Spans containing `<...>`, `$`, `{` or `...` are templates and are skipped.
  * `ics.cli <name>` / `python -m ics.cli <name>`: <name> must be a sub-command defined in ics/ics/cli.py.

A feature that is documented before it is merged (for example work on a branch) can be declared once per file:

    <!-- pending: ics/deploy/standby/ics-promote.sh, promote -->

Listed paths/sub-commands are then allowed to be missing in this file only (and the checker prints them as
"pending" so they are not forgotten). A pending entry that DOES exist is an error: remove it from the list.
"""
from __future__ import annotations

import glob
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT = ["docs/admin", "docs/runbooks", "docs/RELEASING.md"]
TOP_DIRS = ("ics/", "docs/", "blueprints/", "scripts/", "migration/", "portal/", ".github/")
TOP_FILES = {"README.md", "ROADMAP.md", "SECURITY.md", "CONTRIBUTING.md", "CLAUDE.md", "LICENSE", "VERSION", "VERSIONS.json", "CHANGELOG.md"}

LINK = re.compile(r"(?<!\!)\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
SPAN = re.compile(r"`([^`\n]+)`")
PENDING = re.compile(r"<!--\s*pending:\s*(.*?)\s*-->", re.S)
CLI = re.compile(r"ics\.cli\s+([a-z][a-z-]*)")
FENCE = re.compile(r"^(```|~~~)")


def slug(heading: str) -> str:
    s = re.sub(r"`", "", heading.strip().lower())
    s = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", s)
    s = re.sub(r"[^\w\- ]", "", s, flags=re.U)
    return s.replace(" ", "-")


def anchors(path: Path) -> set[str]:
    out: set[str] = set()
    seen: dict[str, int] = {}
    in_fence = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if FENCE.match(line.strip()):
            in_fence = not in_fence
        m = None if in_fence else re.match(r"^#{1,6}\s+(.*?)\s*#*$", line)
        if m:
            s = slug(m.group(1))
            n = seen.get(s, 0)
            seen[s] = n + 1
            out.add(s if n == 0 else f"{s}-{n}")
    return out


def cli_commands() -> set[str]:
    src = (ROOT / "ics/ics/cli.py").read_text(encoding="utf-8")
    return set(re.findall(r'sub\.add_parser\(\s*"([a-z-]+)"', src))


def candidate_paths(span: str) -> list[str]:
    """Every word of the span that is a repository path (so `sudo ics/deploy/x.sh --flag` is checked too)."""
    out = []
    for word in span.split():
        word = word.strip("\"'").rstrip(",.;:)")
        if any(t in word for t in ("<", "$", "{", "...")):
            continue
        if word.startswith(TOP_DIRS) or (word in TOP_FILES and word == span.strip()):
            out.append(word)
    return out


def exists(rel: str) -> bool:
    if any(c in rel for c in "*?["):
        return bool(glob.glob(str(ROOT / rel)))
    return (ROOT / rel).exists()


def files_from(args: list[str]) -> list[Path]:
    out: list[Path] = []
    for a in args or DEFAULT:
        p = (ROOT / a) if not Path(a).is_absolute() else Path(a)
        if p.is_dir():
            out += sorted(p.rglob("*.md"))
        elif p.is_file():
            out.append(p)
        else:
            print(f"ERROR: {a} does not exist")
            raise SystemExit(1)
    return out


def check(path: Path, cmds: set[str]) -> tuple[list[str], list[str]]:
    text = path.read_text(encoding="utf-8")
    rel = path.relative_to(ROOT)
    pend_raw = PENDING.findall(text)
    pending = {x.strip() for chunk in pend_raw for x in chunk.split(",") if x.strip()}
    used: set[str] = set()
    errors: list[str] = []
    lines = text.splitlines()
    in_fence = False
    for n, line in enumerate(lines, 1):
        if FENCE.match(line.strip()):
            in_fence = not in_fence
            continue
        # links (not inside code fences)
        if not in_fence:
            for target in LINK.findall(line):
                if re.match(r"^[a-z]+:", target) or target.startswith("#") and False:
                    continue
                if re.match(r"^[a-z][a-z0-9+.-]*:", target):
                    continue
                file_part, _, frag = target.partition("#")
                dest = path if not file_part else (path.parent / file_part).resolve()
                if file_part and not dest.exists():
                    key = str(dest.relative_to(ROOT)) if ROOT in dest.parents or dest == ROOT else file_part
                    if key in pending:
                        used.add(key)
                        continue
                    errors.append(f"{rel}:{n}: broken link target {target}")
                    continue
                if frag and dest.suffix == ".md" and dest.is_file() and frag not in anchors(dest):
                    errors.append(f"{rel}:{n}: no heading for anchor #{frag} in {dest.relative_to(ROOT)}")
        # cited paths, both in prose spans and in fenced commands
        spans = SPAN.findall(line) if not in_fence else [line.strip()]
        for sp in spans:
            for m in CLI.finditer(sp):
                name = m.group(1)
                if name not in cmds:
                    if name in pending:
                        used.add(name)
                    else:
                        errors.append(f"{rel}:{n}: ics.cli has no sub-command '{name}'")
            if in_fence:
                words = [w.strip("\"'") for w in re.split(r"\s+", sp)]
                cands = [w for w in words if w.startswith(TOP_DIRS) and not any(t in w for t in ("<", "$", "{", "..."))]
            else:
                cands = candidate_paths(sp)
            for c in cands:
                c = c.rstrip(",.;:)\\")
                c = re.sub(r"[#:]\d+(-\d+)?$", "", c)  # path:line or path#L
                if not exists(c):
                    if c in pending:
                        used.add(c)
                    else:
                        errors.append(f"{rel}:{n}: cited path does not exist: {c}")
    notes = []
    for p in sorted(pending):
        if p in used:
            notes.append(f"{rel}: pending (documented before merge): {p}")
        elif exists(p) or p in cmds:
            errors.append(f"{rel}: pending entry '{p}' now exists; remove it from the <!-- pending: --> list")
        else:
            errors.append(f"{rel}: pending entry '{p}' is listed but never cited")
    return errors, notes


def main(argv: list[str]) -> int:
    cmds = cli_commands()
    errors: list[str] = []
    notes: list[str] = []
    files = files_from(argv)
    for f in files:
        e, n = check(f, cmds)
        errors += e
        notes += n
    for n in notes:
        print("note:", n)
    for e in errors:
        print("ERROR:", e)
    print(f"checked {len(files)} files: {len(errors)} problem(s), {len(notes)} pending item(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
