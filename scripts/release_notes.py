#!/usr/bin/env python3
"""Generate GitHub Release notes (Markdown) for a version from its CHANGELOG.md section. No network.

    release_notes.py                 # notes for the version in VERSION
    release_notes.py 0.1.0           # explicit version
    release_notes.py --check         # CI: CHANGELOG has a dated section for VERSION, link refs exist, progress.json agrees

Typical use:  scripts/release_notes.py > /tmp/notes.md && gh release create v$(cat VERSION) --notes-file /tmp/notes.md   (docs/RELEASING.md)
"""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
REPO_URL = "https://github.com/agit8or1/office-unbound"
HEAD = re.compile(r"^## \[(?P<v>[^\]]+)\](?: - (?P<d>\d{4}-\d{2}-\d{2}))?\s*$")


def sections(text: str) -> dict[str, tuple[str | None, str]]:
    """version label -> (date, body) for every `## [x]` heading."""
    out, cur, date, buf = {}, None, None, []
    for line in text.splitlines():
        m = HEAD.match(line)
        if m or line.startswith("[") and re.match(r"^\[[^\]]+\]: ", line):
            if cur is not None:
                out[cur] = (date, "\n".join(buf).strip("\n"))
                cur = None
            if m:
                cur, date, buf = m["v"], m["d"], []
            continue
        if cur is not None:
            buf.append(line)
    if cur is not None:
        out[cur] = (date, "\n".join(buf).strip("\n"))
    return out


def notes(version: str, text: str, repo_url: str = REPO_URL) -> str:
    secs = sections(text)
    if version not in secs or secs[version][0] is None:
        raise SystemExit(f"CHANGELOG.md has no dated section for [{version}]")
    date, body = secs[version]
    # relative links do not resolve inside a GitHub Release: point them at the tagged tree
    body = re.sub(r"\]\((?!https?://|#|mailto:)([^)]+)\)", lambda m: f"]({repo_url}/blob/v{version}/{m.group(1).lstrip('./')})", body)
    prev = [v for v in secs if v not in (version, "Unreleased")]
    footer = [f"Released {date}. Full changelog: {repo_url}/blob/v{version}/CHANGELOG.md"]
    if prev:
        footer.append(f"Changes since {prev[0]}: {repo_url}/compare/v{prev[0]}...v{version}")
    minor = int(version.split(".")[1]) if version.startswith("0.") else None
    if minor is not None and minor >= 10:   # ADR-0011 amendment 2026-11-23: alpha from 0.10.0
        stage = ("This is an alpha (version 0.x): installable by following docs/admin/alpha-install.md and proven on one reference "
                 "installation. Not for production data; read docs/admin/known-limitations.md. The release is not signed with a production "
                 "key unless stated here.\n\n")
    elif minor is not None:
        stage = ("This is a pre-release (version 0.x): a lab-verified pre-alpha. It is not production supported and the release "
                 "is not signed with a production key unless stated here.\n\n")
    else:
        stage = ""
    return f"{stage}{body}\n\n---\n" + "\n".join(footer) + "\n"


def check() -> int:
    errs = []
    text = (ROOT / "CHANGELOG.md").read_text()
    ver = (ROOT / "VERSION").read_text().strip()
    secs = sections(text)
    if "Unreleased" not in secs:
        errs.append("CHANGELOG.md has no [Unreleased] section")
    if re.search(r"-dev(\.\d+)?$", ver):   # 0.2.0-dev and numbered builds 0.2.0-dev.N (ADR-0011 amendment)
        pass  # development line: changes accumulate under [Unreleased] until the release is cut (docs/RELEASING.md)
    elif ver not in secs or secs[ver][0] is None:
        errs.append(f"CHANGELOG.md has no dated [{ver}] section for the VERSION file")
    for v in secs:
        if not re.search(rf"^\[{re.escape(v)}\]: https?://", text, re.M):
            errs.append(f"missing link reference for [{v}]")
    for m in re.finditer(r"\]\((?!https?://|#)([^)#]+)", text):
        if not (ROOT / m.group(1)).exists():
            errs.append(f"broken relative link: {m.group(1)}")
    prog = json.loads((ROOT / "docs" / "progress.json").read_text())
    if prog.get("current_version") != ver:
        errs.append(f"docs/progress.json current_version {prog.get('current_version')!r} != VERSION {ver!r}")
    for e in errs:
        print("release_notes --check:", e, file=sys.stderr)
    if not errs:
        print(f"CHANGELOG.md consistent with VERSION {ver} and progress.json")
    return 1 if errs else 0


def main(argv: list[str]) -> int:
    if "--check" in argv:
        return check()
    ver = next((a for a in argv if not a.startswith("-")), None) or (ROOT / "VERSION").read_text().strip()
    sys.stdout.write(notes(ver.lstrip("v"), (ROOT / "CHANGELOG.md").read_text()))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
