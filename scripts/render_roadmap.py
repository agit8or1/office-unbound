#!/usr/bin/env python3
"""Render ROADMAP.md from docs/progress.json (single source of truth for roadmap + progress).
Usage: render_roadmap.py            # write ROADMAP.md
       render_roadmap.py --check    # exit 1 if ROADMAP.md is out of date or progress.json is invalid
The public website reads docs/progress.json directly (raw.githubusercontent.com/agit8or1/office-unbound/main/docs/progress.json)."""
import json, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC, OUT = ROOT / "docs" / "progress.json", ROOT / "ROADMAP.md"
ICON = {"planned": "⚪", "researching": "🔎", "implementing": "🛠️", "integrated_lab": "🧪", "tested": "✅",
        "alpha": "🅰️", "beta": "🅱️", "production": "🚀", "blocked": "⛔"}


def validate(d: dict) -> None:
    allowed = set(d["status_values"])
    assert d.get("schema") == "office-unbound-progress/1", "unknown schema"
    ids = set()
    for ph in d["phases"]:
        assert ph["status"] in allowed, ph["id"]
        for it in ph["items"]:
            assert it["status"] in allowed, it["id"]
            assert it["id"] not in ids, f"duplicate id {it['id']}"; ids.add(it["id"])
            for ev in it.get("evidence", []):
                assert (ROOT / ev).exists(), f"{it['id']}: evidence path missing: {ev}"
    for a in d["acceptance"]:
        assert a["status"] in allowed, a["id"]


def link(p: str) -> str:
    return f"[`{p}`]({p})"


def render(d: dict) -> str:
    sv = d["status_values"]
    lab = lambda s: f"{ICON.get(s, '')} {sv[s]}"
    out = [f"# {d['project']} roadmap & progress", "",
           f"> Generated from [`docs/progress.json`](docs/progress.json) by `scripts/render_roadmap.py` — edit the JSON, not this file. "
           f"Last updated **{d['updated']}** · stage: **{d['stage']}**.", "", d["summary"], "", "**Principles**", ""]
    out += [f"- {p}" for p in d["principles"]]
    out += ["", "**Status legend:** " + " · ".join(lab(k) for k in sv), ""]
    for ph in d["phases"]:
        out += [f"## {ph['id']} — {ph['name']}  ({lab(ph['status'])})", "", "| | Item | Status | Evidence |", "|---|---|---|---|"]
        for it in ph["items"]:
            ev = ", ".join(link(e) for e in it.get("evidence", [])) or "—"
            title = it["title"] + (f" <br><sub>{it['note']}</sub>" if it.get("note") else "")
            out.append(f"| {it['id']} | {title} | {lab(it['status'])} | {ev} |")
        out.append("")
    done = sum(1 for a in d["acceptance"] if a["status"] in ("integrated_lab", "tested", "alpha", "beta", "production"))
    out += [f"## First functional demo — acceptance tests ({done}/{len(d['acceptance'])} demonstrated in lab)", "",
            "| | Test | Status | Note |", "|---|---|---|---|"]
    out += [f"| {a['id']} | {a['title']} | {lab(a['status'])} | {a.get('note', '')} |" for a in d["acceptance"]]
    out += ["", "## Known limitations", ""] + [f"- {k}" for k in d["known_limitations"]] + [""]
    return "\n".join(out)


def main() -> int:
    d = json.loads(SRC.read_text())
    validate(d)
    text = render(d)
    if "--check" in sys.argv:
        if not OUT.exists() or OUT.read_text() != text:
            print("ROADMAP.md is out of date: run scripts/render_roadmap.py", file=sys.stderr)
            return 1
        print("ROADMAP.md up to date; progress.json valid")
        return 0
    OUT.write_text(text)
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
