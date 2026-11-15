"""Self-contained report writers: JSON + one HTML file (inline CSS, no JS, no external assets).
All dynamic text is HTML-escaped. Report files are written 0600 (they contain user logins)."""
from __future__ import annotations

import html
import json
import os

E = html.escape

CSS = """
:root{--bg:#fff;--fg:#1b1f24;--mut:#59636e;--line:#d0d7de;--v:#1a7f37;--e:#9a6700;--a:#8250df;--bad:#cf222e;--card:#f6f8fa}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--mut:#8d96a0;--line:#30363d;--v:#3fb950;--e:#d29922;--a:#a371f7;--bad:#f85149;--card:#161b22}}
body{background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,sans-serif;margin:0;padding:1rem 1.25rem;max-width:72rem;margin-inline:auto}
h1{font-size:1.5rem}h2{font-size:1.15rem;border-bottom:1px solid var(--line);padding-bottom:.25rem;margin-top:2rem}
table{border-collapse:collapse;width:100%;margin:.5rem 0}th,td{border:1px solid var(--line);padding:.25rem .5rem;text-align:left;vertical-align:top}
th{background:var(--card)}.wrap{overflow-x:auto}.card{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:.75rem 1rem;margin:.5rem 0}
.tag{font-size:.75rem;border-radius:3px;padding:0 .35rem;border:1px solid;white-space:nowrap}
.verified{color:var(--v)}.estimated{color:var(--e)}.assumption{color:var(--a)}.blocker,.major{color:var(--bad)}.mut{color:var(--mut)}
.big{font-size:2rem;font-weight:600}
"""


def _tag(t):
    return f'<span class="tag {E(t)}">{E(t)}</span>'


def _f(field):
    """Render a Field json dict."""
    if not field:
        return '<span class="mut">n/a</span>'
    v = field["value"]
    if isinstance(v, int) and not isinstance(v, bool):
        v = f"{v:,}"
    return f'{E(str(v))} {_tag(field["tag"])}'


def _gib(b):
    return "n/a" if b is None else f"{b / (1 << 30):,.2f} GiB"


def _table(headers, rows):
    h = "".join(f"<th>{E(str(x))}</th>" for x in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return f'<div class="wrap"><table><tr>{h}</tr>{body}</table></div>'


def render_html(r: dict) -> str:
    v, est, risk = r["verified_inventory"], r["estimates"], r["risk"]
    t = v["tenant"]
    p = [f"<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
         f"<title>Migration readiness - {E(str(t['name']['value']))}</title><style>{CSS}</style><body>"]
    p.append(f"<h1>Migration readiness assessment</h1><p class=mut>Source: {E(r['provider'])} tenant "
             f"<b>{E(str(t['name']['value']))}</b> ({E(str(t['id']['value']))}) &middot; collected {E(str(t['collected_at']['value']))} "
             f"&middot; read-only, metadata and counts only. Contains user logins: handle as confidential.</p>")
    p.append("<div class=card><b>Legend</b>: " + " ".join(f"{_tag(k)} {E(d)};" for k, d in r["legend"].items()) + "</div>")
    p.append(f"<div class=card><div class=big>{risk['score']}/100 &mdash; {E(risk['band'])}</div>"
             f"Confidence in this assessment: <b>{E(risk['confidence'])}</b> {_tag('estimated')}<br><span class=mut>{E(risk['note'])}</span></div>")
    if v["partial_failures"] or any(not c.startswith("ok") for c in v["collection_coverage"].values()):
        p.append("<h2>Collection gaps</h2>" + _table(["collector", "state"], [[E(k), E(c)] for k, c in v["collection_coverage"].items()
                                                                          if not c.startswith("ok")]))
        p.append("<ul>" + "".join(f"<li>{E(w)}</li>" for w in v["partial_failures"]) + "</ul>")

    # ---- VERIFIED --------------------------------------------------------------------------------
    p.append("<h2>Part A &mdash; Verified inventory</h2><p class=mut>Everything in this part was read from the source APIs or public DNS.</p>")
    u = v["users"]
    p.append(_table(["metric", "value"], [[E(k.replace("_", " ")), _f(u[k])] for k in u if u[k]]))
    m = v["mailboxes"]
    p.append("<h3>Mailboxes</h3>" + _table(["metric", "value"], [
        ["with usage data", _f(m["with_usage_data"])], ["total size", f"{_gib(m['total_bytes']['value']) if m['total_bytes'] else 'n/a'} {_tag('verified')}"],
        ["total items", _f(m["total_items"]) if m["total_items"] else '<span class="mut">not collected (see Part B estimate)</span>'],
        ["median / p95 / max", f"{_gib(m['size_p50'])} / {_gib(m['size_p95'])} / {_gib(m['size_max'])}"]]))
    p.append(_table(["size bucket", "mailboxes"], [[E(k), n] for k, n in m["size_distribution"].items()]))
    if m["top"]:
        p.append("<details><summary>Largest 20 mailboxes</summary>" + _table(["login", "size", "items"], [
            [E(x["login"]), _gib(x["bytes"]), "n/a" if x["items"] is None else f"{x['items']:,}"] for x in m["top"]]) + "</details>")
    ps = v["personal_storage"]
    p.append("<h3>Personal storage (OneDrive / Drive)</h3>" + _table(["metric", "value"], [
        ["accounts with data", _f(ps["accounts_with_usage_data"])],
        ["total size", f"{_gib(ps['total_bytes']['value']) if ps['total_bytes'] else 'n/a'} {_tag('verified')}"],
        ["total files", _f(ps["total_files"]) if ps["total_files"] else '<span class="mut">not collected</span>'],
        ["median / p95 / max", f"{_gib(ps['size_p50'])} / {_gib(ps['size_p95'])} / {_gib(ps['size_max'])}"]]))
    s = v["sites"]
    if s["count"]["value"]:
        p.append("<h3>SharePoint sites</h3>" + _table(["metric", "value"], [["sites", _f(s["count"])], ["total size", _gib(s["total_bytes"]["value"]) if s["total_bytes"] else "n/a"],
                                                                           ["templates", E(", ".join(f"{k}: {n}" for k, n in s["by_template"].items()))]]))
    g = v["groups"]
    p.append("<h3>Groups</h3>" + _table(["metric", "value"], [["total", _f(g["total"])], ["by kind", E(", ".join(f"{k}: {n}" for k, n in g["by_kind"].items()))]]))
    p.append("<h3>Domains and mail-flow DNS</h3>" + _table(
        ["domain", "verified", "MX", "SPF", "DKIM", "DMARC"],
        [[E(d["name"]), _f(d["verified"])] + ([E(str(d["dns"].get("mx_state"))), E(str(d["dns"].get("spf_state"))),
                                                E(str(d["dns"].get("dkim_state"))), E(str(d["dns"].get("dmarc_state")))]
                                               if d.get("dns") else ['<span class="mut">not checked</span>'] * 4) for d in v["domains"]]))
    cc = v["calendars_contacts"]
    p.append("<h3>Calendars / contacts</h3><p>" + (E(cc["reason"]) if "reason" in cc else
             f"events in sample {_f(cc['events_in_sample'])} ({cc['sampled_users_events']['value']} users); contacts in sample {_f(cc['contacts_in_sample'])}") + "</p>")
    sh = v["sharing_indicators"]
    p.append("<h3>Sharing indicators</h3>" + (_table(["indicator", "value"], [[E(k), _f(x)] for k, x in sh.items()]) if "status" not in sh else f"<p>{E(sh['status'])}</p>"))
    if v["file_size_distribution_sampled"]:
        p.append("<h3>File size distribution (sampled accounts)</h3>" + _table(["bucket", "files"], [[E(k), f"{n:,}"] for k, n in v["file_size_distribution_sampled"]["buckets"].items()]))
    p.append("<details><summary>Collector counts and source signals</summary>" + _table(["key", "value"],
             [[E(k), _f(x)] for k, x in {**v["counts"], **v["source_signals"]}.items()]) + "</details>")

    # ---- ESTIMATES -------------------------------------------------------------------------------
    tr = est["transfer"]
    p.append("<h2>Part B &mdash; Estimates and assumptions</h2><p class=mut>Derived numbers. Change the assumptions and re-run to refine.</p>")
    p.append("<h3>Transfer time (initial sync)</h3><p>" + E(tr["formula"]) + "</p>")
    p.append(_table(["input", "value"], [[E(k), _f(x)] for k, x in tr["inputs"].items()]))
    p.append(_table(["volume", "value"], [[E(k.replace("_", " ")), _f(x)] for k, x in tr["volumes"].items() if k.endswith("items")] +
                    [["mailbox size", _gib(tr["volumes"]["mailbox_bytes"]["value"]) + " " + _tag(tr["volumes"]["mailbox_bytes"]["tag"])],
                     ["file size", _gib(tr["volumes"]["file_bytes"]["value"]) + " " + _tag(tr["volumes"]["file_bytes"]["tag"])]]))
    p.append(_table(["category", "optimistic h", "expected h", "pessimistic h"], [
        [E(k), *(x["value"][q] for q in ("optimistic", "expected", "pessimistic"))] for k, x in tr["hours"].items()]) +
        f"<p class=mut>Excludes: {E(tr['excludes'])}. Effective rate {_f(tr['effective_rate_mbytes_s'])} MB/s.</p>")
    p.append(f"<p>Probable shared mailboxes: {_f(est['shared_mailbox_candidates'])}</p>")
    for k, x in est["extrapolations"].items():
        p.append(f"<p>{E(k.replace('_', ' '))}: {_f(x)} <span class=mut>({E(x['basis'])})</span></p>")

    p.append("<h3>Risk score breakdown</h3>" + _table(["rule", "points", "evidence", "basis"], [
        [E(x["rule"]), x["points"], E(x["evidence"]), _tag(x["tag"])] for x in risk["rules_fired"]]) + f"<p class=mut>Bands: {E(risk['bands'])}</p>")

    p.append("<h2>Part C &mdash; Source features vs target capabilities</h2>" + _table(
        ["id", "feature", "count/state", "impact", "target status (lab facts)", "advice"],
        [[E(f["id"]), E(f["title"]), E(f["state"] if f["count"] is None else str(f["count"])), f'<span class="{E(f["impact"])}">{E(f["impact"])}</span>',
          E(f["target_status"]) + "<br><span class=mut>" + E(f["target_fact"]) + "</span>", E(f["advice"])] for f in r["unsupported_features"]]))

    im = r["identity_mapping"]
    p.append(f"<h2>Part D &mdash; Identity mapping proposal {_tag('assumption')}</h2><ul>" + "".join(f"<li>{E(x)}</li>" for x in im["rules"]) + "</ul>")
    p.append(_table(["issue", "count"], [[E(k.replace("_", " ")), n] for k, n in im["issues"].items()]))
    p.append("<details><summary>First 25 users</summary>" + _table(["source login", "uid", "mail", "action"], [
        [E(x["source_login"]), E(str(x["uid"])), E(x["mail"]), E(x["action"])] for x in im["users"][:25]]) + "<p class=mut>Full mapping in the JSON report.</p></details>")
    p.append("<h2>Limits of this assessment</h2><ul>" + "".join(f"<li>{E(x)}</li>" for x in r["limits"]) + "</ul>")
    rs = r.get("run_stats") or {}
    p.append(f"<p class=mut>Run: {E(json.dumps(rs))}</p></body></html>")
    return "".join(p)


def _write_private(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)


def write(report: dict, out_dir: str) -> tuple[str, str]:
    os.makedirs(out_dir, mode=0o700, exist_ok=True)
    jp, hp = os.path.join(out_dir, "assessment.json"), os.path.join(out_dir, "assessment.html")
    _write_private(jp, json.dumps(report, indent=2, sort_keys=True))
    _write_private(hp, render_html(report))
    return jp, hp
