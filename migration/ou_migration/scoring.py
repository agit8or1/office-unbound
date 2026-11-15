"""Complexity / risk score with transparent, additive rules (0-100, capped). Each fired rule records its
points and the evidence value + tag, so the score can be audited line by line."""
from __future__ import annotations

GIB = 1 << 30
TIB = 1 << 40
BANDS = [(25, "low"), (50, "medium"), (75, "high"), (101, "very-high")]


def _tiers(value, tiers):
    pts = 0
    for thr, p in tiers:
        if value >= thr:
            pts = p
    return pts


def score(inv, features: list[dict], dns: list[dict]) -> dict:
    fired = []

    def add(rule, pts, evidence, tag):
        if pts:
            fired.append({"rule": rule, "points": pts, "evidence": evidence, "tag": tag})

    n = len(inv.users)
    add("scale: user count (>=50:+5, >=250:+10, >=1000:+15)", _tiers(n, [(50, 5), (250, 10), (1000, 15)]), f"{n} users", "verified")
    mail_b = sum(u.mailbox_bytes or 0 for u in inv.users)
    file_b = sum(u.file_bytes or 0 for u in inv.users) + sum(s.bytes or 0 for s in inv.sites)
    tot = mail_b + file_b
    add("volume: total bytes (>=1 TiB:+5, >=5 TiB:+10, >=20 TiB:+15)", _tiers(tot, [(TIB, 5), (5 * TIB, 10), (20 * TIB, 15)]),
        f"{tot / TIB:.2f} TiB", "verified")
    big = max([u.mailbox_bytes or 0 for u in inv.users] + [0])
    add("largest mailbox (>=50 GiB:+5, >=100 GiB:+8)", _tiers(big, [(50 * GIB, 5), (100 * GIB, 8)]), f"{big / GIB:.1f} GiB", "verified")
    bigf = max([u.file_bytes or 0 for u in inv.users] + [0])
    add("largest personal drive (>=250 GiB:+5)", 5 if bigf >= 250 * GIB else 0, f"{bigf / GIB:.1f} GiB", "verified")

    for f in features:
        if f["state"] == "not-assessed":
            if f["impact"] == "blocker":
                add(f"unknown blocker-class source feature: {f['id']}", 10, "cannot be read with minimum permissions; manual confirmation required", "assumption")
            elif f["impact"] == "major":
                add(f"unassessed major risk: {f['id']}", 3, "not assessable by this tool", "assumption")
            continue
        pts = {"blocker": 20, "major": 6, "minor": 2, "info": 0}[f["impact"]]
        add(f"unsupported/partial target feature {f['id']} ({f['impact']})", pts, f"{f['title']}: {f['count']}", "verified")
    if sum(r["points"] for r in fired if "(major)" in r["rule"]) > 24:  # cap majors
        over = sum(r["points"] for r in fired if "(major)" in r["rule"]) - 24
        add("cap on 'major' feature points (24)", -over, "cap", "assumption")

    g = inv.signals.get("guest_users", 0)
    add("guest/external users present (+2)", 2 if g else 0, f"{g} guests", "verified")
    if inv.signals.get("on_prem_sync_enabled"):
        add("hybrid identity: on-premises directory sync enabled (+8)", 8, "organization.onPremisesSyncEnabled = true", "verified")
    for d in dns:
        if d.get("mx_state") == "third-party-filter-or-other":
            add(f"mail flow via third-party gateway on {d['domain']} (+3)", 3, str(d.get("mx")), "verified")
    spf_bad = [d["domain"] for d in dns if d.get("spf_state") in ("missing", "multiple-records(invalid)")]
    add("domains with missing/invalid SPF (+2)", 2 if spf_bad else 0, ", ".join(spf_bad[:5]), "verified")
    unv = [d.name for d in inv.domains if not d.verified]
    add("unverified domains in tenant (+3)", 3 if unv else 0, ", ".join(unv[:5]), "verified")

    sh = inv.sharing or {}
    if sh.get("sample_files"):
        frac = sh.get("sample_anyone_link_files", 0) / sh["sample_files"]
        add("public ('anyone') link files >=2% of sampled files (+5)", 5 if frac >= 0.02 else 0, f"{frac:.1%} of {sh['sample_files']} sampled files", "estimated")

    bad_cov = {k: v for k, v in inv.coverage.items() if not v.startswith("ok")}
    add("incomplete assessment: failed/partial collectors (+4 each, max 16)", min(16, 4 * len(bad_cov)), ", ".join(bad_cov), "verified")

    total = max(0, min(100, sum(r["points"] for r in fired)))
    band = next(b for lim, b in BANDS if total < lim)
    confidence = "high" if not bad_cov and not inv.warnings else "medium" if len(bad_cov) <= 1 else "low"
    return {"score": total, "band": band, "confidence": confidence, "rules_fired": fired,
            "bands": "low<25, medium<50, high<75, very-high>=75",
            "note": "Score measures expected migration effort/risk, not suitability. Unknown (not-assessed) items add risk rather than being ignored."}
