"""Turn a collected Inventory into the assessment report document (JSON-serialisable dict).

Top-level sections keep verified facts and estimates apart:
  verified_inventory   what the source APIs / DNS returned in this run
  estimates            derived numbers (formula + basis given)
  unsupported_features source features mapped to target capability facts
  identity_mapping     proposal (assumption)
  risk                 additive score with every fired rule
"""
from __future__ import annotations

from collections import Counter

from . import capabilities, dns_check, estimate, identity, scoring
from .model import assumption, bucketize, estimated, verified

SCHEMA = "ou-migration-assessment/1"


def _pct(vals, p):
    if not vals:
        return None
    vals = sorted(vals)
    return vals[min(len(vals) - 1, int(round((len(vals) - 1) * p)))]


def build(inv, *, resolver=None, assumptions: estimate.Assumptions | None = None, stats: dict | None = None) -> dict:
    a = assumptions or estimate.Assumptions()
    dns = []
    if resolver is not None:
        for d in inv.domains:
            if d.verified and not d.name.lower().endswith((".onmicrosoft.com", ".mail.onmicrosoft.com")):
                try:
                    d.dns = dns_check.check_domain(resolver, d.name, inv.provider)
                except Exception as e:  # DNS is advisory; never abort the assessment
                    d.dns = {"domain": d.name, "errors": [str(e)[:120]]}
                dns.append(d.dns)
    else:
        inv.warnings.append("DNS posture not checked (no resolver configured)")

    users = inv.users
    mbs = [u.mailbox_bytes for u in users if u.mailbox_bytes is not None]
    fbs = [u.file_bytes for u in users if u.file_bytes is not None]
    kinds = Counter(g.kind for g in inv.groups)
    site_by_tpl = Counter(s.template or "unknown" for s in inv.sites)
    ver = {
        "tenant": {"id": verified(inv.tenant_id).to_json(), "name": verified(inv.tenant_name).to_json(),
                   "provider": verified(inv.provider).to_json(), "collected_at": verified(inv.collected_at).to_json()},
        "collection_coverage": inv.coverage,
        "domains": [{"name": d.name, "verified": verified(d.verified).to_json(), "default": d.is_default,
                     "services": d.services, "dns": d.dns} for d in inv.domains],
        "users": {
            "total": verified(len(users)).to_json(),
            "enabled": verified(sum(u.enabled for u in users)).to_json(),
            "disabled_or_suspended": verified(sum(not u.enabled for u in users)).to_json(),
            "guests": verified(sum(u.user_type == "guest" for u in users)).to_json(),
            "with_aliases": verified(sum(bool(u.aliases) for u in users)).to_json(),
            "total_aliases": verified(sum(len(u.aliases) for u in users)).to_json(),
            "admins": verified(sum(bool(u.is_admin) for u in users)).to_json() if any(u.is_admin is not None for u in users) else None,
        },
        "groups": {"total": verified(len(inv.groups)).to_json(), "by_kind": dict(kinds),
                   "largest_member_counts": sorted((g.members for g in inv.groups if g.members is not None), reverse=True)[:5]},
        "mailboxes": {
            "with_usage_data": verified(len(mbs)).to_json(),
            "total_bytes": verified(sum(mbs)).to_json() if mbs else None,
            "total_items": verified(sum(u.mailbox_items for u in users if u.mailbox_items is not None)).to_json()
            if any(u.mailbox_items is not None for u in users) else None,
            "size_p50": _pct(mbs, 0.5), "size_p95": _pct(mbs, 0.95), "size_max": max(mbs) if mbs else None,
            "size_distribution": bucketize(mbs), "with_archive": verified(sum(bool(u.has_archive) for u in users)).to_json()
            if any(u.has_archive is not None for u in users) else None,
            "top": [{"login": u.login, "bytes": u.mailbox_bytes, "items": u.mailbox_items}
                    for u in sorted((u for u in users if u.mailbox_bytes is not None), key=lambda x: -x.mailbox_bytes)[:20]],
        },
        "personal_storage": {
            "accounts_with_usage_data": verified(len(fbs)).to_json(),
            "total_bytes": verified(sum(fbs)).to_json() if fbs else None,
            "total_files": verified(sum(u.file_count for u in users if u.file_count is not None)).to_json()
            if any(u.file_count is not None for u in users) else None,
            "size_p50": _pct(fbs, 0.5), "size_p95": _pct(fbs, 0.95), "size_max": max(fbs) if fbs else None,
            "size_distribution": bucketize(fbs),
        },
        "sites": {"count": verified(len(inv.sites)).to_json(), "by_template": dict(site_by_tpl),
                  "total_bytes": verified(sum(s.bytes or 0 for s in inv.sites)).to_json() if inv.sites else None,
                  "total_files": verified(sum(s.files or 0 for s in inv.sites)).to_json() if inv.sites else None,
                  "top": [{"url": s.url, "template": s.template, "bytes": s.bytes, "files": s.files}
                          for s in sorted(inv.sites, key=lambda x: -(x.bytes or 0))[:20]]},
        "counts": {k: verified(v).to_json() for k, v in sorted(inv.counts.items())},
        "calendars_contacts": _cal_contacts(inv),
        "file_size_distribution_sampled": ({"buckets": inv.file_size_buckets,
                                            "tag": "verified", "basis": "metadata scan of sampled accounts only; see signals.deep_count_sample_size"}
                                           if inv.file_size_buckets else None),
        "sharing_indicators": ({k: verified(v, "sampled accounts only").to_json() for k, v in inv.sharing.items()} if inv.sharing else
                               {"status": "not collected: needs Sites/Files (M365) or --deep (Google); see limits"}),
        "source_signals": {k: verified(v).to_json() for k, v in sorted(inv.signals.items())},
        "partial_failures": inv.warnings,
    }
    est = {
        "transfer": estimate.compute(inv, a),
        "shared_mailbox_candidates": estimated(sum(u.shared_mailbox_guess for u in users),
                                               "heuristic: sign-in blocked + unlicensed + has mailbox").to_json(),
        "extrapolations": _extrapolate(inv),
    }
    feats = capabilities.map_features(inv)
    ident = identity.propose(inv, {d.name.lower() for d in inv.domains if d.verified})
    return {
        "schema": SCHEMA, "provider": inv.provider,
        "legend": {"verified": "returned by the source API or public DNS in this run",
                   "estimated": "derived from verified inputs by a stated formula/heuristic",
                   "assumption": "operator input or default chosen by this tool"},
        "verified_inventory": ver, "estimates": est, "unsupported_features": feats,
        "identity_mapping": {"tag": "assumption", **ident},
        "risk": scoring.score(inv, feats, dns),
        "run_stats": stats or {}, "limits": LIMITS,
    }


def _cal_contacts(inv):
    c = inv.counts
    if "sample_events_users" not in c:
        return {"status": "not collected",
                "reason": "no content-free count exists in the Reports APIs; M365 needs Calendars.Read/Contacts.Read ($count) via --deep-counts; "
                          "Google has no content-free count (Calendar/People APIs need content scopes)"}
    return {"sampled_users_events": verified(c["sample_events_users"]).to_json(), "events_in_sample": verified(c["sample_events_total"]).to_json(),
            "sampled_users_contacts": verified(c["sample_contacts_users"]).to_json(), "contacts_in_sample": verified(c["sample_contacts_total"]).to_json()}


def _extrapolate(inv):
    out = {}
    c = inv.counts
    pop, samp = inv.signals.get("deep_count_population"), inv.signals.get("deep_count_sample_size")
    if pop and samp and c.get("sample_events_users"):
        out["events_total"] = estimated(int(c["sample_events_total"] / c["sample_events_users"] * pop),
                                        f"sample mean x {pop} mailboxes (sample {c['sample_events_users']})").to_json()
        if c.get("sample_contacts_users"):
            out["contacts_total"] = estimated(int(c["sample_contacts_total"] / c["sample_contacts_users"] * pop),
                                              f"sample mean x {pop} mailboxes").to_json()
    return out


LIMITS = [
    "Content is never read: sizes/counts come from usage reports, $count queries or metadata-only fields.",
    "Reports (M365 D30, Google Reports API) lag by 1-3 days and are snapshots, not live sizes.",
    "Mailbox delegations, shared-mailbox type, retention/legal holds, mail flow rules, transport rules and connectors are NOT readable with the minimum permissions: manual review required.",
    "Item counts per mailbox are only available with --deep (sampled); otherwise estimated from bytes.",
    "Transfer times are estimates from operator-supplied bandwidth and stated throughput assumptions; no throughput was measured.",
    "Target capability statuses are the lab facts of 2026-11-15; 'unproven' means not tested, not unsupported.",
    "Fixtures mirror documented API shapes; behaviour against a real tenant is unverified (docs/status/migration-assessment.md).",
]
