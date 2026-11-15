"""Post-migration verification: source vs target per folder (counts, fingerprint set difference, flags, INTERNALDATE
via fingerprint) plus a seeded random sample of full-body SHA-256 comparisons. Read-only on both sides."""
from __future__ import annotations

import collections
import hashlib
import random

from .mailbox import Mailbox, fingerprint
from .mapping import Mapper


def verify(src: Mailbox, dst: Mailbox, mapper: Mapper, *, mode="strict", sample=10, seed=1) -> dict:
    folders = src.list_folders()
    dst_names = {n for n, _d, _f in dst.list_folders()}
    plans = mapper.map_all(folders)
    by_target = collections.OrderedDict()
    for p in plans:
        if p.target:
            by_target.setdefault(p.target, []).append(p)
    rng = random.Random(seed)
    rep = {"folders": [], "ok": True}
    for target, ps in by_target.items():
        entries = []  # (fp, meta, src_name)
        for p in ps:
            _uv, exists, _n = src.examine(p.src_name)
            if exists:
                for m in src.fetch_meta(src.search_uids(1)):
                    entries.append((fingerprint(m, mode), m, p.src_name))
        wire = ps[0].target_wire
        tm = []
        if wire in dst_names:
            _uv, nxt, tm = dst.scan(wire)
        tfp = collections.defaultdict(list)
        for m in tm:
            tfp[fingerprint(m, mode)].append(m)
        sc = collections.Counter(e[0] for e in entries)
        tc = collections.Counter({k: len(v) for k, v in tfp.items()})
        missing = sum(max(0, n - tc[k]) for k, n in sc.items())
        extra = sum(max(0, n - sc[k]) for k, n in tc.items())
        flag_mismatch = 0
        pairs = []
        used = collections.Counter()
        for fp, m, sname in entries:
            i = used[fp]
            if i < len(tfp.get(fp, [])):
                t = tfp[fp][i]
                used[fp] += 1
                pairs.append((m, t, sname))
                if {f.lower() for f in m.keep_flags()} != {f.lower() for f in t.keep_flags()}:
                    flag_mismatch += 1
        picks = rng.sample(pairs, min(sample, len(pairs))) if sample else []
        bad_hash = 0
        for m, t, sname in picks:
            src.examine(sname)
            a = src.fetch_body(m.uid)
            dst.examine(wire)
            b = dst.fetch_body(t.uid)
            if hashlib.sha256(a).digest() != hashlib.sha256(b).digest():
                bad_hash += 1
        fr = {"target": target, "sources": [p.src_display for p in ps], "source_count": len(entries),
              "target_count": len(tm), "missing_on_target": missing, "extra_on_target": extra,
              "flag_mismatches": flag_mismatch, "sampled": len(picks), "body_hash_mismatches": bad_hash,
              "ok": missing == 0 and flag_mismatch == 0 and bad_hash == 0}
        rep["folders"].append(fr)
        rep["ok"] &= fr["ok"]
    rep["source_total"] = sum(f["source_count"] for f in rep["folders"])
    rep["target_total"] = sum(f["target_count"] for f in rep["folders"])
    return rep
