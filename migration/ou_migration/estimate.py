"""Transfer-time estimate. Every input is an operator ASSUMPTION; the formula is printed in the report.

  bandwidth_MBps   = bandwidth_mbps / 8 * efficiency
  mail rate cap    = parallel_streams * per_stream_MBps          (source-API + target-import bound)
  files rate cap   = parallel_streams * per_stream_MBps
  hours(category)  = max( bytes / min(bandwidth_MBps, cap),  items * per_item_overhead_s / parallel_streams ) / 3600

Result is a range: optimistic = 0.6 x expected, pessimistic = 2.5 x expected (throttling, retries, large items).
Initial sync only; the final delta pass before cutover is NOT included.
"""
from __future__ import annotations

from dataclasses import dataclass

from .model import assumption, estimated, verified


@dataclass
class Assumptions:
    bandwidth_mbps: float = 100.0      # sustained WAN throughput between source tenant and target
    efficiency: float = 0.7            # protocol/TLS/retry overhead
    parallel_streams: int = 4
    per_stream_mbytes_s: float = 1.5   # conservative per-stream rate for source API reads
    mail_item_overhead_s: float = 0.05
    file_item_overhead_s: float = 0.10
    avg_mail_item_kb: float = 75.0     # used only when item counts are not collected
    avg_file_mb: float = 1.0           # used only when file counts are not collected


def compute(inv, a: Assumptions) -> dict:
    mail_b = sum(u.mailbox_bytes or 0 for u in inv.users)
    mail_known = [u for u in inv.users if u.mailbox_bytes is not None]
    mail_items_known = [u for u in mail_known if u.mailbox_items is not None]
    file_b = sum(u.file_bytes or 0 for u in inv.users) + sum(s.bytes or 0 for s in inv.sites)
    file_known = any(u.file_bytes is not None for u in inv.users) or any(s.bytes is not None for s in inv.sites)

    mail_items = sum(u.mailbox_items for u in mail_items_known)
    mail_items_tag = verified(mail_items, "sum of collected item counts") if mail_items_known and len(mail_items_known) == len(mail_known) \
        else estimated(int(mail_items + sum(u.mailbox_bytes for u in mail_known if u.mailbox_items is None) / (a.avg_mail_item_kb * 1024)),
                       f"counted items + remaining bytes / {a.avg_mail_item_kb} KB average item (assumption)")
    file_items_known = sum(u.file_count or 0 for u in inv.users) + sum(s.files or 0 for s in inv.sites)
    file_items_tag = verified(file_items_known, "sum of report file counts") if file_items_known else \
        estimated(int(file_b / (a.avg_file_mb * 1048576)), f"bytes / {a.avg_file_mb} MB average file (assumption)")

    bw = a.bandwidth_mbps / 8 * a.efficiency
    cap = a.parallel_streams * a.per_stream_mbytes_s
    rate = max(0.01, min(bw, cap))

    def hours(nbytes, items, overhead):
        t = max(nbytes / 1048576 / rate, items.value * overhead / a.parallel_streams)
        return t / 3600

    mail_h = hours(mail_b, mail_items_tag, a.mail_item_overhead_s)
    file_h = hours(file_b, file_items_tag, a.file_item_overhead_s)
    total = mail_h + file_h

    def rng(h):
        return {"optimistic": round(h * 0.6, 1), "expected": round(h, 1), "pessimistic": round(h * 2.5, 1)}

    return {
        "inputs": {k: assumption(v, "operator input / default") .to_json() for k, v in vars(a).items()},
        "volumes": {
            "mailbox_bytes": (verified(mail_b, f"{len(mail_known)} mailboxes with usage data") if mail_known
                              else estimated(0, "no mailbox usage collected")).to_json(),
            "mailbox_items": mail_items_tag.to_json(),
            "file_bytes": (verified(file_b, "usage reports / drive quota") if file_known
                           else estimated(0, "no file usage collected")).to_json(),
            "file_items": file_items_tag.to_json()},
        "effective_rate_mbytes_s": estimated(round(rate, 2), "min(bandwidth*efficiency, streams*per_stream)").to_json(),
        "hours": {"mail": estimated(rng(mail_h), "see formula").to_json(), "files": estimated(rng(file_h), "see formula").to_json(),
                  "total": estimated(rng(total), "mail + files, sequential worst case").to_json()},
        "formula": __doc__.strip().split("\n\n")[0],
        "excludes": "final delta sync, DNS cutover, client reconfiguration, mailbox rules/permissions, pre-stage validation",
    }
