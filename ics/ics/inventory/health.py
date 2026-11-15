"""Health rollup (documented in docs/status/provider-proxmox.md).

Per resource:
  node     online -> ok; anything else -> critical
  cluster  not quorate -> critical; some nodes offline -> warning; else ok
  storage  disabled/inactive -> warning; used >= 95% -> critical; >= 85% -> warning; else ok
  guest    running/stopped/paused -> ok (a stopped guest is not unhealthy by itself); anything else -> warning
  endpoint last discovery failed -> critical; never discovered -> unknown; disabled -> unknown (excluded from the rollup)
Any resource whose observed_at is older than `stale_seconds` is reported as "unknown" (we do not know), never ok.
Overall status = worst of critical > warning > unknown > ok over everything; no resources at all -> unknown.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.orm import Session

ORDER = {"ok": 0, "unmanaged": 0, "unknown": 1, "warning": 2, "critical": 3}


def _worst(items: list[str]) -> str:
    return max(items, key=lambda s: ORDER[s]) if items else "unknown"


def node_status(r) -> tuple[str, str | None]:
    if r.managed is False:
        return "unmanaged", "the token has no Sys.Audit on this node (no visibility; not counted, not idle capacity)"
    return ("ok", None) if r.status == "online" else ("critical", f"node is {r.status}")


def cluster_status(r) -> tuple[str, str | None]:
    if r.quorate is False:
        return "critical", "cluster has no quorum"
    if r.nodes_total is not None and r.nodes_online is not None and r.nodes_online < r.nodes_total:
        return "warning", f"{r.nodes_total - r.nodes_online} node(s) offline"
    return "ok", None


def storage_status(r) -> tuple[str, str | None]:
    if r.enabled is False or r.active is False:
        return "warning", "storage is disabled or inactive"
    if r.total and r.used is not None:
        pct = 100.0 * r.used / r.total
        if pct >= 95:
            return "critical", f"{pct:.0f}% full"
        if pct >= 85:
            return "warning", f"{pct:.0f}% full"
    if r.thin and r.total and r.provisioned_bytes and r.provisioned_bytes > r.total:
        return "warning", (f"thin pool overcommitted: {r.provisioned_bytes / r.total:.2f}x provisioned vs physical capacity "
                           "(visible volumes only; real overcommit may be higher)")
    return "ok", None


def guest_status(r) -> tuple[str, str | None]:
    return ("ok", None) if r.status in ("running", "stopped", "paused", "suspended") else ("warning", f"guest status {r.status}")


_FNS = {"infra_nodes": ("node", node_status), "infra_clusters": ("cluster", cluster_status), "infra_storage": ("storage", storage_status),
        "infra_guests": ("guest", guest_status)}


def with_health(row, kind: str, now: datetime, stale_seconds: int) -> dict:
    """Row -> (status, reason) honouring staleness."""
    _, fn = _FNS[kind]
    st, why = fn(row)
    if st == "unmanaged":
        return {"status": st, "reason": why}
    if (now - row.observed_at).total_seconds() > stale_seconds:
        st, why = "unknown", "no recent observation"
    return {"status": st, "reason": why}


def summary(db: Session, stale_seconds: int) -> dict:
    now = datetime.now(timezone.utc)
    reasons, statuses = [], []
    counts: dict = {}
    for table, (label, _) in _FNS.items():
        rows = db.execute(text(f"SELECT * FROM {table}")).all()
        counts[label] = len(rows)
        for r in rows:
            h = with_health(r, table, now, stale_seconds)
            if h["status"] == "unmanaged":
                continue
            statuses.append(h["status"])
            if h["status"] != "ok":
                reasons.append({"resource": label, "id": str(r.id), "name": r.name, "status": h["status"], "reason": h["reason"]})
    eps = db.execute(text("SELECT e.id, e.name, e.enabled, e.detached_at, s.last_discovery_ok, s.last_discovery_at, s.last_error "
                          "FROM endpoints e LEFT JOIN infra_collect_state s ON s.endpoint_id = e.id")).all()
    active = [e for e in eps if e.enabled and e.detached_at is None]
    for e in active:
        if e.last_discovery_at is None:
            st, why = "unknown", "not discovered yet"
        elif e.last_discovery_ok is False:
            st, why = "critical", f"discovery failing: {e.last_error}"
        elif (now - e.last_discovery_at).total_seconds() > stale_seconds:
            st, why = "unknown", "discovery is stale"
        else:
            continue
        statuses.append(st)
        reasons.append({"resource": "endpoint", "id": str(e.id), "name": e.name, "status": st, "reason": why})
    status = _worst(statuses)
    reasons.sort(key=lambda r: -ORDER[r["status"]])
    return {"status": status, "reasons": reasons[:50], "resources": counts, "endpoints_active": len(active), "endpoints_total": len(eps)}
