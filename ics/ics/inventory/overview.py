"""Consolidated multi-cluster view: one row per connected cluster with quorum, nodes, guests, HA, backup coverage, storage with a
capacity projection, data freshness and the infrastructure alert rules configured for it. Everything comes from what the read-only
collectors recorded; a value that was not collected is null with a reason, never estimated.

Projection: least-squares slope of the storage's recorded used bytes (1 h rollups over 30 days, else 5 min over 7 days). Shown only with
at least 24 h of history and 6 samples; otherwise "insufficient history". A flat or shrinking trend is "not growing", not a date."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.orm import Session

MIN_SPAN_S, MIN_SAMPLES, BACKUP_FRESH_H = 86400, 6, 26


def projection(db: Session, endpoint_id: str, storage_row_id: str, used, total) -> dict:
    if not total or used is None:
        return {"days_to_full": None, "note": "size not reported"}
    for res, window in (("1h", "30 days"), ("5m", "7 days")):
        r = db.execute(text(f"SELECT regr_slope(value, extract(epoch FROM ts)) AS slope, count(*) AS n, "
                            f"extract(epoch FROM max(ts) - min(ts)) AS span FROM metric_samples WHERE endpoint_id = :e AND scope_type = 'storage' "
                            f"AND scope_id = :s AND metric = 'used_bytes' AND resolution = '{res}' AND ts > now() - interval '{window}'"),
                       {"e": endpoint_id, "s": storage_row_id}).first()
        if r.n >= MIN_SAMPLES and (r.span or 0) >= MIN_SPAN_S:
            if r.slope is None or r.slope <= 0:
                return {"days_to_full": None, "note": "not growing", "basis": f"{r.n} samples ({res})"}
            days = (float(total) - float(used)) / float(r.slope) / 86400
            return {"days_to_full": round(max(days, 0.0), 1), "growth_bytes_per_day": round(float(r.slope) * 86400),
                    "note": "linear trend of recorded usage", "basis": f"{r.n} samples ({res})"}
    return {"days_to_full": None, "note": "insufficient history (needs 24 h of samples)"}


def overview(db: Session, endpoint_where: str, stale_s: int) -> list[dict]:
    now = datetime.now(timezone.utc)
    eps = db.execute(text("SELECT e.id, e.name, e.display_name, s.last_discovery_at, s.last_discovery_ok, s.last_error, s.complete "
                          f"FROM endpoints e LEFT JOIN infra_collect_state s ON s.endpoint_id = e.id WHERE {endpoint_where} ORDER BY e.name")).all()
    out = []
    for e in eps:
        p = {"e": str(e.id)}
        q = lambda sql: db.execute(text(sql), p).first()  # noqa: E731
        comp = set(e.complete or [])
        cl = q("SELECT name, quorate, version FROM infra_clusters WHERE endpoint_id = :e ORDER BY observed_at DESC LIMIT 1")
        n = q("SELECT count(*) AS total, count(*) FILTER (WHERE status = 'online') AS online, count(*) FILTER (WHERE managed) AS monitored "
              "FROM infra_nodes WHERE endpoint_id = :e")
        g = q("SELECT count(*) AS total, count(*) FILTER (WHERE status = 'running') AS running, count(*) FILTER (WHERE ou_managed) AS managed "
              "FROM infra_guests WHERE endpoint_id = :e")
        ha = None
        if "ha" in comp:
            h = q("SELECT count(*) FILTER (WHERE kind = 'service') AS services, count(*) FILTER (WHERE kind = 'service' AND split_part(lower(state), ' ', 1) "
                  "IN ('error','fence','recovery')) AS problems FROM infra_ha WHERE endpoint_id = :e")
            ha = {"services": h.services, "problems": h.problems}
        bk = None
        if "backups" in comp:
            b = q(f"SELECT count(*) AS guests, count(b.vmid) FILTER (WHERE b.last_at > now() - interval '{BACKUP_FRESH_H} hours') AS fresh, "
                  "count(*) FILTER (WHERE b.vmid IS NULL) AS never FROM infra_guests g LEFT JOIN infra_backups b ON b.endpoint_id = g.endpoint_id "
                  "AND b.vmid = g.vmid WHERE g.endpoint_id = :e")
            f = q("SELECT count(*) FILTER (WHERE status IS NOT NULL AND status <> 'OK') AS failed FROM infra_backup_tasks WHERE endpoint_id = :e "
                  f"AND ended_at > now() - interval '{BACKUP_FRESH_H} hours'") if "backup_tasks" in comp else None
            bk = {"guests": b.guests, "backed_up_recently": b.fresh, "never": b.never, "window_hours": BACKUP_FRESH_H,
                  "failed_tasks": f.failed if f else None}
        storage = []
        for s in db.execute(text("SELECT id, name, node, shared, active, enabled, used, total FROM infra_storage WHERE endpoint_id = :e "
                                 "AND enabled IS NOT FALSE ORDER BY name, node"), p).all():
            if s.shared and any(x["name"] == s.name and x["shared"] for x in storage):
                continue
            pct = round(100.0 * s.used / s.total, 1) if s.total and s.used is not None else None
            storage.append({"name": s.name, "node": "" if s.shared else s.node, "shared": bool(s.shared), "active": s.active, "used": s.used,
                            "total": s.total, "pct": pct, "projection": projection(db, str(e.id), str(s.id), s.used, s.total)})
        al = q("SELECT count(*) AS n, count(*) FILTER (WHERE state = 'critical') AS crit, count(*) FILTER (WHERE state = 'warning') AS warn "
               "FROM checks WHERE kind = 'infra' AND enabled AND config->>'endpoint_id' = :e")
        age = (now - e.last_discovery_at).total_seconds() if e.last_discovery_at else None
        out.append({
            "endpoint_id": str(e.id), "name": e.display_name or e.name, "cluster": cl.name if cl else None, "version": cl.version if cl else None,
            "quorate": cl.quorate if cl else None,
            "freshness": {"last_discovery_at": e.last_discovery_at.isoformat() if e.last_discovery_at else None, "age_seconds": age,
                          "stale": age is None or age > stale_s, "ok": e.last_discovery_ok, "error": e.last_error},
            "nodes": {"total": n.total, "online": n.online, "monitored": n.monitored},
            "guests": {"total": g.total, "running": g.running, "managed": g.managed},
            "ha": ha, "backups": bk, "visibility": sorted(comp),
            "storage": sorted(storage, key=lambda x: -(x["pct"] or 0)),
            "alerts": {"rules": al.n, "critical": al.crit, "warning": al.warn},
        })
    return out
