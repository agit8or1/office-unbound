"""Inventory collectors: periodic discovery (normalized infra_* rows) and the 60 s metrics collector with rollups + retention.

Runs in the worker loop (`tick`). Uses the READ-ONLY inventory credential only; no mutation can happen here.
"""
from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from ..providers.base import ProviderError, Scope
from ..providers.proxmox import open_read_provider
from ..runtime import Runtime

log = logging.getLogger("ics.inventory")

_UPSERT = {
    "infra_clusters": (["name", "quorate", "nodes_total", "nodes_online", "version"], ["endpoint_id", "name"]),
    "infra_nodes": (["name", "status", "cpu_total", "mem_total", "mem_used", "cpu_pct", "disk_total", "disk_used", "uptime", "ip", "managed"],
                    ["endpoint_id", "name"]),
    "infra_storage": (["name", "node", "type", "content", "shared", "enabled", "active", "total", "used", "thin", "provisioned_bytes"], ["endpoint_id", "name", "node"]),
    "infra_networks": (["name", "node", "kind", "vlan_aware", "ports", "cidr", "zone", "tag"], ["endpoint_id", "kind", "name", "node"]),
    "infra_guests": (["vmid", "kind", "node", "name", "status", "tags", "pool", "ou_managed", "ou_deployment_id", "cpus", "mem_max",
                      "disk_max", "uptime", "cpu_pct", "mem_used"], ["endpoint_id", "vmid"]),
    "infra_templates": (["vmid", "kind", "node", "name", "pool", "tags", "disk_max"], ["endpoint_id", "vmid"]),
}
_KIND_TABLE = {"clusters": "infra_clusters", "nodes": "infra_nodes", "storage": "infra_storage", "networks": "infra_networks",
               "guests": "infra_guests", "templates": "infra_templates"}


def _upsert(db: Session, table: str, endpoint_id: str, rows: list[dict], now: datetime) -> None:
    cols, conflict = _UPSERT[table]
    allc = ["endpoint_id"] + cols
    sets = ", ".join(f"{c} = EXCLUDED.{c}" for c in cols if c not in conflict) + ", observed_at = EXCLUDED.observed_at"
    sql = (f"INSERT INTO {table} ({', '.join(allc)}, observed_at) VALUES ({', '.join(':' + c for c in allc)}, :observed_at) "
           f"ON CONFLICT ({', '.join(conflict)}) DO UPDATE SET {sets}")
    for r in rows:
        params = {c: r.get(c) for c in cols}
        if table == "infra_storage" or table == "infra_networks":
            params["node"] = r.get("node") or ""
        params.update(endpoint_id=endpoint_id, observed_at=now)
        db.execute(text(sql), params)


def _endpoint(db: Session, endpoint_id):
    return db.execute(text("SELECT * FROM endpoints WHERE id = :i"), {"i": str(endpoint_id)}).first()


def collect_discovery(rt: Runtime, db: Session, endpoint_id, known: list[str] | None = None) -> dict:
    """Discover one endpoint and upsert the normalized rows. Never raises for provider problems: the failure is recorded in
    infra_collect_state (and returned) so the UI can show it. Rows of an entity kind are pruned only when that kind was
    fetched completely (a node that is down keeps its last-known rows, which then show as stale)."""
    ep = _endpoint(db, endpoint_id)
    if ep is None:
        raise ProviderError("not_found", "endpoint not found")
    eid, now = str(ep.id), datetime.now(timezone.utc)
    try:
        prov = open_read_provider(rt, ep, known)
        disc = prov.discover()
    except Exception as e:  # noqa: BLE001
        msg = e.message if isinstance(e, ProviderError) else f"{type(e).__name__}"
        _state(db, eid, ok=False, error=msg[:500], warnings=[], counts={})
        db.commit()
        return {"ok": False, "error": msg}
    counts = {}
    for kind, table in _KIND_TABLE.items():
        rows = getattr(disc, kind)
        for r in rows:
            if "tags" in r:
                r["tags"] = list(r["tags"])
        _upsert(db, table, eid, rows, now)
        counts[kind] = len(rows)
        if kind in disc.complete:
            db.execute(text(f"DELETE FROM {table} WHERE endpoint_id = :e AND observed_at < :n"), {"e": eid, "n": now})
    _storage_samples(db, eid, now)
    _state(db, eid, ok=True, error=None, warnings=disc.warnings, counts=counts)
    db.commit()
    return {"ok": True, "counts": counts, "warnings": disc.warnings}


def _state(db: Session, eid: str, *, ok: bool, error: str | None, warnings: list[str], counts: dict) -> None:
    db.execute(text(
        "INSERT INTO infra_collect_state (endpoint_id, last_discovery_at, last_discovery_ok, last_error, warnings, counts) "
        "VALUES (:e, now(), :ok, :err, CAST(:w AS jsonb), CAST(:c AS jsonb)) ON CONFLICT (endpoint_id) DO UPDATE SET "
        "last_discovery_at = now(), last_discovery_ok = :ok, last_error = :err, warnings = CAST(:w AS jsonb), "
        "counts = CASE WHEN :ok THEN CAST(:c AS jsonb) ELSE infra_collect_state.counts END"),
        {"e": eid, "ok": ok, "err": error, "w": json.dumps(warnings[:20]), "c": json.dumps(counts)})


def _minute(ts: datetime) -> datetime:
    return ts.replace(second=0, microsecond=0)


def _storage_samples(db: Session, eid: str, now: datetime) -> None:
    rows = db.execute(text("SELECT id, total, used FROM infra_storage WHERE endpoint_id = :e AND observed_at = :n"), {"e": eid, "n": now}).all()
    out = []
    for r in rows:
        for m, v in (("used_bytes", r.used), ("total_bytes", r.total)):
            if v is not None:
                out.append({"e": eid, "t": "storage", "s": str(r.id), "m": m, "ts": _minute(now), "v": float(v)})
    _insert_samples(db, out)


def _insert_samples(db: Session, rows: list[dict]) -> None:
    if rows:
        db.execute(text(
            "INSERT INTO metric_samples (endpoint_id, scope_type, scope_id, metric, resolution, ts, value, vmax) "
            "VALUES (:e, :t, :s, :m, '1m', :ts, :v, :v) ON CONFLICT (endpoint_id, scope_type, scope_id, metric, resolution, ts) "
            "DO UPDATE SET value = EXCLUDED.value, vmax = EXCLUDED.vmax"), rows)


def collect_metrics(rt: Runtime, db: Session, endpoint_id, known: list[str] | None = None, max_guests: int = 200) -> dict:
    ep = _endpoint(db, endpoint_id)
    if ep is None:
        raise ProviderError("not_found", "endpoint not found")
    eid, now = str(ep.id), datetime.now(timezone.utc)
    last = {(r.scope_type, r.scope_id): r.ts for r in db.execute(text(
        "SELECT scope_type, scope_id, max(ts) AS ts FROM metric_samples WHERE endpoint_id = :e AND resolution = '1m' "
        "AND scope_type IN ('node','guest') GROUP BY 1, 2"), {"e": eid})}
    nodes = db.execute(text("SELECT id, name FROM infra_nodes WHERE endpoint_id = :e AND status = 'online' AND managed"), {"e": eid}).all()
    guests = db.execute(text("SELECT id, vmid, kind, node FROM infra_guests WHERE endpoint_id = :e AND status = 'running' "
                             "ORDER BY vmid LIMIT :n"), {"e": eid, "n": max_guests}).all()
    try:
        prov = open_read_provider(rt, ep, known)
    except Exception as e:  # noqa: BLE001
        _mstate(db, eid, type(e).__name__)
        db.commit()
        return {"ok": False}
    out, errors = [], 0

    def pull(scope: Scope, sid, st):
        nonlocal errors
        since = last.get((st, str(sid))) or (now - timedelta(hours=1))
        try:
            for s in prov.metrics(scope, since + timedelta(seconds=1) if (st, str(sid)) in last else since, 60):
                out.append({"e": eid, "t": st, "s": str(sid), "m": s.metric, "ts": _minute(s.ts), "v": s.value})
        except ProviderError:
            errors += 1
    for n in nodes:
        pull(Scope("node", node=n.name), n.id, "node")
    for g in guests:
        pull(Scope("guest", node=g.node, vmid=g.vmid, kind=g.kind), g.id, "guest")
    _insert_samples(db, out)
    _mstate(db, eid, f"{errors} scope(s) could not be read" if errors else None)
    db.commit()
    return {"ok": True, "samples": len(out), "errors": errors}


def _mstate(db: Session, eid: str, err: str | None) -> None:
    db.execute(text(
        "INSERT INTO infra_collect_state (endpoint_id, last_metrics_at, last_metrics_error) VALUES (:e, now(), :x) "
        "ON CONFLICT (endpoint_id) DO UPDATE SET last_metrics_at = now(), last_metrics_error = :x"), {"e": eid, "x": err})


def rollup_and_prune(db: Session, retention_days: int = 30, keep_1m_hours: int = 48, keep_5m_days: int = 7) -> None:
    """1m -> 5m -> 1h (only COMPLETE buckets; idempotent), then retention: 1m 48 h, 5m 7 d, 1h `retention_days` (30)."""
    for src, dst, width, window in (("1m", "5m", "5 minutes", "3 hours"), ("5m", "1h", "1 hour", "6 hours")):
        db.execute(text(
            f"INSERT INTO metric_samples (endpoint_id, scope_type, scope_id, metric, resolution, ts, value, vmax) "
            f"SELECT endpoint_id, scope_type, scope_id, metric, '{dst}', date_bin('{width}', ts, TIMESTAMPTZ '2000-01-01'), avg(value), max(vmax) "
            f"FROM metric_samples WHERE resolution = '{src}' AND ts >= now() - interval '{window}' "
            f"AND ts < date_bin('{width}', now(), TIMESTAMPTZ '2000-01-01') "
            f"GROUP BY endpoint_id, scope_type, scope_id, metric, date_bin('{width}', ts, TIMESTAMPTZ '2000-01-01') "
            f"ON CONFLICT (endpoint_id, scope_type, scope_id, metric, resolution, ts) DO UPDATE SET value = EXCLUDED.value, vmax = EXCLUDED.vmax"))
    for res, iv in (("1m", f"{keep_1m_hours} hours"), ("5m", f"{keep_5m_days} days"), ("1h", f"{retention_days} days")):
        db.execute(text(f"DELETE FROM metric_samples WHERE resolution = '{res}' AND ts < now() - interval '{iv}'"))
    db.commit()


RANGES = {"1h": (3600, "1m", 60), "24h": (86400, "1m", 300), "7d": (7 * 86400, "5m", 3600), "30d": (30 * 86400, "1h", 3600)}


def query_metrics(db: Session, scope_type: str, scope_id: str, metric: str, rng: str) -> dict:
    """Server-side bucketing: the source resolution depends on the range; points are avg/max per bucket."""
    secs, res, bucket = RANGES[rng]
    rows = db.execute(text(
        "SELECT date_bin(make_interval(secs => :b), ts, TIMESTAMPTZ '2000-01-01') AS bucket, avg(value) AS a, max(vmax) AS mx "
        "FROM metric_samples WHERE scope_type = :t AND scope_id = :s AND metric = :m AND resolution = :r "
        "AND ts >= now() - make_interval(secs => :w) GROUP BY 1 ORDER BY 1"),
        {"b": bucket, "t": scope_type, "s": scope_id, "m": metric, "r": res, "w": secs}).all()
    return {"scope": scope_type, "id": scope_id, "metric": metric, "range": rng, "bucket_seconds": bucket, "source_resolution": res,
            "points": [{"ts": r.bucket.isoformat(), "avg": r.a, "max": r.mx} for r in rows]}


# ---- scheduling (called from the worker loop) -----------------------------------------------------------------
_next: dict[tuple[str, str], float] = {}


def tick(rt: Runtime) -> None:
    s = rt.settings
    now = time.monotonic()
    with rt.session() as db:
        eps = db.execute(text("SELECT id FROM endpoints WHERE enabled AND detached_at IS NULL")).all()
    for ep in eps:
        for kind, every in (("discovery", s.inventory_discovery_seconds), ("metrics", s.metrics_interval_seconds)):
            key = (str(ep.id), kind)
            if _next.get(key, 0) > now:
                continue
            _next[key] = now + every
            try:
                with rt.session() as db:
                    (collect_discovery if kind == "discovery" else collect_metrics)(rt, db, ep.id)
            except Exception:  # noqa: BLE001
                log.exception("inventory %s failed", kind)
    key = ("-", "rollup")
    if _next.get(key, 0) <= now:
        _next[key] = now + 300
        try:
            with rt.session() as db:
                rollup_and_prune(db, s.metrics_retention_days)
        except Exception:  # noqa: BLE001
            log.exception("rollup failed")
