"""Read-only glue between the sizing engine (sizer.py, pure) and the database: inventory + endpoint scope for POST /deployments/size,
metric_samples + applied revision for POST /deployments/{slug}/resize-plan. Nothing here writes; nothing here provisions."""
from sqlalchemy import text

from . import ops, sizer
from .plan import PlanInput
from .sizing import SizingSpec

WINDOWS = {"24h": "24 hours", "7d": "7 days", "30d": "30 days"}


def _scope(db, endpoint: str, data: dict) -> sizer.Scope:
    ep = db.execute(text("SELECT allowed_pools, allowed_storage, allowed_networks FROM endpoints WHERE name = :n AND detached_at IS NULL"),
                    {"n": endpoint}).first()
    allowed_sto = list(ep.allowed_storage or []) if ep else []
    backup: dict[str, dict] = {}
    for n in data.get("nodes", []):
        for s in n.get("storage", []) if isinstance(n.get("storage"), list) else []:
            if not isinstance(s, dict) or "backup" not in str(s.get("content", "")) or not s.get("active", 1):
                continue
            nm = s.get("storage")
            if not isinstance(nm, str) or (allowed_sto and nm not in allowed_sto):
                continue
            gb = int(s.get("avail", 0) or 0) // (1024 ** 3)
            cur = backup.get(nm)
            backup[nm] = {"name": nm, "avail_gb": gb if cur is None else min(cur["avail_gb"], gb), "shared": bool(s.get("shared")),
                          "type": str(s.get("type", "")) or None}
    return sizer.Scope(allowed_pools=list(ep.allowed_pools or []) if ep else [], allowed_storage=allowed_sto,
                       allowed_networks=list(ep.allowed_networks or []) if ep else [], backup_storages=[backup[k] for k in sorted(backup)])


def size_request(db, req: sizer.SizeRequest) -> dict:
    """Dry run. Raises KeyError when the endpoint does not exist."""
    data, fn = ops.plan_context(db, req.endpoint, req.deployment_id)
    scope = _scope(db, req.endpoint, data)
    out = sizer.size(req, fn.capacity, fn.catalog, fn, scope)
    out["backup_destinations"] = scope.backup_storages
    return out


def _usage(db, endpoint_id: str, vmid: int, window: str) -> dict:
    rows = db.execute(text(
        "SELECT resolution, metric, avg(value) AS avg, max(vmax) AS peak, count(*) AS n FROM metric_samples "
        "WHERE endpoint_id = :e AND scope_type = 'guest' AND scope_id = :s AND ts >= now() - CAST(:w AS interval) "
        "GROUP BY resolution, metric"), {"e": endpoint_id, "s": str(vmid), "w": WINDOWS[window]}).all()
    if not rows:
        return {"samples": 0}
    res = next(r for r in ("1m", "5m", "1h") if any(x.resolution == r for x in rows))   # finest resolution present
    m = {x.metric: x for x in rows if x.resolution == res}
    cpu, mem = m.get("cpu_pct"), m.get("mem_used_bytes")
    out = {"samples": int(cpu.n if cpu else 0), "resolution": res,
           "cpu_avg_pct": int(round(cpu.avg)) if cpu else 0, "cpu_peak_pct": int(round(cpu.peak)) if cpu else 0,
           "mem_peak_mb": int(mem.peak) // 1048576 if mem else 0}
    du, dt = m.get("disk_used_bytes"), m.get("disk_total_bytes")
    if du and dt and dt.peak > 0 and du.peak > 0:   # qemu guests without the guest agent report 0 used
        out["disk_used_pct"] = int(du.peak * 100 // dt.peak)
    return out


def resize_plan(db, slug: str, window: str = "7d") -> dict:
    """Rerun sizing against actual usage; propose an approval-gated ChangeSet. Writes nothing. KeyError = 404, LookupError = 409."""
    dep = ops._dep(db, slug)
    if dep is None:
        raise KeyError("deployment not found")
    applied = ops._applied_plan(db, dep)
    refs = {r.logical_name: r.provider_ref or {} for r in db.execute(text(
        "SELECT logical_name, provider_ref FROM deployment_resources WHERE deployment_id = :d AND kind = 'vm'"), {"d": str(dep.id)})}
    usage = {}
    for v in applied["vms"]:
        vmid = refs.get(v["name"], {}).get("vmid")
        usage[v["name"]] = _usage(db, str(dep.endpoint_id), int(vmid), window) if vmid is not None and dep.endpoint_id else {"samples": 0}
    recs, ovr = sizer.resize_recommendations(applied["vms"], usage)
    spec = PlanInput.model_validate(dep.desired_spec)
    cur = spec.sizing or SizingSpec()
    out: dict = {"deployment_id": slug, "window": window, "applied_revision": dep.current_revision, "usage": usage,
                 "recommendations": recs, "writes": "none",
                 "note": "proposals only: apply through POST /plans deployment.change (plan_hash + approval); no live resize or migration is assumed"}
    # the current sizing models vs the applied plan (catalog/model changes since deployment)
    d0 = ops.plan_change(db, slug, ops.ChangeSet())[4]
    out["model_drift"] = {"differs": not d0["empty"], "changed": [f"{c['kind']}:{c['name']}" for c in d0["changed"]][:30],
                          "note": "the current catalog/sizing models regenerate a different plan than the applied one" if not d0["empty"] else ""}
    cat = ops.get_catalog()
    comps = {c for v in applied["vms"] for c in v["components"] if cat.components.get(c) and cat.components[c].placement != "every_vm"}
    nodes_cap = ops.plan_context(db, spec.endpoint, spec.deployment_id)[1].capacity
    why = sizer.qualify("ha", comps, cat, nodes_cap, spec.allowed_nodes)
    out["recommendations"].append({"kind": "upgrade_ha", "available": why is None, "why_not": why, "automatic": False,
                                   "requires_downtime": True, "requires_data_migration": True,
                                   "message": "moving to HA changes the layout and needs application data replication/migration"})
    if not ovr:
        out["proposed_change"] = None
        return out
    merged = {**{k: v for k, v in cur.vm_overrides.items()}, **ovr}
    cs = ops.ChangeSet(sizing=cur.model_copy(update={"vm_overrides": merged}))
    _, _, old, new, diff = ops.plan_change(db, slug, cs)
    moved = sorted(v["name"] for v in new["vms"] for o in old["vms"] if o["name"] == v["name"] and o["node"] and v["node"] and o["node"] != v["node"])
    head = [n for n in new["capacity"]["nodes"] if n["memory_free_mb"] < 0 or n["vcpu_free"] < 0]
    if any(e["code"] in sizer.CAPACITY_CODES for e in new["errors"]) or head:
        out["recommendations"].append({"kind": "add_capacity", "automatic": False, "requires_downtime": False, "requires_data_migration": False,
                                       "message": "the increase does not fit the approved nodes: add a node or capacity to the endpoint scope, "
                                                  "or move workloads (needs migration; downtime unless storage is shared)"})
    out["proposed_change"] = {
        "changes": cs.model_dump(mode="json", exclude_none=True), "plan_hash": new["plan_hash"], "executable": new["executable"] and not diff["empty"],
        "errors": new["errors"], "diff": {k: diff[k] for k in ("added", "changed", "removed", "capacity_impact", "downtime_seconds", "disruptive_steps",
                                                                "snapshot_required", "risk", "risk_reasons", "requires_maintenance")},
        "requires_downtime": bool(diff["requires_maintenance"] or diff["downtime_seconds"]), "requires_data_migration": bool(moved),
        "moved_vms": moved, "submit_as": {"action": "deployment.change", "params": {"deployment_id": slug, "changes": cs.model_dump(mode="json", exclude_none=True),
                                                                                    "plan_hash": new["plan_hash"]}}}
    return out
