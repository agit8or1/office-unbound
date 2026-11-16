"""Inventory ledger: what the ICS has seen per endpoint, so changes in Proxmox become visible instead of silently changing what is managed.

After each discovery (collector.collect_discovery) `reconcile` compares the normalized infra_* rows with the ledger by STABLE identity
(vmid, node name, storage id, bridge/vnet, pool id) and records:
  new               first seen after the endpoint's baseline (the first sync is the baseline and is not reported as new)
  missing           not returned by a COMPLETE fetch of that kind any more (deleted, or access revoked in Proxmox)
  moved             a guest's node changed (migration)
  renamed           a guest's name changed
  identity_changed  a guest's type changed under the same VMID (deleted and re-created): never inherits review state
Review (`acknowledge`) only marks an entry as seen. NOTHING here grants access: authorization comes exclusively from the approved policy
(endpoints.allowed_* / managed_vmids) changed through approved plans."""
from __future__ import annotations

import json

from sqlalchemy import text
from sqlalchemy.orm import Session

_COMPLETE = {"guest": ("guests", "templates"), "node": ("nodes",), "storage": ("storage",), "network": ("networks",)}


def current(db: Session, eid: str) -> dict[tuple[str, str], dict]:
    out: dict[tuple[str, str], dict] = {}
    for r in db.execute(text("SELECT vmid, kind, node, name, pool, false AS template FROM infra_guests WHERE endpoint_id = :e UNION ALL "
                             "SELECT vmid, kind, node, name, pool, true FROM infra_templates WHERE endpoint_id = :e"), {"e": eid}).all():
        out[("guest", str(r.vmid))] = {"name": r.name, "node": r.node, "type": ("template-" if r.template else "") + r.kind, "pool": r.pool}
    for r in db.execute(text("SELECT name, status FROM infra_nodes WHERE endpoint_id = :e"), {"e": eid}).all():
        out[("node", r.name)] = {"name": r.name, "node": r.name, "type": "node"}
    for r in db.execute(text("SELECT name, min(type) AS type, bool_or(shared) AS shared FROM infra_storage WHERE endpoint_id = :e GROUP BY name"), {"e": eid}).all():
        out[("storage", r.name)] = {"name": r.name, "node": None, "type": r.type}
    for r in db.execute(text("SELECT name, min(kind) AS kind FROM infra_networks WHERE endpoint_id = :e GROUP BY name"), {"e": eid}).all():
        out[("network", r.name)] = {"name": r.name, "node": None, "type": r.kind}
    return out


def reconcile(db: Session, eid: str, complete: set[str]) -> dict:
    cur = current(db, eid)
    led = {(r.kind, r.key): r for r in db.execute(text("SELECT * FROM inventory_ledger WHERE endpoint_id = :e"), {"e": eid}).all()}
    baseline = not led
    counts = {"new": 0, "changed": 0, "missing": 0}
    for (kind, key), c in cur.items():
        r = led.get((kind, key))
        if r is None:
            db.execute(text("INSERT INTO inventory_ledger (endpoint_id, kind, key, name, node, type, acknowledged_at) "
                            "VALUES (:e, :k, :key, :n, :node, :t, CASE WHEN :b THEN now() ELSE NULL END)"),
                       {"e": eid, "k": kind, "key": key, "n": c["name"], "node": c["node"], "t": c["type"], "b": baseline})
            counts["new"] += 0 if baseline else 1
            continue
        change, detail = None, None
        if kind == "guest":
            base_t = lambda t: (t or "").removeprefix("template-")  # noqa: E731  (converting a guest into a template is not a new identity)
            if r.type and base_t(r.type) != base_t(c["type"]):
                change, detail = "identity_changed", {"was": {"type": r.type, "name": r.name}, "now": {"type": c["type"], "name": c["name"]}}
            elif r.name != c["name"]:
                change, detail = "renamed", {"was": r.name, "now": c["name"]}
            elif r.node and r.node != c["node"]:
                change, detail = "moved", {"was": r.node, "now": c["node"]}
        if change:
            db.execute(text("UPDATE inventory_ledger SET name = :n, node = :node, type = :t, last_seen = now(), missing_since = NULL, change = :c, "
                            "change_detail = CAST(:d AS jsonb), acknowledged_at = NULL WHERE endpoint_id = :e AND kind = :k AND key = :key"),
                       {"e": eid, "k": kind, "key": key, "n": c["name"], "node": c["node"], "t": c["type"], "c": change, "d": json.dumps(detail)})
            counts["changed"] += 1
        else:
            db.execute(text("UPDATE inventory_ledger SET name = :n, node = :node, type = :t, last_seen = now(), missing_since = NULL "
                            "WHERE endpoint_id = :e AND kind = :k AND key = :key"),
                       {"e": eid, "k": kind, "key": key, "n": c["name"], "node": c["node"], "t": c["type"]})
    for (kind, key), r in led.items():
        if (kind, key) in cur or kind not in _COMPLETE or not all(x in complete for x in _COMPLETE[kind]):
            continue
        if r.missing_since is None:
            db.execute(text("UPDATE inventory_ledger SET missing_since = now(), acknowledged_at = NULL WHERE endpoint_id = :e AND kind = :k AND key = :key"),
                       {"e": eid, "k": kind, "key": key})
            counts["missing"] += 1
    return counts


def authorization(ep, kind: str, key: str, pool: str | None = None) -> str:
    """How the APPROVED policy treats this resource (the ledger never changes it)."""
    if kind == "guest":
        v = int(key)
        if v in (ep.protected_vmids or ()):
            return "protected"
        if v in (getattr(ep, "managed_vmids", None) or ()):
            return "operated"
        if v in (ep.allowed_templates or ()):
            return "template"
        if pool and pool in (ep.allowed_pools or ()):
            return "deployment_pool"
        return "not_authorized"
    if kind == "node":
        return "authorized" if key in (ep.allowed_nodes or ()) else "not_authorized"
    if kind == "storage":
        return "authorized" if key in (ep.allowed_storage or ()) else "not_authorized"
    if kind == "network":
        return "authorized" if any(n.split("/")[0] == key for n in (ep.allowed_networks or ())) else "not_authorized"
    return "not_authorized"


def view(db: Session, ep) -> dict:
    eid = str(ep.id)
    pools = {str(r.vmid): r.pool for r in db.execute(text("SELECT vmid, pool FROM infra_guests WHERE endpoint_id = :e UNION ALL "
                                                         "SELECT vmid, pool FROM infra_templates WHERE endpoint_id = :e"), {"e": eid}).all()}
    rows = db.execute(text("SELECT * FROM inventory_ledger WHERE endpoint_id = :e ORDER BY kind, key"), {"e": eid}).all()
    out, counts = [], {"new": 0, "changed": 0, "missing": 0, "authorized": 0}
    for r in rows:
        auth = authorization(ep, r.kind, r.key, pools.get(r.key))
        state = ("missing" if r.missing_since else r.change if r.change and r.acknowledged_at is None
                 else "new" if r.acknowledged_at is None else "known")
        if state == "new":
            counts["new"] += 1
        elif state in ("renamed", "moved", "identity_changed"):
            counts["changed"] += 1
        elif state == "missing" and auth != "not_authorized":
            counts["missing"] += 1
        if auth not in ("not_authorized",):
            counts["authorized"] += 1
        out.append({"kind": r.kind, "key": r.key, "name": r.name, "node": r.node, "type": r.type, "pool": pools.get(r.key) if r.kind == "guest" else None,
                    "authorization": auth, "state": state, "change": r.change_detail if r.change and r.acknowledged_at is None else None,
                    "first_seen": r.first_seen.isoformat(), "last_seen": r.last_seen.isoformat(),
                    "missing_since": r.missing_since.isoformat() if r.missing_since else None})
    return {"endpoint_id": eid, "counts": counts, "resources": out,
            "visibility": "Only resources the integration's read-only credential may see are tracked here. Sign in to Proxmox in Manage access to see "
                          "the whole cluster."}


def acknowledge(db: Session, eid: str, keys: list[tuple[str, str]] | None) -> int:
    if keys is None:
        r = db.execute(text("UPDATE inventory_ledger SET acknowledged_at = now(), change = NULL, change_detail = NULL "
                            "WHERE endpoint_id = :e AND acknowledged_at IS NULL AND missing_since IS NULL"), {"e": eid})
        return r.rowcount or 0
    n = 0
    for kind, key in keys:
        r = db.execute(text("UPDATE inventory_ledger SET acknowledged_at = now(), change = NULL, change_detail = NULL "
                            "WHERE endpoint_id = :e AND kind = :k AND key = :key AND missing_since IS NULL"), {"e": eid, "k": kind, "key": key})
        n += r.rowcount or 0
    return n


def new_count(db: Session, where_active: str) -> int:
    return db.execute(text(f"SELECT count(*) FROM inventory_ledger l JOIN endpoints e ON e.id = l.endpoint_id WHERE ({where_active}) AND "
                           "l.missing_since IS NULL AND l.acknowledged_at IS NULL")).scalar() or 0
