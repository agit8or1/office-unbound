"""InventoryDiscovery for the connection wizard: one read-only pass over the Proxmox API that yields the cluster overview, the resource tree
(nodes -> guests, storage, networks, pools) and whether the signed-in account can set up Office Unbound's restricted access.

Pure reads through any client with `.get(path)`. Usage figures come from /cluster/resources; PVE reports zero usage for objects the account may
not audit, so `audited=False` marks those instead of showing them as idle. Nothing here grants, stores or changes anything."""
from __future__ import annotations

from urllib.parse import quote

from ..proxmox import ProxmoxError

# what the signed-in administrator needs to create the restricted service account, its tokens, roles and ACLs (pveum(1) / API viewer)
SETUP_PRIVS = {
    "/access": ("User.Modify", "Sys.Modify"),          # create the pve-realm service user + tokens; create/update roles
    "/": ("Permissions.Modify", "Sys.Audit"),          # set ACLs on nodes/storage/pools/vms; read cluster state
}


def _opt(c, path, notes: list[str], what: str):
    try:
        return c.get(path)
    except ProxmoxError as e:
        notes.append(f"could not read {what}: {str(e)[:120]}")
        return None


def _num(x) -> float:
    try:
        return float(x or 0)
    except (TypeError, ValueError):
        return 0.0


def account_check(c, username: str | None) -> dict:
    """Can this account provision? -> {ok, missing: [{path, privilege}], remediation}. Uses /access/permissions of the caller itself."""
    missing = []
    for path, privs in SETUP_PRIVS.items():
        try:
            got = (c.get("/access/permissions?path=" + quote(path, safe="/")) or {}).get(path, {})
        except ProxmoxError:
            got = {}
        missing += [{"path": path, "privilege": p} for p in privs if not got.get(p)]
    rem = None
    if missing:
        rem = ("Sign in with root@pam, or give this account the narrowest role that holds the missing privileges, e.g. "
               f"`pveum role add OUSetup -privs \"{','.join(sorted({m['privilege'] for m in missing}))}\"` and "
               f"`pveum acl modify / -user {username or '<account>'} -role OUSetup` (remove it again after setup).")
    return {"ok": not missing, "missing": missing, "remediation": rem}


def discover(c, username: str | None = None) -> dict:
    notes: list[str] = []
    v = c.get("/version")
    status = _opt(c, "/cluster/status", notes, "cluster status") or []
    res = _opt(c, "/cluster/resources", notes, "cluster resources") or []
    cl = next((s for s in status if s.get("type") == "cluster"), None)
    nodes: dict[str, dict] = {}
    for n in c.get("/nodes"):
        nodes[n["node"]] = {"name": n["node"], "status": n.get("status", "unknown"), "cpu": _num(n.get("cpu")), "maxcpu": int(_num(n.get("maxcpu"))),
                            "mem": int(_num(n.get("mem"))), "maxmem": int(_num(n.get("maxmem"))), "uptime": int(_num(n.get("uptime"))),
                            "audited": bool(n.get("maxcpu")), "guests": []}
    guests, storages, pools = [], {}, set()
    for r in res:
        t = r.get("type")
        if t in ("qemu", "lxc") and "vmid" in r:
            g = {"vmid": int(r["vmid"]), "type": t, "name": r.get("name") or "", "node": r.get("node"), "status": r.get("status", "unknown"),
                 "cpus": int(_num(r.get("maxcpu"))), "cpu": _num(r.get("cpu")), "mem": int(_num(r.get("mem"))), "maxmem": int(_num(r.get("maxmem"))),
                 "maxdisk": int(_num(r.get("maxdisk"))), "pool": r.get("pool"), "template": bool(r.get("template")), "tags": r.get("tags") or ""}
            guests.append(g)
            if g["node"] in nodes:
                nodes[g["node"]]["guests"].append(g["vmid"])
        elif t == "storage":
            s = storages.setdefault(r["storage"], {"storage": r["storage"], "type": r.get("plugintype"), "content": r.get("content", ""),
                                                   "shared": bool(r.get("shared")), "nodes": [], "used": 0, "total": 0})
            s["nodes"].append(r.get("node"))
            if s["shared"]:
                s["used"], s["total"] = int(_num(r.get("disk"))), int(_num(r.get("maxdisk")))
            else:
                s["used"] += int(_num(r.get("disk")))
                s["total"] += int(_num(r.get("maxdisk")))
        elif t == "pool" and r.get("pool"):
            pools.add(r["pool"])
    for p in _opt(c, "/pools", notes, "pools") or []:
        pools.add(p["poolid"])
    networks: dict[str, dict] = {}
    for z in _opt(c, "/cluster/sdn/vnets", notes, "SDN vnets") or []:
        networks[z["vnet"]] = {"name": z["vnet"], "kind": "vnet", "zone": z.get("zone"), "nodes": sorted(nodes)}
    for n, nd in nodes.items():
        if nd["status"] != "online":
            continue
        for i in _opt(c, f"/nodes/{quote(n)}/network", notes, f"network of {n}") or []:
            if i.get("type") in ("bridge", "OVSBridge"):
                e = networks.setdefault(i["iface"], {"name": i["iface"], "kind": "bridge", "zone": None, "nodes": []})
                e["nodes"].append(n)
                if i.get("comments"):
                    e["comment"] = str(i["comments"]).strip()[:120]
    online = [x for x in nodes.values() if x["status"] == "online"]
    overview = {
        "name": (cl or {}).get("name") or (next(iter(nodes)) if len(nodes) == 1 else "cluster"),
        "standalone": cl is None, "quorate": bool((cl or {}).get("quorate", 1)), "version": str(v.get("version", "")),
        "nodes_total": len(nodes), "nodes_online": len(online),
        "cpu": {"used": round(sum(x["cpu"] * x["maxcpu"] for x in online), 2), "total": sum(x["maxcpu"] for x in online)},
        "mem": {"used": sum(x["mem"] for x in online), "total": sum(x["maxmem"] for x in online)},
        "storage": {"used": sum(s["used"] for s in storages.values()), "total": sum(s["total"] for s in storages.values())},
        "guests": len(guests), "vms": sum(1 for g in guests if g["type"] == "qemu"), "containers": sum(1 for g in guests if g["type"] == "lxc"),
    }
    return {"cluster": overview, "nodes": sorted(nodes.values(), key=lambda x: x["name"]), "guests": sorted(guests, key=lambda g: g["vmid"]),
            "storages": sorted(storages.values(), key=lambda s: s["storage"]), "networks": sorted(networks.values(), key=lambda x: x["name"]),
            "pools": sorted(pools), "account": account_check(c, username), "notes": notes}


def annotate(tree: dict, ep, ledger_keys: set[tuple[str, str]]) -> dict:
    """Edit mode: mark every discovered resource with how the APPROVED scope treats it and whether the ICS has seen it before. Nothing is granted.
    authorization: operated | template | deployment_pool | protected | authorized | not_authorized;  seen: False = new since the last sync."""
    from ..inventory.ledger import authorization
    for g in tree["guests"]:
        g["authorization"] = authorization(ep, "guest", str(g["vmid"]), g.get("pool"))
        g["seen"] = ("guest", str(g["vmid"])) in ledger_keys
    for n in tree["nodes"]:
        n["authorization"] = authorization(ep, "node", n["name"])
        n["seen"] = ("node", n["name"]) in ledger_keys
    for s in tree["storages"]:
        s["authorization"] = authorization(ep, "storage", s["storage"])
        s["seen"] = ("storage", s["storage"]) in ledger_keys
    for x in tree["networks"]:
        x["authorization"] = authorization(ep, "network", x["name"])
        x["seen"] = ("network", x["name"]) in ledger_keys
    present = ({("guest", str(g["vmid"])) for g in tree["guests"]} | {("node", n["name"]) for n in tree["nodes"]}
               | {("storage", s["storage"]) for s in tree["storages"]} | {("network", x["name"]) for x in tree["networks"]})
    tree["missing"] = [{"kind": k, "key": key} for k, key in sorted(ledger_keys - present) if k != "pool"]
    tree["approved_scope"] = {"nodes": list(ep.allowed_nodes or []), "pools": list(ep.allowed_pools or []), "storages": list(ep.allowed_storage or []),
                              "networks": list(ep.allowed_networks or []), "templates": list(ep.allowed_templates or []),
                              "managed_vmids": list(getattr(ep, "managed_vmids", None) or []), "protected_vmids": list(ep.protected_vmids or [])}
    return tree
