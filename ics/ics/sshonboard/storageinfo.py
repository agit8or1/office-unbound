"""Display-only facts for the discovery step (ADR-0014): thin-pool / ZFS over-provisioning and firewall state. Pure parsing of fixed read-only commands
(`lvs`, `zfs list`, `pvesh get .../firewall/...`); nothing here changes anything and nothing is run on other nodes except the cluster-wide read API
(`pvesh get /nodes/<n>/firewall/...` is answered by the cluster file system, it does not log in anywhere)."""
from __future__ import annotations

import json

from ..proxmox import ProxmoxError

WARN_PCT = 80.0


def _f(v) -> float | None:
    try:
        return float(str(v).strip())
    except (TypeError, ValueError):
        return None


def parse_lvs(raw: str | bytes) -> list[dict]:
    try:
        d = json.loads(raw)
        return list(d["report"][0]["lv"])
    except (ValueError, KeyError, IndexError, TypeError):
        raise ProxmoxError("unexpected lvs output") from None


def thin_pools(lvs_rows: list[dict], storage_cfg: list[dict]) -> list[dict]:
    """One row per thin pool: physical size, data/metadata used %, provisioned (sum of thin volumes' virtual sizes), over-provisioning ratio, and the PVE storages on it."""
    out = []
    for lv in lvs_rows:
        attr = lv.get("lv_attr", "")
        if not attr.startswith("t"):
            continue
        vg, name, size = lv.get("vg_name"), lv.get("lv_name"), _f(lv.get("lv_size"))
        if not size:
            continue
        vols = [v for v in lvs_rows if v.get("vg_name") == vg and v.get("pool_lv") == name and v.get("lv_attr", "").startswith(("V", "v"))]
        prov = sum(_f(v.get("lv_size")) or 0 for v in vols)
        data, meta = _f(lv.get("data_percent")), _f(lv.get("metadata_percent"))
        stor = sorted(s["storage"] for s in storage_cfg if s.get("type") == "lvmthin" and s.get("vgname") == vg and s.get("thinpool") == name)
        warn = []
        if prov > size:
            warn.append(f"over-provisioned {prov / size:.2f}x: virtual sizes add up to more than the physical pool")
        if data is not None and data >= WARN_PCT:
            warn.append(f"data {data:.1f}% used")
        if meta is not None and meta >= WARN_PCT:
            warn.append(f"metadata {meta:.1f}% used")
        out.append({"vg": vg, "pool": name, "storages": stor, "physical_bytes": int(size), "data_percent": data, "metadata_percent": meta,
                    "data_used_bytes": int(size * data / 100) if data is not None else None, "provisioned_bytes": int(prov), "thin_volumes": len(vols),
                    "overprovision_ratio": round(prov / size, 2), "warnings": warn})
    return sorted(out, key=lambda r: (r["vg"], r["pool"]))


def zfs_pools(zfs_text: str, storage_cfg: list[dict]) -> list[dict]:
    rows = []
    for ln in zfs_text.splitlines():
        p = ln.split("\t")
        if len(p) >= 5:
            rows.append({"name": p[0], "used": _f(p[1]), "avail": _f(p[2]), "volsize": _f(p[3]), "refres": _f(p[4])})
    out = []
    for s in storage_cfg:
        if s.get("type") != "zfspool" or not s.get("pool"):
            continue
        root = s["pool"]
        top = next((r for r in rows if r["name"] == root), None)
        below = [r for r in rows if r["name"].startswith(root + "/")]
        pool_root = root.split("/")[0]
        total_row = next((r for r in rows if r["name"] == pool_root), None) or top
        if total_row is None or total_row["used"] is None or total_row["avail"] is None:
            continue
        physical = total_row["used"] + total_row["avail"]
        prov = sum(r["volsize"] or 0 for r in below if r["volsize"])
        thick = sum(r["refres"] or 0 for r in below if r["refres"])
        out.append({"storage": s["storage"], "pool": root, "physical_bytes": int(physical), "used_bytes": int(total_row["used"]), "provisioned_bytes": int(prov),
                    "reserved_bytes": int(thick), "overprovision_ratio": round(prov / physical, 2) if physical else None,
                    "warnings": ([f"over-provisioned {prov / physical:.2f}x"] if physical and prov > physical else [])})
    return out


def firewall_state(adm, node_names: list[str]) -> dict:
    """Datacenter firewall switch, and for EVERY node (read through the cluster API, never by logging in): its firewall option and rule counts.
    Shows which nodes' rules would become active if the datacenter firewall were enabled (e.g. by an SDN isolation change)."""
    notes: list[str] = []

    def get(path):
        try:
            return adm.get(path)
        except ProxmoxError as e:
            notes.append(f"{path}: {str(e)[:80]}")
            return None
    dc = get("/cluster/firewall/options")
    dc = dc if isinstance(dc, dict) else {}
    nodes = []
    for n in node_names:
        o, r = get(f"/nodes/{n}/firewall/options"), get(f"/nodes/{n}/firewall/rules")
        o = o if isinstance(o, dict) else {}
        rules = r if isinstance(r, list) else []
        enabled_rules = [x for x in rules if int(x.get("enable", 0) or 0) == 1]
        node_on = int(o.get("enable", 1)) != 0          # PVE default: the node firewall option is on; it only acts while the datacenter switch is on
        nodes.append({"name": n, "node_firewall_option": node_on, "rules": len(rules), "rules_enabled": len(enabled_rules), "readable": o != {} or r is not None})
    dc_on = int(dc.get("enable", 0) or 0) == 1
    would = [x["name"] for x in nodes if x["rules_enabled"] and x["node_firewall_option"]]
    return {"datacenter_enabled": dc_on, "datacenter_policy_in": dc.get("policy_in"), "datacenter_policy_out": dc.get("policy_out"), "nodes": nodes,
            "nodes_with_rules": [x["name"] for x in nodes if x["rules"]], "rules_would_become_active_on": [] if dc_on else would,
            "note": ("The datacenter firewall is ON: node rules are active now." if dc_on else
                     "The datacenter firewall is OFF. Enabling it (for example for SDN isolation) activates the node rules listed under rules_would_become_active_on."),
            "read_errors": notes[:8]}
