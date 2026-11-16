"""Scope change planning (provider.scope.change): single node <-> more nodes <-> whole cluster, add/remove storages.

Pure computation (no network): given the stored policy/design, the requested target, discovered facts and the guests the ICS manages, it returns the
new policy, the permission diff (ACL entries and role privileges to add/remove), the impact (capacity/visibility, guests that would fall outside the
new scope), the direction (widen / narrow / same), the risk and a hash that binds an approval to exactly this change."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field

from ...provisioning.model import Policy
from ...provisioning.plan import ProvisioningPlan
from ...provisioning.scope_model import ScopeTarget
from . import provisioning as pp


class ScopeChangeError(ValueError):
    pass


def target_policy(old: Policy, t: ScopeTarget, stored_roles: dict | None = None) -> Policy:
    d = old.model_dump(mode="json")
    if stored_roles:
        d["role_names"] = {**d.get("role_names", {}), **stored_roles}      # a scope change never renames roles
    d["scope_mode"] = t.mode
    sc = d["scope"]
    if t.mode == "single_node":
        sc["nodes"] = list(t.nodes)
        d["scope_risk_overrides"] = list(t.risk_overrides)
    else:
        sc["nodes"] = []
        d["scope_risk_overrides"] = []
    if t.storages is not None:
        sc["storages"] = list(t.storages)
    if t.template_vmids is not None:
        sc["template_vmids"] = list(t.template_vmids)
    for k in ("pools", "networks", "managed_vmids"):
        if getattr(t, k) is not None:
            sc[k] = list(getattr(t, k))
    if t.preset is not None and t.preset != d["preset"]:
        if d["preset"] not in ("monitoring", "operations", "deploy"):
            raise ScopeChangeError(f"the permission level '{d['preset']}' cannot be changed here; re-provision the integration instead")
        d["preset"] = t.preset
    if t.allow_migrate is not None:
        d["allow_migrate"] = t.allow_migrate
    try:
        return Policy.model_validate(d)
    except ValueError as e:      # pydantic ValidationError is a ValueError
        msg = "; ".join(x["msg"].removeprefix("Value error, ") for x in e.errors()) if hasattr(e, "errors") else str(e)
        raise ScopeChangeError(msg) from None


def _reach(p: Policy, all_nodes: set[str]) -> dict:
    nodes = set(p.scope.nodes) if p.mode() != "whole_cluster" else (set(p.scope.nodes) | all_nodes)
    return {"nodes": nodes, "storages": set(p.scope.storages) | set(p.scope.backup_storages), "migrate": bool(p.allow_migrate),
            "overrides": set(p.scope_risk_overrides), "whole": p.mode() == "whole_cluster", "templates": set(p.scope.template_vmids)}


def direction(old: Policy, new: Policy, all_nodes: set[str]) -> str:
    a, b = _reach(old, all_nodes), _reach(new, all_nodes)
    wider = (b["nodes"] - a["nodes"]) or (b["storages"] - a["storages"]) or (b["migrate"] and not a["migrate"]) or (b["overrides"] - a["overrides"]) \
        or (b["whole"] and not a["whole"]) or (b["templates"] - a["templates"])      # review 5 M3: a template = VM.Clone/VM.Audit ACLs
    narrower = (a["nodes"] - b["nodes"]) or (a["storages"] - b["storages"]) or (a["migrate"] and not b["migrate"]) or (a["overrides"] - b["overrides"]) \
        or (a["whole"] and not b["whole"]) or (a["templates"] - b["templates"])
    return "widen" if wider else ("narrow" if narrower else "same")


def _covers(old: tuple, new: tuple) -> bool:
    """an old entry covers a new one when subject and role are the same and the new path is the old path or below a propagating old path"""
    (p0, s0, r0, prop0), (p1, s1, r1, _prop1) = old, new
    if s0 != s1 or r0 != r1:
        return False
    return p0 == p1 or (bool(prop0) and (p0 == "/" or p1.startswith(p0.rstrip("/") + "/")))


def _new_reach(added: set[tuple], old: set[tuple]) -> bool:
    """True if any added ACL entry is NOT already covered by the old design (narrowing whole-cluster to one node re-adds /nodes/<n>, covered by /nodes)"""
    return any(not any(_covers(o, a) for o in old) for a in added)


def _entries(d: pp.Design) -> set[tuple]:
    return {tuple(e) for e in pp.acl_entries(d)}


def _managed_guests(facts: pp.Facts | None, db_guests: list[dict]) -> dict[int, dict]:
    out: dict[int, dict] = {}
    for g in db_guests:
        out[int(g["vmid"])] = {"vmid": int(g["vmid"]), "node": g.get("node"), "name": g.get("name"), "deployment": g.get("ou_deployment_id")}
    if facts:
        for vmid, g in facts.guests.items():
            if "ou-managed" in re.split(r"[;, ]", g.get("tags") or ""):
                m = out.setdefault(vmid, {"vmid": vmid})
                m.update(node=g.get("node"), name=g.get("name"))       # live data wins over the last inventory
    return out


@dataclass
class ScopeChange:
    old: Policy
    new: Policy
    direction: str
    plan: ProvisioningPlan
    diff: dict
    impact: dict
    detach: list[int] = field(default_factory=list)
    blocked: list[str] = field(default_factory=list)
    risk: str = "normal"
    hash: str = ""

    def to_dict(self) -> dict:
        return {"direction": self.direction, "risk": self.risk, "blocked": self.blocked, "diff": self.diff, "impact": self.impact, "detach": self.detach,
                "scope_hash": self.hash, "old_scope": scope_summary(self.old), "new_scope": scope_summary(self.new),
                "enforcement_before": [e.__dict__ for e in pp.scope_enforcement(self.old)],
                "enforcement_after": [e.__dict__ for e in pp.scope_enforcement(self.new)]}


def scope_summary(p: Policy) -> dict:
    return {"mode": p.mode(), "nodes": list(p.scope.nodes), "storages": sorted(set(p.scope.storages) | set(p.scope.backup_storages)),
            "migrate": bool(p.allow_migrate), "overrides": list(p.scope_risk_overrides), "templates": sorted(p.scope.template_vmids)}


def _guest_disks(cfg_storages: dict[int, set[str]], vmid: int) -> set[str]:
    return cfg_storages.get(vmid, set())


def parse_config_storages(cfg: dict) -> set[str]:
    out = set()
    for k, v in (cfg or {}).items():
        if re.fullmatch(r"(scsi|virtio|sata|ide|efidisk|tpmstate)\d+|rootfs|mp\d+", k) and isinstance(v, str) and ":" in v and not v.startswith(("none", "/")):
            st = v.split(":", 1)[0]
            if st and "=" not in st and "," not in st:
                out.add(st)
    return out


def build(old: Policy, stored_design: dict, target: ScopeTarget, facts: pp.Facts | None, managed: dict, **kw) -> ScopeChange:
    new = target_policy(old, target, stored_design.get("roles"))
    return build_from(old, stored_design, new, facts, managed, detach_requested=target.detach_orphans, **kw)


def build_from(old: Policy, stored_design: dict, new: Policy, facts: pp.Facts | None, managed: dict, *, detach_requested: bool = False,
               db_guests: list[dict] | None = None, guest_storages: dict[int, set[str]] | None = None, node_rows: list[dict] | None = None,
               pve_major: int | None = None) -> ScopeChange:
    target = type("T", (), {"detach_orphans": detach_requested})()
    all_nodes = set(facts.nodes) if facts else set(old.scope.nodes)
    plan = pp.plan_for(new, facts, pve_major=pve_major or stored_design.get("pve_major"), managed=managed, prune=True, mode="A")
    plan.facts["tokens"] = dict(stored_design["tokens"])
    new = Policy.model_validate(plan.policy)           # whole_cluster: node list normalised from the cluster
    all_nodes |= set(new.scope.nodes)
    dirn = direction(old, new, all_nodes)       # reach-based; the permission diff below can only RAISE it to widen
    d_old = pp.design_from_stored(old, stored_design)
    d_new = pp.design_from_plan(plan, new)
    e_old, e_new = _entries(d_old), _entries(d_new)
    token_change = sorted(set(d_old.tokens) ^ set(d_new.tokens))
    # --- permission diff (deterministic: stored design vs new design; the live plan may add repairs on top)
    def rows(es):
        by: dict[tuple, dict] = {}
        for path, subj, role, prop in sorted(es):
            r = by.setdefault((path, role, prop), {"path": path, "role": role, "propagate": bool(prop), "subjects": [], "enforced_by": "proxmox"})
            r["subjects"].append(subj)
        return list(by.values())
    role_changes = []
    for cap in sorted(set(d_old.roles) | set(d_new.roles)):
        o, n = d_old.roles.get(cap), d_new.roles.get(cap)
        if o is None or n is None:
            role_changes.append({"capability": cap, "role": (n or o)[0], "change": "added" if o is None else "removed"})
        elif o[1] != n[1] or o[0] != n[0]:
            role_changes.append({"capability": cap, "role": n[0], "change": "privileges", "added": sorted(n[1] - o[1]), "removed": sorted(o[1] - n[1])})
    o_s, n_s = scope_summary(old), scope_summary(new)
    if dirn != "widen" and (_new_reach(e_new - e_old, e_old) or any(c["change"] == "added" or (c["change"] == "privileges" and c["added"]) for c in role_changes)):
        dirn = "widen"       # review 5 M3: any ACL entry that grants something the old design did not already cover, or any added role privilege, is a widening
    if dirn == "same" and (e_old - e_new or any(c["change"] == "removed" or (c["change"] == "privileges" and c["removed"]) for c in role_changes)):
        dirn = "narrow"      # only removals: less access (e.g. a guest no longer operated)
    diff = {"acl_add": rows(e_new - e_old), "acl_remove": rows(e_old - e_new), "roles": role_changes,
            "ics_allowlist": {"nodes": {"before": o_s["nodes"], "after": n_s["nodes"]}, "storages": {"before": o_s["storages"], "after": n_s["storages"]}},
            "nodes_added": sorted(set(n_s["nodes"]) - set(o_s["nodes"])), "nodes_removed": sorted(set(o_s["nodes"]) - set(n_s["nodes"])),
            "storages_added": sorted(set(n_s["storages"]) - set(o_s["storages"])), "storages_removed": sorted(set(o_s["storages"]) - set(n_s["storages"])),
            "operated_added": sorted(set(new.scope.managed_vmids) - set(old.scope.managed_vmids)),
            "operated_removed": sorted(set(old.scope.managed_vmids) - set(new.scope.managed_vmids)),
            "pools_added": sorted(set(new.scope.pools) - set(old.scope.pools)), "pools_removed": sorted(set(old.scope.pools) - set(new.scope.pools)),
            "networks_added": sorted(set(new.scope.networks) - set(old.scope.networks)), "networks_removed": sorted(set(old.scope.networks) - set(new.scope.networks)),
            "preset": {"before": old.preset, "after": new.preset}}
    # --- impact
    new_nodes = set(new.scope.nodes) if new.mode() != "whole_cluster" else (set(new.scope.nodes) | all_nodes)
    gone_st = set(diff["storages_removed"])
    mg = _managed_guests(facts, db_guests or [])
    outside = []
    for vmid, g in sorted(mg.items()):
        why = []
        if g.get("node") and g["node"] not in new_nodes:
            why.append(f"runs on node {g['node']}, which leaves the scope")
        bad = _guest_disks(guest_storages or {}, vmid) & gone_st
        if bad:
            why.append("has disks on " + ", ".join(sorted(bad)) + ", which leaves the scope")
        if why:
            outside.append({"vmid": vmid, "name": g.get("name"), "node": g.get("node"), "deployment": g.get("deployment"), "why": why})
    cap = []
    rows_by = {r["node"] if "node" in r else r.get("name"): r for r in (node_rows or [])}
    for n in sorted(all_nodes | set(o_s["nodes"])):
        r = rows_by.get(n, {})
        before, after = n in _reach(old, all_nodes)["nodes"], n in new_nodes
        cap.append({"node": n, "cpus": r.get("maxcpu") or None, "mem_gib": round(r["maxmem"] / 2**30) if r.get("maxmem") else None,
                    "before": before, "after": after, "change": "added" if after and not before else "removed" if before and not after else "kept" if after else "outside"})
    impact = {"capacity": cap, "managed_guests_outside": outside,
              "visibility": {"nodes_visible_before": sorted(n for n in all_nodes if n in _reach(old, all_nodes)["nodes"]), "nodes_visible_after": sorted(n for n in all_nodes if n in new_nodes)},
              "notes": []}
    blocked = list(plan.blocked)
    if token_change:
        blocked.append("this permission level needs a different set of Proxmox tokens (" + ", ".join(token_change) + "); a scope change only edits the existing "
                       "ones. Use 'Change permission level' (re-provisioning with a new restricted token) instead.")
    if diff["operated_removed"]:
        impact["notes"].append(f"Office Unbound stops operating guest(s) {', '.join(map(str, diff['operated_removed']))}. They keep running in Proxmox untouched; "
                               "only Office Unbound's access to them is removed.")
    detach: list[int] = []
    if outside:
        if target.detach_orphans:
            detach = [o["vmid"] for o in outside]
            impact["notes"].append(f"{len(detach)} managed guest(s) will be detached: Office Unbound stops managing them; they keep running in Proxmox untouched.")
        else:
            blocked.append(f"this change would leave {len(outside)} guest(s) managed by Office Unbound outside the new scope ("
                           + ", ".join(f"{o['vmid']} {o.get('name') or ''}".strip() for o in outside[:6]) + (" ..." if len(outside) > 6 else "")
                           + "). Office Unbound could no longer manage or protect them. Move or remove them first, or choose an explicit, separately approved detach.")
    elif target.detach_orphans:
        blocked.append("detach was requested but no managed guest falls outside the new scope")
    risk = "high" if (dirn == "widen" or detach or plan.risk == "high") else "normal"
    sc = ScopeChange(old, new, dirn, plan, diff, impact, detach, blocked, risk)
    sc.hash = scope_hash(sc, e_new, e_old)
    return sc


def scope_hash(sc: ScopeChange, e_new: set, e_old: set) -> str:
    body = {"new": sc.new.model_dump(mode="json"), "old": sc.old.model_dump(mode="json"), "direction": sc.direction, "detach": sorted(sc.detach),
            "add": sorted(map(list, e_new - e_old)), "remove": sorted(map(list, e_old - e_new)), "roles": sc.diff["roles"],
            "role_names": {c: n for c, (n, _) in pp.design_from_plan(sc.plan, sc.new).roles.items()}}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def package_meta(sc: ScopeChange, stored_design: dict) -> dict:
    """What the Mode B script needs beyond the plan: ACL entries to remove, roles to change (old -> new privileges)."""
    d_old = pp.design_from_stored(sc.old, stored_design)
    d_new = pp.design_from_plan(sc.plan, sc.new)
    rm = sorted(_entries(d_old) - _entries(d_new))
    add_back = sorted(_entries(d_old) - _entries(d_new))
    role_up = {}
    for cap, (name, privs) in d_new.roles.items():
        o = d_old.roles.get(cap)
        if o and o[0] == name and o[1] != privs:
            role_up[name] = {"old": sorted(o[1]), "new": sorted(privs)}
    return {"scope_change": {"remove_acl": [list(x) for x in rm], "restore_acl": [list(x) for x in add_back],
                             "undo_acl": [list(x) for x in sorted(_entries(d_new) - _entries(d_old))], "role_updates": role_up,
                             "direction": sc.direction, "old_scope": scope_summary(sc.old), "new_scope": scope_summary(sc.new)}}
