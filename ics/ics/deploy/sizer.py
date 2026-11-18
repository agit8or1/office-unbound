"""Hardware-aware sizing engine (docs/status/sizing-api.md). PURE and deterministic: no I/O, no clock.

    size(request, capacity, catalog, plan_fn, scope) -> SizeResult dict

Every candidate layout is turned into a `PlanInput` (profile `custom`, `custom_layout`, `sizing`) and run through the SAME plan
function as POST /deployments/plan, so the VM list, resources, placement and capacity verdicts the wizard shows are exactly what the
approved plan will contain (same plan_hash). The engine never provisions anything; provisioning stays plan -> approval -> job.
"""
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Callable, Literal

from pydantic import BaseModel, ConfigDict, Field

from .catalog import Catalog
from .plan import FQDN, SLUG, Capacity, PlanInput
from .sizing import SizingSpec, VmOverride, Workload, drivers, service_catalog, services_to_components

ARCHS = ("consolidated", "balanced", "isolated", "ha", "dedicated")
Arch = Literal["consolidated", "balanced", "isolated", "ha", "dedicated"]
DeploymentType = Literal["evaluation", "production", "msp", "custom"]
# plan error codes that mean "does not fit the permitted infrastructure" (others, e.g. artifact_unpinned, block provisioning but not sizing)
CAPACITY_CODES = {"insufficient_capacity", "overcommitted", "thin_overcommit", "insufficient_nodes", "anti_affinity_unsatisfiable",
                  "no_inventory", "unknown_storage", "unknown_node", "pinned_node_unavailable"}
BACKUP_CHANGE_RATE_PCT = 2   # ESTIMATE: daily changed data as % of protected data (incremental backup growth)
CPU_CONTENTION_PCT = 100     # allocated vCPUs above physical cores = possible CPU contention under load
CPU_HEAVY_CONTENTION_PCT = 200


class _M(BaseModel):
    model_config = ConfigDict(extra="forbid")


class WorkloadIn(Workload):
    users: int = Field(ge=1, le=100000, description="total users (MSP: users PER TENANT)")
    tenants: int = Field(default=1, ge=1, le=50, description="MSP only")


class PlacementIn(_M):
    allowed_nodes: list[str] | None = Field(default=None, max_length=64, description="subset of the endpoint's approved nodes; None = all approved")
    storage: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
    bridge: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,15}$")
    vlan: int | None = Field(default=None, ge=1, le=4094)
    pool: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


class BackupIn(_M):
    destination: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$", description="backup-capable storage of the endpoint")
    retention_days: int = Field(default=14, ge=1, le=3650)
    rpo_hours: int = Field(default=24, ge=1, le=720)
    rto_hours: int | None = Field(default=None, ge=1, le=720)
    offsite: bool = False


class UpdatesIn(_M):
    mode: Literal["manual", "maintenance_window"] = "manual"
    window: str | None = Field(default=None, max_length=60, pattern=r"^[A-Za-z0-9 :,-]{1,60}$", description="e.g. 'sun 02:00-04:00'")


class OverridesIn(_M):
    estimate_margin_pct: int | None = Field(default=None, ge=0, le=200)
    tier: Literal["minimum", "recommended"] | None = None
    vm: dict[str, VmOverride] = Field(default_factory=dict, max_length=60, description="by VM name or logical layout name")


class SizeRequest(_M):
    deployment_type: DeploymentType
    customer_id: str = Field(pattern=SLUG)
    deployment_id: str = Field(pattern=SLUG)
    domain: str = Field(pattern=FQDN, max_length=200)
    endpoint: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,62}$")
    workload: WorkloadIn
    services: list[str] = Field(max_length=20, description="mail, calendar, contacts, files, office, chat, meetings, telephony")
    architecture: Arch | None = Field(default=None, description="None = take the recommendation")
    placement: PlacementIn = Field(default_factory=PlacementIn)
    backup: BackupIn = Field(default_factory=BackupIn)
    updates: UpdatesIn = Field(default_factory=UpdatesIn)
    overrides: OverridesIn = Field(default_factory=OverridesIn)
    os_image: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9.-]{1,30}$")


@dataclass
class Scope:
    """Endpoint scope and raw inventory facts the pure engine needs (filled by the API from the endpoint row + latest snapshot)."""
    allowed_pools: list[str] = field(default_factory=list)
    allowed_storage: list[str] = field(default_factory=list)
    allowed_networks: list[str] = field(default_factory=list)
    backup_storages: list[dict] = field(default_factory=list)   # [{name, avail_gb, shared, type}] storages with 'backup' content


def _r(code: str, msg: str, severity: str = "warning", **d) -> dict:
    return {"code": code, "severity": severity, "message": msg, **d}


# ---- layouts --------------------------------------------------------------------------------------------------------

def _ports(cat: Catalog, c: str) -> list[tuple[str, int, int]]:
    return [(p.proto, p.port, p.last) for p in cat.components[c].ports if p.default_enabled]


def _conflict(cat: Catalog, a: str, b: str) -> bool:
    return any(pa == pb and lo <= hi2 and lo2 <= hi for pa, lo, hi in _ports(cat, a) for pb, lo2, hi2 in _ports(cat, b))


def _can_share(cat: Catalog, c: str, members: list[str]) -> bool:
    sc = cat.components[c].sizing
    for m in members:
        sm = cat.components[m].sizing
        if (sc and sc.consolidation.isolation == "required") or (sm and sm.consolidation.isolation == "required"):
            return False
        if (sc and m in sc.consolidation.never_with) or (sm and c in sm.consolidation.never_with) or _conflict(cat, c, m):
            return False
    return True


def _group(cat: Catalog, c: str) -> str:
    s = cat.components[c].sizing
    return s.consolidation.group if s else c


def build_layout(arch: str, comps: set[str], cat: Catalog, multi: bool) -> list[dict]:
    """Deterministic VM layout (list of VmLayout dicts) for an architecture. MSP: edge is one shared VM, everything else per tenant."""
    order = [c for c in cat.dependency_order(comps) if cat.components[c].placement != "every_vm"]
    shared = [c for c in order if multi and c == "edge"]
    order = [c for c in order if c not in shared]
    vms: list[tuple[str, list[str]]] = []
    if arch == "consolidated":
        for c in order:
            for _, members in vms:
                if _can_share(cat, c, members):
                    members.append(c)
                    break
            else:
                vms.append(("core" if not vms else _group(cat, c), [c]))
    elif arch in ("balanced", "dedicated"):
        for c in order:
            g = _group(cat, c)
            slot = next((m for n, m in vms if n == g), None)
            if slot is not None and _can_share(cat, c, slot):
                slot.append(c)
            else:
                vms.append((g if slot is None else c, [c]))
    else:  # isolated / ha
        vms = [(c, [c]) for c in order]
    out = []
    for name, members in vms:
        d = {"name": name, "components": members, "per_tenant": multi}
        if arch == "ha":
            reps = max(cat.components[c].sizing.ha.min_replicas if cat.components[c].sizing else 2 for c in members)
            d.update(replicas=reps, anti_affinity=True)
        out.append(d)
    if shared:
        out.insert(0, {"name": "edge", "components": shared, "per_tenant": False})
    names = [d["name"] for d in out]
    assert len(set(names)) == len(names), names
    return out


def qualify(arch: str, comps: set[str], cat: Catalog, cap: Capacity, allowed_nodes: list[str] | None) -> str | None:
    """None = the infrastructure and the components qualify for `arch`; otherwise the reason it is not offered."""
    usable = [n for n in cap.nodes if n.online and (allowed_nodes is None or n.name in allowed_nodes)]
    if not usable:
        return "no approved online node in the inventory"
    if arch == "ha":
        not_capable = sorted(c for c in comps if cat.components[c].placement != "every_vm"
                             and not (cat.components[c].sizing and cat.components[c].sizing.ha.capable))
        if not_capable:
            return ("application-level HA is not implemented for: " + ", ".join(not_capable)
                    + " (replicated VMs would be independent copies, not HA; Proxmox VM restart is recovery, not HA)")
        need = max((cat.components[c].sizing.ha.min_replicas for c in comps if cat.components[c].sizing), default=2)
        if len(usable) < need:
            return f"HA needs at least {need} approved online nodes for anti-affinity; {len(usable)} available"
    if arch == "dedicated":
        free = [n.name for n in usable if n.foreign_guests == 0]
        if not free:
            return "every approved node already hosts guests outside this deployment (dedicated placement needs an empty node)"
    return None


# ---- capacity analysis -------------------------------------------------------------------------------------------------

def capacity_analysis(plan: dict, inp: PlanInput, cap: Capacity, cat: Catalog, scope: Scope) -> dict:
    pl = cat.meta.placement
    nodes = [n for n in cap.nodes if n.online and (inp.allowed_nodes is None or n.name in inp.allowed_nodes)]
    per_node, warnings = [], []
    placed: dict[str, dict] = {}
    for v in plan["vms"]:
        if v["node"]:
            p = placed.setdefault(v["node"], {"cores": 0, "memory_mb": 0, "vms": 0})
            p["cores"] += v["cores"]
            p["memory_mb"] += v["memory_mb"]
            p["vms"] += 1
    after = {n["name"]: n for n in plan["capacity"]["nodes"]}
    for n in nodes:
        mem_avail = n.memory_mb * (100 - pl.memory_reserve_pct) // 100 - n.used_memory_mb
        cpu_avail = n.cores * pl.cpu_overcommit - n.used_vcpus
        req = placed.get(n.name, {"cores": 0, "memory_mb": 0, "vms": 0})
        ratio = (n.used_vcpus + req["cores"]) * 100 // n.cores if n.cores else 0
        per_node.append({"name": n.name, "physical_cores": n.cores, "memory_mb": n.memory_mb, "existing_vcpus": n.used_vcpus,
                         "existing_memory_mb": n.used_memory_mb, "foreign_guests": n.foreign_guests,
                         "available": {"vcpu": cpu_avail, "memory_mb": mem_avail},
                         "requested": {"vcpu": req["cores"], "memory_mb": req["memory_mb"], "vms": req["vms"]},
                         "headroom": {"vcpu": after.get(n.name, {}).get("vcpu_free", cpu_avail),
                                      "memory_mb": after.get(n.name, {}).get("memory_free_mb", mem_avail),
                                      "memory_pct": (after.get(n.name, {}).get("memory_free_mb", mem_avail) * 100 // mem_avail) if mem_avail > 0 else 0},
                         "vcpu_allocation_pct": ratio})
        if req["vms"] and ratio > CPU_HEAVY_CONTENTION_PCT:
            warnings.append(_r("cpu_contention_high", f"{n.name}: {ratio}% of physical cores allocated as vCPUs after this plan "
                                                      f"(policy limit {pl.cpu_overcommit * 100}%); expect CPU contention under load"))
        elif req["vms"] and ratio > CPU_CONTENTION_PCT:
            warnings.append(_r("cpu_overcommit", f"{n.name}: vCPUs exceed physical cores ({ratio}%); CPU is shared and may contend at peak", "info"))
    used_sto: dict[str, int] = {}
    for v in plan["vms"]:
        for d in v["disks"]:
            if d.get("storage"):
                used_sto[d["storage"]] = used_sto.get(d["storage"], 0) + d["size_gb"]
    sto = []
    for s in cap.storages:
        if scope.allowed_storage and s.name not in scope.allowed_storage:
            continue
        sto.append({"name": s.name, "key": s.key, "shared": not s.nodes, "nodes": s.nodes, "thin": s.thin, "type": s.type or None,
                    "available_gb": s.avail_gb * (100 - pl.storage_reserve_pct) // 100, "requested_gb_all_pools_of_name": used_sto.get(s.name, 0)})
    for name in sorted(used_sto):
        caps = [s for s in cap.storages if s.name == name]
        if caps and all(s.nodes for s in caps):
            warnings.append(_r("local_storage_no_redundancy", f"storage {name} is node-local: a node failure makes its VMs and data unavailable until the node "
                                                              "returns; no live migration or HA restart is possible"))
        if any(s.thin for s in caps):
            warnings.append(_r("thin_storage", f"storage {name} is thin-provisioned: physical space is checked, but pool exhaustion stops all its VMs", "info"))
    domains = sorted({v["node"] for v in plan["vms"] if v["node"]})
    if len(domains) == 1 and len(plan["vms"]) > 0:
        warnings.append(_r("single_failure_domain", f"all VMs are on node {domains[0]}: one node failure stops every service"))
    total_avail = {"vcpu": sum(n["available"]["vcpu"] for n in per_node), "memory_mb": sum(n["available"]["memory_mb"] for n in per_node),
                   "storage_gb": sum(s["available_gb"] for s in sto)}
    req = {k: plan["consumption"][k] for k in ("vms", "cores", "memory_mb", "disk_gb")}
    head = {"vcpu": total_avail["vcpu"] - req["cores"], "memory_mb": total_avail["memory_mb"] - req["memory_mb"],
            "storage_gb": total_avail["storage_gb"] - req["disk_gb"]}
    head["memory_pct"] = head["memory_mb"] * 100 // total_avail["memory_mb"] if total_avail["memory_mb"] > 0 else 0
    return {"available": total_avail, "requested": req, "headroom": head, "nodes": per_node, "storage": sto,
            "failure_domains": {"nodes_used": domains, "count": len(domains)}, "warnings": warnings,
            "policy": {"cpu_overcommit_max": pl.cpu_overcommit, "memory_reserve_pct": pl.memory_reserve_pct,
                       "storage_reserve_pct": pl.storage_reserve_pct, "thin_max_ratio_pct": pl.thin_max_ratio_pct}}


# ---- engine -----------------------------------------------------------------------------------------------------------

def _preference(t: str, users_total: int) -> list[str]:
    if t == "evaluation":
        return ["consolidated", "balanced", "isolated"]
    if t == "msp":
        return ["balanced", "isolated", "consolidated"]
    big = users_total > 500
    return ["ha", *(["isolated", "balanced"] if big else ["balanced", "isolated"]), "dedicated", "consolidated"]


def _bridge_vlan(req: SizeRequest, scope: Scope) -> tuple[str, int | None]:
    if req.placement.bridge:
        return req.placement.bridge, req.placement.vlan
    if scope.allowed_networks:
        b, _, v = scope.allowed_networks[0].partition("/")
        return b, (int(v) if v else req.placement.vlan)
    return "vmbr0", req.placement.vlan


def _storage(req: SizeRequest, cap: Capacity, scope: Scope) -> str | None:
    if req.placement.storage:
        return req.placement.storage
    if not scope.allowed_storage:
        return None   # the planner picks the storage with the most room on each node
    opts = sorted({s.name for s in cap.storages if s.name in scope.allowed_storage},
                  key=lambda n: (-max(s.avail_gb for s in cap.storages if s.name == n), n))
    return opts[0] if opts else scope.allowed_storage[0]


def plan_input_for(req: SizeRequest, arch: str, comps: set[str], cat: Catalog, cap: Capacity, scope: Scope,
                   users: int | None = None, growth: int | None = None) -> PlanInput:
    multi = req.deployment_type == "msp"
    bridge, vlan = _bridge_vlan(req, scope)
    wl = req.workload.model_dump(exclude={"users", "tenants"})
    if growth is not None:
        wl["growth_pct"] = growth
    tier = req.overrides.tier or ("minimum" if req.deployment_type == "evaluation" else "recommended")
    return PlanInput(customer_id=req.customer_id, deployment_id=req.deployment_id, profile="custom", users=users or req.workload.users,
                     tenants=req.workload.tenants if multi else 1, domain=req.domain, endpoint=req.endpoint,
                     pool=req.placement.pool or (scope.allowed_pools[0] if scope.allowed_pools else req.customer_id),
                     storage=_storage(req, cap, scope), bridge=bridge, vlan=vlan, os_image=req.os_image,
                     allowed_nodes=req.placement.allowed_nodes, custom_layout=build_layout(arch, comps, cat, multi),
                     backup_retention_days=req.backup.retention_days,
                     sizing=SizingSpec(workload=Workload(**wl), tier=tier, estimate_margin_pct=req.overrides.estimate_margin_pct,
                                       tenancy="multi" if multi else "single", dedicated_nodes=arch == "dedicated",
                                       vm_overrides=req.overrides.vm))


def _fits(plan: dict) -> bool:
    return not any(e["code"] in CAPACITY_CODES for e in plan["errors"])


def _summary(arch: str, plan: dict) -> dict:
    return {"vms": plan["consumption"]["vms"], "cores": plan["consumption"]["cores"], "memory_mb": plan["consumption"]["memory_mb"],
            "disk_gb": plan["consumption"]["disk_gb"], "fits": _fits(plan),
            "capacity_errors": [e for e in plan["errors"] if e["code"] in CAPACITY_CODES]}


def _evidence(plan: dict, cat: Catalog, comps: set[str]) -> list[dict]:
    """Compare the sized workload with what each component was actually validated at. Never claims an untested load is supported."""
    out = []
    peak: dict[str, Decimal] = {}
    for d in plan.get("sizing", {}).get("vms", {}).values():
        for k, x in d["drivers"].items():
            peak[k] = max(peak.get(k, Decimal(0)), Decimal(x))
    for c in sorted(comps):
        s = cat.components[c].sizing
        if s is None or cat.components[c].placement == "every_vm":
            continue
        v = s.validated
        over = []
        if v.total_users is not None and peak.get("total_user", 0) > v.total_users:
            over.append(f"{int(peak['total_user'])} users vs {v.total_users} tested")
        if v.concurrent is not None and v.concurrent_metric and peak.get(v.concurrent_metric, 0) > v.concurrent:
            over.append(f"{int(peak[v.concurrent_metric])} {v.concurrent_metric} vs {v.concurrent} tested")
        untested = v.total_users is None and v.concurrent is None
        out.append({"component": c, "validated": v.model_dump(mode="json"), "within_validated": not over and not untested,
                    "exceeds": over, "no_load_validation": untested})
    return out


def _backup_check(req: SizeRequest, plan: dict, cat: Catalog, scope: Scope) -> dict:
    b, issues = req.backup, []
    protected = sum(d["size_gb"] for v in plan["vms"] for d in v["disks"] if d["name"] != "root")
    need = protected * (100 + b.retention_days * BACKUP_CHANGE_RATE_PCT) // 100
    dest = next((s for s in scope.backup_storages if s["name"] == b.destination), None) if b.destination else None
    if b.destination is None:
        issues.append(_r("no_backup_destination", "no backup destination selected: data is not protected", "error"))
    elif dest is None:
        issues.append(_r("backup_destination_unknown", f"{b.destination!r} is not a backup-capable storage within the endpoint's approved scope", "error"))
    else:
        if dest["avail_gb"] < need:
            issues.append(_r("backup_space_insufficient", f"{b.destination}: {dest['avail_gb']} GB free, about {need} GB needed for "
                                                          f"{b.retention_days} days (ESTIMATE: {BACKUP_CHANGE_RATE_PCT}%/day change rate)", "error"))
        vm_sto = {d.get("storage") for v in plan["vms"] for d in v["disks"]}
        if b.destination in vm_sto:
            issues.append(_r("backup_on_vm_storage", f"{b.destination} also holds the VM disks: one storage failure loses data and backups", "error"))
    rpo_min = max((c["rpo_hours"] for c in plan["backups"]), default=24)
    if b.rpo_hours < rpo_min:
        issues.append(_r("rpo_not_achievable", f"requested RPO {b.rpo_hours} h, but the components' backup methods give {rpo_min} h "
                                               "(daily schedule; no continuous replication)"))
    if b.offsite:
        issues.append(_r("offsite_not_configured", "an offsite copy is not configured by the deployment plan; set it up in Backups", "info"))
    if b.rto_hours is not None:
        issues.append(_r("rto_unverified", f"RTO {b.rto_hours} h cannot be verified: restore times at this data size were not measured", "info"))
    return {"destination": b.destination, "retention_days": b.retention_days, "rpo_hours": b.rpo_hours, "rto_hours": b.rto_hours,
            "protected_gb": protected, "estimated_backup_gb": need, "estimate": True, "issues": issues,
            "valid": not any(i["severity"] == "error" for i in issues)}


def _max_users(req: SizeRequest, arch: str, comps: set[str], cat: Catalog, cap: Capacity, scope: Scope, plan_fn) -> int:
    """Largest user count (today, no growth) whose sized layout still fits the permitted capacity. Binary search over the plan function."""
    def ok(u: int) -> bool:
        return _fits(plan_fn(plan_input_for(req, arch, comps, cat, cap, scope, users=u, growth=0)))
    if not ok(1):
        return 0
    lo, hi = 1, 100000
    if ok(hi):
        return hi
    while hi - lo > 1:
        mid = (lo + hi) // 2
        lo, hi = (mid, hi) if ok(mid) else (lo, mid)
    return lo


def size(req: SizeRequest, cap: Capacity, cat: Catalog, plan_fn: Callable[[PlanInput], dict], scope: Scope) -> dict:
    comps, unknown = services_to_components(cat, req.services)
    errors = [_r("unknown_service", f"unknown service {s!r}", "error") for s in unknown]
    if req.deployment_type != "msp" and req.workload.tenants != 1:
        errors.append(_r("tenants_need_msp", "more than one tenant needs deployment_type 'msp'", "error"))
    g = Decimal(100 + req.workload.growth_pct) / 100
    users_total = int(req.workload.users * req.workload.tenants * g)
    archs, plans = [], {}
    for a in ARCHS:
        why = qualify(a, comps, cat, cap, req.placement.allowed_nodes)
        entry = {"id": a, "available": why is None, "why_not": why}
        if why is None:
            p = plan_fn(plan_input_for(req, a, comps, cat, cap, scope))
            plans[a] = p
            entry.update(_summary(a, p))
            if not entry["fits"]:
                entry["why_not_fit"] = "; ".join(e["message"] for e in entry["capacity_errors"])[:600]
        archs.append(entry)
    pref = _preference(req.deployment_type, users_total)
    recommended = next((a for a in pref if a in plans and _fits(plans[a])), None)
    selected = req.architecture or recommended
    if req.architecture and req.architecture not in plans:
        errors.append(_r("architecture_not_available", f"{req.architecture}: " + next(x["why_not"] for x in archs if x["id"] == req.architecture), "error"))
        selected = None
    base = {"deployment_type": req.deployment_type, "services": sorted(req.services), "components": sorted(comps),
            "service_catalog": service_catalog(cat), "architectures": archs, "recommended": None, "selected": selected,
            "errors": errors, "writes": "none"}
    if recommended:
        rp = plans[recommended]
        base["recommended"] = {"architecture": recommended, "vms": rp["consumption"]["vms"],
                               "text": f"Recommended: {rp['consumption']['vms']} VMs ({recommended}) based on {req.workload.users} users"
                                       f"{' x ' + str(req.workload.tenants) + ' tenants' if req.deployment_type == 'msp' else ''}, "
                                       f"+{req.workload.growth_pct}% growth, services {', '.join(sorted(req.services)) or 'core only'}, "
                                       f"and {len([n for n in cap.nodes if n.online and (req.placement.allowed_nodes is None or n.name in req.placement.allowed_nodes)])} "
                                       f"approved node(s)"}
    base["alternatives"] = [{"architecture": a["id"], "vms": a.get("vms"), "fits": a.get("fits", False)} for a in archs
                            if a["available"] and a["id"] != recommended]
    if selected is None or selected not in plans:
        base["shortfall"] = _shortfall(req, comps, cat, cap, scope, plan_fn, plans)
        return base
    plan = plans[selected]
    inp = plan_input_for(req, selected, comps, cat, cap, scope)
    capa = capacity_analysis(plan, inp, cap, cat, scope)
    if req.workload.growth_pct:
        capa["growth"] = {"fits_with_growth": _fits(plan), "growth_pct": req.workload.growth_pct,
                          "fits_today": _fits(plan_fn(plan_input_for(req, selected, comps, cat, cap, scope, growth=0)))}
    evidence = _evidence(plan, cat, comps)
    backup = _backup_check(req, plan, cat, scope)
    risks = list(capa["warnings"]) + [i for i in backup["issues"]]
    if selected == "consolidated" and req.deployment_type != "evaluation":
        risks.append(_r("consolidated_production", "every service shares one VM: a single VM or service failure affects all services"))
    for e in evidence:
        if e["exceeds"]:
            risks.append(_r("workload_exceeds_validation", f"{e['component']}: sized workload exceeds what was tested ({'; '.join(e['exceeds'])}); "
                                                           "the numbers are extrapolated estimates", component=e["component"]))
        elif e["no_load_validation"]:
            risks.append(_r("no_load_validation", f"{e['component']}: no load test exists; sizing is estimated", "info", component=e["component"]))
    for c in sorted(comps):
        s = cat.components[c].sizing
        for lim in (s.limitations if s else []):
            risks.append(_r("component_limitation", f"{c}: {lim}", "info", component=c))
    not_ready = []
    if req.deployment_type == "evaluation":
        not_ready.append("evaluation deployment (minimum floors, no redundancy)")
    if inp.sizing and inp.sizing.tier == "minimum":
        not_ready.append("sized at minimum floors")
    if not _fits(plan):
        not_ready.append("does not fit the permitted capacity")
    if any(w["code"] == "cpu_contention_high" for w in capa["warnings"]):
        not_ready.append("heavy CPU over-allocation")
    if not backup["valid"]:
        not_ready.append("backup configuration is not valid")
    if selected == "consolidated" and req.deployment_type != "evaluation":
        not_ready.append("all services on one VM")
    vms = [{"name": v["name"], "logical": v["logical"], "tenant": v["tenant"], "replica": v["replica"],
            "services": sorted({sv for c in v["components"] for sv in (cat.components[c].sizing.services if cat.components[c].sizing else [])}),
            "components": v["components"], "cores": v["cores"], "memory_mb": v["memory_mb"],
            "disk_gb": sum(d["size_gb"] for d in v["disks"]), "disks": v["disks"], "node": v["node"], "anti_affinity": v["anti_affinity"],
            "depends_on": sorted({d for c in v["components"] for d in cat.components[c].depends_on}),
            "sizing": plan.get("sizing", {}).get("vms", {}).get(v["name"])} for v in plan["vms"]]
    shared_all = all(not s.nodes for s in cap.storages if s.name in {d.get("storage") for v in plan["vms"] for d in v["disks"]})
    recovery = {"application_ha": selected == "ha",
                "host_failure": ("VM restart on another node is possible (shared storage, Proxmox HA; not configured by this plan; recovery, not HA)"
                                 if shared_all and capa["failure_domains"]["count"] >= 1 and len(capa["nodes"]) >= 2
                                 else "restore from backup onto a surviving node (node-local storage or a single node)"),
                "backups": plan["backups"]}
    cap_users = _max_users(req, selected, comps, cat, cap, scope, plan_fn)
    scaling = []
    if cap_users and cap_users < 100000:
        scaling.append({"kind": "capacity_limit", "message": f"this layout fits the permitted capacity up to about {cap_users} users "
                                                             "(ESTIMATE from the sizing models, today's workload ratios, no growth)"})
    if selected in ("consolidated", "balanced") and users_total > 250:
        scaling.append({"kind": "split_services", "message": "at this size consider the isolated architecture (one service per VM) to scale and update services independently"})
    ha = next(a for a in archs if a["id"] == "ha")
    if not ha["available"]:
        scaling.append({"kind": "ha_unavailable", "message": "high availability is not offered: " + ha["why_not"]})
    est_flags = next((w["items"] for w in plan["warnings"] if w["code"] == "sizing_estimates"), [])
    base.update({
        "plan_input": inp.model_dump(mode="json", exclude_none=False),
        "plan_hash": plan["plan_hash"], "plan_executable": plan["executable"],
        "plan_blocking": [e for e in plan["errors"] if e["code"] not in CAPACITY_CODES],
        "vms": vms,
        "totals": {k: plan["consumption"][k] for k in ("vms", "cores", "memory_mb", "disk_gb")},
        "capacity": capa, "fits": _fits(plan),
        "production_ready": not not_ready, "production_ready_blockers": not_ready,
        "validated": all(e["within_validated"] for e in evidence), "evidence": evidence,
        "estimated_supported_workload": {"capacity_bound_users": cap_users, "estimate": True,
                                         "basis": "largest user count whose sized layout fits the approved nodes/storage (same services, ratios and margins); "
                                                  "it is NOT a validated or tested capacity - see evidence[]"},
        "backup": backup, "updates": {**req.updates.model_dump(mode="json"),
                                      "note": "updates run only as approved deployment.change plans; nothing is applied automatically"},
        "recovery": recovery, "scaling_recommendations": scaling, "risks": risks,
        "assumptions": _assumptions(req, inp, cat, comps),
        "estimates_flags": est_flags,
    })
    if not _fits(plan):
        base["shortfall"] = _shortfall(req, comps, cat, cap, scope, plan_fn, plans)
    return base


def _assumptions(req: SizeRequest, inp: PlanInput, cat: Catalog, comps: set[str]) -> list[str]:
    w = req.workload
    conc = w.concurrent_users if w.concurrent_users is not None else f"{w.concurrent_pct}% of users"
    out = [f"concurrent users: {conc}; office editors {w.office_editor_pct}%, meeting participants {w.meeting_participant_pct}%, "
           f"phone calls {w.concurrent_call_pct}% of concurrent users (editable ESTIMATES)",
           f"storage per user: mailbox {w.mailbox_gb_per_user} GB, files {w.file_gb_per_user} GB; growth {w.growth_pct}% applied to all user drivers",
           f"per-component floor: {inp.sizing.tier if inp.sizing else 'recommended'}; estimates get each component's safety margin"
           + (f" (overridden to {req.overrides.estimate_margin_pct}%)" if req.overrides.estimate_margin_pct is not None else ""),
           f"VM overhead per VM: {cat.meta.vm_overhead.memory_mb} MB RAM, {cat.meta.vm_overhead.disk_gb} GB disk; node agent on every VM",
           f"host policy: memory reserve {cat.meta.placement.memory_reserve_pct}%, storage reserve {cat.meta.placement.storage_reserve_pct}%, "
           f"max {cat.meta.placement.cpu_overcommit} vCPU per physical core",
           "network bandwidth and disk IOPS are not modelled"]
    return out


def _shortfall(req: SizeRequest, comps: set[str], cat: Catalog, cap: Capacity, scope: Scope, plan_fn, plans: dict) -> dict:
    """Explain what is missing and offer alternatives: other architectures, dropping optional services, smaller floors, more capacity."""
    alts = []
    for a, p in plans.items():
        if _fits(p) and a != req.architecture:
            alts.append({"kind": "architecture", "architecture": a, "vms": p["consumption"]["vms"]})
    optional = [s for s in sorted(set(req.services)) if s not in ("mail", "calendar", "contacts", "files")]
    arch = req.architecture if req.architecture in plans else next((a for a in _preference(req.deployment_type, req.workload.users) if a in plans), None)
    if arch:
        for s in optional:
            c2, _ = services_to_components(cat, [x for x in req.services if x != s])
            if _fits(plan_fn(plan_input_for(req, arch, c2, cat, cap, scope))):
                alts.append({"kind": "drop_service", "service": s, "architecture": arch})
    missing = [{"vm": e.get("vm"), **e["needs"]} for e in (plans[arch]["errors"] if arch else [])
               if e["code"] == "insufficient_capacity" and "needs" in e]
    need = {k: sum(m[k] for m in missing) for k in ("cores", "memory_mb", "disk_gb")}
    if missing:
        alts.append({"kind": "add_capacity", "architecture": arch, "unplaced_vms": missing, "total_needed": need,
                     "message": f"add or free about {need['cores']} vCPU, {need['memory_mb']} MB RAM and {need['disk_gb']} GB on approved nodes/storage"})
    if arch and req.deployment_type != "evaluation" and req.overrides.tier != "minimum":
        alts.append({"kind": "minimum_floors", "message": "evaluation-only: sizing at component minimum floors may fit, but is not production-ready"})
    return {"alternatives": alts, "message": "the selected layout does not fit the permitted infrastructure" if plans else
            "no architecture is available on the approved infrastructure"}


# ---- post-deployment: resize from actual usage -----------------------------------------------------------------------

MEM_HIGH_PCT, MEM_TARGET_PCT, CPU_HIGH_PCT, CPU_TARGET_PCT, DISK_HIGH_PCT = 85, 70, 70, 50, 80
MEM_LOW_PCT, CPU_LOW_PCT = 30, 10


def resize_recommendations(vms: list[dict], usage: dict[str, dict], sizing_vms: dict | None = None) -> tuple[list[dict], dict[str, VmOverride]]:
    """vms: the applied plan's VMs. usage[vm name] = {cpu_avg_pct, cpu_peak_pct, mem_peak_mb, samples, disk_used_pct?}. Returns
    (recommendations, vm_overrides for the increases). Decreases are suggested but never put in the change automatically."""
    recs, ovr = [], {}
    for v in vms:
        u = usage.get(v["name"])
        if not u or not u.get("samples"):
            recs.append({"kind": "no_data", "vm": v["name"], "message": "no metric samples in the window; nothing is concluded for this VM",
                         "automatic": False, "requires_downtime": False, "requires_data_migration": False})
            continue
        new: dict = {}
        mem_pct = u["mem_peak_mb"] * 100 // v["memory_mb"] if v["memory_mb"] else 0
        if mem_pct >= MEM_HIGH_PCT:
            want = -(-u["mem_peak_mb"] * 100 // MEM_TARGET_PCT)
            new["memory_mb"] = -(-want // 256) * 256
        if u["cpu_avg_pct"] >= CPU_HIGH_PCT:
            new["cores"] = max(v["cores"] + 1, -(-v["cores"] * u["cpu_avg_pct"] // CPU_TARGET_PCT))
        evid = {"cpu_avg_pct": u["cpu_avg_pct"], "cpu_peak_pct": u["cpu_peak_pct"], "memory_peak_pct": mem_pct, "samples": u["samples"]}
        if new:
            ovr[v["name"]] = VmOverride(**new)
            recs.append({"kind": "increase_resources", "vm": v["name"], "from": {"cores": v["cores"], "memory_mb": v["memory_mb"]}, "to": new,
                         "evidence": evid, "automatic": False, "requires_downtime": True, "requires_data_migration": False,
                         "message": f"{v['name']}: observed load is high; a CPU/memory change needs a VM restart (live resize is not assumed)"})
        elif mem_pct < MEM_LOW_PCT and u["cpu_peak_pct"] < CPU_LOW_PCT:
            recs.append({"kind": "decrease_resources", "vm": v["name"], "evidence": evid, "automatic": False, "requires_downtime": True,
                         "requires_data_migration": False, "message": f"{v['name']}: consistently idle; consider lowering CPU/RAM "
                                                                      "(not proposed automatically; needs a restart; sized floors still apply)"})
        if u.get("disk_used_pct") is not None and u["disk_used_pct"] >= DISK_HIGH_PCT:
            recs.append({"kind": "expand_storage", "vm": v["name"], "evidence": {"disk_used_pct": u["disk_used_pct"]}, "automatic": False,
                         "requires_downtime": False, "requires_data_migration": False,
                         "message": f"{v['name']}: disks {u['disk_used_pct']}% used; grow the data volume via vm_overrides.disks "
                                    "(online growth of the filesystem inside the guest is not assumed; verify)"})
    return recs, ovr
