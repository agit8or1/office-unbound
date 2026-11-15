"""Deployment plan generation (ADR-0009 section 4): a PURE, deterministic function.

    generate_plan(PlanInput, Capacity, catalog, existing=None) -> dict   (the DeploymentPlan)

No I/O, no clock, no randomness: identical inputs give an identical plan and `plan_hash`. All numbers in the plan are integers or
strings (plans are hashed canonically and stored in the audit trail). The plan is data only; executing it is the executor's job.

DeploymentPlan keys: plan_version, catalog{version,digest}, profile{name,version,maturity}, input, vms[], containers[], services[],
firewall[], dns[], backups[], checks[], steps[] (the dependency DAG in execution order), consumption, capacity{nodes[],storage[]},
warnings[], errors[], executable, plan_hash.
"""
import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .catalog import Catalog, Component, Profile, VmLayout, get_catalog

PLAN_VERSION = 1
SLUG = r"^[a-z0-9][a-z0-9-]{1,30}$"
FQDN = r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$"


class _M(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PlanInput(_M):
    customer_id: str = Field(pattern=SLUG)
    deployment_id: str = Field(pattern=SLUG)
    profile: str = Field(pattern=r"^[a-z][a-z0-9-]{0,40}$")
    users: int = Field(ge=1, le=100000, description="users per tenant")
    tenants: int = Field(default=1, ge=1, le=50)
    domain: str = Field(pattern=FQDN, max_length=200)
    endpoint: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,62}$", description="registered endpoint name")
    pool: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
    storage: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
    bridge: str = Field(default="vmbr0", pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,15}$")
    vlan: int | None = Field(default=None, ge=1, le=4094)
    os_image: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9.-]{1,30}$")
    allowed_nodes: list[str] | None = Field(default=None, max_length=64)
    optional: dict[str, bool] = Field(default_factory=dict, description="override which optional components are enabled")
    custom_layout: list[VmLayout] | None = Field(default=None, max_length=30)
    backup_retention_days: int | None = Field(default=None, ge=1, le=3650)


@dataclass
class NodeCap:
    name: str
    cores: int
    memory_mb: int
    used_memory_mb: int = 0
    used_vcpus: int = 0
    online: bool = True
    foreign_guests: int = 0   # guests on the node that are not part of this deployment


@dataclass
class StorageCap:
    name: str
    avail_gb: int          # PHYSICAL free space (never inflated by thin provisioning)
    nodes: list[str] = field(default_factory=list)   # [] = shared (usable from every node)
    total_gb: int = 0
    thin: bool = False
    provisioned_gb: int | None = None   # already-provisioned virtual size (thin pools); unknown = None

    @property
    def key(self) -> str:
        """Unique id: node-local storage with the same name on several nodes are distinct pools."""
        return self.name if not self.nodes else f"{self.name}@{','.join(sorted(self.nodes))}"


@dataclass
class Capacity:
    nodes: list[NodeCap] = field(default_factory=list)
    storages: list[StorageCap] = field(default_factory=list)
    bridges: list[str] | None = None  # None = unknown (not checked)


@dataclass
class ExistingVm:
    """Current allocation of an already-deployed VM (change planning): placement is pinned and its resources are credited."""
    node: str
    cores: int
    memory_mb: int
    disks: dict[str, tuple[int, str]]  # disk name -> (size_gb, storage)


def canon(v: Any) -> str:
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def plan_hash(plan: dict) -> str:
    return hashlib.sha256(canon({k: v for k, v in plan.items() if k != "plan_hash"}).encode()).hexdigest()


def _err(code: str, msg: str, **d) -> dict:
    return {"code": code, "message": msg, **d}


# ---- expansion ---------------------------------------------------------------------------------------------

@dataclass
class _Vm:
    name: str
    logical: str
    tenant: str | None
    replica: int
    group: str
    components: list[str]
    anti_affinity: bool
    users: int
    cores: int = 0
    memory_mb: int = 0
    disks: list[dict] = field(default_factory=list)
    node: str | None = None


def _tenant_ids(inp: PlanInput, prof: Profile) -> list[str | None]:
    if prof.tenancy == "multi":
        return [f"t{i:02d}" for i in range(1, inp.tenants + 1)]
    return [None]


def _layout(inp: PlanInput, prof: Profile, errors: list[dict]) -> list[VmLayout]:
    if prof.custom:
        if not inp.custom_layout:
            errors.append(_err("custom_layout_missing", "profile 'custom' requires custom_layout"))
            return []
        return list(inp.custom_layout)
    if inp.custom_layout:
        errors.append(_err("custom_layout_not_allowed", f"profile {prof.name!r} has a fixed layout; use profile 'custom' for your own"))
    return list(prof.vms)


def _expand(inp: PlanInput, prof: Profile, cat: Catalog, errors: list[dict]) -> tuple[list[_Vm], set[str]]:
    layout = _layout(inp, prof, errors)
    enabled_opt = {o for o in prof.optional_components if inp.optional.get(o, o in prof.default_optional)}
    for o in inp.optional:
        if o not in prof.optional_components:
            errors.append(_err("unknown_optional", f"{o!r} is not an optional component of profile {prof.name!r}"))
    disabled = set(prof.optional_components) - enabled_opt
    base = f"{inp.customer_id}-{inp.deployment_id}"
    vms: list[_Vm] = []
    tenants = _tenant_ids(inp, prof)
    for lay in layout:
        comps = [c for c in lay.components if c not in disabled]
        for c in comps:
            if c not in cat.components:
                errors.append(_err("unknown_component", f"layout {lay.name!r}: unknown component {c!r}"))
        comps = [c for c in comps if c in cat.components]
        if not comps:
            continue
        for t in (tenants if lay.per_tenant else [None]):
            users = inp.users * (len(tenants) if (prof.tenancy == "multi" and t is None) else 1)
            for r in range(1, lay.replicas + 1):
                name = "-".join(p for p in (base, t, lay.name, f"r{r}" if lay.replicas > 1 else None) if p)
                if len(name) > 63:
                    errors.append(_err("name_too_long", f"VM name {name!r} exceeds 63 characters; shorten customer/deployment ids"))
                vms.append(_Vm(name, lay.name, t, r, "-".join(p for p in (base, t, lay.name) if p), sorted(comps, key=comps.index),
                               lay.anti_affinity, users))
    present = {c for v in vms for c in v.components}
    every = [c for c in cat.components.values() if c.placement == "every_vm"]
    for v in vms:
        seen: dict[tuple, str] = {}
        for cn in [*v.components, *(c.name for c in every)]:
            for p in cat.components[cn].ports:
                if (p.port, p.proto) in seen:
                    errors.append(_err("port_conflict", f"{v.name}: {cn} and {seen[(p.port, p.proto)]} both listen on {p.proto}/{p.port}; "
                                                        "put them on different VMs", vm=v.name))
                seen[(p.port, p.proto)] = cn
    for c in sorted(present):
        for d in cat.components[c].depends_on:
            if d not in present:
                errors.append(_err("missing_dependency", f"component {c!r} needs {d!r}, which is not in the layout (or was disabled)"))
    if prof.tenancy == "single" and inp.tenants != 1:
        errors.append(_err("tenants_not_supported", f"profile {prof.name!r} is single-tenant; use msp-multi for {inp.tenants} tenants"))
    return vms, present


def _size(vms: list[_Vm], cat: Catalog) -> None:
    ov = cat.meta.vm_overhead
    every = [c for c in cat.components.values() if c.placement == "every_vm"]
    for v in vms:
        comps = [cat.components[c] for c in v.components] + every
        v.cores = max(1, ov.cores + sum(c.resources.cores.at(v.users) for c in comps))
        v.memory_mb = ov.memory_mb + sum(c.resources.memory_mb.at(v.users) for c in comps)
        root = ov.disk_gb + sum(c.resources.disk_gb.at(v.users) for c in comps)
        v.disks = [{"name": "root", "size_gb": root, "purpose": "os+software"}]
        for c in comps:
            for vol in c.volumes:
                v.disks.append({"name": f"{c.name}-{vol.name}", "size_gb": max(1, vol.size_gb.at(v.users)), "purpose": f"volume:{vol.path}",
                                "backup": vol.backup})


# ---- placement ----------------------------------------------------------------------------------------------

def _place(vms: list[_Vm], inp: PlanInput, prof: Profile, cat: Catalog, cap: Capacity, existing: dict[str, ExistingVm],
           errors: list[dict], warnings: list[dict]) -> dict:
    """First-fit-decreasing with best-remaining-memory choice; deterministic (sorted keys everywhere)."""
    pl = cat.meta.placement
    nodes = {n.name: n for n in cap.nodes}
    if inp.allowed_nodes is not None:
        for n in inp.allowed_nodes:
            if n not in nodes:
                errors.append(_err("unknown_node", f"allowed node {n!r} is not in the inventory"))
        nodes = {k: n for k, n in nodes.items() if k in inp.allowed_nodes}
    usable = {k: n for k, n in sorted(nodes.items()) if n.online}
    if len(usable) < prof.min_nodes:
        errors.append(_err("insufficient_nodes", f"profile {prof.name!r} needs at least {prof.min_nodes} online node(s); {len(usable)} usable",
                           needed=prof.min_nodes, usable=len(usable)))
    free_mem = {k: n.memory_mb * (100 - pl.memory_reserve_pct) // 100 - n.used_memory_mb for k, n in usable.items()}
    free_cpu = {k: n.cores * pl.cpu_overcommit - n.used_vcpus for k, n in usable.items()}
    caps = {s.key: s for s in cap.storages}
    free_sto = {k: caps[k].avail_gb * (100 - pl.storage_reserve_pct) // 100 for k in sorted(caps)}
    cap_start = dict(free_sto)

    def keys_for(node: str, real: str | None = None) -> list[str]:
        return [k for k in sorted(caps) if (not caps[k].nodes or node in caps[k].nodes) and (real is None or caps[k].name == real)]

    def key_of(real: str, node: str) -> str | None:
        ks = keys_for(node, real)
        return ks[0] if ks else None
    node_load: dict[str, int] = {k: 0 for k in usable}
    foreign_ok = {k for k, n in usable.items() if not (prof.dedicated_nodes and n.foreign_guests > 0)}
    if prof.dedicated_nodes:
        for k in sorted(usable):
            if k not in foreign_ok:
                warnings.append(_err("node_not_dedicated", f"node {k!r} hosts {usable[k].foreign_guests} guest(s) outside this deployment and is excluded (dedicated profile)"))

    # credit existing allocations first (change planning)
    for v in vms:
        ex = existing.get(v.name)
        if ex and ex.node in usable:
            free_mem[ex.node] += ex.memory_mb
            free_cpu[ex.node] += ex.cores
            for _, (sz, st) in ex.disks.items():
                kk = key_of(st, ex.node)
                if kk:
                    free_sto[kk] += sz
    placed_groups: dict[str, set[str]] = {}
    order = sorted(vms, key=lambda v: (v.name not in existing, -v.memory_mb, v.name))
    anti_failed: set[str] = set()
    for v in order:
        need_disk = sum(d["size_gb"] for d in v.disks)
        ex = existing.get(v.name)
        if ex:
            cands = [ex.node] if ex.node in usable else []
            if not cands:
                errors.append(_err("pinned_node_unavailable", f"{v.name}: its current node {ex.node!r} is not usable", vm=v.name))
                continue
            for d in v.disks:  # disks keep their storage; new disks go where root lives
                old = ex.disks.get(d["name"])
                if old and d["size_gb"] < old[0]:
                    errors.append(_err("disk_shrink", f"{v.name}: disk {d['name']} would shrink {old[0]} -> {d['size_gb']} GB; shrinking is not supported", vm=v.name))
                d["storage"] = (old or ex.disks.get("root", (0, "")))[1]
        else:
            cands = [k for k in usable if k in foreign_ok]
        if v.anti_affinity:
            used = placed_groups.get(v.group, set())
            cands = [k for k in cands if k not in used]
        best: tuple | None = None
        short: list[str] = []
        for k in cands:
            mem_after, cpu_after = free_mem[k] - v.memory_mb, free_cpu[k] - v.cores
            if mem_after < 0:
                short.append(f"{k}: {-mem_after} MB RAM short")
                continue
            if cpu_after < 0:
                short.append(f"{k}: {-cpu_after} vCPU short")
                continue
            if ex:
                stos = sorted({d["storage"] for d in v.disks})
                ok = all(key_of(s, k) is not None and free_sto[key_of(s, k)] >= sum(x["size_gb"] for x in v.disks if x["storage"] == s)
                         for s in stos)
                st_choice = None
                if not ok:
                    short.append(f"{k}: storage short")
                    continue
            else:
                allk = keys_for(k, inp.storage)
                opts = [s for s in allk if free_sto[s] >= need_disk]
                if not opts:
                    have = max((free_sto[s] for s in allk), default=0)
                    short.append(f"{k}: storage short by {need_disk - have} GB")
                    continue
                st_choice = max(opts, key=lambda s: (free_sto[s] - need_disk, s))
            sibling_penalty = 1 if k in placed_groups.get(v.group, set()) else 0
            key = (sibling_penalty, -(mem_after // 64), node_load[k], k)
            if best is None or key < best[0]:
                best = (key, k, st_choice)
        if best is None:
            if v.anti_affinity and not cands and v.group not in anti_failed:
                anti_failed.add(v.group)
                errors.append(_err("anti_affinity_unsatisfiable",
                                   f"{v.group}: {len([x for x in vms if x.group == v.group])} replicas need distinct nodes but only "
                                   f"{len(usable)} usable node(s) are available", vm=v.name))
            elif not v.anti_affinity or cands:
                errors.append(_err("insufficient_capacity",
                                   f"no node can host {v.name} ({v.cores} vCPU, {v.memory_mb} MB RAM, {need_disk} GB disk)"
                                   + (": " + "; ".join(short) if short else ""), vm=v.name,
                                   needs={"cores": v.cores, "memory_mb": v.memory_mb, "disk_gb": need_disk}))
            continue
        _, k, st = best
        v.node = k
        free_mem[k] -= v.memory_mb
        free_cpu[k] -= v.cores
        node_load[k] += 1
        placed_groups.setdefault(v.group, set()).add(k)
        if st:
            free_sto[st] -= need_disk
            for d in v.disks:
                d["storage"] = caps[st].name
        else:
            for d in v.disks:
                free_sto[key_of(d["storage"], k)] -= d["size_gb"]
    # remaining capacity (after plan)
    out_nodes = [{"name": k, "memory_free_mb": free_mem[k], "vcpu_free": free_cpu[k], "vms_placed": node_load[k]} for k in sorted(usable)]
    out_sto = [{"name": s, "avail_after_gb": free_sto[s]} for s in sorted(free_sto)]
    for k in sorted(caps):
        c = caps[k]
        if c.thin and c.total_gb > 0:
            used_new = (cap_start[k] - free_sto[k]) if k in cap_start else 0
            prov = (c.provisioned_gb if c.provisioned_gb is not None else c.total_gb - c.avail_gb) + used_new
            ratio_pct = prov * 100 // c.total_gb
            if c.provisioned_gb is None:
                warnings.append(_err("thin_provisioned_unknown", f"storage {k} is thin-provisioned and its provisioned size is unknown; only physical free space is used"))
            if used_new and ratio_pct > pl.thin_max_ratio_pct:
                errors.append(_err("thin_overcommit", f"storage {k} would be provisioned at {ratio_pct}% of physical capacity (policy maximum {pl.thin_max_ratio_pct}%)",
                                   storage=k, ratio_pct=ratio_pct))
            elif used_new and ratio_pct > 100:
                warnings.append(_err("thin_overcommit_warning", f"storage {k} is over-committed ({ratio_pct}% provisioned vs physical) and this plan adds to it"))
    if inp.storage is not None and inp.storage not in {c.name for c in caps.values()}:
        errors.append(_err("unknown_storage", f"storage {inp.storage!r} is not in the inventory"))
    for n in out_nodes:
        if n["memory_free_mb"] < 0 or n["vcpu_free"] < 0:
            errors.append(_err("overcommitted", f"node {n['name']} would be over-committed"))
    return {"nodes": out_nodes, "storage": out_sto}


# ---- derived sections ---------------------------------------------------------------------------------------

def _scope_match(a: str | None, b: str | None) -> bool:
    return a is None or b is None or a == b


def _derive(vms: list[_Vm], inp: PlanInput, prof: Profile, cat: Catalog, warnings: list[dict]) -> dict:
    every = [c for c in cat.components.values() if c.placement == "every_vm"]
    containers, services, firewall, dns, backups, checks = [], [], [], [], [], []
    edge_vms = [v for v in vms if "edge" in v.components]
    retention = inp.backup_retention_days or prof.backup.retention_days
    fw: set[tuple] = set()
    for v in vms:
        dom = inp.domain if v.tenant is None else f"{v.tenant}.{inp.domain}"
        for cname in [*v.components, *(c.name for c in every)]:
            c = cat.components[cname]
            for a in c.artifacts:
                if a.kind == "oci":
                    containers.append({"name": f"{v.name}-{a.name}", "vm": v.name, "component": c.name, "image": a.image, "digest": a.digest,
                                       "version": a.version, "pinned": a.pinned, "runtime": "podman-rootless-quadlet",
                                       "ports": [p.port for p in c.ports], "volumes": [x.path for x in c.volumes]})
                else:
                    services.append({"name": f"{v.name}-{a.name}", "vm": v.name, "component": c.name, "package": a.package,
                                     "version": a.version, "repo": a.repo})
            for p in c.ports:
                if p.exposure == "public":
                    fw.add((v.name, p.port, p.proto, "any", f"{c.name}:{p.name}"))
                elif p.exposure == "ics":
                    fw.add((v.name, p.port, p.proto, "ics-control", f"{c.name}:{p.name}"))
                elif p.exposure == "edge":
                    for e in edge_vms:
                        if e.name != v.name and _scope_match(e.tenant, v.tenant):
                            fw.add((v.name, p.port, p.proto, e.name, f"{c.name}:{p.name}"))
                elif p.exposure == "internal":
                    for o in vms:
                        if o.name != v.name and _scope_match(o.tenant, v.tenant) and any(c.name in cat.components[x].depends_on for x in o.components):
                            fw.add((v.name, p.port, p.proto, o.name, f"{c.name}:{p.name}"))
            if c.placement == "normal":
                for r in c.dns:
                    tgt_vm = v
                    if r.target == "edge" and edge_vms:
                        tgt_vm = next((e for e in edge_vms if _scope_match(e.tenant, v.tenant)), edge_vms[0])
                    host = dom if r.host == "@" else f"{r.host}.{dom}"
                    if r.type == "A":
                        dns.append({"name": host, "type": "A", "value": f"vm:{tgt_vm.name}", "component": c.name})
                    elif r.type == "CNAME":
                        dns.append({"name": host, "type": "CNAME", "value": f"{r.target}.{dom}", "component": c.name})
                    elif r.type == "MX":
                        pri, _, h = r.target.partition(" ")
                        dns.append({"name": host, "type": "MX", "value": f"{pri} {h}.{dom}", "component": c.name})
                    else:
                        dns.append({"name": host, "type": "TXT", "value": r.target, "component": c.name})
            fq = next((r for r in c.dns if r.type == "A"), None)
            fqdn = (dom if fq and fq.host == "@" else f"{fq.host}.{dom}") if fq else None
            for h in c.health_checks:
                checks.append({"name": f"{v.name}-{c.name}-{h.name}", "component": c.name, "vm": v.name, "kind": h.kind,
                               "host": fqdn or f"vm:{v.name}", "port": h.port, "path": h.path, "expect_status": h.expect_status,
                               "interval_seconds": h.interval_seconds})
            vols = [x for x in c.volumes if x.backup]
            if c.backup.method != "stateless" and vols:
                backups.append({"vm": v.name, "component": c.name, "method": c.backup.method, "quiesce": c.backup.quiesce,
                                "volumes": [x.path for x in vols], "schedule": prof.backup.schedule, "retention_days": retention,
                                "offsite": prof.backup.offsite, "rpo_hours": c.backup.rpo_hours, "evidence": c.backup.evidence})
                if c.backup.evidence.startswith("planned"):
                    warnings.append(_err("backup_not_drilled", f"{c.name}: backup/restore has not been drilled ({c.backup.evidence})"))
    for r in sorted(fw):
        firewall.append({"vm": r[0], "port": r[1], "proto": r[2], "from": r[3], "purpose": r[4]})
    seen = set()
    dns_u = []
    for r in sorted(dns, key=lambda r: (r["name"], r["type"], r["value"])):
        k = (r["name"], r["type"], r["value"])
        if k not in seen:
            seen.add(k)
            dns_u.append(r)
    return {"containers": sorted(containers, key=lambda x: x["name"]), "services": sorted(services, key=lambda x: x["name"]),
            "firewall": firewall, "dns": dns_u, "backups": sorted(backups, key=lambda x: (x["vm"], x["component"])),
            "checks": sorted(checks, key=lambda x: x["name"])}


# ---- steps (DAG) --------------------------------------------------------------------------------------------

EST = {"vm.clone": 120, "vm.configure": 20, "vm.start": 60, "agent.enroll": 120, "comp.install": 180, "checks.register": 5, "health.verify": 30}


def _step(key: str, kind: str, target: str, op: str, params: dict, deps: list[str], **extra) -> dict:
    return {"key": key, "kind": kind, "target": target, "op": op, "params": params, "depends_on": sorted(set(deps)),
            "disruptive": extra.get("disruptive", False), "downtime_seconds": extra.get("downtime_seconds", 0), "est_seconds": extra.get("est_seconds", EST.get(key.split(":")[0], 30))}


def _install_params(c: Component) -> list[dict]:
    out = []
    for a in c.artifacts:
        if a.kind == "oci":
            out.append({"runbook": "podman.pull_verified", "params": {"image": a.image, "digest": a.digest}})
            out.append({"runbook": "podman.deploy_unit", "params": {"name": a.name, "image": a.image, "digest": a.digest,
                                                                    "ports": [p.port for p in c.ports]}})
        else:
            out.append({"runbook": "pkg.install_pinned", "params": {"package": a.package, "version": a.version, "repo": a.repo}})
    return out


def order_steps(steps: list[dict]) -> list[dict]:
    """Deterministic Kahn ordering (ties broken by key). Raises ValueError on unknown deps or cycles."""
    by = {s["key"]: s for s in steps}
    if len(by) != len(steps):
        raise ValueError("duplicate step keys")
    indeg = {k: 0 for k in by}
    rev: dict[str, list[str]] = {k: [] for k in by}
    for s in steps:
        for d in s["depends_on"]:
            if d not in by:
                raise ValueError(f"step {s['key']} depends on unknown step {d}")
            indeg[s["key"]] += 1
            rev[d].append(s["key"])
    ready = sorted(k for k, n in indeg.items() if n == 0)
    out = []
    while ready:
        k = ready.pop(0)
        out.append(by[k])
        for m in rev[k]:
            indeg[m] -= 1
            if indeg[m] == 0:
                ready.append(m)
        ready.sort()
    if len(out) != len(steps):
        raise ValueError("dependency cycle in steps")
    return [{**s, "seq": i} for i, s in enumerate(out)]


def create_steps(vms: list[dict], inp: PlanInput, cat: Catalog, extra_nic: bool = True) -> list[dict]:
    osimg = cat.os_image(inp.os_image)
    tmpl = osimg.template if osimg else ""
    steps: list[dict] = []
    inst: dict[str, list[tuple[str, str | None]]] = {}  # component -> [(vm name, tenant)]
    for v in vms:
        for c in v["components"]:
            inst.setdefault(c, []).append((v["name"], v["tenant"]))
    for v in vms:
        n = v["name"]
        steps.append(_step(f"vm.clone:{n}", "provider_task", n, "clone_vm",
                           {"name": n, "template": tmpl, "node": v["node"], "pool": inp.pool,
                            "storage": v["disks"][0].get("storage"), "tags": v["tags"]}, []))
        steps.append(_step(f"vm.configure:{n}", "provider_task", n, "configure_vm",
                           {"cores": v["cores"], "memory_mb": v["memory_mb"], "disks": v["disks"], "nics": v["nics"],
                            "cloud_init": {"hostname": v["hostname"], "agent_enrollment": True, "rootless_podman": True}},
                           [f"vm.clone:{n}"]))
        steps.append(_step(f"vm.start:{n}", "provider_task", n, "power", {"op": "start"}, [f"vm.configure:{n}"]))
        steps.append(_step(f"agent.enroll:{n}", "wait_agent_enrollment", n, "enroll", {"timeout_seconds": 600}, [f"vm.start:{n}"]))
    for v in vms:
        n = v["name"]
        for cname in v["components"]:
            c = cat.components[cname]
            deps = [f"agent.enroll:{n}"]
            for d in (*c.depends_on, *c.after):
                for (vn, vt) in inst.get(d, []):
                    if _scope_match(vt, v["tenant"]):
                        deps.append(f"health.verify:{vn}:{d}")
            steps.append(_step(f"comp.install:{n}:{cname}", "agent_runbook", n, "install", {"component": cname, "runbooks": _install_params(c)}, deps))
            steps.append(_step(f"checks.register:{n}:{cname}", "register_checks", n, "register", {"component": cname},
                               [f"comp.install:{n}:{cname}"]))
            steps.append(_step(f"health.verify:{n}:{cname}", "verify_health", n, "verify", {"component": cname, "timeout_seconds": 300},
                               [f"checks.register:{n}:{cname}"]))
    return steps


# ---- main ---------------------------------------------------------------------------------------------------

def generate_plan(inp: PlanInput, cap: Capacity, cat: Catalog | None = None, existing: dict[str, ExistingVm] | None = None) -> dict:
    cat = cat or get_catalog()
    existing = existing or {}
    errors: list[dict] = []
    warnings: list[dict] = []
    prof = cat.profiles.get(inp.profile)
    base = {"plan_version": PLAN_VERSION, "catalog": {"version": cat.version, "digest": cat.digest},
            "input": inp.model_dump(mode="json")}
    if prof is None:
        errors.append(_err("unknown_profile", f"profile {inp.profile!r} is not in the catalog", available=sorted(cat.profiles)))
        plan = {**base, "profile": None, "vms": [], "containers": [], "services": [], "firewall": [], "dns": [], "backups": [],
                "checks": [], "steps": [], "consumption": {"vms": 0, "cores": 0, "memory_mb": 0, "disk_gb": 0, "est_seconds": 0},
                "capacity": {"nodes": [], "storage": []}, "warnings": warnings, "errors": errors, "executable": False}
        plan["plan_hash"] = plan_hash(plan)
        return plan
    if inp.users > prof.max_users:
        errors.append(_err("users_exceed_profile", f"{inp.users} users exceed profile {prof.name!r} (max {prof.max_users}); pick a larger profile",
                           max_users=prof.max_users))
    elif inp.users * 10 > prof.max_users * 9:
        warnings.append(_err("near_profile_limit", f"{inp.users} users is within 10% of the {prof.name!r} limit ({prof.max_users})"))
    osimg = cat.os_image(inp.os_image)
    if osimg is None:
        errors.append(_err("unknown_os_image", f"os image {inp.os_image!r} is not in the catalog"))
    elif not osimg.sha256:
        warnings.append(_err("os_image_unpinned", f"OS template {osimg.template!r} has no pinned checksum in the catalog"))
    if cap.bridges is not None and inp.bridge not in cap.bridges:
        errors.append(_err("unknown_bridge", f"bridge {inp.bridge!r} is not in the inventory"))
    if not cap.nodes:
        errors.append(_err("no_inventory", "no node inventory is available for the endpoint; run inventory.refresh first"))
    if inp.vlan is None:
        warnings.append(_err("no_vlan_isolation", "no VLAN is set: guests share the untagged bridge network, so tenants/deployments are NOT network-isolated "
                                                  "from other guests on that bridge (firewall rules in the plan still apply inside the VMs)"))
    if osimg is not None and osimg.id != "ubuntu-24.04":
        warnings.append(_err("os_image_unvalidated", f"component packages were validated on Ubuntu 24.04 (noble); {osimg.id} is not validated"))
    if prof.maturity == "experimental":
        warnings.append(_err("profile_experimental", f"profile {prof.name!r} is experimental: layout is generated but has not been validated on a lab or customer run"))
    if prof.ha:
        warnings.append(_err("ha_replication_unvalidated", "HA replicas are placed on distinct nodes, but application-level replication of "
                                                          "LDAP/PostgreSQL/MariaDB/OpenCloud storage is not implemented or validated yet"))
    vms, present = _expand(inp, prof, cat, errors)
    for cn in sorted(present):
        for a in cat.components[cn].artifacts:
            if not a.pinned:
                errors.append(_err("artifact_unpinned", f"{cn}/{a.name}: OCI digest is the unpinned placeholder 'sha256:'; the artifact must be built/pinned before this plan can execute",
                                   component=cn, artifact=a.name))
    assumed = sorted({f"{cn}.{k}" for cn in present for k in ("cores", "memory_mb", "disk_gb")
                      if "assum" in getattr(cat.components[cn].resources, k).source.lower()}
                     | {f"{cn}.volume.{x.name}" for cn in present for x in cat.components[cn].volumes if "assum" in x.size_gb.source.lower()})
    if assumed:
        warnings.append(_err("sizing_assumptions", "some sizing inputs are planning assumptions, not lab measurements: " + ", ".join(assumed), items=assumed))
    _size(vms, cat)
    capacity = _place(vms, inp, prof, cat, cap, existing, errors, warnings)
    derived = _derive(vms, inp, prof, cat, warnings)
    vm_out = []
    tags_base = ["ou-managed", f"ou-deployment-{inp.deployment_id}", f"ou-customer-{inp.customer_id}"]
    for v in sorted(vms, key=lambda x: x.name):
        vm_out.append({
            "name": v.name, "logical": v.logical, "tenant": v.tenant, "replica": v.replica, "group": v.group,
            "components": v.components + sorted(c.name for c in cat.components.values() if c.placement == "every_vm"),
            "os_image": {"id": osimg.id, "template": osimg.template, "sha256": osimg.sha256} if osimg else None,
            "cores": v.cores, "memory_mb": v.memory_mb,
            "disks": [{"name": d["name"], "size_gb": d["size_gb"], "storage": d.get("storage"), "purpose": d["purpose"]} for d in v.disks],
            "nics": [{"bridge": inp.bridge, "vlan": inp.vlan}], "node": v.node, "anti_affinity": v.anti_affinity, "users": v.users,
            "hostname": v.name, "tags": tags_base, "stateful": any(d["name"] != "root" for d in v.disks)})
    try:
        steps = order_steps(create_steps(vm_out, inp, cat))
    except ValueError as e:  # pragma: no cover - catalog validation prevents it
        errors.append(_err("dag_invalid", str(e)))
        steps = []
    total_disk = sum(d["size_gb"] for v in vm_out for d in v["disks"])
    plan = {**base, "profile": {"name": prof.name, "version": prof.version, "maturity": prof.maturity},
            "vms": vm_out, **derived, "steps": steps,
            "consumption": {"vms": len(vm_out), "cores": sum(v["cores"] for v in vm_out), "memory_mb": sum(v["memory_mb"] for v in vm_out),
                            "disk_gb": total_disk, "est_seconds": sum(s["est_seconds"] for s in steps)},
            "capacity": capacity, "warnings": sorted(warnings, key=canon), "errors": sorted(errors, key=canon)}
    plan["executable"] = not plan["errors"]
    plan["plan_hash"] = plan_hash(plan)
    return plan


# ---- capacity from a stored inventory snapshot --------------------------------------------------------------

def capacity_from_inventory(data: dict, deployment_id: str | None = None) -> Capacity:
    """Normalise a Proxmox inventory snapshot (proxmox.ProxmoxReadClient.inventory) into Capacity. Defensive: bad rows are skipped.
    ALL guests count as used (allocated); a deployment's own VMs are credited back via `existing` when planning a change."""
    nodes: list[NodeCap] = []
    storages: dict[str, StorageCap] = {}
    bridges: set[str] | None = None
    tag = f"ou-deployment-{deployment_id}" if deployment_id else None
    for n in data.get("nodes", []):
        info = n.get("info", {}) if isinstance(n.get("info"), dict) else {}
        name = n.get("node")
        if not isinstance(name, str):
            continue
        guests = [g for g in [*n.get("qemu", []), *n.get("lxc", [])] if isinstance(g, dict)]
        mine = [g for g in guests if tag and tag in re.split(r"[;,]", str(g.get("tags", "")))]
        nodes.append(NodeCap(name=name, cores=int(info.get("maxcpu", 0) or 0), memory_mb=int(info.get("maxmem", 0) or 0) // 1048576,
                             used_memory_mb=sum(int(g.get("maxmem", 0) or 0) for g in guests) // 1048576,
                             used_vcpus=sum(int(g.get("cpus", g.get("maxcpu", 0)) or 0) for g in guests),
                             online=n.get("status") == "online" and "error" not in n, foreign_guests=len(guests) - len(mine)))
        for s in n.get("storage", []):
            if not isinstance(s, dict) or "images" not in str(s.get("content", "")) or not s.get("active", 1):
                continue
            nm = s.get("storage")
            if not isinstance(nm, str):
                continue
            avail = int(s.get("avail", 0) or 0) // (1024 ** 3)
            total = int(s.get("total", 0) or 0) // (1024 ** 3)
            thin = "thin" in str(s.get("type", ""))
            prov = s.get("provisioned")
            prov = int(prov) // (1024 ** 3) if isinstance(prov, (int, float)) else None
            if s.get("shared"):
                cur = storages.get(nm)
                storages[nm] = StorageCap(nm, avail if cur is None else min(cur.avail_gb, avail), [], total, thin, prov)
            else:
                storages[f"{nm}@{name}"] = StorageCap(nm, avail, [name], total, thin, prov)
        for b in n.get("network", []):
            if isinstance(b, dict) and b.get("type") in ("bridge", "OVSBridge") and isinstance(b.get("iface"), str):
                bridges = (bridges or set()) | {b["iface"]}
    # node-local storage with the same name on several nodes: keep distinct entries, addressed by name only when unique
    out = sorted(storages.values(), key=lambda s: (s.name, s.nodes))
    return Capacity(sorted(nodes, key=lambda x: x.name), out, sorted(bridges) if bridges is not None else None)
