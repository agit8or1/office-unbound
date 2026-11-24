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
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .netmodel import NetworkModel, resolve as resolve_network
from ..artifacts import REPO_SUITE, SENTINEL_REGISTRY, ArtifactMap, placeholder_images
from .catalog import Catalog, Component, Profile, VmLayout, get_catalog
from . import brand
from .sizing import SizingSpec, ceil as _dceil, component_size, drivers

PLAN_VERSION = 1
SLUG = r"^[a-z0-9][a-z0-9-]{1,30}$"
FQDN = r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$"


class _M(BaseModel):
    model_config = ConfigDict(extra="forbid")


HOSTLABEL = r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$"


def _check_hosts(v: dict[str, str]) -> dict[str, str]:
    for k, x in v.items():
        if not re.match(HOSTLABEL, k) or not (re.match(HOSTLABEL, x) or (re.match(FQDN, x) and len(x) <= 200)):
            raise ValueError(f"host name setting {k!r} -> {x!r}: use a single label (e.g. 'files') or a full name (e.g. 'files.example.com')")
    return v


class TenantNames(_M):
    """One tenant's names. `domain`: its own domain (default <tenant>.<deployment domain>); `hosts`: overrides for this tenant only."""
    domain: str | None = Field(default=None, pattern=FQDN, max_length=200)
    hosts: dict[str, str] = Field(default_factory=dict, max_length=30)

    @field_validator("hosts")
    @classmethod
    def _h(cls, v):
        return _check_hosts(v)


class NameSettings(_M):
    """Host names of the deployment (owner 2026-11-20: "single tenant or multi tenant but we need to make settings for fqdn").
    `hosts` maps a catalog host label (portal, auth, cloud, office, mail, autodiscover, ...) to another label under the (tenant) domain or to a
    full name; `tenants` (multi-tenant: t01, t02, ...) sets a tenant's own domain and per-tenant overrides. Unset = the catalog defaults."""
    hosts: dict[str, str] = Field(default_factory=dict, max_length=30)
    tenants: dict[str, TenantNames] = Field(default_factory=dict, max_length=50)

    @field_validator("hosts")
    @classmethod
    def _h(cls, v):
        return _check_hosts(v)


def scope_domain(inp: "PlanInput", tenant: str | None) -> str:
    t = inp.names.tenants.get(tenant) if (inp.names is not None and tenant is not None) else None
    if t is not None and t.domain:
        return t.domain
    return inp.domain if tenant is None else f"{tenant}.{inp.domain}"


def host_fqdn(inp: "PlanInput", tenant: str | None, label: str) -> str:
    """The full name of catalog host `label` ('@' = the domain itself) in the scope of `tenant` (None = the deployment)."""
    dom = scope_domain(inp, tenant)
    if label == "@":
        return dom
    ov: dict[str, str] = {}
    if inp.names is not None:
        ov.update(inp.names.hosts)
        t = inp.names.tenants.get(tenant) if tenant is not None else None
        if t is not None:
            ov.update(t.hosts)
    v = ov.get(label, label)
    return v if "." in v else f"{v}.{dom}"


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
    enabled_ports: list[str] = Field(default_factory=list, max_length=20, description="opt-in ports that are closed by default, as 'component:port-name' (e.g. chat:federation)")
    custom_layout: list[VmLayout] | None = Field(default=None, max_length=30)
    backup_retention_days: int | None = Field(default=None, ge=1, le=3650)
    sizing: SizingSpec | None = Field(default=None, description="sizing-engine parameters (POST /deployments/size output); None = legacy profile formulas")
    names: NameSettings | None = Field(default=None, description="host names and tenant domains; None = catalog defaults under `domain`")
    vm_names: Literal["role", "legacy"] | None = Field(default=None, description="VM naming: 'role' = <deployment>[-<tenant>]-<role> (gateway, "
                                                       "mail, files, ...); unset/'legacy' = <customer>-<deployment>-<layout> (deployments made before 0.7.2)")


def input_dump(inp: "PlanInput") -> dict:
    """The plan's `input` section. `sizing` is omitted when unset so legacy plans keep their exact hash."""
    d = inp.model_dump(mode="json")
    if d.get("sizing") is None:
        d.pop("sizing", None)
    if d.get("names") is None:
        d.pop("names", None)
    if d.get("vm_names") is None:
        d.pop("vm_names", None)
    return d


def tenancy_of(inp: "PlanInput", prof: Profile) -> str:
    """Effective tenancy: the profile's, except that the custom profile may be made multi-tenant by the sizing engine."""
    if prof.custom and inp.sizing is not None and inp.sizing.tenancy == "multi":
        return "multi"
    return prof.tenancy


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
    type: str = ""                      # provider storage type (lvmthin, zfspool, rbd, nfs, dir, ...); "" = unknown

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
    if tenancy_of(inp, prof) == "multi":
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


def _port_open(cname: str, p, inp: "PlanInput") -> bool:
    return p.default_enabled or f"{cname}:{p.name}" in inp.enabled_ports


ROLES = (("edge", "gateway"), ("groupware", "mail"), ("files", "files"), ("identity", "identity"), ("meetings", "meet"), ("chat", "chat"),
         ("telephony", "phone"))
SERVICE_WORDS = {"identity": "sign-in and directory", "edge": "web entry (gateway)", "portal": "user portal", "files": "files", "office": "documents",
                 "groupware": "mail, calendar, contacts", "meetings": "video meetings", "chat": "chat", "telephony": "telephony"}


def vm_role(components: list[str]) -> str | None:
    """The one-word purpose of a VM from its components (the first match wins: a gateway that also runs identity is 'gateway')."""
    return next((role for comp, role in ROLES if comp in components), None)


def vm_description(slug: str, components: list[str], tenant: str | None = None) -> str:
    """Proxmox notes of a VM: what it is and what it runs, in plain words."""
    words = [SERVICE_WORDS[c] for c in components if c in SERVICE_WORDS]
    who = f"{slug} (customer {tenant})" if tenant else slug
    return f"Office Unbound · {who} · {vm_role(components) or 'service'} VM: " + ", ".join(words)


def _expand(inp: PlanInput, prof: Profile, cat: Catalog, errors: list[dict]) -> tuple[list[_Vm], set[str]]:
    layout = _layout(inp, prof, errors)
    enabled_opt = {o for o in prof.optional_components if inp.optional.get(o, o in prof.default_optional)}
    for o in inp.optional:
        if o not in prof.optional_components:
            errors.append(_err("unknown_optional", f"{o!r} is not an optional component of profile {prof.name!r}"))
    disabled = set(prof.optional_components) - enabled_opt
    role_names = inp.vm_names == "role"
    base = inp.deployment_id if role_names else f"{inp.customer_id}-{inp.deployment_id}"
    vms: list[_Vm] = []
    used: set[str] = set()
    tenants = _tenant_ids(inp, prof)
    for lay in layout:
        comps = [c for c in lay.components if c not in disabled]
        for c in comps:
            if c not in cat.components:
                errors.append(_err("unknown_component", f"layout {lay.name!r}: unknown component {c!r}"))
        comps = [c for c in comps if c in cat.components]
        # every_vm components (the node agent) are added to every VM by the planner itself; naming one in a layout must not add it twice
        # (that produced a self port conflict). A layout that names only every_vm components is a VM with just the agent.
        only_every = bool(comps) and all(cat.components[c].placement == "every_vm" for c in comps)
        comps = [c for c in comps if cat.components[c].placement != "every_vm"]
        comps += sorted(x.name for x in cat.components.values() if x.alongside in comps and x.name not in comps)
        if not comps and not only_every:
            continue
        for t in (tenants if lay.per_tenant else [None]):
            users = inp.users * (len(tenants) if (tenancy_of(inp, prof) == "multi" and t is None) else 1)
            for r in range(1, lay.replicas + 1):
                label = lay.name
                if role_names:   # what the VM is for, readable in Proxmox (owner 2026-11-20: "name the vm's something clear")
                    label = vm_role(comps) or lay.name
                    if "-".join(p for p in (base, t, label) if p) in used and r == 1:
                        label = f"{label}-{lay.name}"
                name = "-".join(p for p in (base, t, label, f"r{r}" if lay.replicas > 1 else None) if p)
                used.add("-".join(p for p in (base, t, label) if p))
                if len(name) > 63:
                    errors.append(_err("name_too_long", f"VM name {name!r} exceeds 63 characters; shorten customer/deployment ids"))
                vms.append(_Vm(name, lay.name, t, r, "-".join(p for p in (base, t, lay.name) if p), sorted(comps, key=comps.index),
                               lay.anti_affinity, users))
    present = {c for v in vms for c in v.components}
    every = [c for c in cat.components.values() if c.placement == "every_vm"]
    known_ports = {f"{c.name}:{p.name}" for c in cat.components.values() for p in c.ports if not p.default_enabled}
    for e in inp.enabled_ports:
        if e not in known_ports:
            errors.append(_err("unknown_enabled_port", f"{e!r} is not an opt-in port of the catalog (opt-in ports: {', '.join(sorted(known_ports)) or 'none'})"))
    for e in inp.enabled_ports:
        if e in known_ports and e.split(":")[0] not in present:
            errors.append(_err("enabled_port_component_absent", f"{e!r} was enabled but its component is not in this deployment"))
    for v in vms:
        seen: list[tuple[int, int, str, str]] = []
        for cn in [*v.components, *(c.name for c in every)]:
            for p in cat.components[cn].ports:
                if not _port_open(cn, p, inp):
                    continue
                for lo, hi, proto, other in seen:
                    if other in p.shared_with or cn in _shared(cat, other, p.port):
                        continue
                    if proto == p.proto and p.port <= hi and lo <= p.last:
                        errors.append(_err("port_conflict", f"{v.name}: {cn} and {other} both listen on {p.proto}/{p.port}"
                                                            f"{'-' + str(p.last) if p.port_end else ''}; put them on different VMs", vm=v.name))
                seen.append((p.port, p.last, p.proto, cn))
    for c in sorted(present):
        for d in cat.components[c].depends_on:
            if d not in present:
                errors.append(_err("missing_dependency", f"component {c!r} needs {d!r}, which is not in the layout (or was disabled)"))
    if inp.sizing is not None and inp.sizing.tenancy == "multi" and not prof.custom:
        errors.append(_err("sizing_tenancy_not_allowed", "sizing.tenancy 'multi' needs the custom profile"))
    if tenancy_of(inp, prof) == "single" and inp.tenants != 1:
        errors.append(_err("tenants_not_supported", f"profile {prof.name!r} is single-tenant; use msp-multi for {inp.tenants} tenants"))
    return vms, present


def vm_minimum(cat: Catalog):
    """The owner's per-VM floor (catalog meta.vm_minimum). One lookup so tests of the per-component arithmetic can switch it off."""
    return cat.meta.vm_minimum


def _size(vms: list[_Vm], cat: Catalog, inp: "PlanInput | None" = None, errors: list[dict] | None = None,
          warnings: list[dict] | None = None) -> dict:
    """Legacy: per-user formulas. With `inp.sizing.workload`: the sizing-engine models (sizing.py). Overrides apply in both modes.
    Returns the plan's `sizing` section ({} for plans without `sizing`)."""
    ov, vmin = cat.meta.vm_overhead, vm_minimum(cat)
    every = [c for c in cat.components.values() if c.placement == "every_vm"]
    spec = inp.sizing if inp is not None else None
    wl = spec.workload if spec is not None else None
    detail: dict = {}
    for v in vms:
        comps = [cat.components[c] for c in v.components] + every
        floor = None
        if wl is None:
            v.cores = max(1, ov.cores + sum(c.resources.cores.at(v.users) for c in comps))
            v.memory_mb = ov.memory_mb + sum(c.resources.memory_mb.at(v.users) for c in comps)
            root = ov.disk_gb + sum(c.resources.disk_gb.at(v.users) for c in comps)
            v.disks = [{"name": "root", "size_gb": root, "purpose": "os+software"}]
            for c in comps:
                for vol in c.volumes:
                    v.disks.append({"name": f"{c.name}-{vol.name}", "size_gb": max(1, vol.size_gb.at(v.users)), "purpose": f"volume:{vol.path}",
                                    "backup": vol.backup})
        else:
            d = drivers(v.users, inp.users, wl)
            sz = {c.name: component_size(c, d, spec, v.users) for c in comps}
            v.cores = max(1, ov.cores + sum(x["cores"] for x in sz.values()))
            v.memory_mb = ov.memory_mb + sum(x["memory_mb"] for x in sz.values())
            v.disks = [{"name": "root", "size_gb": ov.disk_gb + sum(x["disk_gb"] for x in sz.values()), "purpose": "os+software"}]
            for c in comps:
                for vol in c.volumes:
                    v.disks.append({"name": f"{c.name}-{vol.name}", "size_gb": sz[c.name]["volumes"].get(vol.name, max(1, vol.size_gb.at(v.users))),
                                    "purpose": f"volume:{vol.path}", "backup": vol.backup})
            floor = {"cores": max(1, ov.cores + sum(c.sizing.minimum.cores if c.sizing else 0 for c in comps)),
                     "memory_mb": ov.memory_mb + sum(c.sizing.minimum.memory_mb if c.sizing else 0 for c in comps)}
            detail[v.name] = {"drivers": {k: _dceil(x) for k, x in sorted(d.items())},
                              "components": {k: {"cores": x["cores"], "memory_mb": x["memory_mb"], "disk_gb": x["disk_gb"],
                                                 "volumes": dict(sorted(x["volumes"].items())), "estimated": x["estimated"],
                                                 "floor_applied": x["floor_applied"]} for k, x in sorted(sz.items())}}
        v.cores, v.memory_mb = max(v.cores, vmin.cores), max(v.memory_mb, vmin.memory_mb)
        v.disks[0]["size_gb"] = max(v.disks[0]["size_gb"], vmin.root_disk_gb)
        floor = {"cores": max((floor or {}).get("cores", 0), vmin.cores), "memory_mb": max((floor or {}).get("memory_mb", 0), vmin.memory_mb)}
        ovr = (spec.vm_overrides.get(v.name) or spec.vm_overrides.get(v.logical)) if spec is not None else None
        if ovr is None:
            continue
        computed = {"cores": v.cores, "memory_mb": v.memory_mb, "disks": {x["name"]: x["size_gb"] for x in v.disks}}
        if ovr.cores is not None:
            v.cores = ovr.cores
        if ovr.memory_mb is not None:
            v.memory_mb = ovr.memory_mb
        for dn, gb in sorted(ovr.disks.items()):
            if dn not in computed["disks"]:
                if errors is not None:
                    errors.append(_err("override_unknown_disk", f"{v.name}: override names unknown disk {dn!r}", vm=v.name))
                continue
            if gb < computed["disks"][dn]:
                if errors is not None:
                    errors.append(_err("override_below_minimum", f"{v.name}: disk {dn} override {gb} GB is below the sized {computed['disks'][dn]} GB "
                                                                 "(volumes are never under-provisioned)", vm=v.name))
                continue
            for x in v.disks:
                if x["name"] == dn:
                    x["size_gb"] = gb
        if floor is not None and errors is not None:
            for k in ("cores", "memory_mb"):
                if getattr(v, k) < floor[k]:
                    errors.append(_err("override_below_minimum", f"{v.name}: {k} override {getattr(v, k)} is below the minimum (components' documented minimum, catalog vm_minimum) "
                                                                 f"{floor[k]}", vm=v.name))
        if warnings is not None and (v.cores < computed["cores"] or v.memory_mb < computed["memory_mb"]):
            warnings.append(_err("override_below_sizing", f"{v.name}: operator override is below the sized value "
                                                          f"({computed['cores']} vCPU, {computed['memory_mb']} MB)", vm=v.name))
        if v.name in detail:
            detail[v.name]["override"] = {"computed": {"cores": computed["cores"], "memory_mb": computed["memory_mb"]},
                                          "applied": ovr.model_dump(mode="json", exclude_none=True)}
    if spec is None:
        return {}
    unused = sorted(k for k in spec.vm_overrides if k not in {v.name for v in vms} | {v.logical for v in vms})
    if unused and errors is not None:
        errors.append(_err("override_unknown_vm", "vm_overrides name VMs that are not in the layout: " + ", ".join(unused), items=unused))
    return {"model": "engine" if wl is not None else "legacy+overrides", "tier": spec.tier,
            **({"workload": wl.model_dump(mode="json")} if wl is not None else {}), "vms": detail}


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
    dedicated = prof.dedicated_nodes or (inp.sizing is not None and inp.sizing.dedicated_nodes)
    foreign_ok = {k for k, n in usable.items() if not (dedicated and n.foreign_guests > 0)}
    if dedicated:
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


def _name_errors(inp: PlanInput, cat: Catalog, vms: list, dns: list[dict], names: dict | None = None) -> list[dict]:
    """Name settings must name real hosts and tenants, and two different services can never get the same name."""
    out: list[dict] = []
    if inp.names is not None:
        labels = {r.host for c in cat.components.values() for r in c.dns if r.host != "@"}
        tids = {v.tenant for v in vms if v.tenant}
        given = [("", k) for k in inp.names.hosts] + [(t, k) for t, x in inp.names.tenants.items() for k in x.hosts]
        bad = sorted({k for _, k in given if k not in labels})
        if bad:
            out.append(_err("names_unknown_host", "host name settings for hosts the catalog does not have: " + ", ".join(bad)
                            + " (known: " + ", ".join(sorted(labels)) + ")", items=bad))
        badt = sorted(t for t in inp.names.tenants if t not in tids)
        if badt:
            out.append(_err("names_unknown_tenant", "name settings for tenants this deployment does not have: " + ", ".join(badt)
                            + (" (tenants: " + ", ".join(sorted(tids)) + ")" if tids else " (single tenant: use the deployment domain and hosts)"), items=badt))
    owner: dict[str, str] = {}
    for sc, x in sorted((names or {}).items()):
        for label, fqdn in sorted(x["hosts"].items()):
            who = f"{sc + '/' if sc else ''}{label}"
            if fqdn in owner:
                out.append(_err("names_duplicate", f"{fqdn} is set for both {owner[fqdn]} and {who}; give one of them another name", name=fqdn))
            owner.setdefault(fqdn, who)
    seen: dict[str, tuple] = {}
    for r in dns:
        if r["type"] in ("A", "CNAME"):
            k = (r["type"], r.get("component"))   # replicas of one component share a name (round robin)
            if r["name"] in seen and seen[r["name"]] != k:
                out.append(_err("names_duplicate", f"{r['name']} would point at two different services; give one of them another name", name=r["name"]))
            seen.setdefault(r["name"], k)
    return out


# ---- derived sections ---------------------------------------------------------------------------------------

def _scope_match(a: str | None, b: str | None) -> bool:
    return a is None or b is None or a == b


def _derive(vms: list[_Vm], inp: PlanInput, prof: Profile, cat: Catalog, warnings: list[dict]) -> dict:
    every = [c for c in cat.components.values() if c.placement == "every_vm"]
    containers, services, firewall, dns, backups, checks = [], [], [], [], [], []
    edge_vms = [v for v in vms if "edge" in v.components]
    retention = inp.backup_retention_days or prof.backup.retention_days
    fw: set[tuple] = set()
    names: dict[str, dict] = {}
    for v in vms:
        dom = scope_domain(inp, v.tenant)
        scope = names.setdefault(v.tenant or "", {"domain": dom, "hosts": {}})
        for cname in [*v.components, *(c.name for c in every)]:
            c = cat.components[cname]
            bx = {"brand": brand.digest()} if c.name in brand.BRAND_COMPONENTS else {}   # a skin change reconfigures these in place (state._artifacts)
            for a in c.artifacts:
                if a.kind == "oci":
                    containers.append({"name": f"{v.name}-{a.name}", "vm": v.name, "component": c.name, "image": a.image, "digest": a.digest,
                                       "version": a.version, "pinned": a.pinned, "runtime": "podman-rootless-quadlet",
                                       "ports": [p.port for p in c.ports if _port_open(c.name, p, inp)], "volumes": [x.path for x in c.volumes], **bx})
                else:
                    services.append({"name": f"{v.name}-{a.name}", "vm": v.name, "component": c.name, "package": a.package,
                                     "version": a.version, "repo": a.repo, "config_revision": c.config_revision, **bx})
            for p in c.ports:
                if not _port_open(c.name, p, inp):
                    continue
                if p.exposure == "public":
                    fw.add((v.name, p.port, p.proto, "any", f"{c.name}:{p.name}", p.port_end))
                elif p.exposure == "ics":
                    fw.add((v.name, p.port, p.proto, "ics-control", f"{c.name}:{p.name}", p.port_end))
                elif p.exposure == "edge":
                    for e in edge_vms:
                        if e.name != v.name and _scope_match(e.tenant, v.tenant):
                            fw.add((v.name, p.port, p.proto, e.name, f"{c.name}:{p.name}", p.port_end))
                elif p.exposure == "internal":
                    for o in vms:
                        if o.name != v.name and _scope_match(o.tenant, v.tenant) and any(c.name in cat.components[x].depends_on for x in o.components):
                            fw.add((v.name, p.port, p.proto, o.name, f"{c.name}:{p.name}", p.port_end))
            if c.placement == "normal":
                for r in c.dns:
                    tgt_vm = v
                    if r.target == "edge" and edge_vms:
                        tgt_vm = next((e for e in edge_vms if _scope_match(e.tenant, v.tenant)), edge_vms[0])
                    host = host_fqdn(inp, v.tenant, r.host)
                    if r.host != "@":
                        scope["hosts"][r.host] = host
                    if r.type == "A":
                        dns.append({"name": host, "type": "A", "value": f"vm:{tgt_vm.name}", "component": c.name})
                    elif r.type == "CNAME":
                        dns.append({"name": host, "type": "CNAME", "value": host_fqdn(inp, v.tenant, r.target), "component": c.name})
                    elif r.type == "MX":
                        pri, _, h = r.target.partition(" ")
                        dns.append({"name": host, "type": "MX", "value": f"{pri} {host_fqdn(inp, v.tenant, h)}", "component": c.name})
                    else:
                        dns.append({"name": host, "type": "TXT", "value": r.target, "component": c.name})
            fq = next((r for r in c.dns if r.type == "A"), None)
            fqdn = host_fqdn(inp, v.tenant, fq.host) if fq else None
            for h in c.health_checks:
                checks.append({"name": f"{v.name}-{c.name}-{h.name}", "component": c.name, "vm": v.name, "kind": h.kind,
                               "host": fqdn or f"vm:{v.name}", "port": h.port, "path": h.path, "expect_status": h.expect_status,
                               "interval_seconds": h.interval_seconds, **({"body_contains": h.body_contains} if h.body_contains else {})})
            vols = [x for x in c.volumes if x.backup]
            if c.backup.method != "stateless" and vols:
                backups.append({"vm": v.name, "component": c.name, "method": c.backup.method, "quiesce": c.backup.quiesce,
                                "volumes": [x.path for x in vols], "schedule": prof.backup.schedule, "retention_days": retention,
                                "offsite": prof.backup.offsite, "rpo_hours": c.backup.rpo_hours, "evidence": c.backup.evidence})
                if c.backup.evidence.startswith("planned"):
                    warnings.append(_err("backup_not_drilled", f"{c.name}: backup/restore has not been drilled ({c.backup.evidence})"))
    for r in sorted(fw, key=lambda r: (r[0], r[1], r[2], r[3], r[4], r[5] or 0)):
        firewall.append({"vm": r[0], "port": r[1], "proto": r[2], "from": r[3], "purpose": r[4], **({"port_end": r[5]} if r[5] else {})})
    seen = set()
    dns_u = []
    for r in sorted(dns, key=lambda r: (r["name"], r["type"], r["value"])):
        k = (r["name"], r["type"], r["value"])
        if k not in seen:
            seen.add(k)
            dns_u.append(r)
    return {"containers": sorted(containers, key=lambda x: x["name"]), "services": sorted(services, key=lambda x: x["name"]),
            "firewall": firewall, "dns": dns_u, "backups": sorted(backups, key=lambda x: (x["vm"], x["component"])),
            "checks": sorted(checks, key=lambda x: x["name"]),
            "names": {k: {"domain": x["domain"], "hosts": dict(sorted(x["hosts"].items()))} for k, x in sorted(names.items())}}


# ---- steps (DAG) --------------------------------------------------------------------------------------------

EST = {"vm.clone": 120, "vm.configure": 20, "vm.resize": 30, "vm.start": 60, "guest.await_callback": 90, "agent.enroll": 30, "comp.install": 180, "checks.register": 5, "health.verify": 30}


def _step(key: str, kind: str, target: str, op: str, params: dict, deps: list[str], **extra) -> dict:
    return {"key": key, "kind": kind, "target": target, "op": op, "params": params, "depends_on": sorted(set(deps)),
            "disruptive": extra.get("disruptive", False), "downtime_seconds": extra.get("downtime_seconds", 0), "est_seconds": extra.get("est_seconds", EST.get(key.split(":")[0], 30))}


_HOSTREF = re.compile(r"\{host:([a-z0-9-]+)\}")


def _env_value(v: str, domain: str, host=None) -> str:
    """`{domain}` -> the (tenant) domain; `{host:<label>}` -> that catalog host's full name under the name settings."""
    if host is not None:
        v = _HOSTREF.sub(lambda m: host(m.group(1)), v)
    return v.replace("{domain}", domain)


def _install_params(c: Component, domain: str = "", host=None) -> list[dict]:
    """Runbook parameters in exactly the shape the node agent's closed schemas accept (agent/ou_agent/guestspec.py): the image is one
    digest-pinned reference `<registry>/<repo>@sha256:<digest>`, ports carry an explicit bind address."""
    out = []
    for a in c.artifacts:
        if a.kind == "oci":
            ref = f"{a.image}@{a.digest}"
            out.append({"runbook": "podman.pull_verified", "params": {"image": ref}})
            params = {"component": c.name, "name": a.name, "type": "container", "image": ref,
                      "ports": [{"bind": "127.0.0.1" if p.exposure == "local" else "0.0.0.0", "host": p.port, "container": p.port, "proto": p.proto}
                                for p in c.ports if p.name != "agent"]}
            u = getattr(a, "unit", None)
            if u is not None:   # configured unit (artifacts-core): env/volumes/named secrets exactly as the agent's closed schema takes them
                params.update({"type": u.type, "env": {k: _env_value(v, domain, host) for k, v in sorted(u.env.items())},
                               "secrets": [{"name": x.name, "env": x.env} for x in u.secrets],
                               "volumes": [{"name": x.name, "path": x.path, "read_only": x.read_only} for x in u.volumes],
                               "memory_mib": u.memory_mib, "read_only": u.read_only})
                if u.user:
                    params["user"] = u.user
                if u.command:   # only when set: plans of units without a command keep their hash
                    params["command"] = list(u.command)
                if u.capabilities:   # only when set, same reason
                    params["capabilities"] = sorted(u.capabilities)
                if u.type == "container-hostnet":
                    params["ports"] = []   # host networking carries no published ports (the agent refuses both)
            out.append({"runbook": "podman.deploy_unit", "params": params})
        else:
            pkg = {"name": a.package, "version": a.version}
            if a.repo not in REPO_SUITE:
                # a distribution archive keeps only its newest build per pocket: the catalog version is a floor (the agent installs the archive's
                # current security/stable update, never an older one); our own repository stays exact (real VM e2e-fo3, 2026-11-19)
                pkg["match"] = "floor"
            out.append({"runbook": "pkg.install_pinned", "params": {"packages": [pkg]}})
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
        steps.append(_step(f"vm.tag:{n}", "provider_task", n, "finalize_clone", {}, [f"vm.clone:{n}"]))
        steps.append(_step(f"vm.configure:{n}", "provider_task", n, "configure_vm",
                           {"cores": v["cores"], "memory_mb": v["memory_mb"], "disks": v["disks"], "nics": v["nics"],
                            "cloud_init": {"hostname": v["hostname"], "agent_enrollment": True, "rootless_podman": True}},
                           [f"vm.tag:{n}"]))
        # the template's root disk keeps the template size (3 GB on the real cluster): grow it to the planned size before first boot
        # (cloud-initramfs-growroot / cloud-init growpart expand the partition and filesystem)
        steps.append(_step(f"vm.resize:{n}", "provider_task", n, "resize_disk",
                           {"disk": "root", "disk_index": 0, "new_size_gb": v["disks"][0]["size_gb"]}, [f"vm.configure:{n}"]))
        steps.append(_step(f"vm.start:{n}", "provider_task", n, "power", {"op": "start"}, [f"vm.resize:{n}"]))
        steps.append(_step(f"guest.await_callback:{n}", "wait_guest_callback", n, "await_callback", {"timeout_seconds": 600}, [f"vm.start:{n}"]))
        steps.append(_step(f"agent.enroll:{n}", "wait_agent_enrollment", n, "enroll", {"timeout_seconds": 600}, [f"guest.await_callback:{n}"]))
        # the golden image carries the agent it was built with; the catalog pin may be newer: the agent upgrades itself before anything is
        # installed (a no-op when it already runs the pin), so the VM always runs the version the plan records
        agent_pkg = next((a for c in (cat.components[x] for x in v["components"]) if c.placement == "every_vm" for a in c.artifacts
                          if a.kind == "package"), None)
        if agent_pkg is not None:
            steps.append(_step(f"agent.update:{n}", "agent_update", n, "update", {"package": agent_pkg.package, "version": agent_pkg.version,
                                                                                   "timeout_seconds": 300}, [f"agent.enroll:{n}"], est_seconds=30))
    for v in vms:
        n = v["name"]
        for cname in v["components"]:
            c = cat.components[cname]
            if c.placement == "every_vm":   # the node agent: installed by the guest bootstrap (cloud-init bundle), enrolled by agent.enroll
                continue
            # every VM of the deployment first: configuration needs the peers' addresses (name resolution, cfg.firewall peer allowances)
            deps = [f"agent.enroll:{n}"] + [f"agent.enroll:{o['name']}" for o in vms if o["name"] != n] + \
                   [k for k in (f"agent.update:{n}",) if any(x["key"] == k for x in steps)]
            for d in (*c.depends_on, *c.after):
                for (vn, vt) in inst.get(d, []):
                    if _scope_match(vt, v["tenant"]):
                        deps.append(f"health.verify:{vn}:{d}")
            steps.append(_step(f"comp.install:{n}:{cname}", "agent_runbook", n, "install", {"component": cname, "runbooks": _install_params(c, scope_domain(inp, v["tenant"]), lambda lb, t=v["tenant"]: host_fqdn(inp, t, lb))}, deps))
            steps.append(_step(f"checks.register:{n}:{cname}", "register_checks", n, "register", {"component": cname},
                               [f"comp.install:{n}:{cname}"]))
            steps.append(_step(f"health.verify:{n}:{cname}", "verify_health", n, "verify", {"component": cname, "timeout_seconds": 300},
                               [f"checks.register:{n}:{cname}"]))
    return steps


def _nic(inp: PlanInput, net: dict | None, vm: str) -> dict:
    if net is None:
        return {"bridge": inp.bridge, "vlan": inp.vlan}
    d = {"bridge": net["vnet"], "vlan": None}
    if vm in net["addresses"]:
        d.update(ip=net["addresses"][vm], gw=net["gateway"])
    return d


# ---- main ---------------------------------------------------------------------------------------------------

def _shared(cat, comp: str, port: int) -> list[str]:
    return [x for q in cat.components[comp].ports if q.port == port for x in q.shared_with]


def generate_plan(inp: PlanInput, cap: Capacity, cat: Catalog | None = None, existing: dict[str, ExistingVm] | None = None,
                  networks: "NetworkModel | None" = None, scope_networks: tuple[str, ...] | None = None,
                  artifacts: "ArtifactMap | None" = None) -> dict:
    """`artifacts`: the operator's artifact distribution map (ics.artifacts, ADR-0015). The CALLER has already pointed the catalog's OCI images at its
    registry (`artifacts.rewrite_catalog`); here it only decides the plan's `artifacts` section (inside the hash) and the unset-placeholder warning."""
    cat = cat or get_catalog()
    existing = existing or {}
    errors: list[dict] = []
    warnings: list[dict] = []
    prof = cat.profiles.get(inp.profile)
    base = {"plan_version": PLAN_VERSION, "catalog": {"version": cat.version, "digest": cat.digest},
            "input": input_dump(inp)}
    if prof is None:
        errors.append(_err("unknown_profile", f"profile {inp.profile!r} is not in the catalog", available=sorted(cat.profiles)))
        plan = {**base, "profile": None, "vms": [], "containers": [], "services": [], "firewall": [], "dns": [], "backups": [],
                "checks": [], "steps": [], "consumption": {"vms": 0, "cores": 0, "memory_mb": 0, "disk_gb": 0, "est_seconds": 0},
                "capacity": {"nodes": [], "storage": []}, "warnings": warnings, "errors": errors, "executable": False}
        plan["plan_hash"] = plan_hash(plan)
        return plan
    engine = inp.sizing is not None and inp.sizing.workload is not None
    if engine:
        pass   # the sizing engine bounds the workload by capacity and reports unvalidated workloads itself (no fixed profile limit)
    elif inp.users > prof.max_users:
        errors.append(_err("users_exceed_profile", f"{inp.users} users exceed profile {prof.name!r} (max {prof.max_users}); pick a larger profile",
                           max_users=prof.max_users))
    elif inp.users * 10 > prof.max_users * 9:
        warnings.append(_err("near_profile_limit", f"{inp.users} users is within 10% of the {prof.name!r} limit ({prof.max_users})"))
    osimg = cat.os_image(inp.os_image)
    if osimg is None:
        errors.append(_err("unknown_os_image", f"os image {inp.os_image!r} is not in the catalog"))
    elif not osimg.sha256:
        warnings.append(_err("os_image_unpinned", f"OS template {osimg.template!r} has no pinned checksum in the catalog"))
    if networks is None and cap.bridges is not None and inp.bridge not in cap.bridges:
        errors.append(_err("unknown_bridge", f"bridge {inp.bridge!r} is not in the inventory"))
    if not cap.nodes:
        errors.append(_err("no_inventory", "no node inventory is available for the endpoint; run inventory.refresh first"))
    if networks is None and inp.vlan is None:
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
    if artifacts is None:
        ph = placeholder_images(cat, present)
        if ph:
            warnings.append(_err("artifact_base_unset", "OU_ARTIFACT_BASE is not configured: these images still point at the placeholder registry "
                                 f"{SENTINEL_REGISTRY} that no guest can reach: " + ", ".join(ph), items=ph))
    for cn in sorted(present):
        for a in cat.components[cn].artifacts:
            if not a.pinned:
                errors.append(_err("artifact_unpinned", f"{cn}/{a.name}: OCI digest is the unpinned placeholder 'sha256:'; the artifact must be built, signed and pinned before this plan can execute",
                                   component=cn, artifact=a.name))
            elif getattr(a, "signed", True) is False:
                errors.append(_err("artifact_unsigned", f"{cn}/{a.name}: the OCI image is built and pinned by digest but not signed through the hardened signing path; this plan cannot execute until it is signed",
                                   component=cn, artifact=a.name))
    for cn in sorted(present):
        comp = cat.components[cn]
        for n in comp.notices:
            warnings.append(_err("component_notice", f"{cn}: {n}", component=cn))
        if prof.ha and comp.ha_note:
            warnings.append(_err("component_ha_note", f"{cn}: {comp.ha_note}", component=cn))
        if osimg is not None and comp.os_images and osimg.id not in comp.os_images:
            warnings.append(_err("component_os_unvalidated", f"{cn}: its packages were built and validated for {', '.join(comp.os_images)}, "
                                                              f"not {osimg.id}; installation on {osimg.id} is an assumption", component=cn))
    assumed = sorted({f"{cn}.{k}" for cn in present for k in ("cores", "memory_mb", "disk_gb")
                      if "assum" in getattr(cat.components[cn].resources, k).source.lower()}
                     | {f"{cn}.volume.{x.name}" for cn in present for x in cat.components[cn].volumes if "assum" in x.size_gb.source.lower()})
    if engine:
        assumed = []   # engine plans label estimates by evidence (sizing_estimates) instead of parsing source strings
    if assumed:
        warnings.append(_err("sizing_assumptions", "some sizing inputs are planning assumptions, not lab measurements: " + ", ".join(assumed), items=assumed))
    sizing_out = _size(vms, cat, inp, errors, warnings)
    if engine:
        est = sorted({f"{cn}.{k}" for d in sizing_out["vms"].values() for cn, x in d["components"].items() for k in x["estimated"]})
        if est:
            warnings.append(_err("sizing_estimates", "these sizing values are ESTIMATES (safety margin applied), not lab measurements: "
                                 + ", ".join(est), items=est))
    capacity = _place(vms, inp, prof, cat, cap, existing, errors, warnings)
    derived = _derive(vms, inp, prof, cat, warnings)
    errors.extend(_name_errors(inp, cat, vms, derived["dns"], derived["names"]))
    net = None
    if networks is not None:
        net, nerr, nwarn = resolve_network(networks, inp.customer_id, inp.endpoint, inp.bridge, scope_networks, [v.name for v in vms])
        errors.extend(nerr)
        warnings.extend(nwarn)
        if inp.vlan is not None:
            errors.append(_err("network_vlan_with_model", "`vlan` must not be set when a network model assigns the customer's VNet"))
    vm_out = []
    tags_base = ["ou-managed", f"ou-deployment-{inp.deployment_id}", f"ou-customer-{inp.customer_id}"]
    for v in sorted(vms, key=lambda x: x.name):
        vm_out.append({
            "name": v.name, "logical": v.logical, "tenant": v.tenant, "replica": v.replica, "group": v.group,
            "components": v.components + sorted(c.name for c in cat.components.values() if c.placement == "every_vm"),
            "os_image": {"id": osimg.id, "template": osimg.template, "sha256": osimg.sha256} if osimg else None,
            "cores": v.cores, "memory_mb": v.memory_mb,
            "disks": [{"name": d["name"], "size_gb": d["size_gb"], "storage": d.get("storage"), "purpose": d["purpose"]} for d in v.disks],
            "nics": [_nic(inp, net, v.name)], "node": v.node, "anti_affinity": v.anti_affinity, "users": v.users,
            "hostname": v.name, "tags": tags_base, "stateful": any(d["name"] != "root" for d in v.disks)})
    try:
        steps = order_steps(create_steps(vm_out, inp, cat))
    except ValueError as e:  # pragma: no cover - catalog validation prevents it
        errors.append(_err("dag_invalid", str(e)))
        steps = []
    total_disk = sum(d["size_gb"] for v in vm_out for d in v["disks"])
    plan = {**base, "profile": {"name": prof.name, "version": prof.version, "maturity": prof.maturity},
            "vms": vm_out, **derived, **({"sizing": sizing_out} if sizing_out else {}), **({"network": net} if net else {}),
            **({"artifacts": artifacts.describe()} if artifacts is not None else {}), "steps": steps,
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
                storages[nm] = StorageCap(nm, avail if cur is None else min(cur.avail_gb, avail), [], total, thin, prov, str(s.get("type", "")))
            else:
                storages[f"{nm}@{name}"] = StorageCap(nm, avail, [name], total, thin, prov, str(s.get("type", "")))
        for b in n.get("network", []):
            if isinstance(b, dict) and b.get("type") in ("bridge", "OVSBridge") and isinstance(b.get("iface"), str):
                bridges = (bridges or set()) | {b["iface"]}
    # node-local storage with the same name on several nodes: keep distinct entries, addressed by name only when unique
    out = sorted(storages.values(), key=lambda s: (s.name, s.nodes))
    return Capacity(sorted(nodes, key=lambda x: x.name), out, sorted(bridges) if bridges is not None else None)
