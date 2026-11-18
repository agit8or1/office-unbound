"""Sizing model (pure, deterministic): workload -> drivers -> per-component resources from the catalog `sizing` models.

Used by plan.py (`PlanInput.sizing`) so the plan that is hashed, approved and executed carries exactly the numbers the sizing
engine (sizer.py) displayed. Exact decimal arithmetic; results are integers (ceil). Estimates get the component's safety margin.
"""
from decimal import ROUND_CEILING, Decimal
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .catalog import Catalog, Component, ResourceModel

D0 = Decimal(0)


class _M(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Workload(_M):
    """Per-tenant workload (single-tenant: the whole organisation). Ratios are editable defaults; all are ESTIMATES unless the operator knows better."""
    concurrent_users: int | None = Field(default=None, ge=0, le=100000, description="simultaneously active users; default = users * concurrent_pct/100")
    concurrent_pct: int = Field(default=30, ge=1, le=100)
    mailbox_gb_per_user: float = Field(default=2, ge=0, le=1000)
    file_gb_per_user: float = Field(default=5, ge=0, le=10000)
    growth_pct: int = Field(default=0, ge=0, le=500, description="applied to every user-driven driver (sizing target = today x (1 + growth))")
    office_editor_pct: int = Field(default=20, ge=0, le=100, description="% of concurrent users with a document open in the office engine")
    meeting_participant_pct: int = Field(default=20, ge=0, le=100, description="% of concurrent users in a video meeting at peak")
    concurrent_call_pct: int = Field(default=10, ge=0, le=100, description="% of concurrent users on a phone call at peak")


class VmOverride(_M):
    """Operator adjustment of one VM (by full VM name or logical layout name). Values replace the computed ones."""
    cores: int | None = Field(default=None, ge=1, le=256)
    memory_mb: int | None = Field(default=None, ge=256, le=1048576)
    disks: dict[str, int] = Field(default_factory=dict, description="disk name -> size GB (root or <component>-<volume>)")


class SizingSpec(_M):
    """`PlanInput.sizing`: present = sizing-engine plan. `workload` None keeps the legacy per-user formulas (only overrides apply)."""
    workload: Workload | None = None
    tier: Literal["minimum", "recommended"] = Field(default="recommended", description="per-component floor: minimum (evaluation) or recommended (production)")
    estimate_margin_pct: int | None = Field(default=None, ge=0, le=200, description="overrides every component's safety margin on estimates")
    tenancy: Literal["single", "multi"] = Field(default="single", description="multi = per-tenant VMs (custom profile only)")
    dedicated_nodes: bool = Field(default=False, description="refuse nodes that host guests outside this deployment")
    vm_overrides: dict[str, VmOverride] = Field(default_factory=dict, max_length=60)


def drivers(users: int, base_users: int, w: Workload) -> dict[str, Decimal]:
    """Workload drivers for a VM serving `users` (base_users = per-tenant users; shared VMs of a multi-tenant layout serve more)."""
    g = Decimal(100 + w.growth_pct) / 100
    total = Decimal(users) * g
    conc0 = Decimal(w.concurrent_users) * Decimal(users) / Decimal(max(base_users, 1)) if w.concurrent_users is not None \
        else Decimal(users) * w.concurrent_pct / 100
    conc = min(conc0 * g, total)
    return {"total_user": total, "concurrent_user": conc, "office_editor": conc * w.office_editor_pct / 100,
            "meeting_participant": conc * w.meeting_participant_pct / 100, "concurrent_call": conc * w.concurrent_call_pct / 100,
            "mailbox_gb": total * Decimal(str(w.mailbox_gb_per_user)), "file_gb": total * Decimal(str(w.file_gb_per_user))}


def ceil(v: Decimal) -> int:
    return int(v.to_integral_value(rounding=ROUND_CEILING))


def model_value(m: ResourceModel, d: dict[str, Decimal], margin_pct: int) -> tuple[int, bool]:
    """(value, has_estimate). Measured parts count as-is; estimate parts x (1 + margin)."""
    meas, est = D0, D0
    if m.base_evidence == "measured":
        meas += Decimal(str(m.base))
    else:
        est += Decimal(str(m.base))
    for f in m.factors:
        part = Decimal(str(f.value)) * d[f.per]
        if f.evidence == "measured":
            meas += part
        else:
            est += part
    total = meas + est * (100 + margin_pct) / 100
    return ceil(total), est > 0


def margin_of(c: Component, spec: SizingSpec) -> int:
    return spec.estimate_margin_pct if spec.estimate_margin_pct is not None else (c.sizing.safety_margin_pct if c.sizing else 0)


def component_size(c: Component, d: dict[str, Decimal], spec: SizingSpec, users: int) -> dict:
    """{cores, memory_mb, disk_gb, volumes{name: gb}, estimated[list of fields], floor: tier}. Falls back to the legacy formula if a
    component has no sizing model (third-party catalogs)."""
    if c.sizing is None:
        return {"cores": c.resources.cores.at(users), "memory_mb": c.resources.memory_mb.at(users), "disk_gb": c.resources.disk_gb.at(users),
                "volumes": {v.name: max(1, v.size_gb.at(users)) for v in c.volumes}, "estimated": ["legacy_formula"], "floor_applied": []}
    s, mg = c.sizing, margin_of(c, spec)
    floor = s.minimum if spec.tier == "minimum" else s.recommended
    out: dict = {"volumes": {}, "estimated": [], "floor_applied": []}
    for k in ("cores", "memory_mb", "disk_gb"):
        v, est = model_value(getattr(s, k), d, mg)
        if est:
            out["estimated"].append(k)
        fl = getattr(floor, k)
        if fl > v:
            out["floor_applied"].append(k)
        out[k] = max(v, fl)
    for vm in s.volumes:
        v, est = model_value(vm, d, mg)
        out["volumes"][vm.volume] = max(1, v)
        if est:
            out["estimated"].append(f"volume.{vm.volume}")
    return out


def services_to_components(cat: Catalog, services: list[str]) -> tuple[set[str], list[str]]:
    """Selected wizard services -> component set (core components + providers + depends_on closure). Returns (components, unknown)."""
    providers: dict[str, list[str]] = {}
    for c in cat.components.values():
        for sv in (c.sizing.services if c.sizing else []):
            providers.setdefault(sv, []).append(c.name)
    unknown = sorted(s for s in services if s not in providers)
    want = {c.name for c in cat.components.values() if c.sizing and c.sizing.core and c.placement != "every_vm"}
    for s in services:
        want |= set(providers.get(s, []))
    stack = list(want)
    while stack:
        for dep in cat.components[stack.pop()].depends_on:
            if dep not in want:
                want.add(dep)
                stack.append(dep)
    return want, unknown


def service_catalog(cat: Catalog) -> list[dict]:
    out: dict[str, list[str]] = {}
    for c in cat.components.values():
        for sv in (c.sizing.services if c.sizing else []):
            out.setdefault(sv, []).append(c.name)
    return [{"id": k, "components": sorted(v)} for k, v in sorted(out.items())]
