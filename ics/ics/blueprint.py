"""Deployment blueprint schema + dry-run planner. Nothing here executes anything."""
import graphlib

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

_ID = r"^[a-z0-9][a-z0-9-]{1,40}$"
_SEMVER = r"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$"


class VMSize(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cores: int = Field(ge=1, le=64)
    memory_mb: int = Field(ge=512, le=524288)
    disk_gb: int = Field(ge=4, le=8192)


class Component(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=_ID)
    version: str = Field(pattern=_SEMVER, description="pinned x.y.z; 'latest' and ranges are rejected")
    vm: VMSize
    depends_on: list[str] = []


class Target(BaseModel):
    model_config = ConfigDict(extra="forbid")
    endpoint: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,62}$")
    pool: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


class Blueprint(BaseModel):
    model_config = ConfigDict(extra="forbid")
    deployment_id: str = Field(pattern=_ID)
    customer_id: str = Field(pattern=_ID)
    target: Target
    components: list[Component] = Field(min_length=1, max_length=50)

    @model_validator(mode="after")
    def _graph(self):
        names = [c.name for c in self.components]
        if len(set(names)) != len(names):
            raise ValueError("component names must be unique")
        for c in self.components:
            for d in c.depends_on:
                if d not in names:
                    raise ValueError(f"component {c.name!r} depends on unknown component {d!r}")
        try:
            tuple(graphlib.TopologicalSorter({c.name: set(c.depends_on) for c in self.components}).static_order())
        except graphlib.CycleError:
            raise ValueError("dependency cycle between components") from None
        return self


def preview(blueprint_yaml: str, known_endpoints: set[str]) -> dict:
    errors: list[dict] = []
    try:
        raw = yaml.safe_load(blueprint_yaml)
        if not isinstance(raw, dict):
            raise ValueError("blueprint must be a YAML mapping")
        bp = Blueprint.model_validate(raw)
    except yaml.YAMLError as e:
        return {"valid": False, "errors": [{"loc": [], "msg": f"invalid YAML: {e}".splitlines()[0]}]}
    except ValidationError as e:
        return {"valid": False, "errors": [{"loc": list(x["loc"]), "msg": x["msg"]} for x in e.errors()]}
    except ValueError as e:
        return {"valid": False, "errors": [{"loc": [], "msg": str(e)}]}
    if bp.target.endpoint not in known_endpoints:
        return {"valid": False, "errors": [{"loc": ["target", "endpoint"], "msg": "endpoint is not registered"}]}
    by = {c.name: c for c in bp.components}
    order = graphlib.TopologicalSorter({c.name: set(c.depends_on) for c in bp.components}).static_order()
    steps = []
    for i, n in enumerate(order, 1):
        c = by[n]
        steps.append({"order": i, "operation": "create_qemu_vm", "component": n, "version": c.version,
                      "vm_name": f"{bp.customer_id}-{bp.deployment_id}-{n}", "pool": bp.target.pool,
                      "size": c.vm.model_dump(), "after": c.depends_on})
    return {"valid": True, "errors": [], "dry_run": True, "plan": {
        "deployment_id": bp.deployment_id, "customer_id": bp.customer_id, "endpoint": bp.target.endpoint,
        "steps": steps,
        "totals": {"vms": len(steps), "cores": sum(c.vm.cores for c in bp.components),
                   "memory_mb": sum(c.vm.memory_mb for c in bp.components), "disk_gb": sum(c.vm.disk_gb for c in bp.components)}}}
