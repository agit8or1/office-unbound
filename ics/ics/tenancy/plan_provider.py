"""Interface between the customer approval workflow and the provisioning package/permission-plan generator (agent L).

Contract: `register(provider, fn)` where fn(db, rt, customer: dict, params: dict) -> PermissionPlan. The returned object must be
deterministic for the same input and contain NO secrets (it is shown to the customer, stored, hashed and audited). Until L's
generator registers itself, `stub_builder` produces a clearly marked placeholder from caller-supplied `permissions`."""
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class PermissionPlan:
    summary: str
    permissions: list[dict] = field(default_factory=list)  # [{"path": "/pool/ou-lab", "privilege": "VM.Allocate", "reason": "..."}]
    instructions_md: str = ""                               # what the customer's admin must do on their side
    stub: bool = False
    package_files: dict = field(default_factory=dict)       # real Mode B package (name -> text); offered for download on the approval link


Builder = Callable[[object, object, dict, dict], PermissionPlan]
BUILDERS: dict[str, Builder] = {}


def register(provider: str, fn: Builder) -> None:
    BUILDERS[provider] = fn


def stub_builder(db, rt, customer: dict, params: dict) -> PermissionPlan:
    perms = []
    for x in (params.get("permissions") or [])[:200]:
        if isinstance(x, dict):
            perms.append({k: str(x.get(k, ""))[:200] for k in ("path", "privilege", "reason")})
    if not perms:
        perms = [{"path": "/", "privilege": "Sys.Audit", "reason": "read-only inventory (placeholder permission plan)"}]
    lines = [f"# Provisioning instructions for {customer['name']}", "", "STUB PLAN: replace once the provisioning generator is installed.", ""]
    lines += [f"- grant `{p['privilege']}` on `{p['path']}`: {p['reason']}" for p in perms]
    return PermissionPlan(summary=str(params.get("summary") or "Provisioning request")[:500], permissions=perms,
                          instructions_md="\n".join(lines) + "\n", stub=True)


def build(db, rt, customer: dict, params: dict) -> PermissionPlan:
    fn = BUILDERS.get(str(params.get("provider") or "proxmox"), stub_builder)
    return fn(db, rt, customer, params)
