"""guest.power: start / shutdown / stop / reboot an EXISTING guest the administrator authorized individually (operations preset).

Two independent fences: Proxmox (the provision token holds VM.PowerMgmt only on /vms/<vmid> of the selected guests) and the ICS
(EndpointScope.managed, protected guests, the ICS's own VM, templates; ProxmoxMutations.power_managed). Nothing but power control is reachable."""
from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..runtime import Runtime

OPS = ("start", "shutdown", "stop", "reboot")


class GuestPower(BaseModel):
    model_config = ConfigDict(extra="forbid")
    endpoint_id: UUID
    vmid: int = Field(ge=100, le=999_999_999)
    op: Literal["start", "shutdown", "stop", "reboot"]


def risk(p: GuestPower) -> str:
    return "low" if p.op == "start" else "normal"


def precheck(db: Session, rt: Runtime, p: GuestPower) -> dict:
    from ..actions import PlanError
    ep = db.execute(text("SELECT * FROM endpoints WHERE id = :i"), {"i": str(p.endpoint_id)}).first()
    if ep is None:
        raise PlanError(404, "endpoint not found")
    if ep.detached_at is not None or ep.enabled is False:
        raise PlanError(409, "endpoint is disabled or removed")
    if not ep.provision_token_id:
        raise PlanError(409, "this integration has no operations credential (choose the Operations or Deployment permission level)")
    if p.vmid in (ep.protected_vmids or ()):
        raise PlanError(403, f"guest {p.vmid} is protected")
    if p.vmid not in (getattr(ep, "managed_vmids", None) or ()):
        raise PlanError(403, f"guest {p.vmid} is not one of the existing guests this integration may operate (Manage access to add it)")
    out = {"endpoint_name": ep.name, "operation": p.op, "vmid": p.vmid}
    if p.op == "stop":
        out["warning"] = "stop is an immediate power-off (like pulling the plug); prefer shutdown"
    return out


def exec_power(rt: Runtime, db: Session, m: GuestPower, plan, known: list[str]) -> dict:
    from ..providers.proxmox import open_mutations
    ep = db.execute(text("SELECT * FROM endpoints WHERE id = :i"), {"i": str(m.endpoint_id)}).first()
    if ep is None or ep.detached_at is not None:
        raise LookupError("endpoint not found or removed")
    prov = open_mutations(rt, ep, known)
    t = prov.power_managed(m.vmid, m.op)
    st = prov.wait(t, timeout=300.0)
    return {"vmid": m.vmid, "node": t.node, "operation": m.op, "task": t.upid, "state": st.state}
