"""guest.remove: delete a guest or template that Office Unbound left behind, through plan -> approval -> job -> audit.

Only provable leftovers qualify (`leftover_reason`), decided twice: at plan time from the inventory snapshot, and again at execution from the LIVE
Proxmox view (the job deletes nothing if the two disagree):
  * a golden-image template (ou-managed + ou-image) that a newer import superseded: deployments clone only the template `pick_template` chooses
    for that name, so a superseded one is never used again;
  * a stopped guest (ou-managed) whose deployment is destroyed or unknown, or that never received its deployment tag (a clone whose tagging step
    did not run) and is named like a VM of a destroyed deployment.
Never: a guest without ou-managed (not created by Office Unbound), a running guest, a protected guest or the ICS itself, anything outside the
endpoint's pools/nodes, or a guest a live deployment still records. The owner asked for this on 2026-11-19 ("make sure in the future YOU can
clean up") after test runs left superseded templates and untagged clones on the cluster."""
from __future__ import annotations

import re
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..runtime import Runtime

OWNED_TAG, IMAGE_TAG, DEP_PREFIX = "ou-managed", "ou-image", "ou-deployment-"


class GuestRemove(BaseModel):
    model_config = ConfigDict(extra="forbid")
    endpoint_id: UUID
    vmid: int = Field(ge=100, le=999_999_999)
    confirm: str = Field(min_length=1, max_length=120, description="the guest's name, typed again")
    reason: str | None = Field(default=None, max_length=500)


def risk(_p: GuestRemove) -> str:
    return "high"


class NotALeftover(Exception):
    pass


def _deployments(db: Session) -> dict[str, str]:
    return {r.slug.lower(): r.status for r in db.execute(text("SELECT slug, status FROM deployments")).all()}


def _recorded_vmids(db: Session, endpoint_id: str) -> set[int]:
    """VM ids a deployment that is not destroyed still records (its own resources): never a leftover, whatever the tags say."""
    rows = db.execute(text("SELECT r.provider_ref FROM deployment_resources r JOIN deployments d ON d.id = r.deployment_id "
                           "WHERE r.kind = 'vm' AND r.state <> 'removed' AND d.status <> 'destroyed' AND r.provider_ref IS NOT NULL")).all()
    out = set()
    for r in rows:
        v = (r.provider_ref or {}).get("vmid")
        if v is not None:
            out.add(int(v))
    return out


def _vm_name_of(slug: str, name: str) -> bool:
    # legacy <customer>-<deployment>-<layout> and, since 0.7.2, <deployment>-<role>
    return re.fullmatch(r"(c-[0-9a-z]+-)?" + re.escape(slug) + r"-[a-z0-9-]+", name or "") is not None


def leftover_reason(g: dict, is_template: bool, templates: list[dict], deployments: dict[str, str], recorded: set[int]) -> str:
    """Why `g` is a provable leftover, or NotALeftover. `g`/`templates` are discovery rows (vmid, name, tags, status)."""
    from ..deploy.executor import pick_template
    tags, vmid, name = list(g.get("tags") or []), int(g["vmid"]), str(g.get("name") or "")
    if OWNED_TAG not in tags:
        raise NotALeftover(f"guest {vmid} does not carry {OWNED_TAG}: it was not created by Office Unbound; remove it in Proxmox if it is yours")
    if vmid in recorded:
        raise NotALeftover(f"guest {vmid} belongs to a deployment that is not destroyed; change or destroy that deployment instead")
    if is_template:
        if IMAGE_TAG not in tags:
            raise NotALeftover(f"template {vmid} is not an Office Unbound golden image")
        current = pick_template(templates, name)
        if current is None or int(current["vmid"]) == vmid:
            raise NotALeftover(f"template {vmid} is the current {name} (new deployments clone it); import a newer golden image first")
        return f"superseded golden image: deployments clone template {current['vmid']} for {name}"
    if g.get("status") != "stopped":
        raise NotALeftover(f"guest {vmid} is {g.get('status')}; only a stopped guest can be removed (shut it down first)")
    dep = next((t[len(DEP_PREFIX):] for t in tags if t.startswith(DEP_PREFIX)), None)
    if dep is not None:
        st = deployments.get(dep.lower())
        if st not in (None, "destroyed"):
            raise NotALeftover(f"guest {vmid} belongs to deployment {dep} ({st}); change or destroy that deployment instead")
        return f"its deployment {dep} is {'destroyed' if st else 'unknown to this ICS'}"
    live = [s for s, st in deployments.items() if st != "destroyed" and _vm_name_of(s, name)]
    if live:
        raise NotALeftover(f"guest {vmid} is named like a VM of deployment {live[0]}, which is not destroyed")
    gone = sorted((s for s, st in deployments.items() if st == "destroyed" and _vm_name_of(s, name)), key=len, reverse=True)
    if not gone:
        raise NotALeftover(f"guest {vmid} has no deployment tag and is not named like a VM of a destroyed deployment")
    return f"a VM of destroyed deployment {gone[0]} that never received its deployment tag"


def _snapshot_rows(db: Session, endpoint_id: str) -> tuple[list[dict], list[dict]]:
    guests = [dict(r._mapping) for r in db.execute(text("SELECT vmid, name, node, pool, status, tags FROM infra_guests WHERE endpoint_id = :e"),
                                                    {"e": endpoint_id}).all()]
    tpls = [dict(r._mapping) for r in db.execute(text("SELECT vmid, name, node, pool, tags FROM infra_templates WHERE endpoint_id = :e"),
                                                  {"e": endpoint_id}).all()]
    return guests, tpls


def _classify(db: Session, endpoint_id: str, vmid: int, guests: list[dict], tpls: list[dict]) -> tuple[dict, bool, str]:
    g = next((x for x in guests if int(x["vmid"]) == vmid), None)
    is_tpl = g is None
    if is_tpl:
        g = next((x for x in tpls if int(x["vmid"]) == vmid), None)
    if g is None:
        raise NotALeftover(f"guest {vmid} is not visible on this endpoint")
    return g, is_tpl, leftover_reason(g, is_tpl, tpls, _deployments(db), _recorded_vmids(db, endpoint_id))


def precheck(db: Session, rt: Runtime, p: GuestRemove) -> dict:
    from ..actions import PlanError
    ep = db.execute(text("SELECT * FROM endpoints WHERE id = :i"), {"i": str(p.endpoint_id)}).first()
    if ep is None:
        raise PlanError(404, "endpoint not found")
    if ep.detached_at is not None or ep.enabled is False:
        raise PlanError(409, "endpoint is disabled or removed")
    if p.vmid in (ep.protected_vmids or ()):
        raise PlanError(403, f"guest {p.vmid} is protected")
    try:
        g, is_tpl, why = _classify(db, str(p.endpoint_id), p.vmid, *_snapshot_rows(db, str(p.endpoint_id)))
    except NotALeftover as e:
        raise PlanError(409, str(e)) from None
    if p.confirm != g.get("name"):
        raise PlanError(422, "confirm must equal the guest's name")
    return {"endpoint_name": ep.name, "vmid": p.vmid, "name": g.get("name"), "node": g.get("node"), "template": is_tpl, "why": why,
            "effect": "the guest and all its disks are deleted (cannot be undone)"}


def exec_remove(rt: Runtime, db: Session, m: GuestRemove, plan, known: list[str]) -> dict:
    from ..providers.proxmox import open_mutations
    ep = db.execute(text("SELECT * FROM endpoints WHERE id = :i"), {"i": str(m.endpoint_id)}).first()
    if ep is None or ep.detached_at is not None:
        raise LookupError("endpoint not found or removed")
    prov = open_mutations(rt, ep, known)
    d = prov.discover()                      # LIVE view: the plan-time snapshot may be stale
    if not {"guests", "templates"} <= set(d.complete):
        raise LookupError("the live guest list is incomplete; nothing was removed")
    try:
        g, is_tpl, why = _classify(db, str(m.endpoint_id), m.vmid, d.guests, d.templates)
    except NotALeftover as e:
        raise LookupError(f"{e}; nothing was removed") from None
    if g.get("name") != m.confirm:
        raise LookupError("the guest's name changed since approval; nothing was removed")
    t = prov.remove_leftover(m.vmid, template=is_tpl)
    st = prov.wait(t, timeout=600.0)
    return {"vmid": m.vmid, "name": m.confirm, "node": t.node, "template": is_tpl, "why": why, "task": t.upid, "state": st.state}


def list_leftovers(db: Session) -> list[dict]:
    """Every guest/template in the inventory snapshot with its verdict (read-only): what guest.remove would accept, and why not otherwise."""
    out = []
    for ep in db.execute(text("SELECT id, name FROM endpoints WHERE detached_at IS NULL")).all():
        guests, tpls = _snapshot_rows(db, str(ep.id))
        deps, rec = _deployments(db), _recorded_vmids(db, str(ep.id))
        for g, is_tpl in [(x, False) for x in guests] + [(x, True) for x in tpls]:
            try:
                why, ok = leftover_reason(g, is_tpl, tpls, deps, rec), True
            except NotALeftover as e:
                why, ok = str(e), False
            out.append({"endpoint_id": str(ep.id), "endpoint": ep.name, "vmid": int(g["vmid"]), "name": g.get("name"), "node": g.get("node"),
                        "template": is_tpl, "removable": ok, "why": why})
    return sorted(out, key=lambda r: (not r["removable"], r["endpoint"], r["vmid"]))
