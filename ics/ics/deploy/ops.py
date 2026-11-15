"""Typed actions deployment.create / deployment.change / deployment.destroy: params models, plan-time prechecks (risk by diff), and the
job executors that drive the step executor. `actions.py` only wires these in (like identity.py). Nothing here is reachable except
through plan -> approval -> job."""
import hashlib
import json
import logging
import uuid
from typing import Callable, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import text

from .. import audit
from . import executor, state
from .catalog import get_catalog
from .envs import real_env_factory
from .plan import PlanInput, VmLayout, canon, capacity_from_inventory, generate_plan, plan_hash
from .ports import Cancelled, DeployError, ExecEnv, StepFailed

log = logging.getLogger("ics.deploy.ops")
SLUG = r"^[a-z0-9][a-z0-9-]{1,30}$"
ACTIONS = ("deployment.create", "deployment.change", "deployment.destroy")


class DeploymentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    spec: PlanInput
    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$", description="plan_hash returned by POST /deployments/plan; the plan is re-generated and must match")


class ChangeSet(BaseModel):
    model_config = ConfigDict(extra="forbid")
    users: int | None = Field(default=None, ge=1, le=100000)
    profile: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9-]{0,40}$")
    optional: dict[str, bool] | None = None
    custom_layout: list[VmLayout] | None = Field(default=None, max_length=30)
    backup_retention_days: int | None = Field(default=None, ge=1, le=3650)
    allowed_nodes: list[str] | None = Field(default=None, max_length=64)
    tenants: int | None = Field(default=None, ge=1, le=50)

    def apply(self, spec: PlanInput) -> PlanInput:
        new = self.model_dump(exclude_none=True)
        if "optional" in new:  # a toggle adds to the existing overrides, it never wipes the others
            new["optional"] = {**spec.optional, **new["optional"]}
        return PlanInput.model_validate({**spec.model_dump(), **new})


class DeploymentChange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    deployment_id: str = Field(pattern=SLUG)
    changes: ChangeSet
    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    maintenance: Literal["window", "override"] | None = Field(
        default=None, description="required when the change has disruptive steps: 'window' (+ maintenance_window_id of an active window) "
                                  "or 'override' (explicit override; the plan becomes high risk = two approvers)")
    maintenance_window_id: UUID | None = None

    @model_validator(mode="after")
    def _m(self):
        if (self.maintenance == "window") != (self.maintenance_window_id is not None):
            raise ValueError("maintenance 'window' needs maintenance_window_id (and only then)")
        return self


class DeploymentDestroy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    deployment_id: str = Field(pattern=SLUG)
    confirm: str = Field(description="must equal deployment_id")

    @model_validator(mode="after")
    def _c(self):
        if self.confirm != self.deployment_id:
            raise ValueError("confirm must equal deployment_id")
        return self


# ---- environment (providers/agents) wiring -----------------------------------------------------------------------

_env_factory: Callable[[object, dict], ExecEnv] = lambda rt, dep: real_env_factory(rt, dep)  # noqa: E731  (real Proxmox provider; agent port still unconfigured)


def set_env_factory(fn: Callable[[object, dict], ExecEnv]) -> None:
    """The process wires real provider/agent adapters here; tests wire fakes."""
    global _env_factory
    _env_factory = fn


# ---- planning helpers (read-only) --------------------------------------------------------------------------------

def _latest_inventory(db, endpoint_name: str):
    ep = db.execute(text("SELECT id, allowed_nodes FROM endpoints WHERE name = :n AND detached_at IS NULL"), {"n": endpoint_name}).first()
    if ep is None:
        raise KeyError("endpoint not found")
    snap = db.execute(text("SELECT data FROM inventory_snapshots WHERE endpoint_id = :e ORDER BY collected_at DESC LIMIT 1"), {"e": str(ep.id)}).first()
    data = snap.data if snap else {}
    if ep.allowed_nodes:  # capacity is only ever counted on the endpoint's authorized nodes
        data = {**data, "nodes": [n for n in data.get("nodes", []) if n.get("node") in ep.allowed_nodes]}
    return str(ep.id), data


def build_plan(db, spec: PlanInput, existing: dict | None = None) -> dict:
    _, data = _latest_inventory(db, spec.endpoint)
    return generate_plan(spec, capacity_from_inventory(data, spec.deployment_id), get_catalog(), existing)


def _dep(db, slug: str):
    return db.execute(text("SELECT * FROM deployments WHERE slug = :s"), {"s": slug}).first()


def _applied_plan(db, dep) -> dict:
    r = db.execute(text("SELECT plan FROM deployment_revisions WHERE deployment_id = :d AND revision = :r AND status = 'applied'"),
                   {"d": str(dep.id), "r": dep.current_revision}).first()
    if r is None:
        raise LookupError("deployment has no applied revision yet")
    return r.plan


def plan_change(db, slug: str, changes: ChangeSet) -> tuple[object, PlanInput, dict, dict, dict]:
    """(deployment, new_spec, old_plan, new_plan, diff) without side effects."""
    dep = _dep(db, slug)
    if dep is None:
        raise KeyError("deployment not found")
    if dep.status != "active":
        raise LookupError(f"deployment is {dep.status}; only active deployments can be changed")
    old = _applied_plan(db, dep)
    new_spec = changes.apply(PlanInput.model_validate(dep.desired_spec))
    new = build_plan(db, new_spec, state.existing_from_resources(db, str(dep.id)))
    return dep, new_spec, old, new, state.diff_plans(old, new, get_catalog())


def change_preview(db, slug: str, changes: ChangeSet) -> dict:
    dep, _, old, new, diff = plan_change(db, slug, changes)
    return {"deployment_id": slug, "from_revision": dep.current_revision, "plan": new, "diff": diff,
            "executable": new["executable"] and not diff["empty"]}


# ---- plan-time precheck (called by actions.create_plan) ---------------------------------------------------------------

def precheck(db, rt, action: str, p) -> dict:
    """Validate against live state, persist the proposed revision, return audit extras. Raises KeyError(404) / LookupError(409) /
    ValueError(422). The tier is returned under 'risk'."""
    if action == "deployment.create":
        return _pre_create(db, p)
    if action == "deployment.change":
        return _pre_change(db, rt, p)
    return _pre_destroy(db, p)


def _blocking(plan: dict) -> None:
    if plan["errors"]:
        raise ValueError("plan has blocking errors: " + "; ".join(f"{e['code']}: {e['message']}" for e in plan["errors"])[:600])


def _pre_create(db, p: DeploymentCreate) -> dict:
    spec = p.spec
    ep_id, _ = _latest_inventory(db, spec.endpoint)
    plan = build_plan(db, spec)
    _blocking(plan)
    if plan["plan_hash"] != p.plan_hash:
        raise LookupError("the plan changed since it was previewed (inventory, catalog or inputs differ); preview again")
    dep = _dep(db, spec.deployment_id)
    if dep is not None and dep.status not in ("planned", "failed", "provisioning"):
        raise LookupError(f"deployment {spec.deployment_id!r} already exists ({dep.status})")
    if dep is None:
        did = str(db.execute(text(
            "INSERT INTO deployments (slug, customer_id, profile, profile_version, endpoint_id, status, desired_spec) "
            "VALUES (:s, :c, :p, :pv, :e, 'planned', CAST(:d AS jsonb)) RETURNING id"),
            {"s": spec.deployment_id, "c": spec.customer_id, "p": spec.profile, "pv": plan["profile"]["version"], "e": ep_id,
             "d": canon(spec.model_dump(mode="json"))}).scalar())
    else:
        did = str(dep.id)
        db.execute(text("UPDATE deployments SET desired_spec = CAST(:d AS jsonb), profile = :p, profile_version = :pv, status = 'planned', updated_at = now() "
                        "WHERE id = :i"), {"d": canon(spec.model_dump(mode="json")), "p": spec.profile, "pv": plan["profile"]["version"], "i": did})
        db.execute(text("DELETE FROM deployment_revisions WHERE deployment_id = :i AND kind = 'create' AND status IN ('proposed','failed','applying')"
                        " AND plan_hash <> :h"), {"i": did, "h": plan["plan_hash"]})
    _upsert_revision(db, did, 1, "create", plan, spec, None, "high")
    state.add_event(db, did, "planned", f"deployment.create planned ({plan['consumption']['vms']} VMs)", None, {"plan_hash": plan["plan_hash"]})
    return {"risk": "high", "deployment": spec.deployment_id, "plan_hash": plan["plan_hash"], "consumption": plan["consumption"]}


def _upsert_revision(db, did: str, rev: int, kind: str, plan: dict, spec: PlanInput, diff: dict | None, risk: str) -> None:
    db.execute(text(
        "INSERT INTO deployment_revisions (deployment_id, revision, kind, plan_hash, spec_hash, spec, plan, diff, risk) "
        "VALUES (:d, :r, :k, :h, :sh, CAST(:s AS jsonb), CAST(:p AS jsonb), CAST(:df AS jsonb), :rk) "
        "ON CONFLICT (deployment_id, plan_hash) DO UPDATE SET diff = EXCLUDED.diff, risk = EXCLUDED.risk, status = 'proposed'"),
        {"d": did, "r": rev, "k": kind, "h": plan["plan_hash"], "sh": hashlib.sha256(canon(spec.model_dump(mode="json")).encode()).hexdigest(),
         "s": canon(spec.model_dump(mode="json")), "p": canon(plan), "df": canon(diff) if diff is not None else None, "rk": risk})


def _pre_change(db, rt, p: DeploymentChange) -> dict:
    dep, new_spec, old, new, diff = plan_change(db, p.deployment_id, p.changes)
    _blocking(new)
    if new["plan_hash"] != p.plan_hash:
        raise LookupError("the plan changed since it was previewed; preview the change again")
    if diff["empty"]:
        raise ValueError("the change produces no difference")
    risk = diff["risk"]
    if diff["requires_maintenance"]:
        if p.maintenance is None:
            raise ValueError("this change has disruptive steps (" + ", ".join(diff["disruptive_steps"][:4]) + "); set maintenance='window' with an active "
                             "maintenance_window_id, or maintenance='override' (high risk)")
        if p.maintenance == "window":
            w = db.execute(text("SELECT 1 FROM maintenance_windows WHERE id = :i AND ends_at > now()"), {"i": str(p.maintenance_window_id)}).first()
            if w is None:
                raise LookupError("maintenance window not found or already ended")
        else:
            risk = "high"
    rev = db.execute(text("SELECT COALESCE(max(revision), 0) + 1 FROM deployment_revisions WHERE deployment_id = :d"), {"d": str(dep.id)}).scalar()
    _upsert_revision(db, str(dep.id), rev, "change", new, new_spec, diff, risk)
    state.add_event(db, str(dep.id), "change_planned", f"change planned: +{len(diff['added'])} ~{len(diff['changed'])} -{len(diff['removed'])}",
                    None, {"plan_hash": new["plan_hash"], "risk": risk})
    return {"risk": risk, "deployment": p.deployment_id, "plan_hash": new["plan_hash"], "diff_summary": {
        "added": len(diff["added"]), "changed": len(diff["changed"]), "removed": len(diff["removed"]),
        "downtime_seconds": diff["downtime_seconds"], "snapshot_required": diff["snapshot_required"], "risk_reasons": diff["risk_reasons"]}}


def _pre_destroy(db, p: DeploymentDestroy) -> dict:
    dep = _dep(db, p.deployment_id)
    if dep is None:
        raise KeyError("deployment not found")
    if dep.status in ("destroyed", "destroying", "changing", "provisioning"):
        raise LookupError(f"deployment is {dep.status}")
    r = db.execute(text("SELECT plan FROM deployment_revisions WHERE deployment_id = :d AND kind IN ('create','change') "
                        "ORDER BY revision DESC, id DESC LIMIT 1"), {"d": str(dep.id)}).first()
    if r is None:
        raise LookupError("deployment has no plan to destroy")
    rev = db.execute(text("SELECT COALESCE(max(revision), 0) + 1 FROM deployment_revisions WHERE deployment_id = :d"), {"d": str(dep.id)}).scalar()
    destroy_plan = {**{k: r.plan[k] for k in ("vms", "checks", "plan_version")}, "kind": "destroy", "steps": state.destroy_steps(r.plan),
                    "errors": [], "warnings": []}
    destroy_plan["plan_hash"] = plan_hash(destroy_plan)
    _upsert_revision(db, str(dep.id), rev, "destroy", destroy_plan, PlanInput.model_validate(dep.desired_spec), None, "high")
    state.add_event(db, str(dep.id), "destroy_planned", "destroy planned", None, {"plan_hash": destroy_plan["plan_hash"]})
    return {"risk": "high", "deployment": p.deployment_id, "vms": [v["name"] for v in destroy_plan["vms"]], "plan_hash": destroy_plan["plan_hash"]}


# ---- executors (run inside a job) ---------------------------------------------------------------------------------

def _job_id(db, plan) -> str:
    return str(db.execute(text("SELECT id FROM jobs WHERE plan_id = :p"), {"p": str(plan.id)}).scalar())


def _load_revision(db, slug: str, kind: str, plan_hash_: str | None):
    dep = _dep(db, slug)
    if dep is None:
        raise DeployError("deployment not found")
    q = ("SELECT * FROM deployment_revisions WHERE deployment_id = :d AND kind = :k "
         + ("AND plan_hash = :h " if plan_hash_ else "") + "ORDER BY revision DESC, id DESC LIMIT 1")
    rev = db.execute(text(q), {"d": str(dep.id), "k": kind, "h": plan_hash_}).first()
    if rev is None:
        raise DeployError("no proposed revision matches the approved plan")
    return dep, rev


def _verify_integrity(rev) -> dict:
    plan = rev.plan
    if plan_hash(plan) != rev.plan_hash:
        raise DeployError("stored plan does not match its hash; refusing to execute")
    return plan


def _set_status(rt, dep_id: str, status: str, rev_id: int | None = None, rev_status: str | None = None, job_id: str | None = None,
                current_revision: int | None = None, spec: dict | None = None) -> None:
    with rt.session() as db:
        sets, p = ["status = :s", "updated_at = now()"], {"i": dep_id, "s": status}
        if current_revision is not None:
            sets.append("current_revision = :cr")
            p["cr"] = current_revision
        if spec is not None:
            sets.append("desired_spec = CAST(:sp AS jsonb)")
            p["sp"] = canon(spec)
        db.execute(text(f"UPDATE deployments SET {', '.join(sets)} WHERE id = :i"), p)  # noqa: S608
        if rev_id is not None:
            db.execute(text("UPDATE deployment_revisions SET status = :rs, job_id = COALESCE(:j, job_id), "
                            "applied_at = CASE WHEN :rs = 'applied' THEN now() ELSE applied_at END WHERE id = :r"),
                       {"rs": rev_status, "r": rev_id, "j": job_id})
        db.commit()


def _event(rt, dep_id, kind, msg, job_id=None, details=None):
    with rt.session() as db:
        state.add_event(db, dep_id, kind, msg, job_id, details)
        db.commit()


def _run(rt, db, plan_row, dep, rev, steps: list[dict], plan: dict, *, working: str, done: str) -> dict:
    jid = _job_id(db, plan_row)
    did = str(dep.id)
    env = _env_factory(rt, {"slug": dep.slug, "id": did, "created_by": str(plan_row.requested_by), "plan": plan})
    _set_status(rt, did, working, rev.id, "applying", jid)
    _event(rt, did, "job_started", f"{rev.kind} started", jid)
    try:
        res = executor.run_steps(rt, job_id=jid, deployment_id=did, slug=dep.slug, revision=rev.revision, plan=plan, steps=steps, env=env,
                                 created_by=str(plan_row.requested_by))
    except (StepFailed, Cancelled) as e:
        _set_status(rt, did, "active" if rev.kind == "change" else "failed", rev.id, "failed", jid)
        _event(rt, did, "job_failed", str(e)[:300], jid)
        raise
    return {**res, "job_id": jid}


def exec_create(rt, db, m: DeploymentCreate, plan_row, known) -> dict:
    dep, rev = _load_revision(db, m.spec.deployment_id, "create", m.plan_hash)
    plan = _verify_integrity(rev)
    if plan["errors"]:
        raise DeployError("plan has blocking errors; refusing to execute")
    with rt.session() as d2:
        state.sync_resources(d2, str(dep.id), plan)
        d2.commit()
    res = _run(rt, db, plan_row, dep, rev, plan["steps"], plan, working="provisioning", done="active")
    _set_status(rt, str(dep.id), "active", rev.id, "applied", res["job_id"], current_revision=rev.revision)
    _event(rt, str(dep.id), "active", "deployment is active", res["job_id"])
    audit.append(db, "deployment.created", actor_name="worker", resource="deployment", resource_id=str(dep.id),
                 details={"slug": dep.slug, "plan_hash": rev.plan_hash, "vms": [v["name"] for v in plan["vms"]]})
    return {"deployment_id": dep.slug, "revision": rev.revision, "steps": res["steps"], "carried_over_steps": res["carried"]}


def exec_change(rt, db, m: DeploymentChange, plan_row, known) -> dict:
    dep, rev = _load_revision(db, m.deployment_id, "change", m.plan_hash)
    new = _verify_integrity(rev)
    diff = rev.diff
    if dep.status not in ("active", "changing"):
        raise DeployError(f"deployment is {dep.status}")
    if m.maintenance == "window":
        w = db.execute(text("SELECT 1 FROM maintenance_windows WHERE id = :i AND starts_at <= now() AND ends_at > now()"),
                       {"i": str(m.maintenance_window_id)}).first()
        if w is None:
            raise DeployError("the maintenance window is not active now; disruptive steps were not started")
    did = str(dep.id)
    with rt.session() as d2:
        state.sync_resources(d2, did, new)
        for c in diff["changed"]:
            state.set_resource(d2, did, c["kind"], c["name"], state="changing")
        d2.commit()
    res = _run(rt, db, plan_row, dep, rev, diff["steps"], new, working="changing", done="active")
    with rt.session() as d2:
        for c in diff["changed"]:
            state.set_resource(d2, did, c["kind"], c["name"], state="present")
        for r in diff["removed"]:
            state.set_resource(d2, did, r["kind"], r["name"], state="removed")
        d2.execute(text("UPDATE deployment_revisions SET status = 'superseded' WHERE deployment_id = :d AND revision = :r AND status = 'applied'"),
                   {"d": did, "r": dep.current_revision})
        d2.commit()
    _set_status(rt, did, "active", rev.id, "applied", res["job_id"], current_revision=rev.revision, spec=rev.spec)
    _event(rt, did, "changed", f"change applied (revision {rev.revision})", res["job_id"])
    audit.append(db, "deployment.changed", actor_name="worker", resource="deployment", resource_id=did,
                 details={"slug": dep.slug, "revision": rev.revision, "plan_hash": rev.plan_hash, "added": len(diff["added"]),
                          "changed": len(diff["changed"]), "removed": len(diff["removed"])})
    return {"deployment_id": dep.slug, "revision": rev.revision, "steps": res["steps"]}


def exec_destroy(rt, db, m: DeploymentDestroy, plan_row, known) -> dict:
    dep, rev = _load_revision(db, m.deployment_id, "destroy", None)
    plan = _verify_integrity(rev)
    did = str(dep.id)
    res = _run(rt, db, plan_row, dep, rev, plan["steps"], plan, working="destroying", done="destroyed")
    with rt.session() as d2:
        for r in d2.execute(text("SELECT provider_ref FROM deployment_resources WHERE deployment_id = :d AND kind = 'vm'"), {"d": did}).all():
            nid = (r.provider_ref or {}).get("agent_node_id")   # the guest is gone: its node record stays for the audit trail but is no longer active
            if nid:
                d2.execute(text("UPDATE nodes SET status = 'decommissioned' WHERE CAST(id AS text) = :i"), {"i": nid})
        d2.execute(text("UPDATE deployment_resources SET state = 'removed', updated_at = now() WHERE deployment_id = :d"), {"d": did})
        for c in plan["checks"]:
            d2.execute(text("UPDATE checks SET enabled = false WHERE name = :n"), {"n": c["name"]})
        d2.commit()
    _set_status(rt, did, "destroyed", rev.id, "applied", res["job_id"], current_revision=rev.revision)
    _event(rt, did, "destroyed", "deployment destroyed", res["job_id"])
    audit.append(db, "deployment.destroyed", actor_name="worker", resource="deployment", resource_id=did,
                 details={"slug": dep.slug, "vms": [v["name"] for v in plan["vms"]]})
    return {"deployment_id": dep.slug, "destroyed_vms": len(plan["vms"])}


MODELS = {"deployment.create": DeploymentCreate, "deployment.change": DeploymentChange, "deployment.destroy": DeploymentDestroy}
EXECUTORS = {"deployment.create": exec_create, "deployment.change": exec_change, "deployment.destroy": exec_destroy}
__all__ = ["MODELS", "EXECUTORS", "ACTIONS", "precheck", "set_env_factory", "uuid", "json"]
