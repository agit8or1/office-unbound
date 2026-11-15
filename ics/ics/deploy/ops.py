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
from .lease import Lease, guard_env
from .catalog import get_catalog
from .envs import real_env_factory
from .plan import PlanInput, VmLayout, canon, capacity_from_inventory, generate_plan, plan_hash
from .ports import STOP_EVENTS, Cancelled, DeployError, ExecEnv, Fenced, StepFailed

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
    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$", description="plan_hash returned by POST /deployments/{slug}/destroy/preview "
                                                                  "(binds the approval to the applied revision and its exact resource list)")

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


def _busy(db, dep_id: str) -> bool:
    """True while an executor holds a live lease on the deployment (review 3 H1)."""
    return db.execute(text("SELECT 1 FROM deployment_locks WHERE deployment_id = :d AND lease_expires_at > now()"), {"d": dep_id}).first() is not None


def plan_change(db, slug: str, changes: ChangeSet) -> tuple[object, PlanInput, dict, dict, dict]:
    """(deployment, new_spec, old_plan, new_plan, diff) without side effects."""
    dep = _dep(db, slug)
    if dep is None:
        raise KeyError("deployment not found")
    if _busy(db, str(dep.id)):
        raise LookupError("an executor is currently running on this deployment; wait for it to finish")
    if dep.status not in ("active", "changing"):  # 'changing' with no live executor = an interrupted change (re-plan against the applied revision)
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
    if dep is not None and _busy(db, str(dep.id)):
        raise LookupError(f"an executor is currently running on deployment {spec.deployment_id!r}; wait for it to finish")
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


def _upsert_revision(db, did: str, rev: int, kind: str, plan: dict, spec: PlanInput, diff: dict | None, risk: str,
                     base_revision: int | None = None) -> None:
    # review 3 M5: base revision + diff hash are stored with the proposal; an applied/superseded row is never rewritten
    db.execute(text(
        "INSERT INTO deployment_revisions (deployment_id, revision, kind, plan_hash, spec_hash, spec, plan, diff, risk, base_revision, diff_hash) "
        "VALUES (:d, :r, :k, :h, :sh, CAST(:s AS jsonb), CAST(:p AS jsonb), CAST(:df AS jsonb), :rk, :br, :dh) "
        "ON CONFLICT (deployment_id, plan_hash) DO UPDATE SET diff = EXCLUDED.diff, risk = EXCLUDED.risk, status = 'proposed', "
        "base_revision = EXCLUDED.base_revision, diff_hash = EXCLUDED.diff_hash "
        "WHERE deployment_revisions.status IN ('proposed','failed')"),
        {"d": did, "r": rev, "k": kind, "h": plan["plan_hash"], "sh": hashlib.sha256(canon(spec.model_dump(mode="json")).encode()).hexdigest(),
         "s": canon(spec.model_dump(mode="json")), "p": canon(plan), "df": canon(diff) if diff is not None else None, "rk": risk, "br": base_revision,
         "dh": hashlib.sha256(canon(diff).encode()).hexdigest() if diff is not None else None})


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
            w = db.execute(text("SELECT independently_approved FROM maintenance_windows WHERE id = :i AND ends_at > now()"),
                           {"i": str(p.maintenance_window_id)}).first()
            if w is None:
                raise LookupError("maintenance window not found or already ended")
            if not w.independently_approved:  # review 3 L2: a window the requester minted alone cannot lower the approval tier
                raise LookupError("this maintenance window was not approved by anyone other than its requester; use maintenance='override' "
                                  "(high risk, two approvers) or a window approved by a second person")
        else:
            risk = "high"
    rev = db.execute(text("SELECT COALESCE(max(revision), 0) + 1 FROM deployment_revisions WHERE deployment_id = :d"), {"d": str(dep.id)}).scalar()
    _upsert_revision(db, str(dep.id), rev, "change", new, new_spec, diff, risk, base_revision=dep.current_revision)
    state.add_event(db, str(dep.id), "change_planned", f"change planned: +{len(diff['added'])} ~{len(diff['changed'])} -{len(diff['removed'])}",
                    None, {"plan_hash": new["plan_hash"], "risk": risk})
    return {"risk": risk, "deployment": p.deployment_id, "plan_hash": new["plan_hash"], "diff_summary": {
        "added": len(diff["added"]), "changed": len(diff["changed"]), "removed": len(diff["removed"]),
        "downtime_seconds": diff["downtime_seconds"], "snapshot_required": diff["snapshot_required"], "risk_reasons": diff["risk_reasons"]}}


def build_destroy_plan(db, dep) -> dict:
    """Review 3 M2: the destroy plan comes from the APPLIED revision (never a proposed/failed one) plus every VM the deployment actually
    owns (a provider reference and not yet removed), and is bound to the applied revision number. Same function for preview, precheck
    and the re-check at execution, so an approved destroy can only run against exactly the resource list the approvers saw."""
    applied = db.execute(text("SELECT plan FROM deployment_revisions WHERE deployment_id = :d AND status = 'applied' AND kind IN ('create','change') "
                              "AND revision = :r"), {"d": str(dep.id), "r": dep.current_revision}).first()
    names = {v["name"] for v in applied.plan["vms"]} if applied else set()
    checks = [c["name"] for c in applied.plan["checks"]] if applied else []
    for r in db.execute(text("SELECT logical_name FROM deployment_resources WHERE deployment_id = :d AND kind = 'vm' AND provider_ref IS NOT NULL "
                             "AND state <> 'removed'"), {"d": str(dep.id)}):
        names.add(r.logical_name)
    if not names:
        raise LookupError("deployment has no VMs to destroy")
    plan = {"kind": "destroy", "plan_version": applied.plan.get("plan_version") if applied else None, "base_revision": dep.current_revision,
            "vms": [{"name": n} for n in sorted(names)], "checks": [{"name": n} for n in sorted(checks)],
            "steps": state.destroy_steps({"vms": [{"name": n} for n in sorted(names)]}), "errors": [], "warnings": []}
    plan["plan_hash"] = plan_hash(plan)
    return plan


def destroy_preview(db, slug: str) -> dict:
    dep = _dep(db, slug)
    if dep is None:
        raise KeyError("deployment not found")
    if dep.status in ("destroyed", "planned"):
        raise LookupError(f"deployment is {dep.status}")
    if _busy(db, str(dep.id)):
        raise LookupError("an executor is currently running on this deployment; wait for it to finish")
    plan = build_destroy_plan(db, dep)
    return {"deployment_id": slug, "from_revision": dep.current_revision, "plan": plan, "plan_hash": plan["plan_hash"],
            "vms": [v["name"] for v in plan["vms"]]}


def _pre_destroy(db, p: DeploymentDestroy) -> dict:
    dep = _dep(db, p.deployment_id)
    if dep is None:
        raise KeyError("deployment not found")
    if dep.status in ("destroyed", "planned"):
        raise LookupError(f"deployment is {dep.status}")
    if _busy(db, str(dep.id)):
        raise LookupError("an executor is currently running on this deployment; wait for it to finish")
    destroy_plan = build_destroy_plan(db, dep)
    if destroy_plan["plan_hash"] != p.plan_hash:
        raise LookupError("the destroy plan changed since it was previewed (applied revision or resources differ); preview again")
    rev = db.execute(text("SELECT COALESCE(max(revision), 0) + 1 FROM deployment_revisions WHERE deployment_id = :d"), {"d": str(dep.id)}).scalar()
    _upsert_revision(db, str(dep.id), rev, "destroy", destroy_plan, PlanInput.model_validate(dep.desired_spec), None, "high",
                     base_revision=dep.current_revision)
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


def _run(rt, db, plan_row, dep, rev, steps: list[dict], plan: dict, *, working: str, done: str, base_revision: int | None = None,
         verify: Callable[[ExecEnv], None] | None = None) -> dict:
    """Run under the deployment's execution lock (lease + fencing token, review 3 H1). `verify` runs while the lock is still held."""
    jid = _job_id(db, plan_row)
    did = str(dep.id)
    lease = Lease(rt, did, jid, STOP_EVENTS.get(jid))
    lease.acquire()  # DeployError if another executor holds a live lease; nothing is changed in that case
    try:
        if base_revision is not None:  # review 3 M5: re-checked UNDER the lock
            cur = rt_current_revision(rt, did)
            if cur != base_revision:
                raise DeployError(f"the deployment changed since this change was planned (applied revision {cur}, planned against "
                                  f"{base_revision}); preview the change again")
        env = guard_env(_env_factory(rt, {"slug": dep.slug, "id": did}), lease)
        _set_status(rt, did, working, rev.id, "applying", jid)
        _event(rt, did, "job_started", f"{rev.kind} started", jid)
        try:
            res = executor.run_steps(rt, job_id=jid, deployment_id=did, slug=dep.slug, revision=rev.revision, plan=plan, steps=steps, env=env,
                                     created_by=str(plan_row.requested_by), plan_hash=rev.plan_hash, lease=lease,
                                     step_deadline=float(rt.settings.deployment_step_deadline_seconds))
            if verify is not None:
                verify(env)
        except Fenced:
            raise  # not ours any more: touch nothing
        except (StepFailed, Cancelled, DeployError) as e:
            _set_status(rt, did, "active" if rev.kind == "change" else "failed", rev.id, "failed", jid)
            _event(rt, did, "job_failed", str(e)[:300], jid)
            raise
        return {**res, "job_id": jid}
    finally:
        lease.release()


def rt_current_revision(rt, did: str) -> int:
    with rt.session() as d2:
        return d2.execute(text("SELECT current_revision FROM deployments WHERE id = :i"), {"i": did}).scalar()


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
    if rev.base_revision is None or dep.current_revision != rev.base_revision:  # review 3 M5 (re-checked again under the lock)
        raise DeployError(f"the deployment changed since this change was planned (applied revision {dep.current_revision}, planned against "
                          f"{rev.base_revision}); preview the change again")
    if rev.diff_hash != hashlib.sha256(canon(diff).encode()).hexdigest():
        raise DeployError("stored diff does not match its hash; refusing to execute")
    if m.maintenance == "window":
        w = db.execute(text("SELECT 1 FROM maintenance_windows WHERE id = :i AND starts_at <= now() AND ends_at > now() AND independently_approved"),
                       {"i": str(m.maintenance_window_id)}).first()
        if w is None:
            raise DeployError("the maintenance window is not active now (or was not independently approved); disruptive steps were not started")
    did = str(dep.id)
    with rt.session() as d2:
        state.sync_resources(d2, did, new)
        for c in diff["changed"]:
            state.set_resource(d2, did, c["kind"], c["name"], state="changing")
        d2.commit()
    res = _run(rt, db, plan_row, dep, rev, diff["steps"], new, working="changing", done="active", base_revision=rev.base_revision)
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
    dep, rev = _load_revision(db, m.deployment_id, "destroy", m.plan_hash)
    plan = _verify_integrity(rev)
    did = str(dep.id)
    if build_destroy_plan(db, dep)["plan_hash"] != rev.plan_hash:  # review 3 M2: same applied revision + resource list as approved
        raise DeployError("the deployment's applied revision or resources changed since this destroy was approved; preview and approve again")
    with rt.session() as d2:
        refs = {r.logical_name: r.provider_ref for r in d2.execute(text(
            "SELECT logical_name, provider_ref FROM deployment_resources WHERE deployment_id = :d AND kind = 'vm'"), {"d": did})}
    names = [v["name"] for v in plan["vms"]]

    def verify_gone(env: ExecEnv) -> None:
        guests = env.provider.discover().guests
        tag = f"ou-deployment-{dep.slug}"
        left = [n for n in names if refs.get(n) and refs[n].get("vmid") is not None
                and any(int(g.vmid) == int(refs[n]["vmid"]) and tag in g.tags for g in guests)]
        if left:
            with rt.session() as d3:  # the surviving VMs stay tracked (not 'removed')
                for n in left:
                    state.set_resource(d3, did, "vm", n, state="failed")
                d3.commit()
            raise DeployError("destroy is incomplete: VMs still exist: " + ", ".join(left) + "; the deployment was NOT marked destroyed")

    res = _run(rt, db, plan_row, dep, rev, plan["steps"], plan, working="destroying", done="destroyed", verify=verify_gone)
    with rt.session() as d2:
        d2.execute(text("UPDATE deployment_resources SET state = 'removed', updated_at = now() WHERE deployment_id = :d"), {"d": did})
        for c in plan["checks"]:  # review 3 L4: only checks this deployment created
            d2.execute(text("UPDATE checks SET enabled = false WHERE name = :n AND deployment_id = :d"), {"n": c["name"], "d": did})
        d2.commit()
    _set_status(rt, did, "destroyed", rev.id, "applied", res["job_id"], current_revision=rev.revision)
    _event(rt, did, "destroyed", "deployment destroyed", res["job_id"])
    audit.append(db, "deployment.destroyed", actor_name="worker", resource="deployment", resource_id=did,
                 details={"slug": dep.slug, "vms": names, "plan_hash": rev.plan_hash})
    return {"deployment_id": dep.slug, "destroyed_vms": len(names)}


MODELS = {"deployment.create": DeploymentCreate, "deployment.change": DeploymentChange, "deployment.destroy": DeploymentDestroy}
EXECUTORS = {"deployment.create": exec_create, "deployment.change": exec_change, "deployment.destroy": exec_destroy}
__all__ = ["MODELS", "EXECUTORS", "ACTIONS", "precheck", "set_env_factory", "uuid", "json"]
