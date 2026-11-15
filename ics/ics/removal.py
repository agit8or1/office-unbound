"""Typed removal actions (owner request: lab/demo leftovers must be removable through the normal plan -> approval -> job -> audit path).

check.delete, alert_channel.delete, node.decommission, maintenance.cancel, maintenance.delete, plan.archive. None of them weakens a rule:
requester != approver, provenance and risk tiers apply as for every action; every execution re-checks its guard under the job's transaction
and is written to the hash-chained audit with the removed object's identifying details. Plans are evidence and are only ever hidden."""
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text

from . import audit

ZERO64 = "0" * 64


def _errs():
    from .actions import PlanError, PlanIntegrityError  # late import: actions imports this module
    return PlanError, PlanIntegrityError


class CheckDelete(BaseModel):
    model_config = ConfigDict(extra="forbid")
    check_id: UUID
    reason: str | None = Field(default=None, max_length=500)


class ChannelDelete(BaseModel):
    model_config = ConfigDict(extra="forbid")
    channel_id: UUID
    confirm_no_alerting: bool = False      # required to delete the last enabled channel (then the plan is high risk)
    reason: str | None = Field(default=None, max_length=500)


class NodeDecommission(BaseModel):
    model_config = ConfigDict(extra="forbid")
    node_id: UUID
    reason: str = Field(min_length=3, max_length=500)


class MaintenanceTarget(BaseModel):
    model_config = ConfigDict(extra="forbid")
    maintenance_id: UUID
    reason: str | None = Field(default=None, max_length=500)


class PlanArchive(BaseModel):
    model_config = ConfigDict(extra="forbid")
    plan_id: UUID


def channel_risk(p: ChannelDelete) -> str:
    return "high" if p.confirm_no_alerting else "normal"


# ---- guards (shared by plan-time precheck and execution) ------------------------------------------------------------------

def _check_guard(db, check_id) -> object:
    PlanError, _ = _errs()
    c = db.execute(text("SELECT id, name, kind, deployment_id FROM checks WHERE id = :i FOR UPDATE"), {"i": str(check_id)}).first()
    if c is None:
        raise PlanError(404, "check not found")
    if c.deployment_id is not None:
        raise PlanError(409, "this check is managed by a deployment; change or destroy the deployment instead")
    if db.execute(text("SELECT 1 FROM remediation_attempts WHERE check_id = :i AND status IN ('queued','pending_approval','running')"), {"i": str(check_id)}).first():
        raise PlanError(409, "the check is bound to an active remediation attempt; wait for it to finish or let it be superseded")
    return c


def _channel_guard(db, p: ChannelDelete) -> object:
    PlanError, _ = _errs()
    ch = db.execute(text("SELECT id, name, kind, enabled FROM alert_channels WHERE id = :i FOR UPDATE"), {"i": str(p.channel_id)}).first()
    if ch is None:
        raise PlanError(404, "channel not found")
    if ch.enabled and not p.confirm_no_alerting:
        others = db.execute(text("SELECT count(*) FROM alert_channels WHERE enabled AND id <> :i"), {"i": str(p.channel_id)}).scalar()
        if others == 0:
            raise PlanError(409, "this is the last enabled alert channel; set confirm_no_alerting=true (high risk) to remove it")
    return ch


def _node_guard(db, node_id) -> object:
    PlanError, _ = _errs()
    n = db.execute(text("SELECT id, name, status, address, port, tls_fingerprint_sha256, agent_key_fp FROM nodes WHERE id = :i FOR UPDATE"),
                   {"i": str(node_id)}).first()
    if n is None:
        raise PlanError(404, "node not found")
    if n.status == "decommissioned":
        raise PlanError(409, "node is already decommissioned")
    if db.execute(text("SELECT 1 FROM checks WHERE remediation->>'node_id' = :n"), {"n": str(node_id)}).first():
        raise PlanError(409, "a check still has a remediation bound to this node; unbind it first")
    return n


def _window_guard(db, mid, action: str) -> object:
    PlanError, _ = _errs()
    w = db.execute(text("SELECT id, name, check_id, starts_at, ends_at, ends_at > now() AS active FROM maintenance_windows WHERE id = :i FOR UPDATE"),
                   {"i": str(mid)}).first()
    if w is None:
        raise PlanError(404, "maintenance window not found")
    if action == "cancel" and not w.active:
        raise PlanError(409, "the maintenance window has already ended")
    if action == "delete" and w.active:
        raise PlanError(409, "the window is still active or scheduled; cancel it first")
    return w


def _plan_guard(db, plan_id) -> object:
    PlanError, _ = _errs()
    p = db.execute(text("SELECT p.id, p.action, p.status, p.archived_at, j.status AS job_status FROM plans p LEFT JOIN jobs j ON j.plan_id = p.id "
                        "WHERE p.id = :i FOR UPDATE OF p"), {"i": str(plan_id)}).first()
    if p is None:
        raise PlanError(404, "plan not found")
    if p.archived_at is not None:
        raise PlanError(409, "plan is already archived")
    terminal = p.status == "rejected" or (p.status == "approved" and p.job_status in ("succeeded", "failed"))
    if not terminal:
        raise PlanError(409, "only finished plans (rejected, or approved with a finished job) can be archived")
    return p


# ---- plan-time prechecks ---------------------------------------------------------------------------------------------------

def pre_check_delete(db, rt, p: CheckDelete):
    c = _check_guard(db, p.check_id)
    return {"check": c.name}


def pre_channel_delete(db, rt, p: ChannelDelete):
    return {"channel": _channel_guard(db, p).name}


def pre_node_decommission(db, rt, p: NodeDecommission):
    return {"node": _node_guard(db, p.node_id).name}


def pre_maintenance_cancel(db, rt, p: MaintenanceTarget):
    return {"window": _window_guard(db, p.maintenance_id, "cancel").name}


def pre_maintenance_delete(db, rt, p: MaintenanceTarget):
    return {"window": _window_guard(db, p.maintenance_id, "delete").name}


def pre_plan_archive(db, rt, p: PlanArchive):
    return {"plan_action": _plan_guard(db, p.plan_id).action}


# ---- executors ---------------------------------------------------------------------------------------------------------------

def _guarded(fn):
    """Execution-time re-check: a PlanError from a guard means the world changed after approval -> PlanIntegrityError (job fails, nothing deleted)."""
    PlanError, PlanIntegrityError = _errs()
    try:
        return fn()
    except PlanError as e:
        raise PlanIntegrityError(e.msg) from None


def exec_check_delete(rt, db, m: CheckDelete, plan, known) -> dict:
    c = _guarded(lambda: _check_guard(db, m.check_id))
    n = db.execute(text("SELECT count(*) FROM check_results WHERE check_id = :i"), {"i": str(c.id)}).scalar()
    db.execute(text("DELETE FROM checks WHERE id = :i"), {"i": str(c.id)})     # results, incidents, windows, remediation history cascade
    audit.append(db, "check.deleted", actor_name="worker", resource="check", resource_id=str(c.id),
                 details={"name": c.name, "kind": c.kind, "results_deleted": n, "requested_by": str(plan.requested_by), "reason": m.reason, "plan_id": str(plan.id)})
    return {"check_id": str(c.id), "deleted": True, "results_deleted": n}


def exec_channel_delete(rt, db, m: ChannelDelete, plan, known) -> dict:
    ch = _guarded(lambda: _channel_guard(db, m))
    db.execute(text("DELETE FROM alert_channels WHERE id = :i"), {"i": str(ch.id)})
    audit.append(db, "alert_channel.deleted", actor_name="worker", resource="alert_channel", resource_id=str(ch.id),
                 details={"name": ch.name, "kind": ch.kind, "was_enabled": bool(ch.enabled), "confirm_no_alerting": m.confirm_no_alerting,
                          "requested_by": str(plan.requested_by), "reason": m.reason, "plan_id": str(plan.id)})
    return {"channel_id": str(ch.id), "deleted": True}


def exec_node_decommission(rt, db, m: NodeDecommission, plan, known) -> dict:
    n = _guarded(lambda: _node_guard(db, m.node_id))
    db.execute(text("UPDATE nodes SET status = 'decommissioned', decommissioned_at = now(), agent_pubkey = '', tls_fingerprint_sha256 = :z, "
                    "agent_key_fp = :z, capabilities = '{}'::jsonb WHERE id = :i"), {"z": ZERO64, "i": str(n.id)})
    audit.append(db, "node.decommissioned", actor_name="worker", resource="node", resource_id=str(n.id),
                 details={"name": n.name, "address": n.address, "port": n.port, "forgotten_tls_fingerprint": n.tls_fingerprint_sha256.strip(),
                          "forgotten_agent_key_fingerprint": n.agent_key_fp.strip(), "requested_by": str(plan.requested_by), "reason": m.reason,
                          "plan_id": str(plan.id)})
    return {"node_id": str(n.id), "decommissioned": True}


def exec_maintenance_cancel(rt, db, m: MaintenanceTarget, plan, known) -> dict:
    w = _guarded(lambda: _window_guard(db, m.maintenance_id, "cancel"))
    # ends now (a window that has not started yet is removed from the schedule); history row is kept as evidence
    db.execute(text("UPDATE maintenance_windows SET ends_at = now(), starts_at = LEAST(starts_at, now() - interval '1 second') WHERE id = :i"),
               {"i": str(w.id)})
    audit.append(db, "maintenance.cancelled", actor_name="worker", resource="maintenance", resource_id=str(w.id),
                 details={"name": w.name, "requested_by": str(plan.requested_by), "reason": m.reason, "plan_id": str(plan.id)})
    return {"maintenance_id": str(w.id), "cancelled": True}


def exec_maintenance_delete(rt, db, m: MaintenanceTarget, plan, known) -> dict:
    w = _guarded(lambda: _window_guard(db, m.maintenance_id, "delete"))
    db.execute(text("DELETE FROM maintenance_windows WHERE id = :i"), {"i": str(w.id)})
    audit.append(db, "maintenance.deleted", actor_name="worker", resource="maintenance", resource_id=str(w.id),
                 details={"name": w.name, "starts_at": w.starts_at.isoformat(), "ends_at": w.ends_at.isoformat(),
                          "requested_by": str(plan.requested_by), "reason": m.reason, "plan_id": str(plan.id)})
    return {"maintenance_id": str(w.id), "deleted": True}


def exec_plan_archive(rt, db, m: PlanArchive, plan, known) -> dict:
    p = _guarded(lambda: _plan_guard(db, m.plan_id))
    db.execute(text("UPDATE plans SET archived_at = now() WHERE id = :i"), {"i": str(p.id)})      # never deleted: plans are evidence
    audit.append(db, "plan.archived", actor_name="worker", resource="plan", resource_id=str(p.id),
                 details={"plan_action": p.action, "requested_by": str(plan.requested_by), "plan_id": str(plan.id)})
    return {"plan_id": str(p.id), "archived": True}


MODELS = {"check.delete": CheckDelete, "alert_channel.delete": ChannelDelete, "node.decommission": NodeDecommission,
          "maintenance.cancel": MaintenanceTarget, "maintenance.delete": MaintenanceTarget, "plan.archive": PlanArchive}
