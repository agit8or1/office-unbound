"""Closed typed action catalog -> plan -> approval -> single-use job -> execution (all audited)."""
import json
import re
import uuid
from datetime import datetime, timezone
from enum import StrEnum
from typing import Literal, Self
from urllib.parse import urlparse
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator
from sqlalchemy import text
from sqlalchemy.orm import Session

from . import audit
from .proxmox import ProxmoxReadClient, normalize_fingerprint
from .runtime import Runtime


class ActionType(StrEnum):
    endpoint_register = "endpoint.register"
    inventory_refresh = "inventory.refresh"


class EndpointRegister(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,62}$")
    type: Literal["proxmox"]
    base_url: str
    token_id: str = Field(pattern=r"^[^\s!@]+@[A-Za-z0-9._-]+![A-Za-z0-9._-]+$", description="user@realm!tokenname")
    token_secret: SecretStr = Field(min_length=8, max_length=200)
    ca_pem: str | None = Field(default=None, max_length=100_000)
    fingerprint_sha256: str | None = None

    @field_validator("base_url")
    @classmethod
    def _https(cls, v: str) -> str:
        u = urlparse(v)
        if u.scheme != "https" or not u.hostname or u.username or u.password or u.path not in ("", "/") or u.query or u.fragment:
            raise ValueError("base_url must be https://host[:port] with no credentials/path")
        return f"https://{u.netloc}"

    @field_validator("ca_pem")
    @classmethod
    def _pem(cls, v: str | None) -> str | None:
        if v is not None and "BEGIN CERTIFICATE" not in v:
            raise ValueError("ca_pem must contain a PEM certificate")
        return v

    @field_validator("fingerprint_sha256")
    @classmethod
    def _fp(cls, v: str | None) -> str | None:
        return normalize_fingerprint(v) if v is not None else None

    @model_validator(mode="after")
    def _one_trust(self) -> Self:
        if bool(self.ca_pem) == bool(self.fingerprint_sha256):
            raise ValueError("TLS trust is required: provide exactly one of ca_pem or fingerprint_sha256")
        return self


class InventoryRefresh(BaseModel):
    model_config = ConfigDict(extra="forbid")
    endpoint_id: UUID


CATALOG: dict[ActionType, dict] = {
    ActionType.endpoint_register: {"model": EndpointRegister, "risk": "high", "secrets": ("token_secret",)},
    ActionType.inventory_refresh: {"model": InventoryRefresh, "risk": "low", "secrets": ()},
}


class PlanError(Exception):
    def __init__(self, status: int, msg: str):
        self.status, self.msg = status, msg


def create_plan(db: Session, rt: Runtime, user, action: ActionType, params: dict, ip: str | None) -> dict:
    spec = CATALOG[action]
    p = spec["model"].model_validate(params)  # ValidationError -> 422 at the API layer
    full = p.model_dump(mode="json")
    for k in spec["secrets"]:
        full[k] = p.__dict__[k].get_secret_value()
    secret_part = {k: full.pop(k) for k in spec["secrets"]}
    if action == ActionType.inventory_refresh:
        if not db.execute(text("SELECT 1 FROM endpoints WHERE id = :i"), {"i": str(p.endpoint_id)}).first():
            raise PlanError(404, "endpoint not found")
    pid = uuid.uuid4()
    enc = rt.vault.encrypt(json.dumps(secret_part).encode(), f"plan:{pid}") if secret_part else None
    auto = spec["risk"] == "low"
    db.execute(text(
        "INSERT INTO plans (id, action, params, secret_enc, risk, status, requested_by, decided_at) "
        "VALUES (:id, :a, CAST(:p AS jsonb), :s, :r, :st, :u, :d)"),
        {"id": str(pid), "a": action.value, "p": audit.canon(full), "s": enc, "r": spec["risk"],
         "st": "approved" if auto else "pending_approval", "u": user.id, "d": datetime.now(timezone.utc) if auto else None})
    audit.append(db, "plan.create", actor_id=user.id, actor_name=user.username, ip=ip, resource="plan", resource_id=str(pid),
                 details={"action": action.value, "risk": spec["risk"], "params": full, "auto_approved": auto})
    job_id = _enqueue(db, pid, action, user, ip, auto=True) if auto else None
    db.commit()
    return {"plan_id": str(pid), "status": "approved" if auto else "pending_approval", "risk": spec["risk"], "job_id": job_id}


def _enqueue(db: Session, plan_id, action, user, ip, auto: bool = False) -> str:
    jid = db.execute(text("INSERT INTO jobs (plan_id, action, status) VALUES (:p, :a, 'queued') RETURNING id"),
                     {"p": str(plan_id), "a": str(getattr(action, "value", action))}).scalar()
    audit.append(db, "job.queued", actor_id=user.id, actor_name=user.username, ip=ip, resource="job", resource_id=str(jid),
                 details={"plan_id": str(plan_id), "auto_approved": auto})
    return str(jid)


def decide_plan(db: Session, user, plan_id: UUID, approve: bool, ip: str | None) -> dict:
    """Caller has already enforced role >= approver."""
    plan = db.execute(text("SELECT * FROM plans WHERE id = :i FOR UPDATE"), {"i": str(plan_id)}).first()
    if plan is None:
        raise PlanError(404, "plan not found")
    if plan.requested_by == user.id:
        audit.append(db, "plan.self_decision_rejected", actor_id=user.id, actor_name=user.username, ip=ip,
                     resource="plan", resource_id=str(plan_id))
        db.commit()
        raise PlanError(403, "requester cannot approve or reject their own plan")
    if plan.status != "pending_approval":
        raise PlanError(409, f"plan is already {plan.status}")
    db.execute(text("UPDATE plans SET status = :s, decided_by = :u, decided_at = now() WHERE id = :i"),
               {"s": "approved" if approve else "rejected", "u": user.id, "i": str(plan_id)})
    audit.append(db, "plan.approve" if approve else "plan.reject", actor_id=user.id, actor_name=user.username, ip=ip,
                 resource="plan", resource_id=str(plan_id), details={"action": plan.action})
    job_id = _enqueue(db, plan_id, plan.action, user, ip) if approve else None
    if not approve:
        db.execute(text("UPDATE plans SET secret_enc = NULL WHERE id = :i"), {"i": str(plan_id)})
    db.commit()
    return {"plan_id": str(plan_id), "status": "approved" if approve else "rejected", "job_id": job_id}


# ---- execution ------------------------------------------------------------------

def claim_job(rt: Runtime) -> dict | None:
    """Atomically claim one queued job. Concurrent claimers never get the same row."""
    with rt.session() as db:
        row = db.execute(text(
            "SELECT id, plan_id, action FROM jobs WHERE status = 'queued' ORDER BY created_at "
            "LIMIT 1 FOR UPDATE SKIP LOCKED")).first()
        if row is None:
            return None
        db.execute(text("UPDATE jobs SET status = 'running', started_at = now() WHERE id = :i"), {"i": row.id})
        audit.append(db, "job.started", actor_name="worker", resource="job", resource_id=str(row.id), details={"action": row.action})
        db.commit()
        return {"id": row.id, "plan_id": row.plan_id, "action": row.action}


def run_job(rt: Runtime, job: dict) -> None:
    result = error = None
    try:
        with rt.session() as db:
            plan = db.execute(text("SELECT * FROM plans WHERE id = :i"), {"i": job["plan_id"]}).first()
            secrets_ = json.loads(rt.vault.decrypt(plan.secret_enc, f"plan:{plan.id}")) if plan.secret_enc else {}
            action = ActionType(job["action"])
            params = {**plan.params, **secrets_}
            m = CATALOG[action]["model"].model_validate(params)
            result = _EXEC[action](rt, db, m, plan)
            db.commit()
    except Exception as e:  # noqa: BLE001 - recorded as structured job error
        error = {"type": type(e).__name__, "message": str(e)[:500]}
    with rt.session() as db:
        db.execute(text(
            "UPDATE jobs SET status = :s, finished_at = now(), result = CAST(:r AS jsonb), error = CAST(:e AS jsonb) WHERE id = :i"),
            {"s": "failed" if error else "succeeded", "r": json.dumps(result) if result else None,
             "e": json.dumps(error) if error else None, "i": job["id"]})
        db.execute(text("UPDATE plans SET secret_enc = NULL WHERE id = :i"), {"i": job["plan_id"]})
        audit.append(db, "job.failed" if error else "job.succeeded", actor_name="worker", resource="job",
                     resource_id=str(job["id"]), details={"action": job["action"], "result": result, "error": error})
        db.commit()


def _client_for(rt: Runtime, ep) -> ProxmoxReadClient:
    secret = rt.vault.decrypt(ep.token_secret_enc, f"endpoint-token:{ep.id}").decode()
    return ProxmoxReadClient(ep.base_url, ep.token_id, secret, ca_pem=ep.ca_pem, fingerprint_sha256=ep.fingerprint_sha256)


def collect_inventory(rt: Runtime, db: Session, endpoint_id) -> dict:
    ep = db.execute(text("SELECT * FROM endpoints WHERE id = :i"), {"i": str(endpoint_id)}).first()
    if ep is None:
        raise RuntimeError("endpoint not found")
    c = _client_for(rt, ep)
    try:
        data = c.inventory()
    finally:
        c.close()
    sid = db.execute(text(
        "INSERT INTO inventory_snapshots (endpoint_id, collected_at, data) VALUES (:e, now(), CAST(:d AS jsonb)) RETURNING id"),
        {"e": str(ep.id), "d": json.dumps(data)}).scalar()
    return {"snapshot_id": sid, "nodes": len(data["nodes"])}


def _exec_register(rt: Runtime, db: Session, m: EndpointRegister, plan) -> dict:
    eid = uuid.uuid4()
    secret = m.token_secret.get_secret_value()
    c = ProxmoxReadClient(m.base_url, m.token_id, secret, ca_pem=m.ca_pem, fingerprint_sha256=m.fingerprint_sha256)
    try:
        version = c.version()  # connectivity + TLS trust + credential check before we persist anything
    finally:
        c.close()
    db.execute(text(
        "INSERT INTO endpoints (id, name, type, base_url, token_id, token_secret_enc, ca_pem, fingerprint_sha256, created_by) "
        "VALUES (:id, :n, :t, :u, :ti, :ts, :ca, :fp, :cb)"),
        {"id": str(eid), "n": m.name, "t": m.type, "u": m.base_url, "ti": m.token_id,
         "ts": rt.vault.encrypt(secret.encode(), f"endpoint-token:{eid}"), "ca": m.ca_pem, "fp": m.fingerprint_sha256,
         "cb": str(plan.requested_by)})
    audit.append(db, "endpoint.registered", actor_name="worker", resource="endpoint", resource_id=str(eid),
                 details={"name": m.name, "base_url": m.base_url, "token_id": m.token_id,
                          "trust": "fingerprint" if m.fingerprint_sha256 else "ca_bundle", "pve_version": version.get("version")})
    return {"endpoint_id": str(eid), "pve_version": version.get("version")}


def _exec_refresh(rt: Runtime, db: Session, m: InventoryRefresh, plan) -> dict:
    return collect_inventory(rt, db, m.endpoint_id)


_EXEC = {ActionType.endpoint_register: _exec_register, ActionType.inventory_refresh: _exec_refresh}
