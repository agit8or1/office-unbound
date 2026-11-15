"""Closed typed action catalog -> plan -> approval -> single-use job -> execution (all audited)."""
import hashlib
import json
import logging
import re
import threading
import time
import uuid
from datetime import datetime, timezone
from enum import StrEnum
from typing import Literal, Self
from urllib.parse import urlparse
from uuid import UUID

from cryptography import x509
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator
from sqlalchemy import text
from sqlalchemy.orm import Session

from . import audit, auth
from .proxmox import ProxmoxError, ProxmoxReadClient, check_destination, normalize_fingerprint
from .runtime import Runtime
from .vault import VaultError

log = logging.getLogger("ics.actions")


class ActionType(StrEnum):
    endpoint_register = "endpoint.register"
    inventory_refresh = "inventory.refresh"
    user_create = "user.create"
    user_set_role = "user.set_role"


class EndpointRegister(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,62}$")
    type: Literal["proxmox"]
    base_url: str
    token_id: str = Field(pattern=r"^[A-Za-z0-9._-]+@[A-Za-z0-9._-]+![A-Za-z0-9._-]+$", description="user@realm!tokenname")
    token_secret: SecretStr = Field(description="Proxmox API token secret (surrounding whitespace is stripped; [A-Za-z0-9_-]{8,200})")
    ca_pem: str | None = Field(default=None, max_length=100_000)
    fingerprint_sha256: str | None = None

    @field_validator("token_secret", mode="before")
    @classmethod
    def _secret(cls, v):
        """Normalise (strip) and validate strictly. The error text never includes the value."""
        raw = v.get_secret_value() if isinstance(v, SecretStr) else v
        if not isinstance(raw, str):
            raise ValueError("token_secret must be a string")
        raw = raw.strip()
        if not re.fullmatch(r"[A-Za-z0-9_-]{8,200}", raw):
            raise ValueError("token_secret must be 8-200 characters of [A-Za-z0-9_-] (no whitespace or other characters)")
        return raw

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
        if v is None:
            return v
        try:
            certs = x509.load_pem_x509_certificates(v.encode())
        except Exception:  # noqa: BLE001
            raise ValueError("ca_pem must contain valid PEM certificate(s)") from None
        if not certs:
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


class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$")
    role: Literal["viewer", "operator", "approver", "admin"]


class UserSetRole(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$")
    role: Literal["viewer", "operator", "approver", "admin"]


CATALOG: dict[ActionType, dict] = {
    ActionType.endpoint_register: {"model": EndpointRegister, "risk": "high", "secrets": ("token_secret",)},
    ActionType.inventory_refresh: {"model": InventoryRefresh, "risk": "low", "secrets": ()},
    ActionType.user_create: {"model": UserCreate, "risk": "high", "secrets": (), "admin_only": True},
    ActionType.user_set_role: {"model": UserSetRole, "risk": "high", "secrets": (), "admin_only": True},
}


class PlanIntegrityError(Exception):
    pass


class JobTimeout(Exception):
    pass


def endpoint_binding(base_url: str, token_id: str, fingerprint: str | None, ca_pem: str | None) -> str:
    """Digest of an endpoint's trust anchors; bound into approvals and into the token's vault AAD (M5)."""
    return hashlib.sha256(json.dumps([base_url, token_id, fingerprint or "", hashlib.sha256((ca_pem or "").encode()).hexdigest()]).encode()).hexdigest()


def plan_digest(action: str, params: dict, secret_enc: bytes | None, binding: str | None) -> str:
    body = {"action": action, "params": audit.sanitize(params),
            "secret_sha256": hashlib.sha256(bytes(secret_enc)).hexdigest() if secret_enc else None, "binding": binding}
    return hashlib.sha256(audit.canon(body).encode()).hexdigest()


def _ep_binding(db: Session, endpoint_id) -> str | None:
    ep = db.execute(text("SELECT base_url, token_id, fingerprint_sha256, ca_pem FROM endpoints WHERE id = :i"), {"i": str(endpoint_id)}).first()
    return endpoint_binding(ep.base_url, ep.token_id, ep.fingerprint_sha256, ep.ca_pem) if ep else None


class PlanError(Exception):
    def __init__(self, status: int, msg: str):
        self.status, self.msg = status, msg


def create_plan(db: Session, rt: Runtime, user, action: ActionType, params: dict, ip: str | None) -> dict:
    spec = CATALOG[action]
    if spec.get("admin_only") and auth.RANK[user.role] < auth.RANK["admin"]:
        raise PlanError(403, "requires role admin")
    p = spec["model"].model_validate(params)  # ValidationError -> 422 at the API layer
    full = p.model_dump(mode="json")
    for k in spec["secrets"]:
        full[k] = p.__dict__[k].get_secret_value()
    secret_part = {k: full.pop(k) for k in spec["secrets"]}
    binding = None
    extra: dict = {}
    if action == ActionType.inventory_refresh:
        binding = _ep_binding(db, p.endpoint_id)
        if binding is None:
            raise PlanError(404, "endpoint not found")
    elif action == ActionType.endpoint_register:
        try:  # SSRF guard (L3); the resolved addresses are shown to the approver
            extra["resolved_ips"] = check_destination(urlparse(p.base_url).hostname, rt.settings.allow_loopback_endpoints)
        except ProxmoxError as e:
            raise PlanError(422, str(e)) from None
        if db.execute(text("SELECT 1 FROM endpoints WHERE name = :n"), {"n": p.name}).first():
            raise PlanError(409, "endpoint name already exists")
    elif action == ActionType.user_create:
        if db.execute(text("SELECT 1 FROM users WHERE username = :u"), {"u": p.username}).first():
            raise PlanError(409, "username already exists")
    elif action == ActionType.user_set_role:
        if not db.execute(text("SELECT 1 FROM users WHERE username = :u"), {"u": p.username}).first():
            raise PlanError(404, "user not found")
    pid = uuid.uuid4()
    enc = rt.vault.encrypt(json.dumps(secret_part).encode(), f"plan:{pid}") if secret_part else None
    digest = plan_digest(action.value, full, enc, binding)
    auto = spec["risk"] == "low"
    db.execute(text(
        "INSERT INTO plans (id, action, params, secret_enc, risk, status, requested_by, decided_at, params_hash) "
        "VALUES (:id, :a, CAST(:p AS jsonb), :s, :r, :st, :u, :d, :h)"),
        {"id": str(pid), "a": action.value, "p": audit.canon(full), "s": enc, "r": spec["risk"],
         "st": "approved" if auto else "pending_approval", "u": user.id, "d": datetime.now(timezone.utc) if auto else None, "h": digest})
    audit.append(db, "plan.create", actor_id=user.id, actor_name=user.username, ip=ip, resource="plan", resource_id=str(pid),
                 details={"action": action.value, "risk": spec["risk"], "params": full, "auto_approved": auto,
                          "params_hash": digest, **extra})
    job_id = None
    if auto:  # policy approval for low risk; recorded like any approval so the job can verify it
        db.execute(text("INSERT INTO plan_approvals (plan_id, approver_id, params_hash) VALUES (:p, :u, :h)"),
                   {"p": str(pid), "u": user.id, "h": digest})
        job_id = _enqueue(db, pid, action, user, ip, auto=True)
    db.commit()
    return {"plan_id": str(pid), "status": "approved" if auto else "pending_approval", "risk": spec["risk"], "job_id": job_id,
            "params_hash": digest, "approvals_required": 1 if auto else rt.settings.required_approvals_high, **extra}


def _enqueue(db: Session, plan_id, action, user, ip, auto: bool = False) -> str:
    jid = db.execute(text("INSERT INTO jobs (plan_id, action, status) VALUES (:p, :a, 'queued') RETURNING id"),
                     {"p": str(plan_id), "a": str(getattr(action, "value", action))}).scalar()
    audit.append(db, "job.queued", actor_id=user.id, actor_name=user.username, ip=ip, resource="job", resource_id=str(jid),
                 details={"plan_id": str(plan_id), "auto_approved": auto})
    return str(jid)


def _provenance_conflict(db: Session, approver_id, requester_id) -> bool:
    """True if the approver (or anyone in their creation/elevation chain) was created or role-granted by the requester."""
    seen, frontier = set(), [approver_id]
    for _ in range(10):
        nxt = []
        for uid in frontier:
            r = db.execute(text("SELECT created_by, role_set_by FROM users WHERE id = :i"), {"i": str(uid)}).first()
            if r is None:
                continue
            for parent in (r.created_by, r.role_set_by):
                if parent is None:
                    continue
                if parent == requester_id:
                    return True
                if parent not in seen:
                    seen.add(parent)
                    nxt.append(parent)
        frontier = nxt
        if not frontier:
            break
    return False


def _refuse(db, user, ip, plan_id, event: str, msg: str):
    audit.append(db, event, actor_id=user.id, actor_name=user.username, ip=ip, resource="plan", resource_id=str(plan_id))
    db.commit()
    raise PlanError(403, msg)


def decide_plan(db: Session, rt: Runtime, user, plan_id: UUID, approve: bool, ip: str | None) -> dict:
    """Caller has already enforced role >= approver. High-risk plans need `required_approvals_high` distinct approvers."""
    plan = db.execute(text("SELECT * FROM plans WHERE id = :i FOR UPDATE"), {"i": str(plan_id)}).first()
    if plan is None:
        raise PlanError(404, "plan not found")
    if plan.requested_by == user.id:
        _refuse(db, user, ip, plan_id, "plan.self_decision_rejected", "requester cannot approve or reject their own plan")
    if _provenance_conflict(db, user.id, plan.requested_by):
        _refuse(db, user, ip, plan_id, "plan.provenance_rejected",
                "this approver was created or elevated by the requester and cannot decide the requester's plans")
    if plan.action == ActionType.user_set_role.value and plan.params.get("username") == user.username:
        _refuse(db, user, ip, plan_id, "plan.self_decision_rejected", "cannot decide a plan that changes your own role")
    if plan.status != "pending_approval":
        raise PlanError(409, f"plan is already {plan.status}")
    if (datetime.now(timezone.utc) - plan.created_at).total_seconds() > rt.settings.plan_expiry_seconds:
        db.execute(text("UPDATE plans SET secret_enc = NULL, status = 'rejected', decided_at = now() WHERE id = :i"), {"i": str(plan_id)})
        audit.append(db, "plan.expired", actor_name="system", resource="plan", resource_id=str(plan_id))
        db.commit()
        raise PlanError(409, "plan expired")
    if not approve:
        db.execute(text("UPDATE plans SET status = 'rejected', decided_by = :u, decided_at = now(), secret_enc = NULL WHERE id = :i"),
                   {"u": user.id, "i": str(plan_id)})
        audit.append(db, "plan.reject", actor_id=user.id, actor_name=user.username, ip=ip, resource="plan", resource_id=str(plan_id),
                     details={"action": plan.action})
        db.commit()
        return {"plan_id": str(plan_id), "status": "rejected", "job_id": None}
    if db.execute(text("SELECT 1 FROM plan_approvals WHERE plan_id = :p AND approver_id = :u"), {"p": str(plan_id), "u": user.id}).first():
        raise PlanError(409, "you have already approved this plan")
    # the approval binds to the digest computed at plan time over the exact params/secret/trust anchors (M5)
    db.execute(text("INSERT INTO plan_approvals (plan_id, approver_id, params_hash) VALUES (:p, :u, :h)"),
               {"p": str(plan_id), "u": user.id, "h": plan.params_hash})
    n = db.execute(text("SELECT count(*) FROM plan_approvals WHERE plan_id = :p"), {"p": str(plan_id)}).scalar()
    need = rt.settings.required_approvals_high if plan.risk == "high" else 1
    audit.append(db, "plan.approve", actor_id=user.id, actor_name=user.username, ip=ip, resource="plan", resource_id=str(plan_id),
                 details={"action": plan.action, "params_hash": plan.params_hash, "approvals": n, "required": need})
    job_id = None
    status = "pending_approval"
    if n >= need:
        db.execute(text("UPDATE plans SET status = 'approved', decided_by = :u, decided_at = now() WHERE id = :i"),
                   {"u": user.id, "i": str(plan_id)})
        job_id = _enqueue(db, plan_id, plan.action, user, ip)
        status = "approved"
    db.commit()
    return {"plan_id": str(plan_id), "status": status, "job_id": job_id, "approvals": n, "approvals_required": need}


# ---- execution ------------------------------------------------------------------

def claim_job(rt: Runtime) -> dict | None:
    """Atomically claim one queued job. Concurrent claimers never get the same row. Sets a lease (L2)."""
    s = rt.settings
    with rt.session() as db:
        row = db.execute(text(
            "SELECT id, plan_id, action FROM jobs WHERE status = 'queued' ORDER BY created_at "
            "LIMIT 1 FOR UPDATE SKIP LOCKED")).first()
        if row is None:
            return None
        db.execute(text("UPDATE jobs SET status = 'running', started_at = now(), "
                        "lease_expires_at = now() + make_interval(secs => :l) WHERE id = :i"),
                   {"i": row.id, "l": s.job_timeout_seconds + s.job_lease_slack_seconds})
        audit.append(db, "job.started", actor_name="worker", resource="job", resource_id=str(row.id), details={"action": row.action})
        db.commit()
        return {"id": row.id, "plan_id": row.plan_id, "action": row.action}


def reap_expired(rt: Runtime) -> int:
    """Fail jobs whose lease expired (never re-run: at-most-once), wipe their plan secrets, and wipe secrets of expired pending plans."""
    n = 0
    with rt.session() as db:
        rows = db.execute(text(
            "SELECT id, plan_id, action FROM jobs WHERE status = 'running' AND "
            "COALESCE(lease_expires_at, started_at + interval '10 minutes') < now() FOR UPDATE SKIP LOCKED")).all()
        for r in rows:
            err = {"type": "LeaseExpired", "message": "job lease expired (worker crashed or hung); not re-run"}
            db.execute(text("UPDATE jobs SET status = 'failed', finished_at = now(), error = CAST(:e AS jsonb) WHERE id = :i"),
                       {"e": json.dumps(err), "i": r.id})
            db.execute(text("UPDATE plans SET secret_enc = NULL WHERE id = :i"), {"i": r.plan_id})
            audit.append(db, "job.failed", actor_name="worker", resource="job", resource_id=str(r.id),
                         details={"action": r.action, "error": err})
            n += 1
        db.execute(text("UPDATE plans SET secret_enc = NULL WHERE status = 'pending_approval' AND secret_enc IS NOT NULL "
                        "AND created_at < now() - make_interval(secs => :e)"), {"e": rt.settings.plan_expiry_seconds})
        db.commit()
    return n


_SAFE_ERRORS = (ProxmoxError, VaultError, PlanIntegrityError, JobTimeout)


def _error_dict(e: BaseException, known: list[str]) -> dict:
    if isinstance(e, _SAFE_ERRORS):
        msg = str(e)[:500]
    else:  # arbitrary exceptions (pydantic, SQLAlchemy, httpx) can embed parameter values: never pass their text through
        log.error("job failed with %s", type(e).__name__)
        msg = "internal error; see the server log"
    return {"type": type(e).__name__, "message": audit.redact(msg, known)}


def _verify_approval(rt: Runtime, db: Session, plan) -> None:
    """Re-verify, immediately before executing, that the plan still matches what was approved (M5) and approvals suffice."""
    binding = _ep_binding(db, plan.params["endpoint_id"]) if plan.action == ActionType.inventory_refresh.value else None
    digest = plan_digest(plan.action, plan.params, plan.secret_enc, binding)
    appr = db.execute(text("SELECT approver_id, params_hash FROM plan_approvals WHERE plan_id = :p"), {"p": str(plan.id)}).all()
    need = rt.settings.required_approvals_high if plan.risk == "high" else 1
    if digest != plan.params_hash or not appr or any(a.params_hash != digest for a in appr):
        raise PlanIntegrityError("plan parameters or endpoint trust anchors changed after approval; refusing to execute")
    if len({a.approver_id for a in appr}) < need:
        raise PlanIntegrityError("insufficient approvals recorded; refusing to execute")
    if plan.risk == "high" and any(a.approver_id == plan.requested_by for a in appr):
        raise PlanIntegrityError("requester appears among approvers; refusing to execute")


def run_job(rt: Runtime, job: dict) -> None:
    result = error = None
    known: list[str] = []
    box: dict = {}
    cancelled, lock = threading.Event(), threading.Lock()

    def work() -> None:
        try:
            with rt.session() as db:
                plan = db.execute(text("SELECT * FROM plans WHERE id = :i"), {"i": job["plan_id"]}).first()
                _verify_approval(rt, db, plan)
                secrets_ = json.loads(rt.vault.decrypt(plan.secret_enc, f"plan:{plan.id}")) if plan.secret_enc else {}
                known.extend(str(v) for v in secrets_.values())
                action = ActionType(job["action"])
                m = CATALOG[action]["model"].model_validate({**plan.params, **secrets_})
                res = _EXEC[action](rt, db, m, plan, known)
                with lock:
                    if cancelled.is_set():
                        db.rollback()
                        return
                    box["result"] = res
                    db.commit()
        except BaseException as e:  # noqa: BLE001
            box["error"] = e

    t = threading.Thread(target=work, daemon=True, name=f"ics-job-{job['id']}")
    t.start()
    t.join(rt.settings.job_timeout_seconds)
    with lock:
        if t.is_alive() and "result" not in box:
            cancelled.set()
            error = _error_dict(JobTimeout(f"job exceeded its {rt.settings.job_timeout_seconds}s wall-clock budget"), known)
        elif "error" in box:
            error = _error_dict(box["error"], known)
        else:
            result = audit.redact(audit.sanitize(box.get("result")), known) if box.get("result") else None
    for attempt in range(3):  # finalize with retry so a transient DB error cannot leave the job 'running' with its secret
        try:
            with rt.session() as db:
                db.execute(text(
                    "UPDATE jobs SET status = :s, finished_at = now(), result = CAST(:r AS jsonb), error = CAST(:e AS jsonb) WHERE id = :i"),
                    {"s": "failed" if error else "succeeded", "r": audit.canon(result) if result else None,
                     "e": audit.canon(error) if error else None, "i": job["id"]})
                db.execute(text("UPDATE plans SET secret_enc = NULL WHERE id = :i"), {"i": job["plan_id"]})
                audit.append(db, "job.failed" if error else "job.succeeded", actor_name="worker", resource="job",
                             resource_id=str(job["id"]), details=audit.redact({"action": job["action"], "result": result, "error": error}, known))
                db.commit()
            return
        except Exception:  # noqa: BLE001
            log.exception("job finalize failed (attempt %d)", attempt + 1)
            time.sleep(0.5 * (attempt + 1))


def _client_for(rt: Runtime, ep, known: list[str]) -> ProxmoxReadClient:
    aad = f"endpoint-token:{ep.id}:{endpoint_binding(ep.base_url, ep.token_id, ep.fingerprint_sha256, ep.ca_pem)}"
    secret = rt.vault.decrypt(ep.token_secret_enc, aad).decode()
    known.append(secret)
    return _new_client(rt, ep.base_url, ep.token_id, secret, ep.ca_pem, ep.fingerprint_sha256)


def _new_client(rt: Runtime, base_url, token_id, secret, ca_pem, fp) -> ProxmoxReadClient:
    s = rt.settings
    return ProxmoxReadClient(base_url, token_id, secret, ca_pem=ca_pem, fingerprint_sha256=fp, deadline=s.pve_request_deadline_seconds,
                             max_bytes=s.pve_max_response_bytes, allow_loopback=s.allow_loopback_endpoints)


def collect_inventory(rt: Runtime, db: Session, endpoint_id, known: list[str] | None = None) -> dict:
    ep = db.execute(text("SELECT * FROM endpoints WHERE id = :i"), {"i": str(endpoint_id)}).first()
    if ep is None:
        raise PlanIntegrityError("endpoint not found")
    c = _client_for(rt, ep, known if known is not None else [])
    try:
        data = c.inventory()
    finally:
        c.close()
    data = audit.sanitize_numbers(data)
    sid = db.execute(text(
        "INSERT INTO inventory_snapshots (endpoint_id, collected_at, data) VALUES (:e, now(), CAST(:d AS jsonb)) RETURNING id"),
        {"e": str(ep.id), "d": json.dumps(data)}).scalar()
    db.execute(text("DELETE FROM inventory_snapshots WHERE endpoint_id = :e AND id NOT IN "
                    "(SELECT id FROM inventory_snapshots WHERE endpoint_id = :e ORDER BY collected_at DESC, id DESC LIMIT :n)"),
               {"e": str(ep.id), "n": rt.settings.snapshot_retention})
    return {"snapshot_id": sid, "nodes": len(data["nodes"])}


def _exec_register(rt: Runtime, db: Session, m: EndpointRegister, plan, known: list[str]) -> dict:
    eid = uuid.uuid4()
    secret = m.token_secret.get_secret_value()
    c = _new_client(rt, m.base_url, m.token_id, secret, m.ca_pem, m.fingerprint_sha256)
    try:
        version = c.version()  # connectivity + TLS trust + credential check before we persist anything
    finally:
        c.close()
    pve_version = audit.sanitize(version.get("version") if isinstance(version, dict) else None)  # remote-controlled value
    aad = f"endpoint-token:{eid}:{endpoint_binding(m.base_url, m.token_id, m.fingerprint_sha256, m.ca_pem)}"
    db.execute(text(
        "INSERT INTO endpoints (id, name, type, base_url, token_id, token_secret_enc, ca_pem, fingerprint_sha256, created_by) "
        "VALUES (:id, :n, :t, :u, :ti, :ts, :ca, :fp, :cb)"),
        {"id": str(eid), "n": m.name, "t": m.type, "u": m.base_url, "ti": m.token_id,
         "ts": rt.vault.encrypt(secret.encode(), aad), "ca": m.ca_pem, "fp": m.fingerprint_sha256,
         "cb": str(plan.requested_by)})
    audit.append(db, "endpoint.registered", actor_name="worker", resource="endpoint", resource_id=str(eid),
                 details={"name": m.name, "base_url": m.base_url, "token_id": m.token_id,
                          "trust": "fingerprint" if m.fingerprint_sha256 else "ca_bundle", "pve_version": pve_version})
    return {"endpoint_id": str(eid), "pve_version": pve_version}


def _exec_refresh(rt: Runtime, db: Session, m: InventoryRefresh, plan, known: list[str]) -> dict:
    return collect_inventory(rt, db, m.endpoint_id, known)


def _exec_user_create(rt: Runtime, db: Session, m: UserCreate, plan, known: list[str]) -> dict:
    """Creates an *invited* account: no credentials exist. The enrollment token is issued on the host by the CLI."""
    uid = auth.create_invite(db, rt, m.username, m.role, created_by=plan.requested_by, actor="worker", commit=False)
    return {"user_id": uid, "invite": True, "role": m.role}


def _exec_user_set_role(rt: Runtime, db: Session, m: UserSetRole, plan, known: list[str]) -> dict:
    r = db.execute(text("UPDATE users SET role = :r, role_set_by = :by, role_set_at = now() WHERE username = :u RETURNING id"),
                   {"r": m.role, "by": str(plan.requested_by), "u": m.username}).first()
    if r is None:
        raise PlanIntegrityError("user not found")
    audit.append(db, "user.role_set", actor_name="worker", resource="user", resource_id=str(r.id),
                 details={"username": m.username, "role": m.role, "requested_by": str(plan.requested_by)})
    return {"user_id": str(r.id), "role": m.role}


_EXEC = {ActionType.endpoint_register: _exec_register, ActionType.inventory_refresh: _exec_refresh,
         ActionType.user_create: _exec_user_create, ActionType.user_set_role: _exec_user_set_role}
