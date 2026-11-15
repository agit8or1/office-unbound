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

from . import agentclient, alerts, audit, auth, checks as checkmod, identity, monitor
from .identity import IdentityError
from .agentclient import AgentError
from .proxmox import ProxmoxError, ProxmoxReadClient, check_destination, normalize_fingerprint
from .runtime import Runtime
from .vault import VaultError

log = logging.getLogger("ics.actions")


class ActionType(StrEnum):
    endpoint_register = "endpoint.register"
    inventory_refresh = "inventory.refresh"
    user_create = "user.create"
    user_set_role = "user.set_role"
    node_enroll = "node.enroll"
    check_create = "check.create"
    check_set_enabled = "check.set_enabled"
    check_bind_remediation = "check.bind_remediation"
    maintenance_create = "maintenance.create"
    alert_channel_create = "alert_channel.create"
    alert_channel_test = "alert_channel.test"
    incident_ack = "incident.ack"
    runbook_execute = "runbook.execute"
    idm_stack_register = "idm.stack.register"
    idm_user_create = "idm.user.create"
    idm_user_update_groups = "idm.user.update_groups"
    idm_user_disable = "idm.user.disable"
    idm_user_enable = "idm.user.enable"
    idm_user_delete = "idm.user.delete"
    idm_reconcile = "idm.reconcile"


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


NAME_RE = r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$"


class NodeEnroll(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=NAME_RE)
    address: str = Field(pattern=checkmod.HOST_RE)
    port: int = Field(default=8443, ge=1, le=65535)
    tls_fingerprint_sha256: str = Field(description="SHA-256 of the agent's TLS certificate, read from the node console")
    agent_key_fingerprint_sha256: str = Field(description="SHA-256 of the agent's Ed25519 public key, read from the node console")
    enrollment_token: SecretStr = Field(description="one-time enrollment token printed on the node console")

    @field_validator("tls_fingerprint_sha256", "agent_key_fingerprint_sha256")
    @classmethod
    def _fp(cls, v):
        return normalize_fingerprint(v)

    @field_validator("enrollment_token", mode="before")
    @classmethod
    def _tok(cls, v):
        raw = v.get_secret_value() if isinstance(v, SecretStr) else v
        if not isinstance(raw, str) or not re.fullmatch(r"[A-Za-z0-9_-]{20,100}", raw.strip()):
            raise ValueError("enrollment_token has an invalid format")
        return raw.strip()


class CheckCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=NAME_RE)
    kind: Literal["http", "tcp_tls", "imap_login", "smtp_banner", "ews_getfolder"]
    config: dict
    password: SecretStr | None = Field(default=None, description="mailbox/EWS password for imap_login / ews_getfolder (stored in the vault)")
    interval_seconds: int = Field(default=60, ge=5, le=86400)
    fail_threshold: int = Field(default=3, ge=1, le=20)
    recover_threshold: int = Field(default=2, ge=1, le=20)
    remediation: monitor.Remediation | None = None

    @model_validator(mode="after")
    def _cfg(self) -> Self:
        self.config = checkmod.validate_config(self.kind, self.config)  # ValueError/ValidationError -> 422
        need = self.kind in checkmod.NEEDS_PASSWORD
        if need and not self.password:
            raise ValueError(f"{self.kind} needs a password")
        if not need and self.password:
            raise ValueError(f"{self.kind} takes no password")
        return self


class CheckSetEnabled(BaseModel):
    model_config = ConfigDict(extra="forbid")
    check_id: UUID
    enabled: bool


class CheckBindRemediation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    check_id: UUID
    remediation: monitor.Remediation | None = Field(description="null removes the policy")


class MaintenanceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=100)
    check_id: UUID | None = None
    duration_minutes: int = Field(ge=1, le=480)
    reason: str = Field(default="", max_length=200)


class AlertChannelCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=NAME_RE)
    kind: Literal["email", "webhook", "pushover", "sms"]
    config: dict
    secret: SecretStr | None = Field(default=None, description="email password / webhook HMAC key / pushover app token")
    enabled: bool | None = None

    @model_validator(mode="after")
    def _cfg(self) -> Self:
        self.config = alerts.validate_config(self.kind, self.config)
        alerts.validate_secret(self.kind, self.secret.get_secret_value() if self.secret else None, self.config)
        if self.kind in alerts.DISABLED_KINDS:
            if self.enabled:
                raise ValueError(f"{self.kind} is a paid third-party service and cannot be enabled (ADR-0007)")
            self.enabled = False
        elif self.enabled is None:
            self.enabled = True
        return self


class AlertChannelTest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    channel_id: UUID


class IncidentAck(BaseModel):
    model_config = ConfigDict(extra="forbid")
    incident_id: UUID
    note: str = Field(default="", max_length=200)


class RunbookExecute(BaseModel):
    model_config = ConfigDict(extra="forbid")
    node_id: UUID
    runbook: Literal["service.restart", "service.status", "disk.usage"]
    unit: str | None = Field(default=None, pattern=monitor.UNIT_RE)
    path: str | None = Field(default=None, pattern=r"^/[A-Za-z0-9_./-]{0,200}$")
    check_id: UUID | None = Field(default=None, description="re-run this check after the runbook and record verified recovery")
    attempt_id: int | None = None
    verify_timeout_seconds: int = Field(default=0, ge=0, le=45)
    require_approval: bool = Field(default=False, description="policy mode=approval: never auto-approve (review H2)")

    @model_validator(mode="after")
    def _chk(self) -> Self:
        if self.runbook.startswith("service.") and (not self.unit or self.path):
            raise ValueError("service runbooks need `unit` (and no path)")
        if self.runbook == "disk.usage" and (not self.path or self.unit):
            raise ValueError("disk.usage needs `path` (and no unit)")
        return self


def _runbook_risk(p: RunbookExecute) -> str:
    base = monitor.runbook_risk(p.runbook, p.unit)
    # Review H2: an "approval" policy must wait for a human even for low-risk units ("normal" = 1 approver ≠ requester).
    return "normal" if p.require_approval and base == "low" else base


CATALOG: dict[ActionType, dict] = {
    ActionType.endpoint_register: {"model": EndpointRegister, "risk": "high", "secrets": ("token_secret",)},
    ActionType.inventory_refresh: {"model": InventoryRefresh, "risk": "low", "secrets": ()},
    ActionType.user_create: {"model": UserCreate, "risk": "high", "secrets": (), "admin_only": True},
    ActionType.user_set_role: {"model": UserSetRole, "risk": "high", "secrets": (), "admin_only": True},
    ActionType.node_enroll: {"model": NodeEnroll, "risk": "high", "secrets": ("enrollment_token",)},
    ActionType.check_create: {"model": CheckCreate, "risk": "low", "secrets": ("password",)},
    ActionType.check_set_enabled: {"model": CheckSetEnabled, "risk": "low", "secrets": ()},
    ActionType.check_bind_remediation: {"model": CheckBindRemediation, "risk": "low", "secrets": ()},
    ActionType.maintenance_create: {"model": MaintenanceCreate, "risk": "low", "secrets": ()},
    ActionType.alert_channel_create: {"model": AlertChannelCreate, "risk": "high", "secrets": ("secret",)},
    ActionType.alert_channel_test: {"model": AlertChannelTest, "risk": "low", "secrets": ()},
    ActionType.incident_ack: {"model": IncidentAck, "risk": "low", "secrets": ()},
    ActionType.runbook_execute: {"model": RunbookExecute, "risk": _runbook_risk, "secrets": ()},
    # identity lifecycle (identity.py). "risk" here is the catalog default; create_plan computes the real tier (privileged groups raise it to high)
    ActionType.idm_stack_register: {"model": identity.StackRegister, "risk": "high", "secrets": identity.SECRETS["idm.stack.register"]},
    ActionType.idm_user_create: {"model": identity.UserCreate, "risk": "normal", "secrets": ()},
    ActionType.idm_user_update_groups: {"model": identity.UserUpdateGroups, "risk": "normal", "secrets": ()},
    ActionType.idm_user_disable: {"model": identity.UserDisable, "risk": "normal", "secrets": ()},
    ActionType.idm_user_enable: {"model": identity.UserEnable, "risk": "normal", "secrets": ()},
    ActionType.idm_user_delete: {"model": identity.UserDelete, "risk": "high", "secrets": ()},
    ActionType.idm_reconcile: {"model": identity.Reconcile, "risk": "low", "secrets": ()},
}
_IDM = {a for a in ActionType if a.value.startswith("idm.")}


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


# ---- plan-time prechecks for the monitoring / node actions ----------------------------------------------

def _guard(rt: Runtime, host: str | None) -> list[str]:
    if not host:
        return []
    try:
        return check_destination(host, rt.settings.allow_loopback_endpoints)
    except ProxmoxError as e:
        raise PlanError(422, str(e)) from None


def _validate_remediation(db: Session, rem) -> None:
    if rem is None:
        return
    node = db.execute(text("SELECT capabilities FROM nodes WHERE id = :i"), {"i": str(rem.node_id)}).first()
    if node is None:
        raise PlanError(404, "remediation node not found (enroll it first)")
    cap = node.capabilities.get(rem.runbook)
    if cap is None:
        raise PlanError(422, f"node does not offer runbook {rem.runbook}")
    if (rem.unit and rem.unit not in cap.get("units", [])) or (rem.path and rem.path not in cap.get("paths", [])):
        raise PlanError(422, "unit/path is not on that node's agent allowlist")


def _need(db, table: str, id_, what: str):
    r = db.execute(text(f"SELECT * FROM {table} WHERE id = :i"), {"i": str(id_)}).first()  # table names are constants below
    if r is None:
        raise PlanError(404, f"{what} not found")
    return r


def _pre_node_enroll(db, rt, p: NodeEnroll):
    if db.execute(text("SELECT 1 FROM nodes WHERE name = :n"), {"n": p.name}).first():
        raise PlanError(409, "node name already exists")
    return {"resolved_ips": _guard(rt, p.address)}


def _pre_check_create(db, rt, p: CheckCreate):
    if db.execute(text("SELECT 1 FROM checks WHERE name = :n"), {"n": p.name}).first():
        raise PlanError(409, "check name already exists")
    _validate_remediation(db, p.remediation)
    return {"resolved_ips": _guard(rt, checkmod.config_host(p.kind, p.config))}


def _pre_check_set_enabled(db, rt, p: CheckSetEnabled):
    _need(db, "checks", p.check_id, "check")


def _pre_check_bind(db, rt, p: CheckBindRemediation):
    _need(db, "checks", p.check_id, "check")
    _validate_remediation(db, p.remediation)


def _pre_maintenance(db, rt, p: MaintenanceCreate):
    if p.check_id:
        _need(db, "checks", p.check_id, "check")


def _pre_channel_create(db, rt, p: AlertChannelCreate):
    if db.execute(text("SELECT 1 FROM alert_channels WHERE name = :n"), {"n": p.name}).first():
        raise PlanError(409, "channel name already exists")
    return {"resolved_ips": _guard(rt, alerts.config_host(p.kind, p.config))}


def _pre_channel_test(db, rt, p: AlertChannelTest):
    _need(db, "alert_channels", p.channel_id, "channel")


def _pre_ack(db, rt, p: IncidentAck):
    r = _need(db, "incidents", p.incident_id, "incident")
    if r.status == "recovered":
        raise PlanError(409, "incident already recovered")


def _pre_runbook(db, rt, p: RunbookExecute):
    node = _need(db, "nodes", p.node_id, "node")
    cap = node.capabilities.get(p.runbook)
    if cap is None or (p.unit and p.unit not in cap.get("units", [])) or (p.path and p.path not in cap.get("paths", [])):
        raise PlanError(422, "runbook/unit/path is not on that node's agent allowlist")
    if p.check_id:
        _need(db, "checks", p.check_id, "check")


_PRECHECK = {ActionType.node_enroll: _pre_node_enroll, ActionType.check_create: _pre_check_create,
             ActionType.check_set_enabled: _pre_check_set_enabled, ActionType.check_bind_remediation: _pre_check_bind,
             ActionType.maintenance_create: _pre_maintenance, ActionType.alert_channel_create: _pre_channel_create,
             ActionType.alert_channel_test: _pre_channel_test, ActionType.incident_ack: _pre_ack, ActionType.runbook_execute: _pre_runbook}


def create_plan(db: Session, rt: Runtime, user, action: ActionType, params: dict, ip: str | None) -> dict:
    spec = CATALOG[action]
    if spec.get("admin_only") and auth.RANK[user.role] < auth.RANK["admin"]:
        raise PlanError(403, "requires role admin")
    p = spec["model"].model_validate(params)  # ValidationError -> 422 at the API layer
    full = p.model_dump(mode="json")
    for k in spec["secrets"]:
        if p.__dict__[k] is None:
            full.pop(k, None)
        else:
            full[k] = p.__dict__[k].get_secret_value()
    secret_part = {k: full.pop(k) for k in spec["secrets"] if k in full}
    risk = spec["risk"](p) if callable(spec["risk"]) else spec["risk"]
    binding = None
    extra: dict = {}
    if action in _IDM:
        try:
            extra.update(identity.precheck(db, rt, action.value, p))
            risk = identity.risk_for(db, action.value, p)
        except KeyError as e:
            raise PlanError(404, str(e.args[0])) from None
        except LookupError as e:
            raise PlanError(409, str(e)) from None
        except (ValueError, IdentityError) as e:
            raise PlanError(422, str(e)) from None
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
    elif action in _PRECHECK:
        extra.update(_PRECHECK[action](db, rt, p) or {})
    pid = uuid.uuid4()
    enc = rt.vault.encrypt(json.dumps(secret_part).encode(), f"plan:{pid}") if secret_part else None
    digest = plan_digest(action.value, full, enc, binding)
    auto = risk == "low"
    db.execute(text(
        "INSERT INTO plans (id, action, params, secret_enc, risk, status, requested_by, decided_at, params_hash) "
        "VALUES (:id, :a, CAST(:p AS jsonb), :s, :r, :st, :u, :d, :h)"),
        {"id": str(pid), "a": action.value, "p": audit.canon(full), "s": enc, "r": risk,
         "st": "approved" if auto else "pending_approval", "u": user.id, "d": datetime.now(timezone.utc) if auto else None, "h": digest})
    audit.append(db, "plan.create", actor_id=user.id, actor_name=user.username, ip=ip, resource="plan", resource_id=str(pid),
                 details={"action": action.value, "risk": risk, "params": full, "auto_approved": auto,
                          "params_hash": digest, **extra})
    job_id = None
    if auto:  # policy approval for low risk; recorded like any approval so the job can verify it
        db.execute(text("INSERT INTO plan_approvals (plan_id, approver_id, params_hash) VALUES (:p, :u, :h)"),
                   {"p": str(pid), "u": user.id, "h": digest})
        job_id = _enqueue(db, pid, action, user, ip, auto=True)
    db.commit()
    return {"plan_id": str(pid), "status": "approved" if auto else "pending_approval", "risk": risk, "job_id": job_id,
            "params_hash": digest, "approvals_required": rt.settings.required_approvals_high if risk == "high" else 1, **extra}


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


_SAFE_ERRORS = (ProxmoxError, VaultError, PlanIntegrityError, JobTimeout, AgentError, IdentityError)


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


# ---- executors: monitoring / nodes -------------------------------------------------------------------------

def _exec_node_enroll(rt: Runtime, db: Session, m: NodeEnroll, plan, known: list[str]) -> dict:
    token = m.enrollment_token.get_secret_value()
    known.append(token)
    priv = agentclient.load_signing_key(rt.settings.signing_key_file)
    lb = rt.settings.allow_loopback_endpoints
    ident = agentclient.identity(m.address, m.port, m.tls_fingerprint_sha256, allow_loopback=lb)  # TLS pinned to the operator-supplied pin
    if agentclient.key_fingerprint(ident["agent_pubkey"]) != m.agent_key_fingerprint_sha256:
        raise AgentError("agent public key does not match the supplied fingerprint")
    if ident.get("enrolled"):
        raise AgentError("agent is already enrolled; re-arm it on the node console")
    nid = uuid.uuid4()
    resp = agentclient.enroll(m.address, m.port, m.tls_fingerprint_sha256, token=token, ics_pubkey_b64=agentclient.pub_b64(priv.public_key()),
                              node_id=str(nid), expect_agent_pubkey_b64=ident["agent_pubkey"], allow_loopback=lb)
    db.execute(text(
        "INSERT INTO nodes (id, name, address, port, tls_fingerprint_sha256, agent_pubkey, agent_key_fp, capabilities, agent_version, "
        "last_seen_at, created_by) VALUES (:id, :n, :a, :p, :t, :k, :f, CAST(:c AS jsonb), :v, now(), :cb)"),
        {"id": str(nid), "n": m.name, "a": m.address, "p": m.port, "t": m.tls_fingerprint_sha256, "k": ident["agent_pubkey"],
         "f": m.agent_key_fingerprint_sha256, "c": audit.canon(audit.sanitize(resp.get("capabilities", {}))),
         "v": str(audit.sanitize(resp.get("agent_version")))[:40], "cb": str(plan.requested_by)})
    audit.append(db, "node.enrolled", actor_name="worker", resource="node", resource_id=str(nid),
                 details={"name": m.name, "address": m.address, "port": m.port, "agent_key_fingerprint": m.agent_key_fingerprint_sha256,
                          "tls_fingerprint": m.tls_fingerprint_sha256, "capabilities": resp.get("capabilities", {})})
    return {"node_id": str(nid), "capabilities": audit.sanitize(resp.get("capabilities", {}))}


def _exec_check_create(rt: Runtime, db: Session, m: CheckCreate, plan, known: list[str]) -> dict:
    cid = uuid.uuid4()
    enc = None
    if m.password:
        known.append(m.password.get_secret_value())
        enc = rt.vault.encrypt(m.password.get_secret_value().encode(), monitor.check_aad(cid, m.config))
    db.execute(text(
        "INSERT INTO checks (id, name, kind, config, secret_enc, interval_seconds, fail_threshold, recover_threshold, remediation, created_by) "
        "VALUES (:id, :n, :k, CAST(:c AS jsonb), :s, :i, :ft, :rt, CAST(:r AS jsonb), :cb)"),
        {"id": str(cid), "n": m.name, "k": m.kind, "c": audit.canon(m.config), "s": enc, "i": m.interval_seconds, "ft": m.fail_threshold,
         "rt": m.recover_threshold, "r": audit.canon(m.remediation.model_dump(mode="json", exclude_none=True)) if m.remediation else None,
         "cb": str(plan.requested_by)})
    audit.append(db, "check.created", actor_name="worker", resource="check", resource_id=str(cid),
                 details={"name": m.name, "kind": m.kind, "interval_seconds": m.interval_seconds, "has_secret": enc is not None,
                          "remediation": m.remediation.model_dump(mode="json", exclude_none=True) if m.remediation else None})
    return {"check_id": str(cid)}


def _exec_check_set_enabled(rt, db, m: CheckSetEnabled, plan, known) -> dict:
    db.execute(text("UPDATE checks SET enabled = :e, next_run_at = now() WHERE id = :i"), {"e": m.enabled, "i": str(m.check_id)})
    audit.append(db, "check.enabled_set", actor_name="worker", resource="check", resource_id=str(m.check_id), details={"enabled": m.enabled})
    return {"check_id": str(m.check_id), "enabled": m.enabled}


def _exec_check_bind(rt, db, m: CheckBindRemediation, plan, known) -> dict:
    rem = m.remediation.model_dump(mode="json", exclude_none=True) if m.remediation else None
    db.execute(text("UPDATE checks SET remediation = CAST(:r AS jsonb) WHERE id = :i"),
               {"r": audit.canon(rem) if rem else None, "i": str(m.check_id)})
    audit.append(db, "check.remediation_bound", actor_name="worker", resource="check", resource_id=str(m.check_id),
                 details={"remediation": rem, "requested_by": str(plan.requested_by)})
    return {"check_id": str(m.check_id), "remediation": rem}


def _exec_maintenance(rt, db, m: MaintenanceCreate, plan, known) -> dict:
    wid = db.execute(text(
        "INSERT INTO maintenance_windows (name, check_id, starts_at, ends_at, reason, created_by) "
        "VALUES (:n, :c, now(), now() + make_interval(mins => :d), :r, :u) RETURNING id"),
        {"n": m.name, "c": str(m.check_id) if m.check_id else None, "d": m.duration_minutes, "r": m.reason, "u": str(plan.requested_by)}).scalar()
    audit.append(db, "maintenance.created", actor_name="worker", resource="maintenance", resource_id=str(wid),
                 details={"name": m.name, "check_id": str(m.check_id) if m.check_id else None, "minutes": m.duration_minutes, "reason": m.reason})
    return {"maintenance_id": str(wid)}


def _exec_channel_create(rt: Runtime, db: Session, m: AlertChannelCreate, plan, known: list[str]) -> dict:
    cid = uuid.uuid4()
    enc = None
    if m.secret:
        known.append(m.secret.get_secret_value())
        enc = rt.vault.encrypt(m.secret.get_secret_value().encode(), monitor.channel_aad(cid, m.config))
    db.execute(text("INSERT INTO alert_channels (id, name, kind, config, secret_enc, enabled, created_by) "
                    "VALUES (:id, :n, :k, CAST(:c AS jsonb), :s, :e, :u)"),
               {"id": str(cid), "n": m.name, "k": m.kind, "c": audit.canon(m.config), "s": enc, "e": bool(m.enabled), "u": str(plan.requested_by)})
    audit.append(db, "alert_channel.created", actor_name="worker", resource="alert_channel", resource_id=str(cid),
                 details={"name": m.name, "kind": m.kind, "enabled": bool(m.enabled), "has_secret": enc is not None,
                          "config": {k: v for k, v in m.config.items() if k not in ("ca_pem", "user_key")}})
    return {"channel_id": str(cid), "enabled": bool(m.enabled)}


def _exec_channel_test(rt, db, m: AlertChannelTest, plan, known) -> dict:
    ch = db.execute(text("SELECT enabled, kind FROM alert_channels WHERE id = :i"), {"i": str(m.channel_id)}).first()
    if ch is None or not ch.enabled:
        raise PlanIntegrityError("channel not found or disabled")
    nid = db.execute(text("INSERT INTO notifications (channel_id, event, status) VALUES (:c, 'test', 'pending') RETURNING id"),
                     {"c": str(m.channel_id)}).scalar()
    return {"notification_id": nid}


def _exec_ack(rt, db, m: IncidentAck, plan, known) -> dict:
    r = db.execute(text("UPDATE incidents SET status = 'acked', acked_by = :u, acked_at = now(), ack_note = :n "
                        "WHERE id = :i AND status = 'open' RETURNING id"), {"u": str(plan.requested_by), "n": m.note, "i": str(m.incident_id)}).first()
    if r is None:
        raise PlanIntegrityError("incident is not open")
    audit.append(db, "incident.acked", actor_name="worker", resource="incident", resource_id=str(m.incident_id),
                 details={"by": str(plan.requested_by), "note": m.note})
    return {"incident_id": str(m.incident_id), "status": "acked"}


class AgentRejected(AgentError):
    pass


def _exec_runbook(rt: Runtime, db: Session, m: RunbookExecute, plan, known: list[str]) -> dict:
    node = db.execute(text("SELECT * FROM nodes WHERE id = :i"), {"i": str(m.node_id)}).first()
    if node is None:
        raise PlanIntegrityError("node not found")
    jid = str(db.execute(text("SELECT id FROM jobs WHERE plan_id = :p"), {"p": str(plan.id)}).scalar())
    priv = agentclient.load_signing_key(rt.settings.signing_key_file)
    params = {"unit": m.unit} if m.unit else {"path": m.path}
    body = agentclient.build_request(priv, action=m.runbook, params=params, node_id=str(node.id), job_id=jid,
                                     ttl=rt.settings.agent_request_ttl_seconds)
    req = body["req"]
    with rt.session() as d2:  # persisted BEFORE the call, independent of this job's transaction
        d2.execute(text("INSERT INTO agent_requests (node_id, job_id, nonce, action, issued_at, expires_at) "
                        "VALUES (:n, :j, :nc, :a, to_timestamp(:i), to_timestamp(:e))"),
                   {"n": str(node.id), "j": jid, "nc": req["nonce"], "a": m.runbook, "i": req["issued_at"], "e": req["expires_at"]})
        d2.commit()
    code, resp = "error", {}
    try:
        _, resp = agentclient.call(node, priv, action=m.runbook, params=params, job_id=jid, deadline=rt.settings.agent_deadline_seconds,
                                   allow_loopback=rt.settings.allow_loopback_endpoints, req_override=body)
        code = str(resp.get("code"))[:60]
    except AgentError:
        code = "transport_or_signature_error"
        raise
    finally:
        # separate session + commit: evidence of what was sent/answered survives even if this job fails, and it is written BEFORE the
        # verification loop below (an audit insert in this job's own transaction would hold the chain lock during verification -> deadlock)
        with rt.session() as d2:
            d2.execute(text("UPDATE agent_requests SET status = :s, response_code = :c, finished_at = now() WHERE job_id = :j"),
                       {"s": "done" if code == "ok" else "failed", "c": code, "j": jid})
            if code != "transport_or_signature_error":
                d2.execute(text("UPDATE nodes SET last_seen_at = now() WHERE id = :i"), {"i": str(node.id)})
            audit.append(d2, "runbook.executed", actor_name="worker", resource="node", resource_id=str(node.id),
                         details={"runbook": m.runbook, "params": params, "agent_status": resp.get("status", "error"), "agent_code": code,
                                  "job_id": jid, "nonce": req["nonce"]})
            d2.commit()
    if resp.get("status") != "ok":
        raise AgentRejected(f"agent {resp.get('status')}: {code}")
    out = {"runbook": m.runbook, "params": params, "agent_result": audit.sanitize(resp.get("result")), "verified": None, "verification": ""}
    if m.check_id:
        t0 = time.monotonic()
        while True:
            state, o = monitor.run_and_record(rt, m.check_id, remediate=False)
            if state == "ok" or time.monotonic() - t0 >= m.verify_timeout_seconds:
                break
            time.sleep(3)
        out["verified"] = state == "ok"
        out["verification"] = (f"check recovered: state ok after {int(time.monotonic() - t0)} s" if state == "ok"
                               else f"check still {state} after {int(time.monotonic() - t0)} s: {o.message}")[:300]
    return out


_EXEC = {ActionType.endpoint_register: _exec_register, ActionType.inventory_refresh: _exec_refresh,
         ActionType.user_create: _exec_user_create, ActionType.user_set_role: _exec_user_set_role,
         ActionType.node_enroll: _exec_node_enroll, ActionType.check_create: _exec_check_create,
         ActionType.check_set_enabled: _exec_check_set_enabled, ActionType.check_bind_remediation: _exec_check_bind,
         ActionType.maintenance_create: _exec_maintenance, ActionType.alert_channel_create: _exec_channel_create,
         ActionType.alert_channel_test: _exec_channel_test, ActionType.incident_ack: _exec_ack, ActionType.runbook_execute: _exec_runbook,
         **{ActionType(k): v for k, v in identity.EXECUTORS.items()}}
