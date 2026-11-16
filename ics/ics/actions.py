"""Closed typed action catalog -> plan -> approval -> single-use job -> execution (all audited)."""
import hashlib
import json
import logging
import re
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from types import SimpleNamespace
from typing import Literal, Self
from urllib.parse import urlparse
from uuid import UUID

from cryptography import x509
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator
from sqlalchemy import text
from sqlalchemy.orm import Session

from . import release as release_ops
from . import agentclient, alerts, audit, auth, checks as checkmod, endpoint_actions, identity, monitor, removal
from .deploy import ops as deploy_ops
from .deploy import ports as deploy_ports
from .deploy.ports import DeployError
from .provisioning import actions as prov_actions
from .identity import IdentityError
from .agentclient import AgentError
from .backups import ops as backup_ops
from .proxmox import ProxmoxError, ProxmoxReadClient, check_destination, normalize_fingerprint
from .providers.base import ProviderError, job_execution
from .credentials import actions as cred_actions, service as cred_service
from .runtime import Runtime
from .epoch import NotActive
from .tenancy import actions as ten_actions, approvals as tapprovals, policy as tpolicy, resolve as tresolve, scope as tscope
from .vault import VaultError

log = logging.getLogger("ics.actions")


class ActionType(StrEnum):
    endpoint_register = "endpoint.register"
    inventory_refresh = "inventory.refresh"
    endpoint_update = "endpoint.update"
    endpoint_remove = "endpoint.remove"
    endpoint_disable = "endpoint.disable"
    endpoint_enable = "endpoint.enable"
    user_create = "user.create"
    user_set_role = "user.set_role"
    user_invite = "user.invite"
    user_revoke_invite = "user.revoke_invite"
    user_disable = "user.disable"
    user_enable = "user.enable"
    user_revoke_sessions = "user.revoke_sessions"
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
    idm_user_devices = "idm.user.devices"
    idm_user_set_extension = "idm.user.set_extension"
    idm_user_issue_sip_credential = "idm.user.issue_sip_credential"
    deployment_create = "deployment.create"
    deployment_change = "deployment.change"
    deployment_destroy = "deployment.destroy"
    check_delete = "check.delete"
    alert_channel_delete = "alert_channel.delete"
    node_decommission = "node.decommission"
    maintenance_cancel = "maintenance.cancel"
    maintenance_delete = "maintenance.delete"
    plan_archive = "plan.archive"
    provider_provision_plan_preview = "provider.provision.plan_preview"
    provider_provision_apply = "provider.provision.apply"
    provider_provision_package = "provider.provision.package"
    provider_credential_import = "provider.credential.import"
    provider_permissions_reconcile = "provider.permissions.reconcile"
    provider_token_rotate = "provider.token.rotate"
    provider_token_revoke = "provider.token.revoke"
    provider_scope_change = "provider.scope.change"
    provider_scope_package = "provider.scope.package"
    credential_create = "credential.create"
    credential_replace = "credential.replace"
    credential_rotate = "credential.rotate"
    credential_revoke = "credential.revoke"
    credential_test = "credential.test"
    customer_create = "customer.create"
    customer_update = "customer.update"
    operator_set_scope = "operator.set_scope"
    backup_policy_create = "backup.policy.create"
    backup_policy_update = "backup.policy.update"
    backup_run = "backup.run"
    backup_verify = "backup.verify"
    backup_prune = "backup.prune"
    release_promote = "release.promote"


class EndpointRegister(endpoint_actions.ScopeLists):
    model_config = ConfigDict(extra="forbid")
    customer_id: UUID | None = Field(default=None, description="owning customer (default: the MSP-internal customer)")
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,62}$")
    type: Literal["proxmox"]
    base_url: str
    token_id: str = Field(pattern=r"^[A-Za-z0-9._-]+@[A-Za-z0-9._-]+![A-Za-z0-9._-]+$", description="user@realm!tokenname")
    token_secret: SecretStr = Field(description="Proxmox API token secret (surrounding whitespace is stripped; [A-Za-z0-9_-]{8,200})")
    ca_pem: str | None = Field(default=None, max_length=100_000)
    fingerprint_sha256: str | None = None
    display_name: str | None = Field(default=None, max_length=80, pattern=r"^[^\x00-\x1f]*$")
    provision_token_id: str | None = Field(default=None, pattern=endpoint_actions.TOKEN_ID_RE, description="optional second credential (role provision)")
    provision_token_secret: SecretStr | None = None

    @field_validator("provision_token_secret", mode="before")
    @classmethod
    def _psecret(cls, v):
        return endpoint_actions.norm_secret(v)

    @model_validator(mode="after")
    def _prov(self) -> Self:
        if (self.provision_token_id is None) != (self.provision_token_secret is None):
            raise ValueError("provision_token_id and provision_token_secret go together")
        if self.provision_token_id and not self.allowed_pools:
            raise ValueError("a provision credential requires at least one allowed pool")
        if self.provision_token_id and not self.allowed_nodes:
            raise ValueError("a provision credential requires at least one authorized node (allowed_nodes)")
        return self

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


USERNAME_PAT = r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$"
PRIVILEGED = ("approver", "admin")


class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(pattern=USERNAME_PAT)
    role: Literal["viewer", "operator", "approver", "admin"]
    justification: str | None = Field(default=None, max_length=500)  # shown to approvers; part of the approved digest


class UserSetRole(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(pattern=USERNAME_PAT)
    role: Literal["viewer", "operator", "approver", "admin"]
    justification: str | None = Field(default=None, max_length=500)


class UserInvite(BaseModel):
    """Same semantics as user.create (an invite carries no credentials); a written justification is mandatory for approver/admin."""
    model_config = ConfigDict(extra="forbid")
    username: str = Field(pattern=USERNAME_PAT)
    role: Literal["viewer", "operator", "approver", "admin"]
    justification: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def _just(self):
        if self.role in PRIVILEGED and len((self.justification or "").strip()) < 10:
            raise ValueError("a justification (10+ characters) is required for approver/admin accounts")
        return self


class UserTarget(BaseModel):
    """revoke_invite / enable / revoke_sessions."""
    model_config = ConfigDict(extra="forbid")
    username: str = Field(pattern=USERNAME_PAT)
    reason: str | None = Field(default=None, max_length=500)


class UserDisable(UserTarget):
    pass


NAME_RE = r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$"


class NodeEnroll(BaseModel):
    model_config = ConfigDict(extra="forbid")
    customer_id: UUID | None = Field(default=None, description="owning customer (default: derived from the referenced object, else MSP-internal)")
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
    customer_id: UUID | None = Field(default=None, description="owning customer (default: derived from the referenced object, else MSP-internal)")
    name: str = Field(pattern=NAME_RE)
    kind: Literal["http", "tcp_tls", "imap_login", "smtp_banner", "ews_getfolder", "backup"]
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
    customer_id: UUID | None = Field(default=None, description="owning customer (default: derived from the referenced object, else MSP-internal)")
    name: str = Field(min_length=1, max_length=100)
    check_id: UUID | None = None
    duration_minutes: int = Field(ge=1, le=480)
    reason: str = Field(default="", max_length=200)


class AlertChannelCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    customer_id: UUID | None = Field(default=None, description="owning customer (default: derived from the referenced object, else MSP-internal)")
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
    verify_timeout_seconds: int = Field(default=0, ge=0, le=monitor.MAX_VERIFY_TIMEOUT)
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
    ActionType.endpoint_register: {"model": EndpointRegister, "risk": "high", "secrets": ("token_secret", "provision_token_secret")},
    ActionType.inventory_refresh: {"model": InventoryRefresh, "risk": "low", "secrets": ()},
    ActionType.endpoint_update: {"model": endpoint_actions.EndpointUpdate, "risk": endpoint_actions.update_risk,
                                 "secrets": ("token_secret", "provision_token_secret")},
    ActionType.endpoint_remove: {"model": endpoint_actions.EndpointRemove, "risk": "high", "secrets": ()},
    ActionType.endpoint_disable: {"model": endpoint_actions.EndpointToggle, "risk": "normal", "secrets": ()},
    ActionType.endpoint_enable: {"model": endpoint_actions.EndpointToggle, "risk": "normal", "secrets": ()},
    ActionType.user_create: {"model": UserCreate, "risk": "high", "secrets": (), "admin_only": True},
    ActionType.user_set_role: {"model": UserSetRole, "risk": "high", "secrets": (), "admin_only": True},
    ActionType.user_invite: {"model": UserInvite, "risk": lambda p: "high" if p.role in PRIVILEGED else "low", "secrets": (), "admin_only": True},
    ActionType.user_revoke_invite: {"model": UserTarget, "risk": "low", "secrets": (), "admin_only": True},
    ActionType.user_disable: {"model": UserDisable, "risk": "normal", "secrets": (), "admin_only": True},  # high for approver/admin targets
    ActionType.user_enable: {"model": UserTarget, "risk": "normal", "secrets": (), "admin_only": True},    # high for approver/admin targets
    ActionType.user_revoke_sessions: {"model": UserTarget, "risk": "low", "secrets": (), "admin_only": True},
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
    ActionType.idm_user_devices: {"model": identity.UserDevices, "risk": "low", "secrets": ()},
    ActionType.idm_user_set_extension: {"model": identity.UserSetExtension, "risk": "normal", "secrets": ()},
    ActionType.idm_user_issue_sip_credential: {"model": identity.IssueSipCredential, "risk": "normal", "secrets": ()},
    # deployment engine (deploy/ops.py). "risk" is the catalog default; create_plan takes the real tier from the change diff (override => high)
    ActionType.deployment_create: {"model": deploy_ops.DeploymentCreate, "risk": "high", "secrets": ()},
    ActionType.deployment_change: {"model": deploy_ops.DeploymentChange, "risk": "normal", "secrets": ()},
    ActionType.deployment_destroy: {"model": deploy_ops.DeploymentDestroy, "risk": "high", "secrets": ()},
    # removals (removal.py): audited, guarded at plan time AND at execution
    ActionType.check_delete: {"model": removal.CheckDelete, "risk": "normal", "secrets": ()},
    ActionType.alert_channel_delete: {"model": removal.ChannelDelete, "risk": removal.channel_risk, "secrets": ()},
    ActionType.node_decommission: {"model": removal.NodeDecommission, "risk": "high", "secrets": ()},
    ActionType.maintenance_cancel: {"model": removal.MaintenanceTarget, "risk": "normal", "secrets": ()},
    ActionType.maintenance_delete: {"model": removal.MaintenanceTarget, "risk": "normal", "secrets": ()},
    ActionType.plan_archive: {"model": removal.PlanArchive, "risk": "low", "secrets": ()},
    # backup product (backups/ops.py). "risk" is the catalog default; create_plan takes the real tier from backups.ops.risk_for
    ActionType.backup_policy_create: {"model": backup_ops.MODELS["backup.policy.create"], "risk": "normal", "secrets": backup_ops.SECRETS["backup.policy.create"]},
    ActionType.backup_policy_update: {"model": backup_ops.PolicyUpdate, "risk": "normal", "secrets": ()},
    ActionType.backup_run: {"model": backup_ops.BackupRun, "risk": "low", "secrets": ()},
    ActionType.backup_verify: {"model": backup_ops.BackupVerify, "risk": "low", "secrets": ()},
    ActionType.backup_prune: {"model": backup_ops.BackupPrune, "risk": "low", "secrets": ()},
    ActionType.release_promote: {"model": release_ops.ReleasePromote, "risk": release_ops.risk, "secrets": (), "admin_only": True},
}
CATALOG.update({ActionType(k): v for k, v in prov_actions.CATALOG.items()})   # provider provisioning (ics/provisioning/actions.py)
_PROV = {ActionType(k) for k in prov_actions.CATALOG}
CATALOG.update({ActionType(k): v for k, v in {**cred_actions.SPECS, **ten_actions.SPECS}.items()})
_IDM = {a for a in ActionType if a.value.startswith("idm.")}
_DEPLOY = {a for a in ActionType if a.value.startswith("deployment.")}
_BACKUP = {a for a in ActionType if a.value.startswith("backup.")}


class PlanIntegrityError(Exception):
    pass


class JobTimeout(Exception):
    pass


def endpoint_binding(base_url: str, token_id: str, fingerprint: str | None, ca_pem: str | None) -> str:
    """Digest of an endpoint's trust anchors; bound into approvals and into the token's vault AAD (M5)."""
    return hashlib.sha256(json.dumps([base_url, token_id, fingerprint or "", hashlib.sha256((ca_pem or "").encode()).hexdigest()]).encode()).hexdigest()


def needed_approvals(rt: Runtime, plan) -> int:
    """Distinct ICS approvers required: risk tier + the customer policy's extra approvals for sensitive operations."""
    return (rt.settings.required_approvals_high if plan.risk == "high" else 1) + (getattr(plan, "extra_approvals", 0) or 0)


def trust_binding(base_url: str, token_id: str, fingerprint: str | None, ca_pem: str | None, nodes=None) -> str:
    """Credential-release binding: the trust anchors (endpoint_binding) PLUS the node allowlist, so widening the nodes outside an approved
    endpoint.update makes the vault refuse to release the credential. (The vault AAD of legacy blobs stays endpoint_binding.)"""
    nl = sorted(nodes or [])
    return endpoint_binding(base_url, token_id, fingerprint, ca_pem) + ":" + hashlib.sha256(json.dumps(nl).encode()).hexdigest()[:16]


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


def _validate_remediation(db: Session, rem, rt: Runtime | None = None) -> None:
    if rem is None:
        return
    if rt is not None and (rem.backoff_seconds < rt.settings.remediation_min_backoff_seconds
                           or rem.window_seconds < rt.settings.remediation_min_window_seconds):
        raise PlanError(422, f"remediation needs backoff_seconds >= {rt.settings.remediation_min_backoff_seconds} "
                             f"and window_seconds >= {rt.settings.remediation_min_window_seconds}")
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
    s = rt.settings
    if db.execute(text("SELECT count(*) FROM checks")).scalar() >= s.max_checks:
        raise PlanError(409, f"check limit reached ({s.max_checks}); remove unused checks first")
    floor = s.check_min_interval_credentialed_seconds if p.kind in checkmod.NEEDS_PASSWORD else s.check_min_interval_seconds
    if p.interval_seconds < floor:
        raise PlanError(422, f"interval_seconds must be >= {floor} for {p.kind} checks")
    _validate_remediation(db, p.remediation, rt)
    if p.kind == "backup":   # no network destination; the policy must exist
        if db.execute(text("SELECT 1 FROM backup_policies WHERE name = :n"), {"n": p.config["policy"]}).first() is None:
            raise PlanError(404, "backup policy not found")
        return {}
    return {"resolved_ips": _guard(rt, checkmod.config_host(p.kind, p.config))}


def _pre_check_set_enabled(db, rt, p: CheckSetEnabled):
    _need(db, "checks", p.check_id, "check")


def _pre_check_bind(db, rt, p: CheckBindRemediation):
    _need(db, "checks", p.check_id, "check")
    _validate_remediation(db, p.remediation, rt)


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
    if node.status == "decommissioned":
        raise PlanError(409, "node is decommissioned")
    cap = node.capabilities.get(p.runbook)
    if cap is None or (p.unit and p.unit not in cap.get("units", [])) or (p.path and p.path not in cap.get("paths", [])):
        raise PlanError(422, "runbook/unit/path is not on that node's agent allowlist")
    if p.check_id:
        _need(db, "checks", p.check_id, "check")


_PRECHECK = {ActionType.node_enroll: _pre_node_enroll, ActionType.check_create: _pre_check_create,
             ActionType.check_set_enabled: _pre_check_set_enabled, ActionType.check_bind_remediation: _pre_check_bind,
             ActionType.maintenance_create: _pre_maintenance, ActionType.alert_channel_create: _pre_channel_create,
             ActionType.alert_channel_test: _pre_channel_test, ActionType.incident_ack: _pre_ack, ActionType.runbook_execute: _pre_runbook,
             ActionType.check_delete: removal.pre_check_delete, ActionType.alert_channel_delete: removal.pre_channel_delete,
             ActionType.node_decommission: removal.pre_node_decommission, ActionType.maintenance_cancel: removal.pre_maintenance_cancel,
             ActionType.maintenance_delete: removal.pre_maintenance_delete, ActionType.plan_archive: removal.pre_plan_archive, ActionType.release_promote: release_ops.precheck,
**{ActionType(k): v for k, v in {**cred_actions.PRECHECK, **ten_actions.PRECHECK}.items()}}


_USER_TARGET_ACTIONS = {ActionType.user_set_role, ActionType.user_revoke_invite, ActionType.user_disable, ActionType.user_enable,
                        ActionType.user_revoke_sessions}
_SELF_TARGET = {a.value for a in _USER_TARGET_ACTIONS}  # the target user may never decide these plans


def _active_admins_except(db: Session, username: str) -> int:
    return db.execute(text("SELECT count(*) FROM users WHERE role = 'admin' AND enrolled AND NOT disabled AND username <> :u"),
                      {"u": username}).scalar()


def _lock_admins(db: Session) -> None:
    """Review 3 M1: serialise every execution that can shrink the admin set. All active admins are row-locked in a stable order, so two
    concurrent/approved plans cannot both pass the 'another active admin remains' check."""
    db.execute(text("SELECT id FROM users WHERE role = 'admin' AND enrolled AND NOT disabled ORDER BY id FOR UPDATE")).all()


def _user_precheck(db: Session, user, action: ActionType, p, risk: str) -> str:
    t = db.execute(text("SELECT role, enrolled, disabled FROM users WHERE username = :u"), {"u": p.username}).first()
    if t is None:
        raise PlanError(404, "user not found")
    if p.username == user.username:
        raise PlanError(422, "you cannot target your own account; ask another admin")
    last_admin = t.role == "admin" and t.enrolled and not t.disabled and _active_admins_except(db, p.username) == 0
    if action == ActionType.user_set_role:
        if t.role == p.role:
            raise PlanError(409, f"user already has role {p.role}")
        if last_admin and p.role != "admin":
            raise PlanError(409, "refusing to demote the last active admin")
    elif action == ActionType.user_revoke_invite:
        if t.enrolled or t.disabled:
            raise PlanError(409, "only a pending invitation can be revoked")
        if t.role in PRIVILEGED:  # review 3 L5: a privileged account in host-CLI recovery is not 'enrolled'; revoking it needs a second person
            risk = "high"
    elif action == ActionType.user_disable:
        if not t.enrolled:
            raise PlanError(409, "account has not completed enrollment; revoke the invitation instead")
        if t.disabled:
            raise PlanError(409, "account is already disabled")
        if last_admin:
            raise PlanError(409, "refusing to disable the last active admin")
        risk = "high" if t.role in PRIVILEGED else "normal"
    elif action == ActionType.user_enable:
        if not t.disabled or not t.enrolled:
            raise PlanError(409, "only a disabled, enrolled account can be re-enabled")
        risk = "high" if t.role in PRIVILEGED else "normal"
    return risk


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
    # review 7 H-4: the customer is DERIVED from every resource the params reference; the caller's customer_id may only confirm it
    if getattr(user, "customer_ids", None) is not None:
        for _path, _kind, _c in tresolve.references(db, action.value, full):
            if _c and not tscope.allowed(user, _c):
                raise PlanError(404, "not found")   # same answer as a missing object: another customer's resources are not disclosed
    try:
        derived_cust = tresolve.derive(db, action.value, full)
    except tresolve.CustomerConflict as e:
        raise PlanError(409, str(e)) from None
    risk = spec["risk"](p) if callable(spec["risk"]) else spec["risk"]
    risk = _silencing_risk(db, rt, action, p, user, risk)
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
    backup_cust = None
    if action in _BACKUP and action != ActionType.backup_policy_create:
        try:
            backup_cust = backup_ops.policy_customer(db, p.policy)
        except KeyError:
            raise PlanError(404, "backup policy not found") from None
        if getattr(user, "customer_ids", None) is not None and (backup_cust is None or not tscope.allowed(user, backup_cust)):
            raise PlanError(404, "backup policy not found")   # same answer as a missing policy: existence is not disclosed to a scoped operator
    if action == ActionType.backup_policy_create and getattr(user, "customer_ids", None) is not None and not (p.customer_id and tscope.allowed(user, p.customer_id)):
        raise PlanError(404, "not found")
    if action in _BACKUP:
        try:
            extra.update(backup_ops.precheck(db, rt, action.value, p))
            risk = backup_ops.risk_for(db, action.value, p)
        except KeyError as e:
            raise PlanError(404, str(e.args[0])) from None
        except LookupError as e:
            raise PlanError(409, str(e)) from None
        except ValueError as e:
            raise PlanError(422, str(e)) from None
    if action in _DEPLOY:
        try:
            extra.update(deploy_ops.precheck(db, rt, action.value, p))
            risk = extra.pop("risk")
        except KeyError as e:
            raise PlanError(404, str(e.args[0])) from None
        except LookupError as e:
            raise PlanError(409, str(e)) from None
        except ValueError as e:
            raise PlanError(422, str(e)) from None
    if action.value in endpoint_actions.BINDING_ACTIONS:
        binding = _ep_binding(db, p.endpoint_id)
        if binding is None:
            raise PlanError(404, "endpoint not found")
        if action != ActionType.inventory_refresh:
            extra.update(endpoint_actions.precheck(db, rt, action.value, p))
    elif action == ActionType.endpoint_register:
        try:  # SSRF guard (L3); the resolved addresses are shown to the approver
            extra["resolved_ips"] = check_destination(urlparse(p.base_url).hostname, rt.settings.allow_loopback_endpoints)
        except ProxmoxError as e:
            raise PlanError(422, str(e)) from None
        if db.execute(text("SELECT 1 FROM endpoints WHERE name = :n"), {"n": p.name}).first():
            raise PlanError(409, "endpoint name already exists")
    elif action in (ActionType.user_create, ActionType.user_invite):
        if db.execute(text("SELECT 1 FROM users WHERE username = :u"), {"u": p.username}).first():
            raise PlanError(409, "username already exists")
    elif action in _USER_TARGET_ACTIONS:
        risk = _user_precheck(db, user, action, p, risk)
    elif action in _PRECHECK:
        extra.update(_PRECHECK[action](db, rt, p) or {})
    if action in _PROV:
        extra.update(prov_actions.precheck(db, rt, action.value, p))
        pr = extra.get("preview_risk")
        if pr in _RISK_ORDER and _RISK_ORDER[pr] > _RISK_ORDER[risk]:
            risk = pr
    # ---- customer scoping + policy (agent M) ----
    cust = derived_cust
    if backup_cust:
        cust = backup_cust
    if action == ActionType.endpoint_register and not cust:
        cust = full["customer_id"] = tscope.DEFAULT_CUSTOMER
    if action in _PROV:
        try:
            cust = prov_actions.bind_customer(db, action.value, p, full, cust, spec["model"], tscope.DEFAULT_CUSTOMER)
        except ValueError as e:
            raise PlanError(409, str(e)) from None
    if getattr(user, "customer_ids", None) is not None and (cust is None or action.value in ("customer.create", "customer.update", "operator.set_scope")):
        raise PlanError(404, "not found")  # scoped operators may only act on objects of their customers
    if cust and not tscope.allowed(user, cust):
        raise PlanError(404, "not found")
    if action == ActionType.operator_set_scope and getattr(user, "customer_ids", None) is not None:
        raise PlanError(403, "only an all-customers admin can change operator scopes")
    decision = tpolicy.Decision()
    if cust and action not in (ActionType.customer_create, ActionType.customer_update, ActionType.operator_set_scope):
        try:
            decision = tpolicy.evaluate(db, cust, action.value, p)
        except tpolicy.PolicyDenied as e:
            raise PlanError(403, str(e)) from None
        extra.update({"customer_id": str(cust), "extra_approvals": decision.extra_approvals,
                      "customer_approval_required": decision.customer_approval})
    pid = uuid.uuid4()
    if action in _PROV and secret_part:
        # temporary provisioning credentials live ONLY in the credential subsystem (envelope encrypted, <= 15 min, wiped by the discard logic)
        enc = None
        cred_service.create(db, rt, provider="proxmox", customer_id=cust or tscope.DEFAULT_CUSTOMER, label=f"temporary provisioning ({action.value})",
                            credential_type="password" if "admin_password" in secret_part else "api_token", purpose="temporary_provisioning",
                            secret=json.dumps(secret_part), identity=(full.get("admin_username") or full.get("admin_token_id")),
                            expires_at=datetime.now(timezone.utc) + timedelta(seconds=prov_actions.TEMP_CRED_TTL), actor=user.username,
                            actor_id=user.id, reason=f"plan {pid}", ip=ip, cred_id=pid)
        digest = plan_digest(action.value, full, prov_actions.temp_cred_blob(pid), binding)
    else:
        enc = rt.vault.encrypt(json.dumps(secret_part).encode(), f"plan:{pid}") if secret_part else None
        digest = plan_digest(action.value, full, enc, binding)
    auto = risk == "low" and not decision.customer_approval and decision.extra_approvals == 0
    db.execute(text(
        "INSERT INTO plans (id, action, params, secret_enc, risk, status, requested_by, decided_at, params_hash, customer_id, extra_approvals) "
        "VALUES (:id, :a, CAST(:p AS jsonb), :s, :r, :st, :u, :d, :h, :cu, :xa)"),
        {"id": str(pid), "a": action.value, "p": audit.canon(full), "s": enc, "r": risk,
         "st": "approved" if auto else "pending_approval", "u": user.id, "d": datetime.now(timezone.utc) if auto else None, "h": digest,
         "cu": str(cust) if cust else None, "xa": decision.extra_approvals})
    if decision.customer_approval:
        try:
            draft = tapprovals.create_draft(db, rt, user, cust, f"{action.value} requested by {user.username}",
                                            {"provider": "proxmox", "summary": f"ICS action {action.value}", "permissions": full.get("permissions", []),
                                             "action": action.value, "request": full}, plan_id=pid, ip=ip)
        except tapprovals.ApprovalError as e:
            raise PlanError(e.status if e.status in (404, 409, 422) else 422, e.msg) from None
        db.execute(text("UPDATE plans SET customer_approval_id = :a WHERE id = :p"), {"a": draft["id"], "p": str(pid)})
        extra["customer_approval_id"] = draft["id"]
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
            "params_hash": digest, "approvals_required": (rt.settings.required_approvals_high if risk == "high" else 1) + decision.extra_approvals, **extra}


_RISK_ORDER = {"low": 0, "normal": 1, "high": 2}


def _silencing_risk(db: Session, rt: Runtime, action: ActionType, p, user, risk: str) -> str:
    """Review M4: one operator must not be able to silence alerting alone. A global or long maintenance window needs two approvers;
    disabling a check needs one (not the requester); a burst of acknowledgements needs one."""
    new = risk
    if action == ActionType.maintenance_create and (p.check_id is None or p.duration_minutes > rt.settings.maintenance_max_unapproved_minutes):
        new = "high"
    elif action == ActionType.check_set_enabled and not p.enabled:
        new = "normal"
    elif action == ActionType.incident_ack:
        n = db.execute(text("SELECT count(*) FROM plans WHERE action = 'incident.ack' AND requested_by = :u AND created_at > now() - interval '1 hour'"),
                       {"u": user.id}).scalar()
        if n >= rt.settings.ack_burst_limit:
            new = "normal"
    return new if _RISK_ORDER[new] > _RISK_ORDER[risk] else risk


def _stale_remediation(db: Session, params: dict) -> str | None:
    """Review M3: a remediation plan is only valid while its check is still critical and its attempt was not superseded."""
    aid = params.get("attempt_id")
    if aid is None:
        return None
    r = db.execute(text("SELECT a.status, c.state, c.enabled FROM remediation_attempts a JOIN checks c ON c.id = a.check_id WHERE a.id = :a"),
                   {"a": aid}).first()
    if r is None or r.status == "superseded" or r.state != "critical" or not r.enabled:
        return "remediation is stale: the check is no longer critical (or was disabled); nothing was executed"
    return None


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
    # review 5 M4: the approver must be in scope of the plan's customer (a customer-less plan is MSP-wide: scoped operators may not decide it)
    if (plan.customer_id is not None and not tscope.allowed(user, plan.customer_id)) or (plan.customer_id is None and getattr(user, "customer_ids", None) is not None):
        raise PlanError(404, "plan not found")
    if plan.requested_by == user.id:
        _refuse(db, user, ip, plan_id, "plan.self_decision_rejected", "requester cannot approve or reject their own plan")
    if _provenance_conflict(db, user.id, plan.requested_by):
        _refuse(db, user, ip, plan_id, "plan.provenance_rejected",
                "this approver was created or elevated by the requester and cannot decide the requester's plans")
    if plan.action in _SELF_TARGET and plan.params.get("username") == user.username:
        _refuse(db, user, ip, plan_id, "plan.self_decision_rejected", "cannot decide a plan that changes your own role")
    if plan.status != "pending_approval":
        raise PlanError(409, f"plan is already {plan.status}")
    if (datetime.now(timezone.utc) - plan.created_at).total_seconds() > rt.settings.plan_expiry_seconds:
        db.execute(text("UPDATE plans SET secret_enc = NULL, status = 'rejected', decided_at = now() WHERE id = :i"), {"i": str(plan_id)})
        prov_actions.scrub_expired_credentials(db)
        audit.append(db, "plan.expired", actor_name="system", resource="plan", resource_id=str(plan_id))
        db.commit()
        raise PlanError(409, "plan expired")
    if approve and plan.action == ActionType.runbook_execute.value and (why := _stale_remediation(db, plan.params)):
        db.execute(text("UPDATE plans SET status = 'rejected', decided_at = now(), secret_enc = NULL WHERE id = :i"), {"i": str(plan_id)})
        audit.append(db, "plan.superseded", actor_name="system", resource="plan", resource_id=str(plan_id), details={"reason": why})
        db.commit()
        raise PlanError(409, why)
    if not approve:
        db.execute(text("UPDATE plans SET status = 'rejected', decided_by = :u, decided_at = now(), secret_enc = NULL WHERE id = :i"),
                   {"u": user.id, "i": str(plan_id)})
        prov_actions.scrub_expired_credentials(db)
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
    need = needed_approvals(rt, plan)
    audit.append(db, "plan.approve", actor_id=user.id, actor_name=user.username, ip=ip, resource="plan", resource_id=str(plan_id),
                 details={"action": plan.action, "params_hash": plan.params_hash, "approvals": n, "required": need})
    job_id = None
    status = "pending_approval"
    waiting = None
    if n >= need and plan.customer_approval_id and not tapprovals.gate_ok(db, plan.customer_approval_id):
        waiting = "customer_approval"
    if n >= need and waiting is None:
        db.execute(text("UPDATE plans SET status = 'approved', decided_by = :u, decided_at = now() WHERE id = :i"),
                   {"u": user.id, "i": str(plan_id)})
        job_id = _enqueue(db, plan_id, plan.action, user, ip)
        status = "approved"
    db.commit()
    return {"plan_id": str(plan_id), "status": status, "job_id": job_id, "approvals": n, "approvals_required": need,
            **({"waiting_for": waiting} if waiting else {})}


# ---- execution ------------------------------------------------------------------

def claim_job(rt: Runtime, backup_lane: bool = False) -> dict | None:
    """Atomically claim one queued job. Concurrent claimers never get the same row. Sets a lease (L2).
    Two lanes: backup.* jobs (minutes to an hour) are claimed only by the backup lane, everything else only by the main lane."""
    s = rt.settings
    with rt.session() as db:
        try:
            rt.assert_active(db, lock=True)   # review 7 H-5: a fenced/standby/superseded controller claims NOTHING (FOR SHARE: a concurrent fence waits for this txn)
        except NotActive:
            return None
        row = db.execute(text(
            "SELECT id, plan_id, action FROM jobs WHERE status = 'queued' AND (action LIKE 'backup.%') = :b ORDER BY created_at "
            "LIMIT 1 FOR UPDATE SKIP LOCKED"), {"b": backup_lane}).first()
        if row is None:
            return None
        db.execute(text("UPDATE jobs SET status = 'running', started_at = now(), "
                        "lease_expires_at = now() + make_interval(secs => :l) WHERE id = :i"),
                   {"i": row.id, "l": (s.backup_job_timeout_seconds if backup_lane else s.job_timeout_seconds) + s.job_lease_slack_seconds})
        audit.append(db, "job.started", actor_name="worker", resource="job", resource_id=str(row.id), details={"action": row.action})
        db.commit()
        return {"id": row.id, "plan_id": row.plan_id, "action": row.action}


def reap_expired(rt: Runtime) -> int:
    """Fail jobs whose lease expired (never re-run: at-most-once), wipe their plan secrets, and wipe secrets of expired pending plans."""
    try:
        rt.assert_active()    # review 7 H-5
    except NotActive:
        return 0
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
            db.execute(text("DELETE FROM deployment_locks WHERE job_id = :i"), {"i": r.id})  # the abandoned executor is fenced out (review 3 H1)
            audit.append(db, "job.failed", actor_name="worker", resource="job", resource_id=str(r.id),
                         details={"action": r.action, "error": err})
            n += 1
        db.execute(text("UPDATE plans SET secret_enc = NULL WHERE status = 'pending_approval' AND secret_enc IS NOT NULL "
                        "AND created_at < now() - make_interval(secs => :e)"), {"e": rt.settings.plan_expiry_seconds})
        prov_actions.scrub_expired_credentials(db)   # temporary provisioning credentials live at most 15 minutes
        db.commit()
    try:      # review 5 L1: sweepers for one-time secrets that outlived their purpose
        from .guest import bootsecrets
        bootsecrets.sweep(rt)
        identity.sweep_sip_credentials(rt)
    except Exception:  # noqa: BLE001
        log.exception("secret sweeper failed")
    return n


_SAFE_ERRORS = (cred_service.CredentialUnavailable, ProviderError, ProxmoxError, VaultError, PlanIntegrityError, JobTimeout, AgentError, IdentityError, DeployError, backup_ops.BackupError)


def _error_dict(e: BaseException, known: list[str]) -> dict:
    if isinstance(e, _SAFE_ERRORS):
        msg = str(e)[:500]
    else:  # arbitrary exceptions (pydantic, SQLAlchemy, httpx) can embed parameter values: never pass their text through
        log.error("job failed with %s", type(e).__name__)
        msg = "internal error; see the server log"
    return {"type": type(e).__name__, "message": audit.redact(msg, known)}


def _verify_approval(rt: Runtime, db: Session, plan) -> None:
    """Re-verify, immediately before executing, that the plan still matches what was approved (M5) and approvals suffice."""
    binding = _ep_binding(db, plan.params["endpoint_id"]) if plan.action in endpoint_actions.BINDING_ACTIONS else None
    blob = plan.secret_enc
    if blob is None and plan.action in prov_actions.CATALOG and prov_actions.has_temp_cred(db, plan.id):
        blob = prov_actions.temp_cred_blob(plan.id)
    digest = plan_digest(plan.action, plan.params, blob, binding)
    appr = db.execute(text("SELECT approver_id, params_hash FROM plan_approvals WHERE plan_id = :p"), {"p": str(plan.id)}).all()
    need = needed_approvals(rt, plan)
    if getattr(plan, "customer_approval_id", None) and not tapprovals.gate_ok(db, plan.customer_approval_id):
        raise PlanIntegrityError("customer approval is missing; refusing to execute")
    if digest != plan.params_hash or not appr or any(a.params_hash != digest for a in appr):
        raise PlanIntegrityError("plan parameters or endpoint trust anchors changed after approval; refusing to execute")
    if len({a.approver_id for a in appr}) < need:
        raise PlanIntegrityError("insufficient approvals recorded; refusing to execute")
    if plan.risk == "high" and any(a.approver_id == plan.requested_by for a in appr):
        raise PlanIntegrityError("requester appears among approvers; refusing to execute")


def run_job(rt: Runtime, job: dict) -> None:
    try:
        rt.assert_active()    # review 7 H-5: fenced between claim and run: do not execute (the lease expires and the job is failed, never re-run)
    except NotActive:
        return
    result = error = None
    known: list[str] = []
    box: dict = {}
    cancelled, lock = threading.Event(), threading.Lock()
    deploy = str(job["action"]).startswith("deployment.")
    if deploy:
        deploy_ports.STOP_EVENTS[str(job["id"])] = cancelled  # set => the executor thread is fenced (lease.Lease.check)

    def work() -> None:
        try:
            with rt.session() as db:
                plan = db.execute(text("SELECT * FROM plans WHERE id = :i"), {"i": job["plan_id"]}).first()
                _verify_approval(rt, db, plan)
                action = ActionType(job["action"])
                if plan.secret_enc:
                    secrets_ = json.loads(rt.vault.decrypt(plan.secret_enc, f"plan:{plan.id}"))
                elif action in _PROV:
                    secrets_ = prov_actions.load_temp_cred(rt, db, plan.id, job["id"])
                else:
                    secrets_ = {}
                known.extend(str(v) for v in secrets_.values())
                m = CATALOG[action]["model"].model_validate({**plan.params, **secrets_})
                with job_execution(job["id"]):  # provider mutations are only reachable from here (providers.base)
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
    if deploy:  # review 3 H1: no fixed wall clock; the executor renews its own lease per heartbeat and enforces per-step deadlines
        while t.is_alive():
            t.join(1.0)
            if t.is_alive() and not _still_running(rt, job["id"]):  # reaped / failed elsewhere: fence the thread, do not touch the job
                cancelled.set()
                deploy_ports.STOP_EVENTS.pop(str(job["id"]), None)
                return
        deploy_ports.STOP_EVENTS.pop(str(job["id"]), None)
    else:
        budget = rt.settings.backup_job_timeout_seconds if job["action"].startswith("backup.") else rt.settings.job_timeout_seconds
        t.join(budget)
    with lock:
        if t.is_alive() and "result" not in box:
            cancelled.set()
            error = _error_dict(JobTimeout(f"job exceeded its {rt.settings.backup_job_timeout_seconds if str(job["action"]).startswith("backup.") else rt.settings.job_timeout_seconds}s wall-clock budget"), known)
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
                prov_actions.scrub_expired_credentials(db)   # temporary provisioning credentials die with the job
                audit.append(db, "job.failed" if error else "job.succeeded", actor_name="worker", resource="job",
                             resource_id=str(job["id"]), details=audit.redact({"action": job["action"], "result": result, "error": error}, known))
                db.commit()
            return
        except Exception:  # noqa: BLE001
            log.exception("job finalize failed (attempt %d)", attempt + 1)
            time.sleep(0.5 * (attempt + 1))


def _still_running(rt: Runtime, job_id) -> bool:
    try:
        with rt.session() as db:
            return db.execute(text("SELECT status FROM jobs WHERE id = :i"), {"i": str(job_id)}).scalar() == "running"
    except Exception:  # noqa: BLE001  (transient DB error: keep waiting)
        return True


def _client_for(rt: Runtime, ep, known: list[str]) -> ProxmoxReadClient:
    secret = cred_service.endpoint_secret(rt, ep, "inventory", actor="inventory")
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


def _exec_refresh(rt: Runtime, db: Session, m: InventoryRefresh, plan, known: list[str]) -> dict:
    out = collect_inventory(rt, db, m.endpoint_id, known)
    db.commit()  # keep the raw snapshot even if the normalized discovery below has problems
    try:
        from .inventory import collector
        d = collector.collect_discovery(rt, db, m.endpoint_id, known)
        out["discovery"] = {"ok": d["ok"], "counts": d.get("counts"), "error": d.get("error")}
    except Exception as e:  # noqa: BLE001
        out["discovery"] = {"ok": False, "error": type(e).__name__}
    return out


def _exec_user_create(rt: Runtime, db: Session, m: UserCreate, plan, known: list[str]) -> dict:
    """Creates an *invited* account: no credentials exist. The enrollment token is issued on the host by the CLI."""
    uid = auth.create_invite(db, rt, m.username, m.role, created_by=plan.requested_by, actor="worker", commit=False,
                            extra={"plan_id": str(plan.id), "justification": getattr(m, "justification", None)})
    return {"user_id": uid, "invite": True, "role": m.role}


def _exec_user_set_role(rt: Runtime, db: Session, m: UserSetRole, plan, known: list[str]) -> dict:
    _lock_admins(db)
    old = db.execute(text("SELECT role, enrolled, disabled FROM users WHERE username = :u FOR UPDATE"), {"u": m.username}).first()
    if old is None:
        raise PlanIntegrityError("user not found")
    if old.role == "admin" and old.enrolled and not old.disabled and m.role != "admin" and _active_admins_except(db, m.username) == 0:
        raise PlanIntegrityError("refusing to demote the last active admin")
    r = db.execute(text("UPDATE users SET role = :r, role_set_by = :by, role_set_at = now() WHERE username = :u RETURNING id"),
                   {"r": m.role, "by": str(plan.requested_by), "u": m.username}).first()
    audit.append(db, "user.role_set", actor_name="worker", resource="user", resource_id=str(r.id),
                 details={"username": m.username, "role": m.role, "previous_role": old.role, "requested_by": str(plan.requested_by),
                          "plan_id": str(plan.id), "justification": m.justification})
    return {"user_id": str(r.id), "role": m.role}


def _lock_target(db: Session, username: str):
    r = db.execute(text("SELECT id, role, enrolled, disabled FROM users WHERE username = :u FOR UPDATE"), {"u": username}).first()
    if r is None:
        raise PlanIntegrityError("user not found")
    return r


def _exec_user_revoke_invite(rt, db, m: UserTarget, plan, known) -> dict:
    t = _lock_target(db, m.username)
    if t.enrolled or t.disabled:
        raise PlanIntegrityError("not a pending invitation")
    db.execute(text("UPDATE users SET disabled = true, enrollment_token_hash = NULL, enrollment_expires_at = NULL, "
                    "password_hash = NULL, totp_secret_enc = NULL WHERE id = :i"), {"i": t.id})
    audit.append(db, "user.invite_revoked", actor_name="worker", resource="user", resource_id=str(t.id),
                 details={"username": m.username, "requested_by": str(plan.requested_by), "plan_id": str(plan.id), "reason": m.reason})
    return {"user_id": str(t.id), "revoked": True}


def _exec_user_disable(rt, db, m: UserDisable, plan, known) -> dict:
    _lock_admins(db)
    t = _lock_target(db, m.username)
    if not t.enrolled or t.disabled:
        raise PlanIntegrityError("account cannot be disabled in its current state")
    if t.role == "admin" and _active_admins_except(db, m.username) == 0:
        raise PlanIntegrityError("refusing to disable the last active admin")
    db.execute(text("UPDATE users SET disabled = true WHERE id = :i"), {"i": t.id})
    n = db.execute(text("DELETE FROM sessions WHERE user_id = :i"), {"i": t.id}).rowcount
    audit.append(db, "user.disabled", actor_name="worker", resource="user", resource_id=str(t.id),
                 details={"username": m.username, "requested_by": str(plan.requested_by), "plan_id": str(plan.id),
                          "reason": m.reason, "sessions_ended": n})
    return {"user_id": str(t.id), "disabled": True, "sessions_ended": n}


def _exec_user_enable(rt, db, m: UserTarget, plan, known) -> dict:
    t = _lock_target(db, m.username)
    if not t.disabled or not t.enrolled:
        raise PlanIntegrityError("account cannot be enabled in its current state")
    db.execute(text("UPDATE users SET disabled = false WHERE id = :i"), {"i": t.id})
    audit.append(db, "user.enabled", actor_name="worker", resource="user", resource_id=str(t.id),
                 details={"username": m.username, "requested_by": str(plan.requested_by), "plan_id": str(plan.id), "reason": m.reason})
    return {"user_id": str(t.id), "disabled": False}


def _exec_user_revoke_sessions(rt, db, m: UserTarget, plan, known) -> dict:
    t = _lock_target(db, m.username)
    n = db.execute(text("DELETE FROM sessions WHERE user_id = :i"), {"i": t.id}).rowcount
    audit.append(db, "user.sessions_revoked", actor_name="worker", resource="user", resource_id=str(t.id),
                 details={"username": m.username, "requested_by": str(plan.requested_by), "plan_id": str(plan.id),
                          "reason": m.reason, "sessions": n})
    return {"user_id": str(t.id), "sessions_revoked": n}


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
        "last_seen_at, created_by, customer_id) VALUES (:id, :n, :a, :p, :t, :k, :f, CAST(:c AS jsonb), :v, now(), :cb, :cu)"),
        {"cu": str(plan.customer_id or tscope.DEFAULT_CUSTOMER), "id": str(nid), "n": m.name, "a": m.address, "p": m.port, "t": m.tls_fingerprint_sha256, "k": ident["agent_pubkey"],
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
        "INSERT INTO checks (id, name, kind, config, secret_enc, interval_seconds, fail_threshold, recover_threshold, remediation, created_by, customer_id) "
        "VALUES (:id, :n, :k, CAST(:c AS jsonb), :s, :i, :ft, :rt, CAST(:r AS jsonb), :cb, :cu)"),
        {"cu": str(plan.customer_id or tscope.DEFAULT_CUSTOMER), "id": str(cid), "n": m.name, "k": m.kind, "c": audit.canon(m.config), "s": enc, "i": m.interval_seconds, "ft": m.fail_threshold,
         "rt": m.recover_threshold, "r": audit.canon(m.remediation.model_dump(mode="json", exclude_none=True)) if m.remediation else None,
         "cb": str(plan.requested_by)})
    audit.append(db, "check.created", actor_name="worker", resource="check", resource_id=str(cid),
                 details={"name": m.name, "kind": m.kind, "interval_seconds": m.interval_seconds, "has_secret": enc is not None,
                          "remediation": m.remediation.model_dump(mode="json", exclude_none=True) if m.remediation else None})
    return {"check_id": str(cid)}


def _exec_check_set_enabled(rt, db, m: CheckSetEnabled, plan, known) -> dict:
    db.execute(text("UPDATE checks SET enabled = :e, next_run_at = now() WHERE id = :i"), {"e": m.enabled, "i": str(m.check_id)})
    audit.append(db, "check.enabled_set", actor_name="worker", resource="check", resource_id=str(m.check_id), details={"enabled": m.enabled})
    if not m.enabled:
        inc = db.execute(text("SELECT id FROM incidents WHERE check_id = :c AND status IN ('open','acked')"), {"c": str(m.check_id)}).first()
        if inc:
            who = db.execute(text("SELECT username FROM users WHERE id = :u"), {"u": str(plan.requested_by)}).scalar()
            monitor.enqueue_notifications(db, SimpleNamespace(id=m.check_id), inc.id, "check_disabled",
                                          detail=f"disabled by {who} while the incident is open", force=True)
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
        "INSERT INTO maintenance_windows (name, check_id, starts_at, ends_at, reason, created_by, customer_id) "
        "VALUES (:n, :c, now(), now() + make_interval(mins => :d), :r, :u, :cu) RETURNING id"),
        {"cu": str(plan.customer_id or tscope.DEFAULT_CUSTOMER), "n": m.name, "c": str(m.check_id) if m.check_id else None, "d": m.duration_minutes, "r": m.reason, "u": str(plan.requested_by)}).scalar()
    # review 3 L2: only a window someone OTHER than the requester approved may later lower a deployment change's approval tier
    if db.execute(text("SELECT 1 FROM plan_approvals WHERE plan_id = :p AND approver_id <> :u"), {"p": str(plan.id), "u": str(plan.requested_by)}).first():
        db.execute(text("UPDATE maintenance_windows SET independently_approved = true WHERE id = :i"), {"i": wid})
    audit.append(db, "maintenance.created", actor_name="worker", resource="maintenance", resource_id=str(wid),
                 details={"name": m.name, "check_id": str(m.check_id) if m.check_id else None, "minutes": m.duration_minutes, "reason": m.reason})
    who = db.execute(text("SELECT username FROM users WHERE id = :u"), {"u": str(plan.requested_by)}).scalar()
    scope = db.execute(text("SELECT name FROM checks WHERE id = :c"), {"c": str(m.check_id)}).scalar() if m.check_id else "ALL checks"
    detail = (f"Maintenance window '{m.name}' started by {who} for {m.duration_minutes} min; scope: {scope}; reason: {m.reason or '-'}. "
              "Alerts and automatic remediation for this scope are suppressed until it ends.")
    monitor.enqueue_notifications(db, SimpleNamespace(id=None), None, "maintenance_started", re.sub(r"[^\x20-\x7e]", "?", detail)[:400], force=True)
    return {"maintenance_id": str(wid)}


def _exec_channel_create(rt: Runtime, db: Session, m: AlertChannelCreate, plan, known: list[str]) -> dict:
    cid = uuid.uuid4()
    enc = None
    if m.secret:
        known.append(m.secret.get_secret_value())
        enc = rt.vault.encrypt(m.secret.get_secret_value().encode(), monitor.channel_aad(cid, m.config))
    db.execute(text("INSERT INTO alert_channels (id, name, kind, config, secret_enc, enabled, created_by, customer_id) "
                    "VALUES (:id, :n, :k, CAST(:c AS jsonb), :s, :e, :u, :cu)"),
               {"cu": str(plan.customer_id or tscope.DEFAULT_CUSTOMER), "id": str(cid), "n": m.name, "k": m.kind, "c": audit.canon(m.config), "s": enc, "e": bool(m.enabled), "u": str(plan.requested_by)})
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
    r = db.execute(text("UPDATE incidents SET status = 'acked', acked_by = :u, acked_at = now(), ack_note = :n, escalated_at = NULL "
                        "WHERE id = :i AND status = 'open' RETURNING id"), {"u": str(plan.requested_by), "n": m.note, "i": str(m.incident_id)}).first()
    if r is None:
        raise PlanIntegrityError("incident is not open")
    audit.append(db, "incident.acked", actor_name="worker", resource="incident", resource_id=str(m.incident_id),
                 details={"by": str(plan.requested_by), "note": m.note})
    return {"incident_id": str(m.incident_id), "status": "acked"}


class AgentRejected(AgentError):
    pass


def _exec_runbook(rt: Runtime, db: Session, m: RunbookExecute, plan, known: list[str]) -> dict:
    if m.attempt_id is not None and (why := _stale_remediation(db, {"attempt_id": m.attempt_id})):
        raise PlanIntegrityError(why)
    node = db.execute(text("SELECT * FROM nodes WHERE id = :i"), {"i": str(m.node_id)}).first()
    if node is None or node.status == "decommissioned":
        raise PlanIntegrityError("node not found or decommissioned")
    jid = str(db.execute(text("SELECT id FROM jobs WHERE plan_id = :p"), {"p": str(plan.id)}).scalar())
    priv = agentclient.load_signing_key(rt.settings.signing_key_file)
    params = {"unit": m.unit} if m.unit else {"path": m.path}
    body = agentclient.build_request(priv, action=m.runbook, params=params, node_id=str(node.id), job_id=jid,
                                     ttl=rt.settings.agent_request_ttl_seconds, epoch=rt.agent_epoch())
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


_EXEC = {ActionType.endpoint_register: endpoint_actions.exec_register, ActionType.inventory_refresh: _exec_refresh,
         ActionType.user_create: _exec_user_create, ActionType.user_set_role: _exec_user_set_role,
         ActionType.user_invite: _exec_user_create, ActionType.user_revoke_invite: _exec_user_revoke_invite,
         ActionType.user_disable: _exec_user_disable, ActionType.user_enable: _exec_user_enable,
         ActionType.user_revoke_sessions: _exec_user_revoke_sessions,
         ActionType.node_enroll: _exec_node_enroll, ActionType.check_create: _exec_check_create,
         ActionType.check_set_enabled: _exec_check_set_enabled, ActionType.check_bind_remediation: _exec_check_bind,
         ActionType.maintenance_create: _exec_maintenance, ActionType.alert_channel_create: _exec_channel_create,
         ActionType.alert_channel_test: _exec_channel_test, ActionType.incident_ack: _exec_ack, ActionType.runbook_execute: _exec_runbook,
         ActionType.check_delete: removal.exec_check_delete, ActionType.alert_channel_delete: removal.exec_channel_delete,
         ActionType.node_decommission: removal.exec_node_decommission, ActionType.maintenance_cancel: removal.exec_maintenance_cancel,
         ActionType.maintenance_delete: removal.exec_maintenance_delete, ActionType.plan_archive: removal.exec_plan_archive,
         **{ActionType(k): v for k, v in identity.EXECUTORS.items()},
         **{ActionType(k): v for k, v in deploy_ops.EXECUTORS.items()},
         **{ActionType(k): v for k, v in endpoint_actions.EXECUTORS.items()},
         **{ActionType(k): v for k, v in prov_actions.EXECUTORS.items()},
         **{ActionType(k): v for k, v in {**cred_actions.EXECUTORS, **ten_actions.EXECUTORS}.items()},
         ActionType.release_promote: release_ops.exec_promote,
         **{ActionType(k): v for k, v in backup_ops.EXECUTORS.items()}}
