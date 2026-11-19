"""Typed provisioning actions (all are plans -> approval by risk -> single-use job -> audit):

  provider.provision.plan_preview   low     read-only: discover + compute the permission plan; stores it, returns its hash
  provider.provision.apply          high    MODE A: apply a previewed plan with TEMPORARY admin credentials, capture token secrets into the vault
  provider.provision.package        normal  MODE B: generate the customer package (script, commands, report, JSON, rollback)
  provider.credential.import        normal  MODE B step 2: import the customer-created token(s); validate against the package; register the endpoint
  provider.permissions.reconcile    high    restore a drifted integration to its stored policy (previewed plan, hash-bound)
  provider.token.rotate             high    issue a new token generation, switch the vault, delete the old token
  provider.token.revoke             high    delete the tokens (and optionally what the ICS created) and destroy the stored credentials

Temporary credentials (admin password / privileged token) are plan secrets: encrypted with the vault under the plan id, NEVER in params,
audit or job results, valid for TEMP_CRED_TTL seconds, decrypted only inside the job, wiped from the plan row when the job ends
(success or failure) and by the reaper when the plan is rejected/expired.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from functools import wraps
from typing import Literal
from urllib.parse import urlparse
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError, field_validator, model_validator
from sqlalchemy import text
from sqlalchemy.orm import Session

from .. import audit, endpoint_actions as ea
from ..credentials import service as cred_service
from ..providers.base import ProviderError
from ..providers.proxmox import provisioning as pp
from ..providers.proxmox import scope_change as sc_mod
from ..providers.proxmox.admin import ProxmoxAdminClient
from ..proxmox import ProxmoxError, normalize_fingerprint
from ..runtime import Runtime
from .model import ConflictChoices, Policy
from .scope_model import ScopeTarget

TEMP_CRED_TTL = 15 * 60
USER_RE = r"^[^@\s!:/]{1,64}@[A-Za-z0-9._-]{1,32}$"
SECRETS = ("admin_password", "admin_token_secret", "inventory_token_secret", "provision_token_secret")


class Conn(BaseModel):
    """Either an existing endpoint, or the connection details of a cluster that is not registered yet."""
    endpoint_id: UUID | None = None
    customer_id: UUID | None = None      # owner of a NOT-yet-registered cluster (defaults to the MSP's internal customer); must match the endpoint's
    name: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9_-]{0,62}$")
    base_url: str | None = None
    ca_pem: str | None = Field(default=None, max_length=100_000)
    fingerprint_sha256: str | None = None

    @field_validator("base_url")
    @classmethod
    def _u(cls, v):
        return ea._check_url(v) if v is not None else v

    @field_validator("ca_pem")
    @classmethod
    def _c(cls, v):
        return ea._check_ca(v)

    @field_validator("fingerprint_sha256")
    @classmethod
    def _f(cls, v):
        return normalize_fingerprint(v) if v is not None else v

    def _conn_ok(self, required: bool):
        if self.endpoint_id is not None:
            if self.base_url or self.ca_pem or self.fingerprint_sha256 or self.name:
                raise ValueError("endpoint_id cannot be combined with connection details")
        elif self.base_url or self.name or self.ca_pem or self.fingerprint_sha256:
            if not (self.base_url and self.name and (bool(self.ca_pem) != bool(self.fingerprint_sha256))):
                raise ValueError("a new connection needs name, base_url and exactly one of ca_pem / fingerprint_sha256")
        elif required:
            raise ValueError("either endpoint_id or name+base_url+trust anchor is required")


class TempCreds(BaseModel):
    """TEMPORARY provisioning credentials: a signed-in Proxmox admin session (`admin_session`: wizard login incl. second factor; the server copies
    its ticket into the plan's temporary credential, so the job never needs a password or a TOTP code), PVE admin user+password, OR an existing
    privileged API token. `admin_ticket` / `admin_csrf` / `admin_ticket_user` are set by the server only (refused from clients in create_plan)."""
    admin_username: str | None = Field(default=None, pattern=USER_RE)
    admin_password: SecretStr | None = None
    admin_token_id: str | None = Field(default=None, pattern=ea.TOKEN_ID_RE)
    admin_token_secret: SecretStr | None = None
    admin_session: UUID | None = None
    admin_ticket_user: str | None = Field(default=None, pattern=USER_RE)
    admin_ticket: SecretStr | None = None
    admin_csrf: SecretStr | None = None

    @field_validator("admin_token_secret", mode="before")
    @classmethod
    def _s(cls, v):
        return ea.norm_secret(v)

    def has_creds(self) -> bool:
        """At plan time a named session counts (create_plan copies its ticket in); at execution the ticket itself must be present."""
        return bool((self.admin_username and self.admin_password) or (self.admin_token_id and self.admin_token_secret)
                    or (self.admin_ticket and self.admin_csrf and self.admin_ticket_user) or self.admin_session is not None)

    def _shape(self):
        pw = bool(self.admin_username) or self.admin_password is not None
        tk = bool(self.admin_token_id) or self.admin_token_secret is not None
        ss = self.admin_session is not None
        if int(pw) + int(tk) + int(ss) > 1:
            raise ValueError("supply one of: a Proxmox sign-in session, admin username+password, or an admin token")
        if (self.admin_ticket is not None or self.admin_csrf is not None) and not ss:
            raise ValueError("credential is incomplete")
        if (bool(self.admin_username) != (self.admin_password is not None)) or (bool(self.admin_token_id) != (self.admin_token_secret is not None)):
            raise ValueError("credential is incomplete")


class PlanPreview(Conn, TempCreds):
    model_config = ConfigDict(extra="forbid")
    purpose: Literal["provision", "reconcile", "scope_change"] = "provision"
    policy: Policy | None = None
    scope_target: ScopeTarget | None = None
    pve_major: Literal[8, 9] | None = Field(default=None, description="only for an offline preview")
    choices: ConflictChoices | None = Field(default=None, description="purpose=provision only: what to do with each conflicting pre-existing object "
                                            "and which Office Unbound leftovers to remove. Bound into the plan hash; re-checked at apply.")

    @model_validator(mode="after")
    def _chk(self):
        self._conn_ok(False)
        self._shape()
        if self.choices is not None and (self.purpose != "provision" or not self.has_creds()):
            raise ValueError("conflict choices and cleanup apply to a provisioning preview with temporary provisioning credentials")
        if self.purpose == "scope_change":
            if self.endpoint_id is None or self.scope_target is None or self.policy is not None:
                raise ValueError("a scope-change preview names an endpoint and a scope_target (the policy itself is not edited here)")
            return self
        if self.scope_target is not None:
            raise ValueError("scope_target only applies to purpose=scope_change")
        if self.purpose == "reconcile" and (self.endpoint_id is None or self.policy is not None):
            raise ValueError("a reconcile preview names an endpoint and uses its stored policy (it cannot change the policy)")
        if self.purpose == "provision" and self.policy is None:
            raise ValueError("policy is required")
        if self.endpoint_id is None and not self.base_url and not self.pve_major:
            raise ValueError("offline preview needs pve_major")
        return self


class ProvisionApply(Conn, TempCreds):
    model_config = ConfigDict(extra="forbid")
    preview_id: UUID
    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _chk(self):
        self._conn_ok(True)
        self._shape()
        return self


class ProvisionPackage(Conn):
    model_config = ConfigDict(extra="forbid")
    policy: Policy
    pve_major: Literal[8, 9] | None = None

    @model_validator(mode="after")
    def _chk(self):
        self._conn_ok(False)
        if self.endpoint_id is None and self.pve_major is None:
            raise ValueError("pve_major is required (no connected cluster to detect it from)")
        return self


class CredentialImport(Conn):
    model_config = ConfigDict(extra="forbid")
    package_id: UUID
    inventory_token_id: str = Field(pattern=ea.TOKEN_ID_RE)
    inventory_token_secret: SecretStr
    provision_token_id: str | None = Field(default=None, pattern=ea.TOKEN_ID_RE)
    provision_token_secret: SecretStr | None = None

    @field_validator("inventory_token_secret", "provision_token_secret", mode="before")
    @classmethod
    def _s(cls, v):
        return ea.norm_secret(v)

    @model_validator(mode="after")
    def _chk(self):
        self._conn_ok(True)
        if (self.provision_token_id is None) != (self.provision_token_secret is None):
            raise ValueError("provision token id and secret go together")
        return self


class PermissionsReconcile(TempCreds):
    model_config = ConfigDict(extra="forbid")
    endpoint_id: UUID
    preview_id: UUID
    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _chk(self):
        self._shape()
        return self


class TokenRotate(TempCreds):
    model_config = ConfigDict(extra="forbid")
    endpoint_id: UUID
    kinds: list[Literal["inventory", "provision"]] = Field(default_factory=lambda: ["inventory", "provision"], min_length=1)

    @model_validator(mode="after")
    def _chk(self):
        self._shape()
        return self


class TokenRevoke(TempCreds):
    model_config = ConfigDict(extra="forbid")
    endpoint_id: UUID
    confirm_name: str = Field(max_length=63)
    delete_user: bool = False
    delete_roles: bool = False

    @model_validator(mode="after")
    def _chk(self):
        self._shape()
        return self


class ScopeChange(TempCreds):
    """provider.scope.change: apply a previewed scope change (Mode A, temporary admin credentials) or confirm that the customer ran the Mode B package."""
    model_config = ConfigDict(extra="forbid")
    endpoint_id: UUID
    preview_id: UUID
    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    direction: Literal["widen", "narrow", "same"]
    detach: bool = False
    execution: Literal["mode_a", "confirm_package"] = "mode_a"
    package_id: UUID | None = None

    @model_validator(mode="after")
    def _chk(self):
        self._shape()
        if self.execution == "confirm_package" and (self.package_id is None or self.has_creds()):
            raise ValueError("confirming a package needs package_id and no administrator credentials")
        if self.execution == "mode_a" and self.package_id is not None:
            raise ValueError("package_id only applies to execution=confirm_package")
        return self


class ScopePackage(BaseModel):
    """provider.scope.package: Mode B. The customer-runnable script for a previewed scope change (no credentials involved)."""
    model_config = ConfigDict(extra="forbid")
    endpoint_id: UUID
    preview_id: UUID
    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    direction: Literal["widen", "narrow", "same"]
    detach: bool = False


def _scope_risk(p) -> str:
    return "high" if (p.direction == "widen" or p.detach) else "normal"


def _pkg_risk(p: ProvisionPackage) -> str:
    return "high" if (p.policy.preset == "full_admin" or p.policy.allow_cicustom or p.policy.approve_elevated) else "normal"


ADMIN_SECRETS = ("admin_password", "admin_token_secret", "admin_ticket", "admin_csrf")
SERVER_ONLY = ("admin_ticket", "admin_csrf", "admin_ticket_user")
SESSION_FINAL = ("provider.provision.apply", "provider.permissions.reconcile", "provider.token.rotate", "provider.token.revoke", "provider.scope.change",
                 "provider.cleanup")


def session_target(db: Session, full: dict) -> tuple[str | None, str | None, str | None]:
    """(base_url, ca_pem, fingerprint) the plan will talk to: the endpoint's anchors, or the new connection's."""
    if full.get("endpoint_id"):
        ep = _ep(db, full["endpoint_id"])
        if ep is None:
            return None, None, None
        return ep.base_url, ep.ca_pem, ep.fingerprint_sha256
    return full.get("base_url"), full.get("ca_pem"), full.get("fingerprint_sha256")


CATALOG = {
    "provider.provision.plan_preview": {"model": PlanPreview, "risk": "low", "secrets": ADMIN_SECRETS},
    "provider.provision.apply": {"model": ProvisionApply, "risk": "high", "secrets": ADMIN_SECRETS},
    "provider.provision.package": {"model": ProvisionPackage, "risk": _pkg_risk, "secrets": ()},
    "provider.credential.import": {"model": CredentialImport, "risk": "normal", "secrets": ("inventory_token_secret", "provision_token_secret")},
    "provider.permissions.reconcile": {"model": PermissionsReconcile, "risk": "high", "secrets": ADMIN_SECRETS},
    "provider.token.rotate": {"model": TokenRotate, "risk": "high", "secrets": ADMIN_SECRETS},
    "provider.token.revoke": {"model": TokenRevoke, "risk": "high", "secrets": ADMIN_SECRETS},
    "provider.scope.change": {"model": ScopeChange, "risk": _scope_risk, "secrets": ADMIN_SECRETS},
    "provider.scope.package": {"model": ScopePackage, "risk": _scope_risk, "secrets": ()},
}


# ---------------------------------------------------------------------------------------------------- helpers
def _ep(db: Session, eid):
    return db.execute(text("SELECT * FROM endpoints WHERE id = :i"), {"i": str(eid)}).first()


def _artifact(db: Session, aid, kind: str):
    r = db.execute(text("SELECT * FROM provision_artifacts WHERE id = :i AND kind = :k"), {"i": str(aid), "k": kind}).first()
    return r


def _stored(db: Session, eid):
    return db.execute(text("SELECT * FROM endpoint_policy WHERE endpoint_id = :e"), {"e": str(eid)}).first()


def safe(fn):
    """Provider/validation errors become operator-readable job errors (the job runner only passes ProxmoxError text through)."""
    @wraps(fn)
    def run(*a, **k):
        try:
            return fn(*a, **k)
        except ProviderError as e:
            raise ProxmoxError(e.message) from None
        except ValidationError:     # pydantic echoes input values (could be a secret): withhold the details
            raise ProxmoxError("a parameter was rejected during execution (details withheld to protect credentials)") from None
        except (pp.PlanBuildError, ValueError) as e:
            raise ProxmoxError(str(e)[:400]) from None
    return run


def _need_creds(rt: Runtime, m, plan) -> None:
    age = (datetime.now(timezone.utc) - plan.created_at).total_seconds()
    if age > TEMP_CRED_TTL:
        raise ProxmoxError(f"the temporary provisioning credentials expired (they are valid for {TEMP_CRED_TTL // 60} minutes after the plan is created); "
                           "create a new plan")
    if not m.has_creds():
        raise ProxmoxError("the temporary provisioning credentials are no longer available (expired, rejected or already discarded)")


def _kw(rt: Runtime, ca, fp) -> dict:
    s = rt.settings
    return dict(ca_pem=ca, fingerprint_sha256=fp, deadline=s.pve_request_deadline_seconds, max_bytes=s.pve_max_response_bytes,
                allow_loopback=s.allow_loopback_endpoints)


def open_admin(rt: Runtime, m, base_url, ca, fp, known: list[str]) -> ProxmoxAdminClient:
    if getattr(m, "admin_session", None) is not None and getattr(m, "admin_ticket", None) is None:
        raise ProxmoxError("the Proxmox sign-in for this plan is no longer available (expired or already used): sign in again and create a new plan")
    if getattr(m, "admin_ticket", None) is not None:
        t, c = m.admin_ticket.get_secret_value(), m.admin_csrf.get_secret_value() if m.admin_csrf else ""
        known += [t, c]
        return ProxmoxAdminClient(base_url, username=m.admin_ticket_user, ticket=t, csrf=c, **_kw(rt, ca, fp))
    pw = m.admin_password.get_secret_value() if m.admin_password else None
    ts = m.admin_token_secret.get_secret_value() if m.admin_token_secret else None
    known += [x for x in (pw, ts) if x]
    return ProxmoxAdminClient(base_url, username=m.admin_username, password=pw, token_id=m.admin_token_id, token_secret=ts, **_kw(rt, ca, fp))


class _Reader:
    def __init__(self, c):
        self.get, self.close = c._get, c.close


def _resolve(db: Session, m):
    if m.endpoint_id is not None:
        ep = _ep(db, m.endpoint_id)
        if ep is None or ep.detached_at is not None:
            raise ProxmoxError("endpoint not found or removed")
        return ep.base_url, ep.ca_pem, ep.fingerprint_sha256, ep
    return m.base_url, m.ca_pem, m.fingerprint_sha256, None


def _managed(db: Session, ep) -> dict:
    if ep is None:
        return {}
    r = _stored(db, ep.id)
    return dict(r.managed) if r else {}


def _owned(db: Session) -> dict:
    """Everything a CONNECTED (not removed) integration holds in any Proxmox cluster: its service user, tokens, roles and pools (stored
    provisioning state plus the endpoint's own token ids and pool allowlist). Nothing in here is ever offered as a leftover."""
    o: dict[str, set] = {"users": set(), "tokens": set(), "roles": set(), "pools": set()}
    rows = db.execute(text("SELECT e.token_id, e.provision_token_id, e.allowed_pools, p.managed, p.design FROM endpoints e "
                           "LEFT JOIN endpoint_policy p ON p.endpoint_id = e.id WHERE e.detached_at IS NULL")).all()
    for r in rows:
        for t in (r.token_id, r.provision_token_id):
            if t:
                o["tokens"].add(t)
                o["users"].add(t.split("!")[0])
        o["pools"] |= set(r.allowed_pools or [])
        mg, dz = dict(r.managed or {}), dict(r.design or {})
        if mg.get("user"):
            o["users"].add(mg["user"])
        o["tokens"] |= set(mg.get("tokens") or [])
        o["users"] |= {t.split("!")[0] for t in mg.get("tokens") or []}
        o["roles"] |= set(mg.get("roles") or []) | set((dz.get("roles") or {}).values())
        o["pools"] |= set(mg.get("pools") or [])
    return {k: sorted(v) for k, v in o.items()}


def _save_artifact(db: Session, kind: str, ep_id, plan_hash, data: dict, user, customer_id=None) -> str:
    aid = uuid.uuid4()
    db.execute(text("INSERT INTO provision_artifacts (id, kind, endpoint_id, plan_hash, data, created_by, customer_id) VALUES "
                    "(:i, :k, :e, :h, CAST(:d AS jsonb), :u, :c)"),
               {"i": str(aid), "k": kind, "e": str(ep_id) if ep_id else None, "h": plan_hash, "d": json.dumps(data, default=str), "u": user,
                "c": str(customer_id) if customer_id else None})
    return str(aid)


def _summary(plan_dict: dict) -> dict:
    return {"plan_hash": plan_dict["plan_hash"], "risk": plan_dict["risk"], "summary": plan_dict["summary"], "blocked": plan_dict["blocked"],
            "conflicts": plan_dict["conflicts"], "warnings": plan_dict["warnings"][:20],
            "elevated": plan_dict["elevated"], "consequences": plan_dict["consequences"],
            "steps": [f"{s['op']} {s['kind']} {s['target']}" for s in plan_dict["steps"] if s["op"] != "noop"][:120]}


# ---------------------------------------------------------------------------------------------------- prechecks (plan time)
def precheck(db: Session, rt: Runtime, action: str, p) -> dict:
    from ..actions import PlanError, _guard
    extra: dict = {}
    eid = getattr(p, "endpoint_id", None)
    ep = None
    if eid is not None:
        ep = _ep(db, eid)
        if ep is None:
            raise PlanError(404, "endpoint not found")
        if ep.detached_at is not None:
            raise PlanError(409, "endpoint is removed (detached)")
        extra["endpoint_name"] = ep.name
    elif getattr(p, "base_url", None):
        try:
            extra["resolved_ips"] = _guard(rt, urlparse(p.base_url).hostname)
        except ProxmoxError as e:
            raise PlanError(422, str(e)) from None
        if db.execute(text("SELECT 1 FROM endpoints WHERE name = :n"), {"n": p.name}).first():
            raise PlanError(409, "endpoint name already exists")
    if action in ("provider.provision.apply", "provider.permissions.reconcile"):
        if not p.has_creds():
            raise PlanError(422, "temporary provisioning credentials are required")
        art = _artifact(db, p.preview_id, "plan")
        if art is None:
            raise PlanError(404, "preview not found: run provider.provision.plan_preview first")
        if art.plan_hash != p.plan_hash:
            raise PlanError(409, "plan_hash does not match the stored preview")
        pd = art.data["plan"]
        if pd["blocked"]:
            raise PlanError(409, "the previewed plan is blocked: " + "; ".join(pd["blocked"]))
        if (action == "provider.permissions.reconcile") != (art.data.get("purpose") == "reconcile"):
            raise PlanError(409, "preview purpose does not match this action")
        if action == "provider.permissions.reconcile" and str(art.endpoint_id) != str(eid):
            raise PlanError(409, "preview belongs to another endpoint")
        extra["plan_summary"] = _summary(pd)
    elif action in ("provider.scope.change", "provider.scope.package"):
        art = _artifact(db, p.preview_id, "plan")
        if art is None or art.data.get("purpose") != "scope_change":
            raise PlanError(404, "scope-change preview not found: run provider.provision.plan_preview with purpose=scope_change first")
        if str(art.endpoint_id) != str(eid):
            raise PlanError(409, "preview belongs to another endpoint")
        if art.plan_hash != p.plan_hash:
            raise PlanError(409, "plan_hash does not match the stored preview")
        sd = art.data["scope"]
        if sd["blocked"]:
            raise PlanError(409, "the previewed scope change is blocked: " + "; ".join(sd["blocked"]))
        if sd["direction"] != p.direction or bool(sd["detach"]) != bool(p.detach):
            raise PlanError(409, "direction/detach do not match the previewed change (they decide the risk and the approvals)")
        if action == "provider.scope.change" and p.execution == "mode_a" and not p.has_creds():
            raise PlanError(422, "temporary provisioning credentials are required (or use the Mode B package and confirm it)")
        if action == "provider.scope.change" and p.execution == "confirm_package":
            pk = _artifact(db, p.package_id, "package")
            if pk is None or str(pk.data.get("scope_preview_id")) != str(p.preview_id):
                raise PlanError(404, "scope package not found for this preview")
        extra["preview_risk"] = sd.get("risk", "high" if sd["direction"] == "widen" else "normal")   # review 5 M3: the plan takes max(risk_fn, preview risk)
        extra["scope_change"] = {"direction": sd["direction"], "old": sd["old_scope"], "new": sd["new_scope"], "detach": sd["detach"],
                                 "acl_add": len(sd["diff"]["acl_add"]), "acl_remove": len(sd["diff"]["acl_remove"])}
    elif action == "provider.token.revoke":
        if p.confirm_name != ep.name:
            raise PlanError(422, "confirm_name does not match the endpoint name")
        if _stored(db, ep.id) is None:
            raise PlanError(409, "this endpoint has no provisioning policy (it was registered manually): nothing to revoke here; use endpoint.remove")
        if (p.delete_user or p.delete_roles) and not p.has_creds():
            raise PlanError(422, "deleting the service user or roles needs the temporary provisioning credentials")
        extra["revokes_remote"] = p.has_creds()
    elif action == "provider.cleanup":
        from . import cleanup
        extra.update(cleanup.precheck(db, rt, p, ep))
    elif action == "provider.token.rotate":
        if _stored(db, ep.id) is None:
            raise PlanError(409, "this endpoint has no provisioning policy")
        if not p.has_creds():
            raise PlanError(422, "temporary provisioning credentials are required")
    elif action == "provider.credential.import":
        art = _artifact(db, p.package_id, "package")
        if art is None:
            raise PlanError(404, "package not found")
        extra["package_plan_hash"] = art.plan_hash
    elif action == "provider.provision.plan_preview":
        if p.purpose == "reconcile" and (ep is None or _stored(db, ep.id) is None):
            raise PlanError(409, "endpoint has no stored policy to reconcile to")
    return extra


# ---------------------------------------------------------------------------------------------------- executors
def _facts_client(rt: Runtime, m, db: Session, base_url, ca, fp, ep, known: list[str]):
    """(client with .get, closer). Admin credentials when supplied, otherwise the endpoint's inventory token (read-only)."""
    if getattr(m, "has_creds", None) and m.has_creds():
        a = open_admin(rt, m, base_url, ca, fp, known)
        return a, a.discard
    if ep is not None:
        from ..actions import _client_for
        c = _client_for(rt, ep, known)
        return _Reader(c), c.close
    return None, (lambda: None)


def _db_guests(db: Session, eid) -> list[dict]:
    return [dict(vmid=r.vmid, node=r.node, name=r.name, ou_deployment_id=r.ou_deployment_id) for r in
            db.execute(text("SELECT vmid, node, name, ou_deployment_id FROM infra_guests WHERE endpoint_id = :e AND ou_managed"), {"e": str(eid)}).all()]


def _scope_inputs(cli, facts: pp.Facts, db_guests: list[dict]) -> tuple[list[dict], dict[int, set[str]]]:
    """Node capacity rows and the storages used by managed guests (read-only GETs, best effort)."""
    try:
        rows = list(cli.get("/nodes"))
    except ProxmoxError:
        rows = []
    stor: dict[int, set[str]] = {}
    managed = {g["vmid"]: g for g in db_guests}
    for vmid, g in facts.guests.items():
        if "ou-managed" in (g.get("tags") or "").split(";"):
            managed.setdefault(vmid, {"vmid": vmid, "node": g.get("node")})
    for vmid, g in managed.items():
        live = facts.guests.get(vmid, {})
        node, kind = live.get("node") or g.get("node"), "lxc" if live.get("type") == "lxc" else "qemu"
        if not node:
            continue
        try:
            stor[vmid] = sc_mod.parse_config_storages(cli.get(f"/nodes/{node}/{kind}/{vmid}/config"))
        except ProxmoxError:
            pass
    return rows, stor


def _preview_scope(rt: Runtime, db: Session, m: PlanPreview, plan, known: list[str], base_url, ca, fp, ep, stored) -> dict:
    if stored is None:
        raise ProxmoxError("this endpoint has no provisioning policy; scope changes apply to provisioned integrations")
    if m.has_creds():
        _need_creds(rt, m, plan)
    cli, close = _facts_client(rt, m, db, base_url, ca, fp, ep, known)
    try:
        facts = pp.collect_facts(cli)
        dbg = _db_guests(db, ep.id)
        rows, gst = _scope_inputs(cli, facts, dbg)
    finally:
        close()
    old = Policy.model_validate(stored.policy)
    sc = sc_mod.build(old, stored.design, m.scope_target, facts, dict(stored.managed), db_guests=dbg, guest_storages=gst, node_rows=rows)
    pd = sc.plan.to_dict()
    data = {"plan": pd, "purpose": "scope_change", "scope": {**sc.to_dict(), "detach": sc.detach}, "policy_new": sc.new.model_dump(mode="json"),
            "target": m.scope_target.model_dump(mode="json"), "conn": {"base_url": base_url}}
    aid = _save_artifact(db, "plan", ep.id, sc.hash, data, plan.requested_by, plan.customer_id)
    audit.append(db, "provider.scope.previewed", actor_name="worker", resource="endpoint", resource_id=str(ep.id),
                 details={"preview_id": aid, "scope_hash": sc.hash, "direction": sc.direction, "blocked": sc.blocked,
                          "old": sc_mod.scope_summary(sc.old), "new": sc_mod.scope_summary(sc.new)})
    return {"preview_id": aid, "plan_hash": sc.hash, "risk": sc.risk, "direction": sc.direction, "blocked": sc.blocked, "scope": data["scope"],
            "summary": pd["summary"], "plan": pd}


@safe
def exec_preview(rt: Runtime, db: Session, m: PlanPreview, plan, known: list[str]) -> dict:
    base_url, ca, fp, ep = _resolve(db, m)
    stored = _stored(db, ep.id) if ep else None
    if m.purpose == "scope_change":
        return _preview_scope(rt, db, m, plan, known, base_url, ca, fp, ep, stored)
    if m.purpose == "reconcile":
        policy = Policy.model_validate(stored.policy)
    else:
        policy = m.policy
    if m.has_creds():
        _need_creds(rt, m, plan)
    cli, close = _facts_client(rt, m, db, base_url, ca, fp, ep, known) if (m.base_url or ep) else (None, lambda: None)
    try:
        facts = pp.collect_facts(cli) if cli is not None else None
    finally:
        close()
    owned = _owned(db) if (facts is not None and m.has_creds()) else None
    pl = pp.plan_for(policy, facts, pve_major=m.pve_major, managed=_managed(db, ep), prune=(m.purpose == "reconcile"), mode="A",
                     choices=m.choices, owned=owned)
    pd = pl.to_dict()
    aid = _save_artifact(db, "plan", ep.id if ep else None, pd["plan_hash"],
                         {"plan": pd, "purpose": m.purpose, "conn": {"base_url": base_url, "name": m.name},
                          **({"choices": m.choices.model_dump(mode="json")} if m.choices is not None else {})}, plan.requested_by,
                         plan.customer_id)
    audit.append(db, "provider.provision.previewed", actor_name="worker", resource="plan", resource_id=str(plan.id),
                 details={"preview_id": aid, "plan_hash": pd["plan_hash"], "purpose": m.purpose, "summary": pd["summary"], "blocked": pd["blocked"]})
    return {"preview_id": aid, "plan_hash": pd["plan_hash"], "risk": pd["risk"], "summary": pd["summary"], "plan": pd}


def _verify_all(rt: Runtime, base_url, ca, fp, policy: Policy, d: pp.Design, secrets: dict[str, tuple[str, str]], facts: pp.Facts | None,
                known: list[str]) -> dict:
    from ..actions import _new_client
    out = {}
    nodes = sorted(facts.nodes) if facts else []
    stores = sorted(facts.storages) if facts else []
    for kind, (tid, sec) in secrets.items():
        known.append(sec)
        c = _new_client(rt, base_url, tid, sec, ca, fp)
        try:
            out[kind] = pp.verify_token(_Reader(c), d, policy, kind, nodes, stores)
        finally:
            c.close()
    out["ok"] = all(v["ok"] for v in out.values())
    return out


def _problem(v: dict) -> str:
    bits = []
    for kind, r in v.items():
        if kind == "ok" or r["ok"]:
            continue
        for k in ("missing", "unexpected", "forbidden", "unauthorized_exposure", "scope_reach"):
            if r[k]:
                bits.append(f"{kind} token {k}: " + "; ".join(f"{x['path']} {','.join(x['privileges'])}" for x in r[k])[:200])
        for vb in r["verbs"]:
            if not vb["ok"]:
                bits.append(f"{kind} token cannot {vb['verb']}")
    return " | ".join(bits)[:500] or "verification failed"


def _scope_kwargs(policy: Policy) -> dict:
    s = policy.scope
    return dict(allowed_pools=s.pools or None, allowed_storage=sorted(set(s.storages + s.backup_storages + s.import_storages)) or None,
                allowed_nodes=s.nodes or None, allowed_networks=s.networks or None, allowed_templates=s.template_vmids or None, allow_cicustom=policy.allow_cicustom,
                protected_vmids=s.protected_vmids or None, managed_vmids=s.managed_vmids or None)


def _register(rt: Runtime, db: Session, m, plan, known: list[str], ep, base_url, ca, fp, policy: Policy, secrets: dict, d: pp.Design) -> str:
    """Write the endpoint (new or existing) with the captured/imported tokens: the same code path as endpoint.register / endpoint.update."""
    from ..actions import EndpointRegister
    inv_id, inv_sec = secrets["inventory"]
    prov = secrets.get("provision")
    if not prov and "provision" in d.tokens:
        raise ProxmoxError("the provision token is missing")
    trust = {"ca_pem": ca} if ca else {"fingerprint_sha256": fp}
    if ep is None:
        reg = EndpointRegister(name=m.name, type="proxmox", base_url=base_url, token_id=inv_id, token_secret=inv_sec,
                               provision_token_id=prov[0] if prov else None, provision_token_secret=prov[1] if prov else None,
                               customer_id=getattr(m, "customer_id", None), **_scope_kwargs(policy), **trust)
        return ea.exec_register(rt, db, reg, plan, known)["endpoint_id"]
    upd = ea.EndpointUpdate(endpoint_id=ep.id, token_id=inv_id, token_secret=inv_sec,
                            **({"provision_token_id": prov[0], "provision_token_secret": prov[1]} if prov else {"remove_provision": bool(ep.provision_token_id)}),
                            **_scope_kwargs(policy))
    ea.exec_update(rt, db, upd, plan, known)
    return str(ep.id)


def _upsert_policy(db: Session, eid, policy: Policy, pd: dict, plan_obj_design: dict, mode: str, managed: dict, tokens: dict, verification: dict) -> None:
    db.execute(text(
        "INSERT INTO endpoint_policy (endpoint_id, policy, design, plan_hash, mode, managed, tokens, status, last_verification, last_verified_at, updated_at) "
        "VALUES (:e, CAST(:p AS jsonb), CAST(:d AS jsonb), :h, :m, CAST(:mg AS jsonb), CAST(:t AS jsonb), 'ok', CAST(:v AS jsonb), now(), now()) "
        "ON CONFLICT (endpoint_id) DO UPDATE SET policy = EXCLUDED.policy, design = EXCLUDED.design, plan_hash = EXCLUDED.plan_hash, mode = EXCLUDED.mode, "
        "managed = EXCLUDED.managed, tokens = EXCLUDED.tokens, status = 'ok', last_verification = EXCLUDED.last_verification, "
        "last_verified_at = now(), last_drift = NULL, last_drift_at = NULL, updated_at = now()"),
        {"e": str(eid), "p": json.dumps(policy.model_dump(mode="json")), "d": json.dumps(plan_obj_design), "h": pd["plan_hash"], "m": mode,
         "mg": json.dumps(managed), "t": json.dumps(tokens), "v": json.dumps(audit.sanitize(verification), default=str)})


def _merge_managed(old: dict, res: pp.ApplyResult) -> dict:
    c = res.created
    m = {k: list(old.get(k, [])) for k in ("pools", "roles", "tokens", "acl")}
    m["user"] = old.get("user") or c["user"]
    for k in ("pools", "roles", "tokens"):
        m[k] = sorted(set(m[k]) | set(c[k]))
    m["roles"] = sorted(set(m["roles"]) | set(c.get("adopted_roles") or []))      # overwritten by the approver's choice: now Office Unbound's
    m["acl"] = sorted({tuple(x) for x in m["acl"]} | {tuple(x) for x in c["acl"]})
    m["acl"] = [list(x) for x in m["acl"]]
    return m


def _token_state(d: pp.Design, gens: dict | None = None) -> dict:
    return {k: {"id": f"{d.userid}!{n}", "gen": (gens or {}).get(k, 1)} for k, n in d.tokens.items()}


@safe
def exec_apply(rt: Runtime, db: Session, m: ProvisionApply, plan, known: list[str]) -> dict:
    return _apply(rt, db, m, plan, known, reconcile=False)


@safe
def exec_reconcile(rt: Runtime, db: Session, m: PermissionsReconcile, plan, known: list[str]) -> dict:
    return _apply(rt, db, m, plan, known, reconcile=True)


def _apply(rt: Runtime, db: Session, m, plan, known: list[str], reconcile: bool) -> dict:
    _need_creds(rt, m, plan)
    base_url, ca, fp, ep = _resolve(db, m)
    art = _artifact(db, m.preview_id, "plan")
    if art is None or art.plan_hash != m.plan_hash:
        raise ProxmoxError("the approved preview is missing or does not match the approved plan hash")
    stored = _stored(db, ep.id) if ep else None
    if reconcile and stored is None:
        raise ProxmoxError("endpoint has no stored policy")
    policy = Policy.model_validate(stored.policy if reconcile else art.data["plan"]["policy"])
    admin = open_admin(rt, m, base_url, ca, fp, known)
    res = None
    try:
        facts = pp.collect_facts(admin)
        managed = dict(stored.managed) if (stored and reconcile) else _managed(db, ep)
        # the approved choices are re-validated against the cluster NOW: same choices + same cluster => same plan hash, anything else refuses
        choices = ConflictChoices.model_validate(art.data["choices"]) if (art.data.get("choices") and not reconcile) else None
        pl = pp.plan_for(policy, facts, managed=managed, prune=reconcile, mode="A", choices=choices, owned=_owned(db) if not reconcile else None)
        pd = pl.to_dict()
        if pd["plan_hash"] != m.plan_hash:
            raise ProxmoxError("the cluster changed since the plan was previewed and approved (plan hash differs): nothing was applied; preview again")
        if pl.blocked:
            raise ProxmoxError("plan is blocked: " + "; ".join(pl.blocked))
        d = pp.design_from_plan(pl, policy)
        res = pp.apply_plan(admin, pl, d)
        secrets = dict(res.secrets)
        if reconcile:
            from ..actions import _client_for
            secrets = {}
            old_tokens = stored.tokens
            for kind, t in old_tokens.items():
                secrets[kind] = (t["id"], _vault_token(rt, ep, kind))
            known += [s for _, s in secrets.values()]
        verification = _verify_all(rt, base_url, ca, fp, policy, d, secrets, facts, known)
        if not verification["ok"]:
            raise ProxmoxError("verification of the resulting permissions failed: " + _problem(verification))
        eid = str(ep.id) if (ep and reconcile) else _register(rt, db, m, plan, known, ep, base_url, ca, fp, policy, secrets, d)
        mg = _merge_managed(managed, res)
        gens = {k: v.get("gen", 1) for k, v in (stored.tokens if stored else {}).items()} if reconcile else {}
        _upsert_policy(db, eid, policy, pd, pp.stored_design(pl), "A", mg, _token_state(d, gens), verification)
        audit.append(db, "provider.permissions.reconciled" if reconcile else "provider.provision.applied", actor_name="worker", resource="endpoint",
                     resource_id=eid, details={"plan_hash": pd["plan_hash"], "mode": "A", "steps": res.log, "removed": res.removed, "verification_ok": True,
                                               "temporary_credentials": "discarded"})
        return {"endpoint_id": eid, "plan_hash": pd["plan_hash"], "applied": res.log, "verification": _verif_public(verification),
                "temporary_credentials": "discarded"}
    except BaseException:
        if res is not None:
            left = pp.rollback_created(admin, res)
            audit.append(db, "provider.provision.rolled_back", actor_name="worker", resource="plan", resource_id=str(plan.id),
                         details={"undeleted": left, "created": res.log})
        raise
    finally:
        admin.discard()


def _verif_public(v: dict) -> dict:
    return {k: ({"ok": r["ok"], "verbs": r["verbs"], "missing": r["missing"], "unexpected": r["unexpected"], "scope_reach": r.get("scope_reach", [])} if k != "ok" else r) for k, r in v.items()}


def _vault_token(rt: Runtime, ep, kind: str) -> str:
    """Token secrets live only in the credential subsystem (ics.credentials); no parallel storage."""
    return cred_service.endpoint_secret(rt, ep, kind, actor="provisioning")


def _commit_scope(rt: Runtime, db: Session, plan, ep, stored, sc, pl, res, verification, known: list[str]) -> None:
    """One transaction (the job's): the ICS allowlists and the stored policy change together, after Proxmox is verified."""
    new = sc.new
    s = new.scope
    upd = ea.EndpointUpdate(endpoint_id=ep.id, allowed_nodes=s.nodes or None, allowed_storage=sorted(set(s.storages + s.backup_storages + s.import_storages)) or None,
                            allowed_templates=s.template_vmids or None, allowed_pools=list(s.pools), allowed_networks=list(s.networks),
                            managed_vmids=list(s.managed_vmids))
    ea.exec_update(rt, db, upd, plan, known)      # re-probes with the new scope and the stored tokens; nothing is persisted if that fails
    mg = _merge_managed(dict(stored.managed), res) if res is not None else dict(stored.managed)
    gone = {st.target for st in pl.steps if st.kind == "acl" and st.op == "remove"}
    gone |= {f"{r['path']}|{x}|{r['role']}" for r in sc.diff["acl_remove"] for x in r["subjects"]}
    mg["acl"] = [a for a in mg.get("acl", []) if "|".join(a) not in gone]
    if sc.detach:
        mg["detached_guests"] = sorted(set(mg.get("detached_guests", [])) | set(sc.detach))
        db.execute(text("UPDATE infra_guests SET ou_managed = false WHERE endpoint_id = :e AND vmid = ANY(:v)"), {"e": str(ep.id), "v": list(sc.detach)})
    sd = pp.stored_design(pl)
    sd["tokens"] = dict(stored.design["tokens"])
    _upsert_policy(db, ep.id, new, pl.to_dict(), sd, stored.mode, mg, stored.tokens, verification)
    audit.append(db, "provider.scope.changed", actor_name="worker", resource="endpoint", resource_id=str(ep.id),
                 details={"direction": sc.direction, "old": sc_mod.scope_summary(sc.old), "new": sc_mod.scope_summary(sc.new), "scope_hash": sc.hash,
                          "detached": sc.detach, "verification_ok": True, "acl_added": len(sc.diff["acl_add"]), "acl_removed": len(sc.diff["acl_remove"])})


def _scope_artifact(db: Session, m, ep, stored):
    art = _artifact(db, m.preview_id, "plan")
    if art is None or art.plan_hash != m.plan_hash or art.data.get("purpose") != "scope_change":
        raise ProxmoxError("the approved scope-change preview is missing or does not match the approved hash")
    if stored is None or str(art.endpoint_id) != str(ep.id):
        raise ProxmoxError("the preview does not belong to this integration")
    return art


def _vault_secrets(rt: Runtime, ep, stored, known: list[str]) -> dict:
    secrets = {kind: (t["id"], _vault_token(rt, ep, kind)) for kind, t in stored.tokens.items()}
    known += [x for _, x in secrets.values()]
    return secrets


@safe
def exec_scope_change(rt: Runtime, db: Session, m: ScopeChange, plan, known: list[str]) -> dict:
    base_url, ca, fp, ep = _resolve(db, m)
    stored = _stored(db, ep.id)
    art = _scope_artifact(db, m, ep, stored)
    old = Policy.model_validate(stored.policy)
    new = Policy.model_validate(art.data["policy_new"])
    detach_req = bool(art.data["scope"]["detach"])
    managed = dict(stored.managed)
    if m.execution == "confirm_package":
        from ..actions import _client_for
        c0 = _client_for(rt, ep, known)
        try:
            facts = pp.collect_facts(_Reader(c0))
            dbg = _db_guests(db, ep.id)
            rows, gst = _scope_inputs(_Reader(c0), facts, dbg)      # review 5 L6: the same live inputs as Mode A, so orphans are really found
        finally:
            c0.close()
        sc = sc_mod.build_from(old, stored.design, new, facts, managed, detach_requested=detach_req, db_guests=dbg, guest_storages=gst, node_rows=rows)
        if sc.direction != art.data["scope"]["direction"]:
            raise ProxmoxError("the scope change no longer matches the approved preview")
        if sc.impact["managed_guests_outside"] and not sc.detach:     # orphans re-checked now; other plan blockers refer to a cluster the package already changed
            raise ProxmoxError("scope change is blocked now: managed guests would be left outside the new scope (" + "; ".join(b for b in sc.blocked if "outside the new scope" in b)[:300] + ")")
        d = pp.design_from_stored(new, stored.design)
        verification = _verify_all(rt, base_url, ca, fp, new, d, _vault_secrets(rt, ep, stored, known), facts, known)
        if not verification["ok"]:
            raise ProxmoxError("Proxmox does not yet match the new scope (has the package been run on the cluster?): " + _problem(verification))
        _commit_scope(rt, db, plan, ep, stored, sc, sc.plan, None, verification, known)
        return {"endpoint_id": str(ep.id), "direction": sc.direction, "mode": "B", "scope": sc_mod.scope_summary(new), "verification": _verif_public(verification)}
    _need_creds(rt, m, plan)
    admin = open_admin(rt, m, base_url, ca, fp, known)
    res = None
    restore_needed = False
    try:
        facts = pp.collect_facts(admin)
        dbg = _db_guests(db, ep.id)
        rows, gst = _scope_inputs(admin, facts, dbg)
        sc = sc_mod.build_from(old, stored.design, new, facts, managed, detach_requested=detach_req, db_guests=dbg, guest_storages=gst, node_rows=rows)
        if sc.hash != m.plan_hash:
            raise ProxmoxError("the cluster or the managed guests changed since the scope change was previewed and approved: nothing was applied; preview again")
        if sc.blocked:
            raise ProxmoxError("scope change is blocked: " + "; ".join(sc.blocked))
        d = pp.design_from_stored(sc.new, stored.design)
        restore_needed = True
        res = pp.apply_plan(admin, sc.plan, pp.design_from_plan(sc.plan, sc.new))
        verification = _verify_all(rt, base_url, ca, fp, sc.new, d, _vault_secrets(rt, ep, stored, known), facts, known)
        if not verification["ok"]:
            raise ProxmoxError("verification of the resulting permissions failed: " + _problem(verification))
        _commit_scope(rt, db, plan, ep, stored, sc, sc.plan, res, verification, known)
        restore_needed = False
        return {"endpoint_id": str(ep.id), "direction": sc.direction, "mode": "A", "scope": sc_mod.scope_summary(sc.new), "applied": res.log,
                "verification": _verif_public(verification), "temporary_credentials": "discarded"}
    except BaseException:
        if res is not None and res.storage_content:
            left_st = pp.rollback_storage_content(admin, res)     # storage content added by this change (image import storage)
            audit.append(db, "provider.scope.storage_restored", actor_name="worker", resource="endpoint", resource_id=str(ep.id), details={"undone_failed": left_st})
        if restore_needed:
            try:   # put the previous permissions back: the stored policy is still the old one, so a reconcile-style plan restores exactly it
                f2 = pp.collect_facts(admin)
                back = pp.plan_for(old, f2, managed=managed, prune=True, mode="A")
                left = pp.apply_plan(admin, back, pp.design_from_stored(old, stored.design))
                audit.append(db, "provider.scope.reverted", actor_name="worker", resource="endpoint", resource_id=str(ep.id), details={"restored": left.log})
            except Exception as e:  # noqa: BLE001
                audit.append(db, "provider.scope.revert_failed", actor_name="worker", resource="endpoint", resource_id=str(ep.id), details={"error": str(e)[:200]})
        raise
    finally:
        admin.discard()


@safe
def exec_scope_package(rt: Runtime, db: Session, m: ScopePackage, plan, known: list[str]) -> dict:
    base_url, ca, fp, ep = _resolve(db, m)
    stored = _stored(db, ep.id)
    art = _scope_artifact(db, m, ep, stored)
    old = Policy.model_validate(stored.policy)
    new = Policy.model_validate(art.data["policy_new"])
    sc = sc_mod.build_from(old, stored.design, new, None, dict(stored.managed), detach_requested=bool(art.data["scope"]["detach"]), db_guests=_db_guests(db, ep.id))
    if sc.direction != art.data["scope"]["direction"] or sc.blocked and not art.data["scope"]["blocked"]:
        raise ProxmoxError("the scope change cannot be recomputed as previewed: " + "; ".join(sc.blocked))
    pid = str(uuid.uuid4())
    meta = {"package_id": pid, **sc_mod.package_meta(sc, stored.design)}
    files = pp.ProxmoxPackageGenerator(new).generate(sc.plan, meta)
    sd = pp.stored_design(sc.plan)
    sd["tokens"] = dict(stored.design["tokens"])
    db.execute(text("INSERT INTO provision_artifacts (id, kind, endpoint_id, plan_hash, data, created_by, customer_id) VALUES "
                    "(:i, 'package', :e, :h, CAST(:d AS jsonb), :u, :c)"),
               {"i": pid, "e": str(ep.id), "h": art.plan_hash, "u": plan.requested_by, "c": str(plan.customer_id) if plan.customer_id else None,
                "d": json.dumps({"files": files, "plan": sc.plan.to_dict(), "design": sd, "policy": new.model_dump(mode="json"), "scope_preview_id": str(m.preview_id)})})
    audit.append(db, "provider.scope.package_generated", actor_name="worker", resource="package", resource_id=pid,
                 details={"scope_hash": art.plan_hash, "direction": sc.direction, "files": sorted(files)})
    return {"package_id": pid, "plan_hash": art.plan_hash, "files": sorted(files), "direction": sc.direction}


@safe
def exec_package(rt: Runtime, db: Session, m: ProvisionPackage, plan, known: list[str]) -> dict:
    base_url, ca, fp, ep = _resolve(db, m)
    cli, close = _facts_client(rt, m, db, base_url, ca, fp, ep, known) if ep else (None, lambda: None)
    try:
        facts = pp.collect_facts(cli) if cli is not None else None
    finally:
        close()
    pl = pp.plan_for(m.policy, facts, pve_major=m.pve_major, managed=_managed(db, ep), mode="B")
    pid = str(uuid.uuid4())
    files = pp.ProxmoxPackageGenerator(m.policy).generate(pl, {"package_id": pid})
    pd = pl.to_dict()
    db.execute(text("INSERT INTO provision_artifacts (id, kind, endpoint_id, plan_hash, data, created_by, customer_id) VALUES "
                    "(:i, 'package', :e, :h, CAST(:d AS jsonb), :u, :c)"),
               {"i": pid, "e": str(ep.id) if ep else None, "h": pd["plan_hash"], "c": str(plan.customer_id) if plan.customer_id else None,
                "d": json.dumps({"files": files, "plan": pd, "design": pp.stored_design(pl), "policy": m.policy.model_dump(mode="json")}), "u": plan.requested_by})
    audit.append(db, "provider.provision.package_generated", actor_name="worker", resource="package", resource_id=pid,
                 details={"plan_hash": pd["plan_hash"], "files": sorted(files), "summary": pd["summary"]})
    return {"package_id": pid, "plan_hash": pd["plan_hash"], "files": sorted(files), "summary": pd["summary"]}


@safe
def exec_import(rt: Runtime, db: Session, m: CredentialImport, plan, known: list[str]) -> dict:
    base_url, ca, fp, ep = _resolve(db, m)
    art = _artifact(db, m.package_id, "package")
    if art is None:
        raise ProxmoxError("package not found")
    policy = Policy.model_validate(art.data["policy"])
    d = pp.design_from_stored(policy, art.data["design"])
    secrets = {"inventory": (m.inventory_token_id, m.inventory_token_secret.get_secret_value())}
    if m.provision_token_id:
        secrets["provision"] = (m.provision_token_id, m.provision_token_secret.get_secret_value())
    for kind, (tid, _) in secrets.items():
        if kind not in d.tokens or tid != f"{d.userid}!{d.tokens[kind]}":
            raise ProxmoxError(f"the {kind} token {tid} is not one of the tokens defined by the package "
                               f"({', '.join(d.userid + '!' + t for t in d.tokens.values())})")
    if set(d.tokens) != set(secrets):
        raise ProxmoxError("import both tokens named in the package (inventory and provision)")
    from ..actions import _new_client
    c0 = _new_client(rt, base_url, *secrets["inventory"], ca, fp)
    try:
        facts = pp.collect_facts(_Reader(c0))
    except ProxmoxError:
        facts = None
    finally:
        c0.close()
    verification = _verify_all(rt, base_url, ca, fp, policy, d, secrets, facts, known)
    if not verification["ok"]:
        raise ProxmoxError("the imported token does not match the package's permission policy: " + _problem(verification))
    eid = _register(rt, db, m, plan, known, ep, base_url, ca, fp, policy, secrets, d)
    pl = art.data["plan"]
    mg = {"user": d.userid, "roles": [s["target"] for s in pl["steps"] if s["kind"] == "role" and s["op"] == "create"],
          "tokens": [t for t, _ in secrets.values()], "pools": [s["target"] for s in pl["steps"] if s["kind"] == "pool" and s["op"] == "create"],
          "acl": [], "assumed": "created by the customer's provisioning script (Mode B)"}
    _upsert_policy(db, eid, policy, pl, art.data["design"], "B", mg, _token_state(d), verification)
    audit.append(db, "provider.credential.imported", actor_name="worker", resource="endpoint", resource_id=eid,
                 details={"package_id": str(m.package_id), "plan_hash": art.plan_hash, "tokens": [t for t, _ in secrets.values()], "verification_ok": True})
    return {"endpoint_id": eid, "plan_hash": art.plan_hash, "verification": _verif_public(verification)}


def _acl_specs_for(d: pp.Design, kind: str):
    return [(a.path, d.roles[a.cap][0], a.propagate) for a in d.acl if kind in a.tokens]


@safe
def exec_rotate(rt: Runtime, db: Session, m: TokenRotate, plan, known: list[str]) -> dict:
    _need_creds(rt, m, plan)
    base_url, ca, fp, ep = _resolve(db, m)
    st = _stored(db, ep.id)
    policy = Policy.model_validate(st.policy)
    d_old = pp.design_from_stored(policy, st.design)
    gens = {k: v.get("gen", 1) for k, v in st.tokens.items()}
    new_names = dict(d_old.tokens)
    for k in m.kinds:
        if k in new_names:
            new_names[k] = f"{policy.token_base}-{'inv' if k == 'inventory' else 'prov'}-g{gens.get(k, 1) + 1}"
    d_new = pp.design_from_stored(policy, {**st.design, "tokens": new_names})
    admin = open_admin(rt, m, base_url, ca, fp, known)
    made: list[tuple[str, str]] = []
    try:
        secrets: dict[str, tuple[str, str]] = {}
        for k in m.kinds:
            if k not in d_new.tokens:
                continue
            out = admin.token_add(d_new.userid, new_names[k], f"{pp.MARK} {k} generation {gens.get(k, 1) + 1}", 1)
            tid = f"{d_new.userid}!{new_names[k]}"
            made.append((d_new.userid, new_names[k]))
            secrets[k] = (tid, out["value"])
            known.append(out["value"])
            for path, role, prop in _acl_specs_for(d_new, k):
                admin.acl_set(path, role, token=tid, propagate=prop)
        # unchanged kinds keep using their vault secret (needed for the endpoint rewrite and the verification)
        for k, t in st.tokens.items():
            if k not in secrets:
                secrets[k] = (t["id"], _vault_token(rt, ep, k))
                known.append(secrets[k][1])
        facts = pp.collect_facts(admin)
        verification = _verify_all(rt, base_url, ca, fp, policy, d_new, secrets, facts, known)
        if not verification["ok"]:
            raise ProxmoxError("the new token generation failed verification; the old token was left in place: " + _problem(verification))
        _register(rt, db, m, plan, known, ep, base_url, ca, fp, policy, secrets, d_new)
    except BaseException:
        for u, n in reversed(made):
            try:
                admin.token_delete(u, n)
            except Exception:  # noqa: BLE001
                pass
        admin.discard()
        raise
    left = []
    for k in m.kinds:
        if k in d_old.tokens and d_old.tokens[k] != new_names[k]:
            try:
                admin.token_delete(d_old.userid, d_old.tokens[k])
            except Exception:  # noqa: BLE001
                left.append(f"{d_old.userid}!{d_old.tokens[k]}")
    admin.discard()
    mg = dict(st.managed)
    mg["tokens"] = sorted((set(mg.get("tokens", [])) - {f"{d_old.userid}!{d_old.tokens[k]}" for k in m.kinds if k in d_old.tokens}) | {t for t, _ in secrets.values()})
    new_gens = {**gens, **{k: gens.get(k, 1) + 1 for k in m.kinds if k in d_new.tokens}}
    _upsert_policy(db, ep.id, policy, {"plan_hash": st.plan_hash}, {**st.design, "tokens": new_names}, st.mode, mg, _token_state(d_new, new_gens), verification)
    audit.append(db, "provider.token.rotated", actor_name="worker", resource="endpoint", resource_id=str(ep.id),
                 details={"kinds": m.kinds, "new_tokens": [secrets[k][0] for k in m.kinds if k in secrets], "old_tokens_left": left,
                          "temporary_credentials": "discarded"})
    return {"endpoint_id": str(ep.id), "rotated": m.kinds, "old_tokens_not_deleted": left, "temporary_credentials": "discarded"}


@safe
def exec_revoke(rt: Runtime, db: Session, m: TokenRevoke, plan, known: list[str]) -> dict:
    base_url, ca, fp, ep = _resolve(db, m)
    st = _stored(db, ep.id)
    policy = Policy.model_validate(st.policy)
    d = pp.design_from_stored(policy, st.design)
    mg = dict(st.managed)
    remote: list[str] = []
    undone: list[str] = []
    if m.has_creds():
        _need_creds(rt, m, plan)
        admin = open_admin(rt, m, base_url, ca, fp, known)
        try:
            for k, t in st.tokens.items():
                u, _, n = t["id"].partition("!")
                try:
                    admin.token_delete(u, n)
                    remote.append(f"token {t['id']} deleted")
                except Exception:  # noqa: BLE001
                    undone.append(f"token {t['id']}")
            if m.delete_user and mg.get("user"):
                for path, subj, role in mg.get("acl", []):
                    if "!" not in subj:
                        try:
                            admin.acl_set(path, role, user=subj, delete=True)
                        except Exception:  # noqa: BLE001
                            pass
                for path, subj, role, _ in pp.acl_entries(d):
                    if "!" not in subj:
                        try:
                            admin.acl_set(path, role, user=subj, delete=True)
                        except Exception:  # noqa: BLE001
                            pass
                try:
                    admin.user_delete(mg["user"])
                    remote.append(f"user {mg['user']} deleted")
                except Exception:  # noqa: BLE001
                    undone.append(f"user {mg['user']}")
            if m.delete_roles:
                for r in mg.get("roles", []):          # only roles THIS integration created
                    try:
                        admin.role_delete(r)
                        remote.append(f"role {r} deleted")
                    except Exception:  # noqa: BLE001
                        undone.append(f"role {r}")
        finally:
            admin.discard()
    for role in ("inventory", "provision"):
        cred_service.release_endpoint_role(db, ep, role, actor="provider.token.revoke", reason="integration revoked")   # ciphertext destroyed
    db.execute(text("UPDATE endpoints SET enabled = false, token_secret_enc = '\\x'::bytea, provision_token_id = NULL, provision_secret_enc = NULL "
                    "WHERE id = :i"), {"i": str(ep.id)})
    db.execute(text("UPDATE endpoint_policy SET status = 'revoked', updated_at = now() WHERE endpoint_id = :i"), {"i": str(ep.id)})
    audit.append(db, "provider.token.revoked", actor_name="worker", resource="endpoint", resource_id=str(ep.id),
                 details={"remote": remote, "not_removed": undone, "stored_credentials": "destroyed",
                          "note": "" if m.has_creds() else "tokens remain valid in Proxmox until deleted there (use the rollback script)"})
    return {"endpoint_id": str(ep.id), "remote": remote, "not_removed": undone, "stored_credentials": "destroyed", "endpoint": "disabled"}


from . import customer_plan as _customer_plan  # noqa: E402
_customer_plan.register()   # the customer approval link shows the real permission plan and package

EXECUTORS = {"provider.provision.plan_preview": exec_preview, "provider.provision.apply": exec_apply, "provider.provision.package": exec_package,
             "provider.credential.import": exec_import, "provider.permissions.reconcile": exec_reconcile, "provider.token.rotate": exec_rotate,
             "provider.token.revoke": exec_revoke, "provider.scope.change": exec_scope_change, "provider.scope.package": exec_scope_package}


def scrub_expired_credentials(db: Session) -> int:
    """Discard temporary provisioning credentials: (1) legacy plan-row secrets of provisioning plans past the TTL / rejected, and (2) every
    `temporary_provisioning` credential that is expired, whose plan was rejected or vanished, or whose job has finished (ciphertext destroyed)."""
    r = db.execute(text("UPDATE plans SET secret_enc = NULL WHERE action IN ('provider.provision.plan_preview', 'provider.provision.apply', "
                        "'provider.permissions.reconcile', 'provider.token.rotate', 'provider.token.revoke', 'provider.scope.change') AND secret_enc IS NOT NULL AND "
                        "(created_at < now() - make_interval(secs => :t) OR status = 'rejected')"), {"t": TEMP_CRED_TTL})
    n = r.rowcount or 0
    rows = db.execute(text(
        "SELECT c.id FROM credentials c LEFT JOIN plans p ON p.id = c.id WHERE c.purpose = 'temporary_provisioning' AND c.provider NOT IN ('pve-ssh', 'pve-admin') AND c.purged_at IS NULL AND "
        "(c.expires_at <= now() OR p.created_at < now() - make_interval(secs => :t) OR p.id IS NULL OR p.status = 'rejected' OR EXISTS (SELECT 1 FROM jobs j WHERE j.plan_id = p.id "
        "AND j.status IN ('succeeded', 'failed'))) FOR UPDATE OF c"), {"t": TEMP_CRED_TTL}).all()
    for c in rows:
        cred_service.revoke(db, c.id, actor="system", reason="temporary provisioning credential discarded")
        n += 1
    return n


# ---------------------------------------------------------------------------------------------------- integration with the credential vault / policy
def temp_cred_blob(plan_id) -> bytes:
    """What the plan digest binds in place of an encrypted secret blob: the id of the (write-once) temporary credential."""
    return f"credential:{plan_id}".encode()


def has_temp_cred(db: Session, plan_id) -> bool:
    return db.execute(text("SELECT 1 FROM credentials WHERE id = :i AND purpose = 'temporary_provisioning'"), {"i": str(plan_id)}).first() is not None


def load_temp_cred(rt: Runtime, db: Session, plan_id, job_id) -> dict:
    """Decrypt the plan's temporary credentials (inside the job only). Unavailable (expired/discarded) -> a job error."""
    if not has_temp_cred(db, plan_id):
        return {}
    try:
        return json.loads(cred_service.get_secret(rt, plan_id, use="provision.temporary", actor=f"job:{job_id}"))
    except cred_service.CredentialUnavailable:
        raise ProxmoxError("the temporary provisioning credentials are no longer available (expired, rejected or already discarded)") from None


def bind_customer(db: Session, action: str, p, full: dict, cust, model, default_customer: str):
    """Customer a provider.* plan belongs to (policy + scoping key). Endpoint-bound -> the endpoint's customer; an explicit customer_id must agree;
    unbound -> explicit or the MSP's internal customer. Referenced previews/packages must belong to the same customer."""
    ep_cust = None
    eid = getattr(p, "endpoint_id", None)
    if eid is not None:
        r = db.execute(text("SELECT customer_id FROM endpoints WHERE id = :i"), {"i": str(eid)}).first()
        ep_cust = str(r.customer_id) if r else None
    explicit = full.get("customer_id")
    if ep_cust and explicit and str(explicit) != ep_cust:
        raise ValueError("customer_id does not match the endpoint's customer")
    cust = ep_cust or (str(explicit) if explicit else None) or (cust and str(cust)) or default_customer
    if "customer_id" in model.model_fields and eid is None:
        full["customer_id"] = cust
    for k, kind in (("preview_id", "plan"), ("package_id", "package")):
        if getattr(p, k, None) is not None:
            art = _artifact(db, getattr(p, k), kind)
            if art is not None and art.customer_id is not None and str(art.customer_id) != cust:
                raise ValueError(f"{k} belongs to another customer")
    return cust


# provider.cleanup lives in its own module (it imports TempCreds/open_admin from here)
from . import cleanup as _cleanup  # noqa: E402

CATALOG["provider.cleanup"] = {"model": _cleanup.ProviderCleanup, "risk": "high", "secrets": ADMIN_SECRETS, "admin_only": True}
EXECUTORS["provider.cleanup"] = _cleanup.exec_cleanup
