"""Typed actions: credential.create / replace / rotate / revoke / test. Secrets travel only in the plan's encrypted secret part."""
from datetime import datetime
from types import SimpleNamespace
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator
from sqlalchemy import text

from . import service

_NAME = r"^[A-Za-z0-9][A-Za-z0-9 _.:/-]{0,99}$"
_META = r"^[A-Za-z0-9][A-Za-z0-9 _.:-]{0,99}$"


def _secret(v):
    raw = v.get_secret_value() if isinstance(v, SecretStr) else v
    if not isinstance(raw, str):
        raise ValueError("secret must be a string")
    raw = raw.strip()
    if not 8 <= len(raw) <= 16384 or "\x00" in raw:
        raise ValueError("secret must be 8-16384 characters")
    return raw


class CredentialCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,30}$", description="proxmox now; ssh, docker, podman, backup, storage, network, monitoring later")
    customer_id: UUID
    label: str = Field(pattern=_NAME)
    credential_type: Literal["api_token", "password", "ssh_key", "client_cert"]
    purpose: Literal["inventory", "provision", "temporary_provisioning"]
    identity: str | None = Field(default=None, max_length=200, pattern=r"^[^\x00-\x1f]*$", description="non-secret id, e.g. token id or username")
    secret: SecretStr
    datacenter: str | None = Field(default=None, pattern=_META)
    cluster: str | None = Field(default=None, pattern=_META)
    host: str | None = Field(default=None, pattern=r"^[A-Za-z0-9.:-]{1,253}$")
    expires_at: datetime | None = None
    endpoint_id: UUID | None = Field(default=None, description="attach to this endpoint (needs `role`)")
    role: Literal["inventory", "provision"] | None = None
    reason: str = Field(default="", max_length=300)
    permissions: list[dict[str, str]] = Field(default_factory=list, max_length=100, description="permissions the customer is asked to grant (shown in the approval request)")

    _s = field_validator("secret", mode="before")(_secret)

    @model_validator(mode="after")
    def _ep(self):
        if (self.endpoint_id is None) != (self.role is None):
            raise ValueError("endpoint_id and role go together")
        if self.expires_at is not None and self.expires_at.tzinfo is None:
            raise ValueError("expires_at needs a timezone")
        return self


class CredentialSupersede(BaseModel):
    """replace: the customer issued a new credential (identity may change). rotate: same identity, new secret value."""
    model_config = ConfigDict(extra="forbid")
    credential_id: UUID
    secret: SecretStr
    identity: str | None = Field(default=None, max_length=200, pattern=r"^[^\x00-\x1f]*$")
    expires_at: datetime | None = None
    reason: str = Field(min_length=3, max_length=300)

    _s = field_validator("secret", mode="before")(_secret)


class CredentialRotate(CredentialSupersede):
    identity: None = None


class CredentialRevoke(BaseModel):
    model_config = ConfigDict(extra="forbid")
    credential_id: UUID
    reason: str = Field(min_length=3, max_length=300)


class CredentialTest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    credential_id: UUID


def _cred(db, cid):
    from ..actions import PlanError
    r = service.get_row(db, cid)
    if r is None:
        raise PlanError(404, "credential not found")
    return r


def precheck(db, rt, action: str, p) -> dict:
    from ..actions import PlanError
    if action == "credential.create":
        c = db.execute(text("SELECT disabled_at FROM customers WHERE id = :i"), {"i": str(p.customer_id)}).first()
        if c is None or c.disabled_at is not None:
            raise PlanError(404, "customer not found")
        if p.endpoint_id:
            ep = db.execute(text("SELECT customer_id FROM endpoints WHERE id = :i"), {"i": str(p.endpoint_id)}).first()
            if ep is None or ep.customer_id != p.customer_id:
                raise PlanError(422, "endpoint not found for this customer")
        return {"customer_id": str(p.customer_id)}
    r = _cred(db, p.credential_id)
    extra = {"provider": r.provider, "label": r.label, "customer_id": str(r.customer_id), "status": r.status}
    if action != "credential.test" and r.status in ("revoked", "retired"):
        raise PlanError(409, f"credential is {r.status}; create a new credential instead")
    if action == "credential.test" and r.status in ("revoked", "retired"):
        raise PlanError(409, f"credential is {r.status}")
    return extra


def _validate_new(rt, db, old, secret: str, identity: str | None) -> None:
    """A replacement must authenticate before anything is persisted (same rule as endpoint.update)."""
    tester = service.TESTERS.get(old.provider)
    if tester is None:
        return
    ep = db.execute(text("SELECT * FROM endpoints WHERE inventory_credential_id = :c OR provision_credential_id = :c"), {"c": str(old.id)}).first()
    if ep is None:
        return
    ok, msg = tester(rt, SimpleNamespace(identity=identity or old.identity), secret, ep)
    if not ok:
        raise service.CredentialUnavailable(f"new credential was rejected: {msg}")


def exec_create(rt, db, m: CredentialCreate, plan, known):
    secret = m.secret.get_secret_value()
    known.append(secret)
    actor = f"plan:{plan.id}"
    cid = service.create(db, rt, provider=m.provider, customer_id=m.customer_id, label=m.label, credential_type=m.credential_type,
                         purpose=m.purpose, secret=secret, identity=m.identity, datacenter=m.datacenter, cluster=m.cluster, host=m.host,
                         expires_at=m.expires_at, actor=actor, actor_id=plan.requested_by, reason=m.reason)
    if m.endpoint_id:
        col = service.ROLE_COL[m.role]
        old = db.execute(text(f"SELECT {col} AS c FROM endpoints WHERE id = :e"), {"e": str(m.endpoint_id)}).scalar()
        if old:
            db.execute(text("UPDATE credentials SET status = 'retired', retire_after = now() + make_interval(days => :d), replaced_by = :n "
                            "WHERE id = :o AND status NOT IN ('revoked','retired')"), {"d": service.RETIRE_GRACE_DAYS, "n": cid, "o": str(old)})
            service._event(db, old, "replaced_by", actor, m.reason, cid)
        db.execute(text(f"UPDATE endpoints SET {col} = :c WHERE id = :e"), {"c": cid, "e": str(m.endpoint_id)})
    return {"credential_id": cid}


def _exec_super(kind: str):
    def run(rt, db, m: CredentialSupersede, plan, known):
        secret = m.secret.get_secret_value()
        known.append(secret)
        old = service.get_row(db, m.credential_id)
        if old is None:
            raise service.CredentialUnavailable("credential not found")
        _validate_new(rt, db, old, secret, m.identity)
        nid = service.supersede(db, rt, m.credential_id, secret=secret, identity=m.identity, expires_at=m.expires_at,
                                actor=f"plan:{plan.id}", actor_id=plan.requested_by, reason=m.reason, kind=kind)
        return {"credential_id": nid, "previous_credential_id": str(m.credential_id), "previous_retired_for_days": service.RETIRE_GRACE_DAYS}
    return run


def exec_revoke(rt, db, m: CredentialRevoke, plan, known):
    service.revoke(db, m.credential_id, actor=f"plan:{plan.id}", actor_id=plan.requested_by, reason=m.reason)
    return {"credential_id": str(m.credential_id), "revoked": True}


def exec_test(rt, db, m: CredentialTest, plan, known):
    return service.test(db, rt, m.credential_id, actor=f"plan:{plan.id}", actor_id=plan.requested_by)


SPECS = {
    "credential.create": {"model": CredentialCreate, "risk": "high", "secrets": ("secret",)},
    "credential.replace": {"model": CredentialSupersede, "risk": "high", "secrets": ("secret",)},
    "credential.rotate": {"model": CredentialRotate, "risk": "normal", "secrets": ("secret",)},
    "credential.revoke": {"model": CredentialRevoke, "risk": "high", "secrets": ()},
    "credential.test": {"model": CredentialTest, "risk": "low", "secrets": ()},
}
EXECUTORS = {"credential.create": exec_create, "credential.replace": _exec_super("replaced"), "credential.rotate": _exec_super("rotated"),
             "credential.revoke": exec_revoke, "credential.test": exec_test}
PRECHECK = {k: (lambda db, rt, p, _k=k: precheck(db, rt, _k, p)) for k in SPECS}
