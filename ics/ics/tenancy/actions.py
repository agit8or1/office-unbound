"""Typed actions for MSP customers, their policies and operator scoping (all admin-only, high risk, 2 approvers)."""
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import text

from .. import audit
from . import policy

_NAME = r"^[A-Za-z0-9][A-Za-z0-9 _.&()-]{0,99}$"
Mode = Literal["auto", "customer_approval", "monitoring_only"]


class _Policy(BaseModel):
    extra_approvals: dict[str, int] | None = Field(default=None, description=f"extra distinct approvers per category {policy.CATEGORIES}")

    @field_validator("extra_approvals")
    @classmethod
    def _x(cls, v):
        if v is not None:
            policy.validate_policy(True, "monitoring_only", v)
        return v


class CustomerCreate(_Policy):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=_NAME)
    msp_owned: bool = False
    provisioning_mode: Mode | None = None
    contact_name: str | None = Field(default=None, max_length=100, pattern=r"^[^\x00-\x1f]*$")
    contact_email: str | None = Field(default=None, max_length=200, pattern=r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$")
    slug: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9-]{1,30}$", description="deployment customer_id; derived from the name when omitted")
    external_ref: str | None = Field(default=None, max_length=100, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,99}$",
                                     description="the MSP system's own id for this customer (e.g. a clientst0r organization id)")
    adopt_existing_deployments: bool = Field(default=False, description="review 6 M3: an explicit slug may equal the customer_id of EXISTING deployments only with this flag, "
                                             "which binds those deployments to this customer (the approvers see the list)")

    @model_validator(mode="after")
    def _m(self):
        if self.provisioning_mode is None:
            self.provisioning_mode = "auto" if self.msp_owned else "customer_approval"
        policy.validate_policy(self.msp_owned, self.provisioning_mode, self.extra_approvals or {})
        return self


class CustomerUpdate(_Policy):
    model_config = ConfigDict(extra="forbid")
    customer_id: UUID
    provisioning_mode: Mode | None = None
    contact_name: str | None = Field(default=None, max_length=100, pattern=r"^[^\x00-\x1f]*$")
    contact_email: str | None = Field(default=None, max_length=200, pattern=r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$")
    disabled: bool | None = None
    slug: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9-]{1,30}$", description="explicit deployment mapping: the new slug; if it equals the customer_id of existing "
                             "deployments, adopt_existing_deployments must be true (they are then bound to this customer)")
    adopt_existing_deployments: bool = False


class OperatorSetScope(BaseModel):
    """Restrict an ICS operator to specific customers, or grant the MSP-wide scope. Independent of any tenant identity."""
    model_config = ConfigDict(extra="forbid")
    username: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$")
    all_customers: bool
    customer_ids: list[UUID] = Field(default_factory=list, max_length=200)

    @model_validator(mode="after")
    def _s(self):
        if self.all_customers and self.customer_ids:
            raise ValueError("all_customers excludes customer_ids")
        return self


def _orphans(db, slug: str) -> list[str]:
    """Deployments whose free-text customer_id equals `slug` (they would be bound to whoever owns that slug)."""
    return [r.slug for r in db.execute(text("SELECT slug FROM deployments WHERE customer_id = :s ORDER BY slug"), {"s": slug}).all()]


def _adoption_check(db, slug: str | None, adopt: bool) -> dict:
    from ..actions import PlanError
    if not slug:
        return {}
    o = _orphans(db, slug)
    if o and not adopt:
        raise PlanError(409, "slug equals the customer_id of existing deployments (" + ", ".join(o[:5]) + "); they are bound to a customer only explicitly: "
                        "set adopt_existing_deployments=true, or choose another slug")
    return {"adopts_deployments": o} if o else {}


def precheck(db, rt, action: str, p) -> dict:
    from ..actions import PlanError
    if action == "customer.create":
        extra = _adoption_check(db, p.slug, p.adopt_existing_deployments)
        if db.execute(text("SELECT 1 FROM customers WHERE name = :n"), {"n": p.name}).first():
            raise PlanError(409, "customer name already exists")
        if p.slug and db.execute(text("SELECT 1 FROM customers WHERE slug = :s"), {"s": p.slug}).first():
            raise PlanError(409, "customer slug already exists")
        if p.external_ref and db.execute(text("SELECT 1 FROM customers WHERE external_ref = :s"), {"s": p.external_ref}).first():
            raise PlanError(409, "external_ref already linked to another customer")
        return extra
    elif action == "customer.update":
        c = db.execute(text("SELECT * FROM customers WHERE id = :i"), {"i": str(p.customer_id)}).first()
        if c is None:
            raise PlanError(404, "customer not found")
        extra = _adoption_check(db, p.slug, p.adopt_existing_deployments) if p.slug and p.slug != c.slug else {}
        if p.slug and p.slug != c.slug and db.execute(text("SELECT 1 FROM customers WHERE slug = :s"), {"s": p.slug}).first():
            raise PlanError(409, "customer slug already exists")
        mode = p.provisioning_mode or c.provisioning_mode
        try:
            policy.validate_policy(c.msp_owned, mode, p.extra_approvals if p.extra_approvals is not None else c.extra_approvals)
        except ValueError as e:
            raise PlanError(422, str(e)) from None
        return extra
    else:
        if not db.execute(text("SELECT 1 FROM users WHERE username = :u"), {"u": p.username}).first():
            raise PlanError(404, "user not found")
        found = db.execute(text("SELECT count(*) FROM customers WHERE id = ANY(CAST(:c AS uuid[]))"), {"c": [str(i) for i in p.customer_ids]}).scalar()
        if found != len(set(p.customer_ids)):
            raise PlanError(404, "customer not found")
    return {}


def slugify(name: str) -> str:
    import re
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:28].strip("-")
    return s if len(s) >= 2 else "c-" + s.ljust(2, "0")


def _free_slug(db, base: str) -> str:
    slug, n = base, 1
    while db.execute(text("SELECT 1 FROM customers WHERE slug = :s"), {"s": slug}).first() or _orphans(db, slug):   # never derive a slug that would capture a deployment
        n += 1
        slug = f"{base[:27]}-{n}"
    return slug


def exec_create(rt, db, m: CustomerCreate, plan, known):
    slug = m.slug or _free_slug(db, slugify(m.name))
    if db.execute(text("SELECT 1 FROM customers WHERE slug = :s"), {"s": slug}).first():
        raise ValueError("customer slug already in use")
    if _orphans(db, slug) and not m.adopt_existing_deployments:   # re-checked at execution (TOCTOU with a deployment created after approval)
        raise ValueError("slug equals the customer_id of existing deployments; not adopted without adopt_existing_deployments")
    cid = db.execute(text("INSERT INTO customers (name, msp_owned, provisioning_mode, extra_approvals, contact_name, contact_email, created_by, slug, external_ref) "
                          "VALUES (:n, :o, :m, CAST(:x AS jsonb), :cn, :ce, :u, :sl, :er) RETURNING id"),
                     {"n": m.name, "o": m.msp_owned, "m": m.provisioning_mode, "x": audit.canon(m.extra_approvals or {}),
                      "cn": m.contact_name, "ce": m.contact_email, "u": str(plan.requested_by), "sl": slug, "er": m.external_ref}).scalar()
    adopted = _orphans(db, slug)
    audit.append(db, "customer.created", actor_name="worker", resource="customer", resource_id=str(cid),
                 details={"adopted_deployments": adopted, "name": m.name, "msp_owned": m.msp_owned, "provisioning_mode": m.provisioning_mode, "extra_approvals": m.extra_approvals or {}})
    return {"customer_id": str(cid), "slug": slug}


def exec_update(rt, db, m: CustomerUpdate, plan, known):
    c = db.execute(text("SELECT * FROM customers WHERE id = :i FOR UPDATE"), {"i": str(m.customer_id)}).first()
    new = {"provisioning_mode": m.provisioning_mode or c.provisioning_mode,
           "extra_approvals": m.extra_approvals if m.extra_approvals is not None else c.extra_approvals,
           "contact_name": m.contact_name if m.contact_name is not None else c.contact_name,
           "contact_email": m.contact_email if m.contact_email is not None else c.contact_email}
    if m.slug and m.slug != c.slug:
        if db.execute(text("SELECT 1 FROM customers WHERE slug = :s"), {"s": m.slug}).first():
            raise ValueError("customer slug already in use")
        if _orphans(db, m.slug) and not m.adopt_existing_deployments:
            raise ValueError("slug equals the customer_id of existing deployments; not adopted without adopt_existing_deployments")
        if _orphans(db, c.slug):
            raise ValueError("deployments are bound to the current slug; re-slugging would orphan them (destroy or move them first)")
        db.execute(text("UPDATE customers SET slug = :s WHERE id = :i"), {"s": m.slug, "i": str(c.id)})
    db.execute(text("UPDATE customers SET provisioning_mode = :m, extra_approvals = CAST(:x AS jsonb), contact_name = :cn, contact_email = :ce, "
                    "disabled_at = CASE WHEN CAST(:d AS boolean) IS NULL THEN disabled_at WHEN :d THEN COALESCE(disabled_at, now()) ELSE NULL END "
                    "WHERE id = :i"),
               {"m": new["provisioning_mode"], "x": audit.canon(new["extra_approvals"]), "cn": new["contact_name"], "ce": new["contact_email"],
                "d": m.disabled, "i": str(c.id)})
    audit.append(db, "customer.updated", actor_name="worker", resource="customer", resource_id=str(c.id),
                 details={"name": c.name, "from_mode": c.provisioning_mode, "to_mode": new["provisioning_mode"],
                          "extra_approvals": new["extra_approvals"], "disabled": m.disabled})
    return {"customer_id": str(c.id)}


def exec_scope(rt, db, m: OperatorSetScope, plan, known):
    u = db.execute(text("SELECT id FROM users WHERE username = :u FOR UPDATE"), {"u": m.username}).first()
    db.execute(text("UPDATE users SET all_customers = :a WHERE id = :i"), {"a": m.all_customers, "i": str(u.id)})
    db.execute(text("DELETE FROM operator_customers WHERE user_id = :i"), {"i": str(u.id)})
    for cid in sorted(set(m.customer_ids)):
        db.execute(text("INSERT INTO operator_customers (user_id, customer_id) VALUES (:u, :c)"), {"u": str(u.id), "c": str(cid)})
    audit.append(db, "operator.scope_set", actor_name="worker", resource="user", resource_id=str(u.id),
                 details={"username": m.username, "all_customers": m.all_customers, "customer_ids": sorted(str(c) for c in m.customer_ids)})
    return {"username": m.username, "all_customers": m.all_customers, "customers": len(set(m.customer_ids))}


SPECS = {
    "customer.create": {"model": CustomerCreate, "risk": "high", "secrets": (), "admin_only": True},
    "customer.update": {"model": CustomerUpdate, "risk": "high", "secrets": (), "admin_only": True},
    "operator.set_scope": {"model": OperatorSetScope, "risk": "high", "secrets": (), "admin_only": True},
}
EXECUTORS = {"customer.create": exec_create, "customer.update": exec_update, "operator.set_scope": exec_scope}
PRECHECK = {k: (lambda db, rt, p, _k=k: precheck(db, rt, _k, p)) for k in SPECS}
