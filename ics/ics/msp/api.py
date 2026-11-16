"""/api/msp/v1/* resource handlers. Reads need `view`; previews and plan submissions need `plan`; approving needs `approve` (off by default);
every mutation is a typed plan (customer.*, deployment.*, idm.*) that humans approve unless the client's approved policy says otherwise."""
import base64
import re
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator
from sqlalchemy import text

from .. import audit, identity
from ..actions import ActionType, PlanError, create_plan, decide_plan
from ..deploy import ops, state
from ..deploy.plan import PlanInput
from . import events as mevents, metering
from .gateway import BASE, Ctx, MspError, Router

SLUG = r"^[a-z0-9][a-z0-9-]{1,30}$"
UID = r"^[a-z][a-z0-9._-]{1,31}$"
MAX_WEBHOOKS = 10


def _iso(v):
    return v.isoformat() if isinstance(v, datetime) else v


# ---- request bodies ------------------------------------------------------------------------------------------------------------------

class CustomerIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9 _.&()-]{0,99}$")
    slug: str | None = Field(default=None, pattern=SLUG)
    external_ref: str | None = Field(default=None, max_length=100, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,99}$")
    contact_name: str | None = Field(default=None, max_length=100, pattern=r"^[^\x00-\x1f]*$")
    contact_email: str | None = Field(default=None, max_length=200, pattern=r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$")
    msp_owned: bool = False


class CustomerPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    contact_name: str | None = Field(default=None, max_length=100, pattern=r"^[^\x00-\x1f]*$")
    contact_email: str | None = Field(default=None, max_length=200, pattern=r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$")

    @model_validator(mode="after")
    def _one(self):
        if self.contact_name is None and self.contact_email is None:
            raise ValueError("give contact_name and/or contact_email")
        return self


class DeploymentCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    spec: dict
    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class ChangePreviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    changes: ops.ChangeSet


class ChangeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    changes: ops.ChangeSet
    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    maintenance: Literal["window", "override"] | None = None
    maintenance_window_id: UUID | None = None


class DestroyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirm: str
    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class UserCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    stack: str | None = None
    uid: str = Field(pattern=UID)
    display_name: str = Field(min_length=1, max_length=100)
    mail: str = Field(max_length=254)
    groups: list[str] = Field(default_factory=list, max_length=20)
    mailbox: bool = True


class UserPatchIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    stack: str | None = None
    add: list[str] = Field(default_factory=list, max_length=20)
    remove: list[str] = Field(default_factory=list, max_length=20)


class UserOpIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    stack: str | None = None
    reason: str = Field(default="", max_length=200)


class WebhookIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str = Field(max_length=500)
    events: list[Literal["plan.approved", "plan.rejected", "job.completed", "job.failed", "incident.opened", "incident.recovered"]] = Field(min_length=1)
    description: str | None = Field(default=None, max_length=200)


# ---- helpers -------------------------------------------------------------------------------------------------------------------------

def _uuid(v: str, what: str = "resource") -> str:
    try:
        return str(UUID(v))
    except ValueError:
        raise MspError(404, "not_found", f"{what} not found") from None


def _customer(ctx: Ctx, cid: str):
    c = ctx.db.execute(text("SELECT * FROM customers WHERE id = :i"), {"i": _uuid(cid, "customer")}).first()
    if c is None or not ctx.in_scope(c.id):
        raise MspError(404, "not_found", "customer not found")
    ctx.audit_extra["customer_id"] = str(c.id)
    return c


def _cview(c) -> dict:
    return {"id": str(c.id), "name": c.name, "slug": c.slug, "external_ref": c.external_ref, "msp_owned": c.msp_owned,
            "provisioning_mode": c.provisioning_mode, "contact_name": c.contact_name, "contact_email": c.contact_email,
            "disabled": c.disabled_at is not None, "created_at": _iso(c.created_at)}


def _page(ctx: Ctx) -> tuple[int, str | None]:
    try:
        limit = int(ctx.query.get("limit", 50))
    except ValueError:
        raise MspError(422, "validation_error", "limit must be an integer") from None
    if not 1 <= limit <= 200:
        raise MspError(422, "validation_error", "limit must be 1-200")
    cur = ctx.query.get("cursor")
    if cur:
        try:
            cur = base64.urlsafe_b64decode(cur.encode()).decode()
        except Exception:  # noqa: BLE001
            raise MspError(422, "validation_error", "invalid cursor") from None
    return limit, cur or None


def _next(rows: list, limit: int, key) -> str | None:
    return base64.urlsafe_b64encode(key(rows[limit - 1]).encode()).decode() if len(rows) > limit else None


def _plan_error(e: PlanError) -> MspError:
    code = {403: "policy_denied", 404: "not_found", 409: "conflict", 422: "validation_error"}.get(e.status, "plan_error")
    return MspError(e.status if e.status in (403, 404, 409, 422) else 422, code, str(e.msg))


def _auto_policy(ctx: Ctx):
    def ok(cust, risk) -> bool:
        if "execute" not in ctx.client.perms or risk != "low" or not cust:
            return False
        return bool(ctx.db.execute(text("SELECT msp_owned FROM customers WHERE id = :i"), {"i": str(cust)}).scalar())
    return ok


def _submit(ctx: Ctx, action: str, params: dict) -> tuple[int, dict]:
    try:
        out = create_plan(ctx.db, ctx.rt, ctx.client.user, ActionType(action), params, ctx.ip, commit=False, msp_auto=_auto_policy(ctx))
    except ValidationError as e:
        raise MspError(422, "validation_error", "request validation failed",
                       [{"loc": [str(x) for x in err["loc"]], "msg": err["msg"]} for err in e.errors()]) from None
    except PlanError as e:
        raise _plan_error(e) from None
    ctx.audit_extra["plan_id"] = out["plan_id"]
    return 202, plan_out(ctx, out)


def plan_out(ctx: Ctx, o: dict) -> dict:
    return {"plan_id": o["plan_id"], "status": o["status"], "risk": o["risk"], "approvals_required": o["approvals_required"],
            "job_id": o.get("job_id"), "params_hash": o["params_hash"], "customer_id": o.get("customer_id"),
            "waiting_for": "customer_approval" if o.get("customer_approval_id") else None, "customer_approval_id": o.get("customer_approval_id"),
            "links": {"plan": f"{BASE}/plans/{o['plan_id']}"}}


def _stack(ctx: Ctx, customer, name: str | None) -> str:
    rows = ctx.db.execute(text("SELECT name FROM idm_stacks WHERE customer_id = :c ORDER BY name"), {"c": str(customer.id)}).all()
    names = [r.name for r in rows]
    if name is not None:
        if name not in names:
            raise MspError(404, "not_found", "identity stack not found for this customer")
        return name
    if not names:
        raise MspError(409, "no_identity_stack", "this customer has no identity stack linked (plan msp.stack.link in the console)")
    if len(names) > 1:
        raise MspError(422, "validation_error", "the customer has several identity stacks; pass `stack`", {"stacks": names})
    return names[0]


def _deployment(ctx: Ctx, slug: str):
    d = ctx.db.execute(text("SELECT d.*, c.id AS cust_id FROM deployments d LEFT JOIN customers c ON c.slug = d.customer_id WHERE d.slug = :s"),
                       {"s": slug}).first()
    if d is None or (ctx.client.customer_ids is not None and (d.cust_id is None or str(d.cust_id) not in ctx.client.customer_ids)):
        raise MspError(404, "not_found", "deployment not found")
    ctx.audit_extra["deployment"] = slug
    if d.cust_id:
        ctx.audit_extra["customer_id"] = str(d.cust_id)
    return d


def _endpoint_ok(ctx: Ctx, endpoint_name: str) -> None:
    """A customer-scoped client may only deploy onto endpoints owned by customers in its scope."""
    if ctx.client.customer_ids is None:
        return
    r = ctx.db.execute(text("SELECT customer_id FROM endpoints WHERE name = :n AND detached_at IS NULL"), {"n": endpoint_name}).first()
    if r is None or str(r.customer_id) not in ctx.client.customer_ids:
        raise MspError(404, "not_found", "endpoint not found")


def _guard(fn):
    """Maps engine exceptions of the preview helpers to API errors."""
    try:
        return fn()
    except KeyError as e:
        raise MspError(404, "not_found", str(e.args[0]) if e.args else "not found") from None
    except LookupError as e:
        raise MspError(409, "conflict", str(e)) from None
    except (ValueError, ValidationError) as e:
        raise MspError(422, "validation_error", str(e)[:500]) from None


def register(app) -> None:
    r = Router(app)

    # ---- identity of the caller -------------------------------------------------------------------------------------------------
    @r.route("GET", "/me", "view", "me")
    def me(ctx: Ctx):
        c = ctx.client
        return 200, {"client_id": c.client_id, "name": c.row.name, "permissions": [x for x in ("view", "plan", "approve", "execute") if x in c.perms], "all_customers": c.customer_ids is None,
                     "customer_ids": sorted(c.customer_ids) if c.customer_ids is not None else None,
                     "rate_limit_per_minute": c.row.rate_limit_per_minute, "api_version": "v1"}

    # ---- customers --------------------------------------------------------------------------------------------------------------
    @r.route("GET", "/customers", "view", "customers.list")
    def customers_list(ctx: Ctx):
        limit, cur = _page(ctx)
        ext = ctx.query.get("external_ref")
        rows = ctx.db.execute(text(f"SELECT * FROM customers WHERE {ctx.scope_clause('id')} AND (CAST(:c AS text) IS NULL OR slug > :c) "
                                   "AND (CAST(:e AS text) IS NULL OR external_ref = :e) ORDER BY slug LIMIT :n"),
                              {"c": cur, "e": ext, "n": limit + 1}).all()
        return 200, {"items": [_cview(c) for c in rows[:limit]], "next_cursor": _next(rows, limit, lambda c: c.slug)}

    @r.route("POST", "/customers", "plan", "customers.create")
    def customers_create(ctx: Ctx):
        if ctx.client.customer_ids is not None:
            raise MspError(403, "forbidden", "only an all-customers API client can create customers")
        b = ctx.json(CustomerIn)
        return _submit(ctx, "customer.create", b.model_dump(exclude_none=True))

    @r.route("GET", "/customers/{customer_id}", "view", "customers.get")
    def customers_get(ctx: Ctx, customer_id: str):
        return 200, _cview(_customer(ctx, customer_id))

    @r.route("PATCH", "/customers/{customer_id}", "plan", "customers.update")
    def customers_update(ctx: Ctx, customer_id: str):
        c = _customer(ctx, customer_id)
        b = ctx.json(CustomerPatch)
        return _submit(ctx, "customer.update", {"customer_id": str(c.id), **b.model_dump(exclude_none=True)})

    @r.route("GET", "/customers/{customer_id}/usage", "view", "customers.usage")
    def customers_usage(ctx: Ctx, customer_id: str):
        return 200, metering.usage(ctx.db, _customer(ctx, customer_id))

    # ---- deployments ------------------------------------------------------------------------------------------------------------
    def _spec(ctx: Ctx, c, raw: dict) -> PlanInput:
        if not isinstance(raw, dict):
            raise MspError(422, "validation_error", "spec must be an object")
        if raw.get("customer_id") not in (None, c.slug):
            raise MspError(422, "validation_error", "spec.customer_id must be omitted or equal the customer's slug", {"slug": c.slug})
        try:
            spec = PlanInput.model_validate({**raw, "customer_id": c.slug})
        except ValidationError as e:
            raise MspError(422, "validation_error", "request validation failed",
                           [{"loc": [str(x) for x in err["loc"]], "msg": err["msg"]} for err in e.errors()]) from None
        _endpoint_ok(ctx, spec.endpoint)
        return spec

    @r.route("POST", "/customers/{customer_id}/deployments/preview", "plan", "deployments.preview")
    def deployments_preview(ctx: Ctx, customer_id: str):
        c = _customer(ctx, customer_id)
        spec = _spec(ctx, c, ctx.json())
        return 200, _guard(lambda: ops.build_plan(ctx.db, spec))

    @r.route("POST", "/customers/{customer_id}/deployments", "plan", "deployments.create")
    def deployments_create(ctx: Ctx, customer_id: str):
        c = _customer(ctx, customer_id)
        b = ctx.json(DeploymentCreateIn)
        spec = _spec(ctx, c, b.spec)
        return _submit(ctx, "deployment.create", {"spec": spec.model_dump(mode="json"), "plan_hash": b.plan_hash})

    @r.route("GET", "/deployments", "view", "deployments.list")
    def deployments_list(ctx: Ctx):
        limit, cur = _page(ctx)
        cid = _uuid(ctx.query["customer_id"], "customer") if ctx.query.get("customer_id") else None
        rows = ctx.db.execute(text(
            "SELECT d.slug, d.customer_id AS customer_slug, c.id AS customer_id, d.profile, d.profile_version, d.status, d.current_revision, d.created_at, d.updated_at "
            f"FROM deployments d LEFT JOIN customers c ON c.slug = d.customer_id WHERE {ctx.scope_clause('c.id')} "
            "AND (CAST(:c AS text) IS NULL OR d.slug > :c) AND (CAST(:cu AS uuid) IS NULL OR c.id = CAST(:cu AS uuid)) ORDER BY d.slug LIMIT :n"),
            {"c": cur, "cu": cid, "n": limit + 1}).all()
        items = [{"slug": d.slug, "customer_id": str(d.customer_id) if d.customer_id else None, "profile": d.profile, "profile_version": d.profile_version,
                  "status": d.status, "current_revision": d.current_revision, "created_at": _iso(d.created_at), "updated_at": _iso(d.updated_at)}
                 for d in rows[:limit]]
        return 200, {"items": items, "next_cursor": _next(rows, limit, lambda d: d.slug)}

    @r.route("GET", "/deployments/{slug}", "view", "deployments.get")
    def deployments_get(ctx: Ctx, slug: str):
        d = _deployment(ctx, slug)
        revs = ctx.db.execute(text("SELECT revision, kind, plan_hash, risk, status, job_id, created_at, applied_at FROM deployment_revisions "
                                   "WHERE deployment_id = :d ORDER BY revision, id"), {"d": str(d.id)}).all()
        counts = ctx.db.execute(text("SELECT kind, state, count(*) AS n FROM deployment_resources WHERE deployment_id = :d GROUP BY kind, state"),
                                {"d": str(d.id)}).all()
        job = next((x.job_id for x in reversed(revs) if x.job_id), None)
        steps = []
        if job:
            steps = [{"seq": s.seq, "key": s.step_key, "kind": s.kind, "target": s.target, "op": s.op, "status": s.status, "attempts": s.attempts,
                      "error": s.error_message, "started_at": _iso(s.started_at), "finished_at": _iso(s.finished_at)}
                     for s in ctx.db.execute(text("SELECT seq, step_key, kind, target, op, status, attempts, error_message, started_at, finished_at "
                                                  "FROM job_steps WHERE job_id = :j ORDER BY seq"), {"j": str(job)})]
        return 200, {"slug": d.slug, "customer_id": str(d.cust_id) if d.cust_id else None, "profile": d.profile, "profile_version": d.profile_version,
                     "status": d.status, "current_revision": d.current_revision, "created_at": _iso(d.created_at),
                     "revisions": [{"revision": x.revision, "kind": x.kind, "plan_hash": x.plan_hash, "risk": x.risk, "status": x.status,
                                    "job_id": str(x.job_id) if x.job_id else None, "created_at": _iso(x.created_at), "applied_at": _iso(x.applied_at)} for x in revs],
                     "resource_summary": [{"kind": c.kind, "state": c.state, "count": c.n} for c in counts],
                     "latest_job_id": str(job) if job else None, "latest_job_steps": steps}

    @r.route("GET", "/deployments/{slug}/health", "view", "deployments.health")
    def deployments_health(ctx: Ctx, slug: str):
        d = _deployment(ctx, slug)
        db = ctx.db
        snap = db.execute(text("SELECT collected_at, data FROM inventory_snapshots WHERE endpoint_id = :e ORDER BY collected_at DESC LIMIT 1"),
                          {"e": str(d.endpoint_id)}).first() if d.endpoint_id else None
        guests = [g for n in (snap.data.get("nodes", []) if snap else []) for g in n.get("qemu", []) if isinstance(g, dict)]
        res = [{"kind": x.kind, "name": x.logical_name, "desired": x.desired, "actual": x.actual, "state": x.state, "provider_ref": x.provider_ref}
               for x in db.execute(text("SELECT * FROM deployment_resources WHERE deployment_id = :d"), {"d": str(d.id)})]
        findings = state.drift_findings(res, guests, d.slug) if snap else []
        checks = db.execute(text("SELECT state, count(*) AS n FROM checks WHERE deployment_id = :d AND enabled GROUP BY state"), {"d": str(d.id)}).all()
        cs = {x.state: x.n for x in checks}
        inc = db.execute(text("SELECT i.id, i.severity, i.title, i.status, i.opened_at FROM incidents i JOIN checks c ON c.id = i.check_id "
                              "WHERE c.deployment_id = :d AND i.status IN ('open','acked') ORDER BY i.opened_at DESC LIMIT 50"), {"d": str(d.id)}).all()
        if d.status in ("planned", "provisioning", "destroying", "destroyed"):
            overall = "unknown"
        elif d.status == "failed" or cs.get("critical") or any(i.severity == "critical" for i in inc):
            overall = "unhealthy"
        elif findings or inc or cs.get("warning"):
            overall = "degraded"
        elif not checks and not snap:
            overall = "unknown"
        else:
            overall = "healthy"
        return 200, {"slug": d.slug, "deployment_status": d.status, "health": overall, "inventory_at": _iso(snap.collected_at) if snap else None,
                     "checks": {"ok": cs.get("ok", 0), "warning": cs.get("warning", 0), "critical": cs.get("critical", 0), "unknown": cs.get("unknown", 0)},
                     "active_incidents": [{"id": str(i.id), "severity": i.severity, "title": i.title, "status": i.status, "opened_at": _iso(i.opened_at)} for i in inc],
                     "drift": {"in_sync": not findings, "findings": len(findings), "types": sorted({f["type"] for f in findings})}}

    @r.route("POST", "/deployments/{slug}/changes/preview", "plan", "deployments.change_preview")
    def change_preview(ctx: Ctx, slug: str):
        _deployment(ctx, slug)
        b = ctx.json(ChangePreviewIn)
        return 200, _guard(lambda: ops.change_preview(ctx.db, slug, b.changes))

    @r.route("POST", "/deployments/{slug}/changes", "plan", "deployments.change")
    def change_create(ctx: Ctx, slug: str):
        _deployment(ctx, slug)
        b = ctx.json(ChangeIn)
        return _submit(ctx, "deployment.change", {"deployment_id": slug, **b.model_dump(mode="json", exclude_none=True)})

    @r.route("POST", "/deployments/{slug}/destroy/preview", "plan", "deployments.destroy_preview")
    def destroy_preview(ctx: Ctx, slug: str):
        _deployment(ctx, slug)
        return 200, _guard(lambda: ops.destroy_preview(ctx.db, slug))

    @r.route("POST", "/deployments/{slug}/destroy", "plan", "deployments.destroy")
    def destroy_create(ctx: Ctx, slug: str):
        _deployment(ctx, slug)
        b = ctx.json(DestroyIn)
        return _submit(ctx, "deployment.destroy", {"deployment_id": slug, "confirm": b.confirm, "plan_hash": b.plan_hash})

    # ---- users (identity lifecycle) ---------------------------------------------------------------------------------------------
    @r.route("GET", "/customers/{customer_id}/users", "view", "users.list")
    def users_list(ctx: Ctx, customer_id: str):
        c = _customer(ctx, customer_id)
        limit, cur = _page(ctx)
        st = ctx.query.get("state")
        if st is not None and st not in ("active", "disabled", "deleted"):
            raise MspError(422, "validation_error", "state must be active, disabled or deleted")
        rows = ctx.db.execute(text(
            "SELECT s.name AS stack, u.uid, u.id, u.mail, u.display_name, u.groups, u.state, u.created_at, u.disabled_at FROM idm_users u "
            "JOIN idm_stacks s ON s.id = u.stack_id WHERE s.customer_id = :c AND (CAST(:s AS text) IS NULL OR u.state = :s) "
            "AND (CAST(:k AS text) IS NULL OR (u.uid || '|' || u.id::text) > :k) ORDER BY u.uid, u.id LIMIT :n"),
            {"c": str(c.id), "s": st, "k": cur, "n": limit + 1}).all()
        items = [{"stack": u.stack, "uid": u.uid, "mail": u.mail, "display_name": u.display_name, "groups": u.groups, "state": u.state,
                  "created_at": _iso(u.created_at), "disabled_at": _iso(u.disabled_at)} for u in rows[:limit]]
        return 200, {"items": items, "next_cursor": _next(rows, limit, lambda u: f"{u.uid}|{u.id}")}

    @r.route("POST", "/customers/{customer_id}/users", "plan", "users.create")
    def users_create(ctx: Ctx, customer_id: str):
        c = _customer(ctx, customer_id)
        b = ctx.json(UserCreateIn)
        return _submit(ctx, "idm.user.create", {"stack": _stack(ctx, c, b.stack), "uid": b.uid, "display_name": b.display_name, "mail": b.mail,
                                                "groups": b.groups, "mailbox": b.mailbox})

    @r.route("PATCH", "/customers/{customer_id}/users/{uid}", "plan", "users.update_groups")
    def users_patch(ctx: Ctx, customer_id: str, uid: str):
        c = _customer(ctx, customer_id)
        b = ctx.json(UserPatchIn)
        return _submit(ctx, "idm.user.update_groups", {"stack": _stack(ctx, c, b.stack), "uid": uid, "add": b.add, "remove": b.remove})

    def _user_op(action: str, with_reason_required: bool = False):
        def h(ctx: Ctx, customer_id: str, uid: str):
            c = _customer(ctx, customer_id)
            b = ctx.json(UserOpIn, optional=not with_reason_required)
            p = {"stack": _stack(ctx, c, b.stack), "uid": uid, "reason": b.reason}
            return _submit(ctx, action, p)
        return h

    r.route("POST", "/customers/{customer_id}/users/{uid}/disable", "plan", "users.disable")(_user_op("idm.user.disable"))
    r.route("POST", "/customers/{customer_id}/users/{uid}/enable", "plan", "users.enable")(_user_op("idm.user.enable"))
    r.route("DELETE", "/customers/{customer_id}/users/{uid}", "plan", "users.delete")(_user_op("idm.user.delete", True))

    @r.route("POST", "/customers/{customer_id}/identity/reconcile", "plan", "identity.reconcile")
    def reconcile(ctx: Ctx, customer_id: str):
        c = _customer(ctx, customer_id)
        b = ctx.json(UserOpIn, optional=True)
        return _submit(ctx, "idm.reconcile", {"stack": _stack(ctx, c, b.stack)})

    # ---- plans / jobs -----------------------------------------------------------------------------------------------------------
    def _plan_view(ctx: Ctx, p) -> dict:
        db = ctx.db
        n = db.execute(text("SELECT count(*) FROM plan_approvals WHERE plan_id = :p"), {"p": str(p.id)}).scalar()
        j = db.execute(text("SELECT id, status, created_at, started_at, finished_at, result, error FROM jobs WHERE plan_id = :p"), {"p": str(p.id)}).first()
        ca = db.execute(text("SELECT id, status FROM customer_approvals WHERE id = :i"), {"i": str(p.customer_approval_id)}).first() if p.customer_approval_id else None
        mine = p.requested_by == ctx.client.user.id
        who = db.execute(text("SELECT client_id FROM msp_clients WHERE user_id = :u"), {"u": str(p.requested_by)}).first()
        need = (ctx.rt.settings.required_approvals_high if p.risk == "high" else 1) + (p.extra_approvals or 0)
        out = {"plan_id": str(p.id), "action": p.action, "risk": p.risk, "status": p.status, "customer_id": str(p.customer_id) if p.customer_id else None,
               "requested_by": f"msp_client:{who.client_id}" if who else "console", "own": mine, "created_at": _iso(p.created_at),
               "decided_at": _iso(p.decided_at), "approvals": n, "approvals_required": need,
               "waiting_for": "customer_approval" if ca and ca.status not in ("approved", "provisioned") and p.status == "pending_approval" else None,
               "customer_approval": {"id": str(ca.id), "status": ca.status} if ca else None,
               "execution": None, "params": audit.scrub(p.params) if mine else None}
        if j:
            out["execution"] = {"job_id": str(j.id), "status": j.status, "queued_at": _iso(j.created_at), "started_at": _iso(j.started_at),
                                "finished_at": _iso(j.finished_at), "result": audit.scrub(j.result) if j.result else None,
                                "error": {"type": j.error.get("type"), "message": j.error.get("message")} if j.error else None}
        return out

    def _plan(ctx: Ctx, pid: str):
        p = ctx.db.execute(text(f"SELECT * FROM plans WHERE id = :i AND ({ctx.scope_clause('customer_id')})"), {"i": _uuid(pid, "plan")}).first()
        if p is None or (ctx.client.customer_ids is not None and p.customer_id is None):
            raise MspError(404, "not_found", "plan not found")
        if p.customer_id:
            ctx.audit_extra["customer_id"] = str(p.customer_id)
        ctx.audit_extra["plan_id"] = str(p.id)
        return p

    @r.route("GET", "/plans/{plan_id}", "view", "plans.get")
    def plans_get(ctx: Ctx, plan_id: str):
        return 200, _plan_view(ctx, _plan(ctx, plan_id))

    @r.route("GET", "/plans", "view", "plans.list")
    def plans_list(ctx: Ctx):
        limit, cur = _page(ctx)
        st = ctx.query.get("status")
        if st is not None and st not in ("pending_approval", "approved", "rejected"):
            raise MspError(422, "validation_error", "status must be pending_approval, approved or rejected")
        cid = _uuid(ctx.query["customer_id"], "customer") if ctx.query.get("customer_id") else None
        rows = ctx.db.execute(text(
            f"SELECT * FROM plans WHERE {ctx.scope_clause('customer_id')} {'AND customer_id IS NOT NULL' if ctx.client.customer_ids is not None else ''} "
            "AND (CAST(:s AS text) IS NULL OR status = :s) AND (CAST(:c AS uuid) IS NULL OR customer_id = CAST(:c AS uuid)) "
            "AND (CAST(:k AS text) IS NULL OR (to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US') || '|' || id::text) < :k) "
            "AND archived_at IS NULL ORDER BY created_at DESC, id DESC LIMIT :n"), {"s": st, "c": cid, "k": cur, "n": limit + 1}).all()
        key = lambda p: p.created_at.astimezone(__import__("datetime").timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "|" + str(p.id)  # noqa: E731
        return 200, {"items": [_plan_view(ctx, p) for p in rows[:limit]], "next_cursor": _next(rows, limit, key)}

    @r.route("POST", "/plans/{plan_id}/approve", "approve", "plans.approve")
    def plans_approve(ctx: Ctx, plan_id: str):
        """Peer approval by an API client: only with the `approve` permission (granted by an approved policy), never the client's own
        plans (decide_plan), only non-high-risk plans of MSP-owned customers."""
        p = _plan(ctx, plan_id)
        if p.customer_id is None or not ctx.db.execute(text("SELECT msp_owned FROM customers WHERE id = :i"), {"i": str(p.customer_id)}).scalar():
            raise MspError(403, "approval_not_permitted", "API clients may only approve plans of MSP-owned customers")
        if p.risk == "high":
            raise MspError(403, "approval_not_permitted", "high-risk plans need human approvers")
        try:
            out = decide_plan(ctx.db, ctx.rt, ctx.client.user, p.id, True, ctx.ip)
        except PlanError as e:
            raise MspError(e.status if e.status in (403, 404, 409) else 422, "approval_refused" if e.status == 403 else "conflict", str(e.msg)) from None
        return 200, {"plan_id": out["plan_id"], "status": out["status"], "job_id": out.get("job_id"), "approvals": out.get("approvals"),
                     "approvals_required": out.get("approvals_required"), "waiting_for": out.get("waiting_for")}

    @r.route("POST", "/plans/{plan_id}/enrollment", "plan", "plans.enrollment")
    def plans_enrollment(ctx: Ctx, plan_id: str):
        """The one-time enrollment token of an executed idm.user.create / idm.user.enable plan this client requested (shown once)."""
        p = _plan(ctx, plan_id)
        tok = identity.reveal_enrollment(ctx.db, ctx.rt, ctx.client.user, p.id)
        if not tok:
            raise MspError(404, "not_found", "no unrevealed, unexpired enrollment for this plan (it must be executed, requested by this client, and not yet revealed)")
        return 200, tok

    @r.route("GET", "/jobs/{job_id}", "view", "jobs.get")
    def jobs_get(ctx: Ctx, job_id: str):
        j = ctx.db.execute(text("SELECT j.plan_id FROM jobs j WHERE j.id = :i"), {"i": _uuid(job_id, "job")}).first()
        if j is None:
            raise MspError(404, "not_found", "job not found")
        p = _plan(ctx, str(j.plan_id))
        v = _plan_view(ctx, p)["execution"]
        steps = [{"seq": s.seq, "key": s.step_key, "kind": s.kind, "target": s.target, "op": s.op, "status": s.status, "attempts": s.attempts,
                  "error": s.error_message} for s in ctx.db.execute(text("SELECT seq, step_key, kind, target, op, status, attempts, error_message "
                                                                         "FROM job_steps WHERE job_id = :j ORDER BY seq"), {"j": job_id})]
        return 200, {**v, "plan_id": str(p.id), "action": p.action, "steps": steps}

    # ---- webhooks + event feed --------------------------------------------------------------------------------------------------
    def _wh(ctx: Ctx, wid: str):
        w = ctx.db.execute(text("SELECT * FROM msp_webhooks WHERE id = :i AND client_id = :c AND deleted_at IS NULL"),
                           {"i": _uuid(wid, "webhook"), "c": str(ctx.client.row.id)}).first()
        if w is None:
            raise MspError(404, "not_found", "webhook not found")
        return w

    def _whv(w, secret: str | None = None) -> dict:
        d = {"id": str(w.id), "url": w.url, "events": list(w.events), "description": w.description, "enabled": w.enabled, "created_at": _iso(w.created_at)}
        if secret:
            d["secret"] = secret
            d["secret_note"] = "shown once; verify X-MSP-Signature with it"
        return d

    @r.route("GET", "/webhooks", "view", "webhooks.list")
    def webhooks_list(ctx: Ctx):
        rows = ctx.db.execute(text("SELECT * FROM msp_webhooks WHERE client_id = :c AND deleted_at IS NULL ORDER BY created_at"), {"c": str(ctx.client.row.id)}).all()
        return 200, {"items": [_whv(w) for w in rows]}

    @r.route("POST", "/webhooks", "plan", "webhooks.create")
    def webhooks_create(ctx: Ctx):
        b = ctx.json(WebhookIn)
        try:
            mevents.check_url(b.url, ctx.rt.settings.allow_loopback_endpoints, ctx.rt.settings.msp_webhook_allow)
        except ValueError as e:
            raise MspError(422, "validation_error", str(e)) from None
        if ctx.db.execute(text("SELECT count(*) FROM msp_webhooks WHERE client_id = :c AND deleted_at IS NULL"), {"c": str(ctx.client.row.id)}).scalar() >= MAX_WEBHOOKS:
            raise MspError(409, "conflict", f"at most {MAX_WEBHOOKS} webhooks per API client")
        import uuid as _u
        wid, secret = str(_u.uuid4()), mevents.new_webhook_secret()
        ctx.db.execute(text("INSERT INTO msp_webhooks (id, client_id, url, description, events, secret_enc) VALUES (:i, :c, :u, :d, :e, :s)"),
                       {"i": wid, "c": str(ctx.client.row.id), "u": b.url, "d": b.description, "e": sorted(set(b.events)),
                        "s": ctx.rt.vault.encrypt(secret.encode(), f"msp-webhook:{wid}")})
        w = ctx.db.execute(text("SELECT * FROM msp_webhooks WHERE id = :i"), {"i": wid}).first()
        return 201, _whv(w, secret)

    @r.route("GET", "/webhooks/{webhook_id}", "view", "webhooks.get")
    def webhooks_get(ctx: Ctx, webhook_id: str):
        return 200, _whv(_wh(ctx, webhook_id))

    @r.route("DELETE", "/webhooks/{webhook_id}", "plan", "webhooks.delete")
    def webhooks_delete(ctx: Ctx, webhook_id: str):
        w = _wh(ctx, webhook_id)
        ctx.db.execute(text("UPDATE msp_webhooks SET enabled = false, deleted_at = now() WHERE id = :i"), {"i": str(w.id)})
        ctx.db.execute(text("UPDATE msp_deliveries SET status = 'dead', last_error = 'webhook deleted' WHERE webhook_id = :i AND status = 'pending'"), {"i": str(w.id)})
        return 200, {"id": str(w.id), "deleted": True}

    @r.route("POST", "/webhooks/{webhook_id}/rotate-secret", "plan", "webhooks.rotate")
    def webhooks_rotate(ctx: Ctx, webhook_id: str):
        w = _wh(ctx, webhook_id)
        secret = mevents.new_webhook_secret()
        ctx.db.execute(text("UPDATE msp_webhooks SET secret_enc = :s WHERE id = :i"), {"s": ctx.rt.vault.encrypt(secret.encode(), f"msp-webhook:{w.id}"), "i": str(w.id)})
        return 200, _whv(w, secret)

    @r.route("GET", "/webhooks/{webhook_id}/deliveries", "view", "webhooks.deliveries")
    def webhooks_deliveries(ctx: Ctx, webhook_id: str):
        w = _wh(ctx, webhook_id)
        rows = ctx.db.execute(text("SELECT d.id, d.event_id, e.type, d.status, d.attempts, d.last_status, d.last_error, d.next_attempt_at, d.delivered_at "
                                   "FROM msp_deliveries d JOIN msp_events e ON e.id = d.event_id WHERE d.webhook_id = :w ORDER BY d.created_at DESC LIMIT 100"),
                              {"w": str(w.id)}).all()
        return 200, {"items": [{"id": str(x.id), "event_id": str(x.event_id), "type": x.type, "status": x.status, "attempts": x.attempts,
                                "last_status": None, "last_error": "delivery failed" if x.last_error else None, "next_attempt_at": _iso(x.next_attempt_at),
                                "delivered_at": _iso(x.delivered_at)} for x in rows]}

    @r.route("GET", "/events", "view", "events.list")
    def events_list(ctx: Ctx):
        """Polling alternative to webhooks (and the way to catch up after downtime): events visible to this client, oldest first after `after_seq`."""
        try:
            after = int(ctx.query.get("after_seq", 0))
            limit = int(ctx.query.get("limit", 100))
        except ValueError:
            raise MspError(422, "validation_error", "after_seq and limit must be integers") from None
        limit = min(max(limit, 1), 500)
        sc = "TRUE" if ctx.client.customer_ids is None else f"customer_id IS NOT NULL AND {ctx.scope_clause('customer_id')}"
        rows = ctx.db.execute(text(f"SELECT seq, id, type, customer_id, data, created_at FROM msp_events WHERE seq > :a AND {sc} ORDER BY seq LIMIT :n"),
                              {"a": after, "n": limit}).all()
        return 200, {"items": [{"seq": e.seq, **mevents.envelope(e)} for e in rows], "next_after_seq": rows[-1].seq if rows else after}
