"""Tenant admin (Organization Admin) service layer. NOT the operator API.

Trust model (ADR-0002: tenant administrators never hold infrastructure privileges):
  * Every request carries TWO proofs. (1) a per-customer SERVICE credential `tsk_<key_id>.<secret>` held by the portal (only its sha256 is stored here);
    it fixes the customer and nothing else. (2) the end user's own Keycloak access token. The ICS verifies its signature against the JWKS of THAT
    customer's realm (issuer/client come from the ICS database, never from the token), requires the realm role `org-admin`, and for state-changing
    calls re-checks live in Keycloak that the user is still enabled and still holds the role.
  * Why not token exchange: exchange would need a Keycloak-side permission model per customer and produces a token for a different audience that the
    ICS would still have to validate. Validating the portal-client access token directly keeps one realm-signed proof, no new Keycloak configuration,
    and the ICS can bind issuer + azp + role to the customer it already knows from the credential.
  * Mutations are NOT executed here: they become ordinary idm.* plans requested by a per-customer principal (an ICS users row that can never log in,
    scoped to exactly that customer), approved under the customer's policy, executed by the normal worker and hash-chained in the audit log together
    with the end user's identity."""
import hashlib
import hmac
import json
import re
import secrets
import ssl
import time
from datetime import datetime, timezone

import httpx
from fastapi import HTTPException, Request
from pydantic import ValidationError
from sqlalchemy import text

from .. import actions, audit, auth, identity, mailadmin
from ..tenancy import scope as tscope
from . import jwtv

KEY_RE = re.compile(r"^tsk_([a-z0-9]{12})\.([A-Za-z0-9_-]{43})$")
APP_LABELS = {"mail": "Mail, calendar and contacts", "files": "Files and documents"}
DEFAULT_POLICY = {"self_service_auto": True, "destructive_approval": "second_admin", "dkim_selector": "default", "extra_groups": []}
MAX_LOGO = 200_000
JWKS_REFETCH_MIN_SECONDS = 60.0   # review 6 L4: an unknown `kid` may force a refetch at most once a minute per stack
HEX = re.compile(r"^#[0-9a-fA-F]{6}$")

_JWKS: dict[str, tuple[float, dict]] = {}


class TenantError(Exception):
    def __init__(self, status: int, msg: str):
        self.status, self.msg = status, msg


# ---- pluggable remote checks (replaced in tests) -------------------------------------------------------------------------------
def fetch_jwks(stack_cfg: dict) -> dict:
    ctx = ssl.create_default_context(cadata=stack_cfg["identity_ca_pem"])
    url = f"{stack_cfg['kc_url'].rstrip('/')}/realms/{stack_cfg['kc_realm']}/protocol/openid-connect/certs"
    with httpx.Client(verify=ctx, timeout=8.0, trust_env=False, follow_redirects=False) as c:
        r = c.get(url)
        r.raise_for_status()
        return r.json()


def live_user_check(rt, stack: "identity.Stack", sub: str, role: str) -> bool:
    """True if the Keycloak user still exists, is enabled and holds the role (composite). Called for every state-changing request."""
    kc = identity.Keycloak(rt, stack)
    try:
        u = kc.req("GET", f"/users/{sub}", ok=(200, 404))
        if u.status_code != 200 or not u.json().get("enabled"):
            return False
        roles = kc.req("GET", f"/users/{sub}/role-mappings/realm/composite").json()
        return any(r.get("name") == role for r in roles)
    finally:
        kc.close()


def target_privileged_check(rt, stack: "identity.Stack", uid: str, role: str) -> bool:
    """True if the target user holds the organisation-admin role in Keycloak. FAIL-CLOSED: any error means 'treat as privileged'
    (the request then needs a second decision and its link is never shown to the requester)."""
    try:
        kc = identity.Keycloak(rt, stack)
        try:
            ku = kc.find(uid)
            if ku is None:
                return False
            roles = kc.req("GET", f"/users/{ku['id']}/role-mappings/realm/composite").json()
            return any(r.get("name") == role for r in roles)
        finally:
            kc.close()
    except Exception:  # noqa: BLE001
        return True


HOOKS = {"fetch_jwks": fetch_jwks, "live": live_user_check, "target_privileged": target_privileged_check}


# ---- binding -------------------------------------------------------------------------------------------------------------------
def _mint() -> tuple[str, str, str]:
    kid = "".join(secrets.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(12))
    sec = secrets.token_urlsafe(32)
    return kid, f"tsk_{kid}.{sec}", hashlib.sha256(sec.encode()).hexdigest()


def bind(db, rt, user, customer_id, stack_name: str, *, portal_client_id: str = "ou-portal", admin_role: str = "org-admin",
         policy: dict | None = None, app_groups: dict | None = None, ip=None) -> dict:
    """Operator action (admin, all-customers): ties an identity stack to a customer and issues the portal's service credential (shown once)."""
    cust = db.execute(text("SELECT id, name, disabled_at FROM customers WHERE id = :i"), {"i": str(customer_id)}).first()
    if cust is None or cust.disabled_at is not None:
        raise TenantError(404, "customer not found")
    stack = db.execute(text("SELECT * FROM idm_stacks WHERE name = :n"), {"n": stack_name}).first()
    if stack is None:
        raise TenantError(404, "identity stack not found")
    if db.execute(text("SELECT 1 FROM tenant_admin_bindings WHERE customer_id = :c OR stack_id = :s"), {"c": str(customer_id), "s": str(stack.id)}).first():
        raise TenantError(409, "this customer or stack already has an organization-admin binding")
    if str(stack.customer_id) not in (str(customer_id), tscope.DEFAULT_CUSTOMER):
        raise TenantError(409, "stack belongs to another customer")
    allowed, priv = set(stack.config["allowed_groups"]), set(stack.config.get("privileged_groups", []))
    app_groups = app_groups or {"mail": stack.config.get("entitlement_group", "mail-users")}
    for a, g in app_groups.items():
        if a not in APP_LABELS or g not in allowed or g in priv:
            raise TenantError(422, f"app group mapping {a}={g} is not allowed (unknown app, group not in the stack, or privileged)")
    pol = {**DEFAULT_POLICY, **(policy or {}), "app_groups": app_groups}
    if pol["destructive_approval"] not in ("second_admin", "msp"):
        raise TenantError(422, "destructive_approval must be second_admin or msp")
    short = str(customer_id)[:8]
    ids = []
    for suffix, role in (("req", "operator"), ("appr", "approver")):  # unloginable principals: not enrolled, no password, no TOTP
        uid = auth.create_invite(db, rt, f"tenant-{short}-{suffix}", role, created_by=user.id, actor=user.username, commit=False,
                                 extra={"tenant_principal_for": str(customer_id)})
        db.execute(text("UPDATE users SET all_customers = false WHERE id = :i"), {"i": uid})
        db.execute(text("INSERT INTO operator_customers (user_id, customer_id) VALUES (:u, :c)"), {"u": uid, "c": str(customer_id)})
        ids.append(uid)
    kid, key, h = _mint()
    db.execute(text("INSERT INTO tenant_admin_bindings (customer_id, stack_id, key_id, key_sha256, requester_id, approver_id, portal_client_id, admin_role, "
                    "policy, app_access) VALUES (:c, :s, :k, :h, :r, :a, :p, :ro, CAST(:pol AS jsonb), CAST(:ap AS jsonb))"),
               {"c": str(customer_id), "s": str(stack.id), "k": kid, "h": h, "r": ids[0], "a": ids[1], "p": portal_client_id, "ro": admin_role,
                "pol": json.dumps(pol), "ap": json.dumps({a: True for a in app_groups})})
    db.execute(text("UPDATE idm_stacks SET customer_id = :c WHERE id = :s"), {"c": str(customer_id), "s": str(stack.id)})
    audit.append(db, "tenant.bound", actor_id=user.id, actor_name=user.username, ip=ip, resource="customer", resource_id=str(customer_id),
                 details={"stack": stack_name, "key_id": kid, "portal_client_id": portal_client_id, "policy": pol})
    db.commit()
    return {"customer_id": str(customer_id), "key_id": kid, "service_key": key, "note": "shown once; store it in the portal's secret file"}


def rotate_key(db, user, customer_id, ip=None) -> dict:
    b = db.execute(text("SELECT key_id FROM tenant_admin_bindings WHERE customer_id = :c FOR UPDATE"), {"c": str(customer_id)}).first()
    if b is None:
        raise TenantError(404, "no binding")
    kid, key, h = _mint()
    db.execute(text("UPDATE tenant_admin_bindings SET key_id = :k, key_sha256 = :h, rotated_at = now() WHERE customer_id = :c"), {"k": kid, "h": h, "c": str(customer_id)})
    audit.append(db, "tenant.key_rotated", actor_id=user.id, actor_name=user.username, ip=ip, resource="customer", resource_id=str(customer_id),
                 details={"old_key_id": b.key_id, "key_id": kid})
    db.commit()
    return {"key_id": kid, "service_key": key}


# ---- request authentication ----------------------------------------------------------------------------------------------------
class Ctx:
    def __init__(self, db, rt, binding, stack_row, ip):
        self.db, self.rt, self.binding, self.stack_row, self.ip = db, rt, binding, stack_row, ip
        self.customer_id = str(binding.customer_id)
        self.sub = self.username = self.name = None
        self.roles: set = set()
        self._stack = None

    @property
    def policy(self) -> dict:
        return {**DEFAULT_POLICY, **(self.binding.policy or {})}

    @property
    def cfg(self) -> dict:
        return self.stack_row.config

    @property
    def stack(self):
        if self._stack is None:
            self._stack = identity.load_stack(self.rt, self.stack_row.name)
        return self._stack

    def principal(self, which: str):
        row = self.db.execute(text("SELECT * FROM users WHERE id = :i"), {"i": str(self.binding.requester_id if which == "req" else self.binding.approver_id)}).first()
        u = auth.User(row)
        u.customer_ids = frozenset({self.customer_id})
        return u

    def identity_details(self) -> dict:
        return {"tenant_user_sub": self.sub, "tenant_user": self.username, "customer_id": self.customer_id, "realm": self.cfg["kc_realm"]}


# ---- unauthenticated-failure throttle + aggregate counters (review 6 M4) ----------------------------------------------------------------
# A request without a valid service credential must cost the ICS no database write: no audit row (each takes the global audit lock) and no unbounded
# growth. Failures are counted per address (in memory, bounded) and answered 429 over the limit; the totals are written as ONE summary row per window.
FAIL_LIMIT, FAIL_WINDOW, FAIL_TRACKED, SUMMARY_EVERY = 20, 60.0, 5000, 300.0
_fails: dict[str, list[float]] = {}
_agg = {"count": 0, "throttled": 0, "last_flush": time.monotonic()}


def _over_limit(ip: str | None) -> bool:
    now = time.monotonic()
    hits = [t for t in _fails.get(ip or "?", []) if now - t < FAIL_WINDOW]
    return len(hits) >= FAIL_LIMIT


def _note_unauth_failure(db, ip: str | None) -> None:
    now = time.monotonic()
    k = ip or "?"
    if k not in _fails and len(_fails) >= FAIL_TRACKED:   # evict the stalest address instead of clearing everything
        _fails.pop(min(_fails, key=lambda a: _fails[a][-1] if _fails[a] else 0.0), None)
    _fails[k] = [t for t in _fails.get(k, []) if now - t < FAIL_WINDOW] + [now]
    _agg["count"] += 1
    if now - _agg["last_flush"] >= SUMMARY_EVERY:
        n, th = _agg["count"], _agg["throttled"]
        _agg.update(count=0, throttled=0, last_flush=now)
        audit.append(db, "tenant.auth_failed_summary", actor_name="tenant-api", details={"unauthenticated_failures": n, "throttled": th,
                                                                                          "window_seconds": int(SUMMARY_EVERY)})
        db.commit()


def _fail_unauth(db, request: Request) -> None:
    _note_unauth_failure(db, auth.client_ip(request))
    raise HTTPException(401, "not authorised")


def _fail(db, request: Request, why: str, status: int, **d):
    audit.append(db, "tenant.auth_failed", actor_name="tenant-api", ip=auth.client_ip(request), details={"reason": why, "path": request.scope["path"], **d})
    db.commit()
    raise HTTPException(status, "not authorised" if status in (401, 403) else why)


def authenticate(db, rt, request: Request, *, need_user: bool = True, mutating: bool = False) -> "Ctx | deployment.DeploymentCtx":
    if _over_limit(auth.client_ip(request)):
        _agg["throttled"] += 1
        raise HTTPException(429, "too many failed attempts; try again in a minute")
    key = request.headers.get("x-ou-tenant-key", "")
    if key.startswith("tdk_"):   # the portal of a deployment the ICS created (tenant_admin/deployment.py)
        from . import deployment
        return deployment.authenticate(db, rt, request, key, need_user=need_user, mutating=mutating)
    m = KEY_RE.match(key)
    row = None
    if m:
        row = db.execute(text("SELECT b.*, c.disabled_at AS c_disabled FROM tenant_admin_bindings b JOIN customers c ON c.id = b.customer_id WHERE b.key_id = :k"),
                         {"k": m.group(1)}).first()
    ok = row is not None and hmac.compare_digest(row.key_sha256, hashlib.sha256((m.group(2) if m else "").encode()).hexdigest())
    if not ok or row.disabled_at is not None or row.c_disabled is not None:
        _fail_unauth(db, request)   # no audit row per request (M4); counted and summarised
    stack_row = db.execute(text("SELECT * FROM idm_stacks WHERE id = :i"), {"i": str(row.stack_id)}).first()
    ctx = Ctx(db, rt, row, stack_row, auth.client_ip(request))
    if not need_user:
        return ctx
    tok = request.headers.get("x-ou-user-token", "")
    cfg = stack_row.config
    issuer = f"{cfg['kc_url'].rstrip('/')}/realms/{cfg['kc_realm']}"
    try:
        jw = _JWKS.get(str(row.stack_id))
        if jw is None or time.monotonic() - jw[0] > 600:
            jw = (time.monotonic(), HOOKS["fetch_jwks"](cfg))
            _JWKS[str(row.stack_id)] = jw
        try:
            claims = jwtv.verify(tok, jw[1], issuer=issuer, client_id=row.portal_client_id)
        except jwtv.TokenError as e:
            if "unknown signing key" not in str(e) or time.monotonic() - jw[0] < JWKS_REFETCH_MIN_SECONDS:
                raise
            jw = (time.monotonic(), HOOKS["fetch_jwks"](cfg))   # key rotation: one refetch
            _JWKS[str(row.stack_id)] = jw
            claims = jwtv.verify(tok, jw[1], issuer=issuer, client_id=row.portal_client_id)
    except jwtv.TokenError as e:
        _fail(db, request, "bad_user_token", 401, detail=str(e), customer_id=str(row.customer_id))
    except (httpx.HTTPError, OSError, KeyError, ValueError):
        raise HTTPException(503, "the sign-in service could not be reached")
    roles = jwtv.realm_roles(claims)
    if row.admin_role not in roles:
        _fail(db, request, "missing_org_admin_role", 403, sub=claims["sub"], customer_id=str(row.customer_id))
    ctx.sub, ctx.roles = claims["sub"], roles
    ctx.username = str(claims.get("preferred_username") or claims["sub"])[:64]
    ctx.name = str(claims.get("name") or ctx.username)[:100]
    if mutating:
        try:
            alive = HOOKS["live"](rt, ctx.stack, ctx.sub, row.admin_role)
        except identity.IdentityError:
            raise HTTPException(503, "the directory could not be reached")
        if not alive:
            _fail(db, request, "admin_no_longer_valid", 403, sub=ctx.sub, customer_id=str(row.customer_id))
    return ctx


# ---- reads ---------------------------------------------------------------------------------------------------------------------
def assignable_groups(ctx: Ctx) -> dict[str, str]:
    """group -> label. Only groups mapped to an app (or explicitly listed by the MSP) and never a privileged group."""
    pol, priv = ctx.policy, set(ctx.cfg.get("privileged_groups", []))
    out = {g: APP_LABELS.get(a, a) for a, g in (pol.get("app_groups") or {}).items()}
    for g in pol.get("extra_groups", []):
        out.setdefault(g, g)
    return {g: l for g, l in out.items() if g not in priv and g in set(ctx.cfg["allowed_groups"])}


def user_view(ctx: Ctx, r) -> dict:
    ag = ctx.policy.get("app_groups") or {}
    return {"uid": r.uid, "display_name": r.display_name, "mail": r.mail, "state": r.state, "groups": [g for g in r.groups if g in assignable_groups(ctx)],
            "apps": {a: (g in r.groups) for a, g in ag.items()}, "created_at": r.created_at.isoformat(),
            "disabled_at": r.disabled_at.isoformat() if r.disabled_at else None, "is_you": r.uid == ctx.username}


def list_users(ctx: Ctx) -> list[dict]:
    rows = ctx.db.execute(text("SELECT * FROM idm_users WHERE stack_id = :s AND state <> 'deleted' ORDER BY display_name, uid LIMIT 1000"), {"s": str(ctx.stack_row.id)}).all()
    return [user_view(ctx, r) for r in rows]


def get_user(ctx: Ctx, uid: str) -> dict:
    r = ctx.db.execute(text("SELECT * FROM idm_users WHERE stack_id = :s AND uid = :u AND state <> 'deleted'"), {"s": str(ctx.stack_row.id), "u": uid}).first()
    if r is None:
        raise TenantError(404, "user not found")
    v = user_view(ctx, r)
    v["history"] = requests_view(ctx, uid=uid, limit=10)
    return v


def _state(r) -> tuple[str, str]:
    if r.job_status == "succeeded":
        return "done", "Done"
    if r.job_status == "failed":
        return "failed", "Did not complete"
    if r.job_status in ("queued", "running"):
        return "working", "In progress"
    if r.plan_status == "rejected":
        return "rejected", "Declined"
    if r.plan_status == "pending_approval":
        return ("waiting_admin", "Waiting for a second administrator") if r.approval_mode == "second_admin" else ("waiting_msp", "Waiting for your service provider")
    return "working", "In progress"


def requests_view(ctx: Ctx, uid: str | None = None, plan_id=None, limit: int = 50) -> list[dict]:
    rows = ctx.db.execute(text(
        "SELECT t.*, p.status AS plan_status, p.risk, j.status AS job_status, j.error AS job_error, j.finished_at, "
        "(SELECT count(*) FROM plan_approvals a WHERE a.plan_id = p.id) AS approvals "
        "FROM tenant_requests t JOIN plans p ON p.id = t.plan_id LEFT JOIN jobs j ON j.plan_id = p.id "
        "WHERE t.customer_id = :c AND (CAST(:u AS text) IS NULL OR t.target_uid = :u) AND (CAST(:p AS text) IS NULL OR t.plan_id = CAST(:p AS uuid)) "
        "ORDER BY t.created_at DESC LIMIT :n"), {"c": ctx.customer_id, "u": uid, "p": str(plan_id) if plan_id else None, "n": limit}).all()
    out = []
    for r in rows:
        code, label = _state(r)
        out.append({"id": str(r.plan_id), "kind": r.kind, "target_uid": r.target_uid, "summary": r.summary, "state": code, "state_label": label,
                    "approval_mode": r.approval_mode, "requested_by": r.requester_name, "requested_by_sub": r.requester_sub,
                    "decided_by": r.decided_by_name, "created_at": r.created_at.isoformat(), "risk": r.risk,
                    "can_decide": code == "waiting_admin" and r.requester_sub != ctx.sub,
                    "error": (r.job_error or {}).get("message") if r.job_status == "failed" else None})
    return out


# ---- mutations: plans under the customer's policy -------------------------------------------------------------------------------
def _insert_approval(db, rt, plan_id, approver, ip) -> str | None:
    plan = db.execute(text("SELECT * FROM plans WHERE id = :i FOR UPDATE"), {"i": str(plan_id)}).first()
    if plan.status != "pending_approval":
        raise TenantError(409, f"request is already {plan.status}")
    db.execute(text("INSERT INTO plan_approvals (plan_id, approver_id, params_hash) VALUES (:p, :u, :h)"), {"p": str(plan_id), "u": approver.id, "h": plan.params_hash})
    n = db.execute(text("SELECT count(*) FROM plan_approvals WHERE plan_id = :p"), {"p": str(plan_id)}).scalar()
    job = None
    if n >= actions.needed_approvals(rt, plan):
        db.execute(text("UPDATE plans SET status = 'approved', decided_by = :u, decided_at = now() WHERE id = :i"), {"u": approver.id, "i": str(plan_id)})
        job = actions._enqueue(db, plan_id, plan.action, approver, ip, auto=True)
    return job


def target_is_privileged(ctx: Ctx, uid: str) -> bool:
    """Administrators of the organisation and members of the stack's privileged groups (review 6 H2)."""
    try:
        if identity.target_is_privileged(ctx.db, ctx.stack_row.name, uid):
            return True
    except KeyError:
        return True
    return bool(HOOKS["target_privileged"](ctx.rt, ctx.stack, uid, ctx.binding.admin_role))


def submit(ctx: Ctx, kind: str, action: str, params: dict, summary: str, target_uid: str | None) -> dict:
    db, rt = ctx.db, ctx.rt
    if action in identity.CREDENTIAL_TAKEOVER_ACTIONS and target_uid:
        # the plan itself carries the verdict: risk_for makes it HIGH (never auto-approved, never decided by its requester)
        params = {**params, "privileged_target": target_is_privileged(ctx, target_uid)}
    try:
        res = actions.create_plan(db, rt, ctx.principal("req"), actions.ActionType(action), {"stack": ctx.stack_row.name, **params}, ctx.ip)
    except ValidationError as e:
        db.rollback()
        raise TenantError(422, "Please check the details: " + "; ".join(f"{x['loc'][-1]} {x['msg']}" for x in e.errors()[:3])) from None
    except actions.PlanError as e:
        db.rollback()
        raise TenantError(e.status if e.status in (404, 409, 422) else 422, e.msg) from None
    pid = res["plan_id"]
    if res["risk"] == "high":
        mode = ctx.policy["destructive_approval"]
    else:
        mode = "auto" if ctx.policy["self_service_auto"] else "second_admin"
    db.execute(text("UPDATE plans SET tenant_required = 1 WHERE id = :i"), {"i": pid})
    db.execute(text("INSERT INTO tenant_requests (plan_id, customer_id, kind, target_uid, summary, requester_sub, requester_name, approval_mode) "
                    "VALUES (:p, :c, :k, :t, :s, :sub, :n, :m)"),
               {"p": pid, "c": ctx.customer_id, "k": kind, "t": target_uid, "s": summary[:200], "sub": ctx.sub, "n": ctx.username, "m": mode})
    audit.append(db, "tenant.request", actor_name=f"tenant:{ctx.username}", ip=ctx.ip, resource="plan", resource_id=pid,
                 details={"kind": kind, "action": action, "target_uid": target_uid, "approval_mode": mode, "risk": res["risk"], **ctx.identity_details()})
    job = None
    if mode == "auto":
        job = _insert_approval(db, rt, pid, ctx.principal("appr"), ctx.ip)
        audit.append(db, "tenant.auto_approved", actor_name=f"tenant:{ctx.username}", ip=ctx.ip, resource="plan", resource_id=pid,
                     details={"policy": "self_service_auto", **ctx.identity_details()})
    db.commit()
    return {"id": pid, "state": "working" if job else ("waiting_admin" if mode == "second_admin" else "waiting_msp"), "approval_mode": mode, "risk": res["risk"]}


def decide(ctx: Ctx, plan_id, approve: bool) -> dict:
    db, rt = ctx.db, ctx.rt
    t = db.execute(text("SELECT * FROM tenant_requests WHERE plan_id = :p AND customer_id = :c FOR UPDATE"), {"p": str(plan_id), "c": ctx.customer_id}).first()
    if t is None:
        raise TenantError(404, "request not found")
    if t.approval_mode != "second_admin":
        raise TenantError(409, "this request is not waiting for an administrator of your organisation")
    if t.decision is not None:
        raise TenantError(409, "this request was already decided")
    if t.requester_sub == ctx.sub:
        audit.append(db, "tenant.self_approval_refused", actor_name=f"tenant:{ctx.username}", ip=ctx.ip, resource="plan", resource_id=str(plan_id), details=ctx.identity_details())
        db.commit()
        raise TenantError(403, "a second administrator has to decide this request, not the person who made it")
    if approve:
        job = _insert_approval(db, rt, plan_id, ctx.principal("appr"), ctx.ip)
    else:
        db.execute(text("UPDATE plans SET status = 'rejected', decided_by = :u, decided_at = now(), secret_enc = NULL WHERE id = :i AND status = 'pending_approval'"),
                   {"u": ctx.binding.approver_id, "i": str(plan_id)})
    db.execute(text("UPDATE tenant_requests SET decision = :d, decided_by_sub = :s, decided_by_name = :n, decided_at = now() WHERE plan_id = :p"),
               {"d": "approved" if approve else "rejected", "s": ctx.sub, "n": ctx.username, "p": str(plan_id)})
    audit.append(db, "tenant.approved" if approve else "tenant.rejected", actor_name=f"tenant:{ctx.username}", ip=ctx.ip, resource="plan", resource_id=str(plan_id),
                 details=ctx.identity_details())
    db.commit()
    return {"id": str(plan_id), "decision": "approved" if approve else "rejected"}


def reveal_enrollment(ctx: Ctx, plan_id) -> dict:
    t = ctx.db.execute(text("SELECT 1 FROM tenant_requests WHERE plan_id = :p AND customer_id = :c"), {"p": str(plan_id), "c": ctx.customer_id}).first()
    if t is None:
        raise TenantError(404, "request not found")
    pl = ctx.db.execute(text("SELECT params FROM plans WHERE id = :p"), {"p": str(plan_id)}).first()
    if pl is not None and (pl.params.get("privileged_target") or identity.target_is_privileged(ctx.db, ctx.stack_row.name, str(pl.params.get("uid", "")))):
        audit.append(ctx.db, "tenant.enrollment_link_refused", actor_name=f"tenant:{ctx.username}", ip=ctx.ip, resource="plan", resource_id=str(plan_id),
                     details={"reason": "privileged_target", **ctx.identity_details()})
        ctx.db.commit()
        raise TenantError(403, "This account belongs to an administrator. The sign-in link is delivered to the account owner directly, not through you.")
    r = identity.reveal_enrollment(ctx.db, ctx.rt, ctx.principal("req"), plan_id)
    if not r:
        raise TenantError(409, "the sign-up link is not ready yet, was already shown once, or has expired")
    audit.append(ctx.db, "tenant.enrollment_link_shown", actor_name=f"tenant:{ctx.username}", ip=ctx.ip, resource="plan", resource_id=str(plan_id),
                 details={"uid": r["uid"], **ctx.identity_details()})
    ctx.db.commit()
    return {"token": r["token"], "uid": r["uid"], "stack": r["stack"], "expires_at": r["expires_at"]}


# ---- aliases, shared mailboxes, quotas (mailadmin.py) ------------------------------------------------------------------------------
def aliases_view(ctx: Ctx) -> dict:
    sid = str(ctx.stack_row.id)
    al: dict[str, list[str]] = {}
    for r in ctx.db.execute(text("SELECT uid, alias FROM idm_aliases WHERE stack_id = :s ORDER BY alias"), {"s": sid}).all():
        al.setdefault(r.uid, []).append(r.alias)
    ent = ctx.cfg["entitlement_group"]
    users = [{"uid": r.uid, "display_name": r.display_name, "mail": r.mail, "aliases": al.get(r.uid, [])}
             for r in ctx.db.execute(text("SELECT * FROM idm_users WHERE stack_id = :s AND state = 'active' ORDER BY display_name, uid LIMIT 1000"), {"s": sid}).all()
             if ent in (r.groups or [])]
    return {"domains": mailadmin.alias_domains(ctx.cfg), "max_aliases": mailadmin.MAX_ALIASES, "users": users}


def shared_view(ctx: Ctx) -> dict:
    sid = str(ctx.stack_row.id)
    rows = ctx.db.execute(text("SELECT * FROM idm_shared_mailboxes WHERE stack_id = :s AND state = 'active' ORDER BY name"), {"s": sid}).all()
    grants: dict[str, dict[str, list[str]]] = {}
    for g in ctx.db.execute(text("SELECT g.shared_id, g.uid, g.kind FROM idm_shared_grants g JOIN idm_shared_mailboxes m ON m.id = g.shared_id WHERE m.stack_id = :s ORDER BY g.uid"),
                            {"s": sid}).all():
        grants.setdefault(str(g.shared_id), {}).setdefault(g.kind, []).append(g.uid)
    people = [{"uid": r.uid, "display_name": r.display_name} for r in ctx.db.execute(
        text("SELECT uid, display_name, groups FROM idm_users WHERE stack_id = :s AND state = 'active' ORDER BY display_name, uid LIMIT 1000"), {"s": sid}).all()
        if ctx.cfg["entitlement_group"] in (r.groups or [])]
    return {"mailboxes": [{"name": r.name, "mail": r.mail, "display_name": r.display_name, "created_at": r.created_at.isoformat(),
                           "grants": {k: grants.get(str(r.id), {}).get(k, []) for k in mailadmin.KINDS}} for r in rows],
            "kinds": [{"key": k, "label": mailadmin.KIND_LABELS[k]} for k in mailadmin.KINDS], "people": people, "domain": ctx.cfg["mail_domain"]}


def quotas_view(ctx: Ctx, live: bool = True) -> dict:
    sid = str(ctx.stack_row.id)
    rows = [r for r in ctx.db.execute(text("SELECT * FROM idm_users WHERE stack_id = :s AND state = 'active' ORDER BY display_name, uid LIMIT 1000"), {"s": sid}).all()]
    q = {r.uid: r for r in ctx.db.execute(text("SELECT * FROM idm_quotas WHERE stack_id = :s"), {"s": sid}).all()}
    use = {"users": {}, "available": {"mail": False, "files": False}}
    if live and rows:
        use = mailadmin.usage(ctx.rt, ctx.stack_row.name, [(r.uid, r.entry_uuid) for r in rows])
    out = []
    for r in rows:
        mq, u = q.get(r.uid), use["users"].get(r.uid) or {}
        mail, files = u.get("mail"), u.get("files")
        out.append({"uid": r.uid, "display_name": r.display_name, "has_mailbox": ctx.cfg["entitlement_group"] in (r.groups or []),
                    "mail": {"used_bytes": (mail or {}).get("used_bytes"), "limit_kb": (mail or {}).get("storage_kb") if mail else (mq.mail_storage_kb if mq else None),
                             "send_kb": (mail or {}).get("send_kb") if mail else None, "receive_kb": (mail or {}).get("receive_kb") if mail else None},
                    "files": {"used_bytes": (files or {}).get("used_bytes"), "limit_bytes": ((files or {}).get("total_bytes") or None) if files else (mq.files_quota_bytes or None if mq else None)}})
    return {"users": out, "available": use["available"], "files_quota_supported": bool(ctx.cfg.get("oc_quota_user") and ctx.cfg.get("files_url"))}


# ---- branding / apps ----------------------------------------------------------------------------------------------------------------
def _lum(h: str) -> float:
    c = [int(h[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    c = [x / 12.92 if x <= 0.03928 else ((x + 0.055) / 1.055) ** 2.4 for x in c]
    return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]


def contrast_with_white(h: str) -> float:
    return 1.05 / (_lum(h) + 0.05)


def set_branding(ctx: Ctx, display_name: str | None, accent: str | None) -> dict:
    b = dict(ctx.binding.branding or {})
    if display_name is not None:
        dn = display_name.strip()
        if not 1 <= len(dn) <= 60 or re.search(r"[\x00-\x1f\x7f<>]", dn):
            raise TenantError(422, "The organisation name must be 1 to 60 characters.")
        b["display_name"] = dn
    if accent is not None:
        if not HEX.match(accent):
            raise TenantError(422, "Choose a colour as six hex digits, for example #1a5fb4.")
        if contrast_with_white(accent) < 4.5:
            raise TenantError(422, "That colour is too light: white text on buttons would be hard to read. Pick a darker shade.")
        b["accent"] = accent.lower()
    ctx.db.execute(text("UPDATE tenant_admin_bindings SET branding = CAST(:b AS jsonb) WHERE customer_id = :c"), {"b": json.dumps(b), "c": ctx.customer_id})
    audit.append(ctx.db, "tenant.branding_changed", actor_name=f"tenant:{ctx.username}", ip=ctx.ip, resource="customer", resource_id=ctx.customer_id,
                 details={"branding": b, **ctx.identity_details()})
    ctx.db.commit()
    return b


SVG_NS = "http://www.w3.org/2000/svg"
SVG_ELEMENTS = {"svg", "g", "path", "rect", "circle", "ellipse", "line", "polyline", "polygon", "text", "tspan", "defs", "lineargradient", "radialgradient",
                "stop", "clippath", "mask", "title", "desc", "use", "symbol"}
SVG_ATTRS = {"xmlns", "viewbox", "width", "height", "x", "y", "x1", "y1", "x2", "y2", "cx", "cy", "r", "rx", "ry", "d", "points", "fill", "fill-opacity",
             "fill-rule", "stroke", "stroke-width", "stroke-linecap", "stroke-linejoin", "stroke-opacity", "stroke-dasharray", "opacity", "transform",
             "id", "offset", "stop-color", "stop-opacity", "gradientunits", "gradienttransform", "clip-path", "clip-rule", "mask", "preserveaspectratio",
             "font-family", "font-size", "font-weight", "text-anchor", "dx", "dy", "version", "class", "href", "xlink:href", "xmlns:xlink", "fx", "fy"}


def _svg_check(data: bytes) -> bool:
    """Allowlist parse (review 6 L1): XML parser, no DTD/entities, every element in the SVG namespace and on the allowlist, every attribute on the allowlist,
    references only to in-document ids. Namespaced scripts (`<x:script xmlns:x=svg-ns>`), `<set>`/`<animate>` and data/javascript URLs are all refused."""
    import xml.etree.ElementTree as ET
    if re.search(rb"<!\s*(DOCTYPE|ENTITY)", data, re.I):
        return False
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return False
    for el in root.iter():
        if not isinstance(el.tag, str) or not el.tag.startswith("{" + SVG_NS + "}"):
            return False
        if el.tag.rsplit("}", 1)[1].lower() not in SVG_ELEMENTS:
            return False
        for k, v in el.attrib.items():
            name = k.rsplit("}", 1)[1] if k.startswith("{") else k
            if k.startswith("{"):
                name = "xlink:" + name if k.startswith("{http://www.w3.org/1999/xlink}") else None
            if name is None or name.lower() not in SVG_ATTRS:
                return False
            if name.lower() in ("href", "xlink:href") and not v.strip().startswith("#"):
                return False
            if re.search(r"url\s*\(\s*[\"']?\s*(?!#)|javascript:|data:|expression\s*\(", v, re.I):
                return False
    return True


def sniff_logo(data: bytes) -> str:
    if len(data) > MAX_LOGO:
        raise TenantError(422, "The logo is too large. Use a file under 200 KB.")
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if re.match(rb"\s*(<\?xml[^>]*>\s*)?(<!--.*?-->\s*)*<svg[\s>]", data, re.S | re.I):
        if not _svg_check(data):
            raise TenantError(422, "This SVG contains scripts or links and cannot be used. Export a plain logo.")
        return "image/svg+xml"
    raise TenantError(422, "Use a PNG, JPEG or plain SVG image.")


def set_logo(ctx: Ctx, data: bytes | None) -> None:
    ct = sniff_logo(data) if data else None
    ctx.db.execute(text("UPDATE tenant_admin_bindings SET logo = :l, logo_type = :t WHERE customer_id = :c"), {"l": data, "t": ct, "c": ctx.customer_id})
    audit.append(ctx.db, "tenant.logo_changed", actor_name=f"tenant:{ctx.username}", ip=ctx.ip, resource="customer", resource_id=ctx.customer_id,
                 details={"removed": data is None, "bytes": len(data or b""), **ctx.identity_details()})
    ctx.db.commit()


def set_apps(ctx: Ctx, apps: dict) -> dict:
    ag = ctx.policy.get("app_groups") or {}
    if set(apps) - set(ag) or not all(isinstance(v, bool) for v in apps.values()):
        raise TenantError(422, "unknown application")
    cur = {**(ctx.binding.app_access or {}), **apps}
    ctx.db.execute(text("UPDATE tenant_admin_bindings SET app_access = CAST(:a AS jsonb) WHERE customer_id = :c"), {"a": json.dumps(cur), "c": ctx.customer_id})
    audit.append(ctx.db, "tenant.apps_changed", actor_name=f"tenant:{ctx.username}", ip=ctx.ip, resource="customer", resource_id=ctx.customer_id,
                 details={"apps": cur, **ctx.identity_details()})
    ctx.db.commit()
    return cur


def public_branding(binding, customer_name: str) -> dict:
    b = binding.branding or {}
    return {"display_name": b.get("display_name") or customer_name, "accent": b.get("accent"), "has_logo": binding.logo is not None,
            "apps": {a: bool(v) for a, v in (binding.app_access or {}).items()}, "app_labels": {a: APP_LABELS.get(a, a) for a in (binding.app_access or {})}}
