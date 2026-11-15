import hashlib
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from uuid import UUID

import pyotp
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import text
from sqlalchemy.orm import Session

from . import audit, auth
from .actions import CATALOG, ActionType, PlanError, create_plan, decide_plan
from .auth import ROLES, User, client_ip, cookie_name, get_db, require
from .blueprint import preview
from .config import Settings
from .runtime import Runtime
from .worker import Worker

API = "/api/v1"


class LoginIn(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=1024)
    totp_code: str = Field(max_length=32)


class UserIn(BaseModel):
    username: str = Field(max_length=64)
    role: str = Field(max_length=16)


class EnrollIn(BaseModel):
    username: str = Field(max_length=64)
    token: str = Field(max_length=200)
    password: str = Field(max_length=1024)


class EnrollConfirmIn(BaseModel):
    username: str = Field(max_length=64)
    token: str = Field(max_length=200)
    totp_code: str = Field(max_length=32)


class PlanIn(BaseModel):
    action: ActionType
    params: dict


class PreviewIn(BaseModel):
    blueprint_yaml: str


def _iso(v):
    return v.isoformat() if isinstance(v, datetime) else v


def _row(r, *drop):
    return {k: (str(v) if v is not None and (k.endswith("id") or k == "id") else _iso(v)) for k, v in r._mapping.items() if k not in drop}


SECURITY_HEADERS = [
    (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"),
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"x-frame-options", b"DENY"),
    (b"cross-origin-resource-policy", b"same-origin"),
    (b"cache-control", b"no-store"),
]


class SecurityHeadersAndLimits:
    """Pure ASGI middleware: security headers on every response and a request body cap (L6/M6)."""

    def __init__(self, app, max_body: int, relax_paths: tuple[str, ...] = ()):
        self.app, self.max_body, self.relax = app, max_body, relax_paths

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        relaxed = scope["path"].startswith(self.relax) if self.relax else False

        async def send_h(msg):
            if msg["type"] == "http.response.start":
                names = {h[0].lower() for h in msg.get("headers", [])}
                msg = {**msg, "headers": list(msg.get("headers", [])) + [
                    h for h in SECURITY_HEADERS if h[0] not in names and not (relaxed and h[0] == b"content-security-policy")]}
            await send(msg)

        async def too_big():
            body = b'{"detail":"request body too large"}'
            await send_h({"type": "http.response.start", "status": 413,
                          "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
            await send_h({"type": "http.response.body", "body": body})

        cl = dict(scope["headers"]).get(b"content-length")
        if cl and cl.isdigit() and int(cl) > self.max_body:
            return await too_big()
        seen = 0
        started = False

        async def recv():
            nonlocal seen
            m = await receive()
            if m["type"] == "http.request":
                seen += len(m.get("body", b""))
                if seen > self.max_body:
                    raise _TooBig()
            return m

        async def send_track(msg):
            nonlocal started
            if msg["type"] == "http.response.start":
                started = True
            await send_h(msg)

        try:
            await self.app(scope, recv, send_track)
        except _TooBig:
            if not started:
                await too_big()


class _TooBig(Exception):
    pass


def create_app(settings: Settings | None = None, runtime: Runtime | None = None) -> FastAPI:
    rt = runtime or Runtime(settings)
    worker = Worker(rt) if rt.settings.worker_enabled else None

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if worker:
            worker.start()
        yield
        if worker:
            worker.stop()

    docs = rt.settings.enable_docs  # off in production: Swagger UI is CDN-hosted (M6)
    app = FastAPI(title="Office Unbound ICS", version="0.1.0", lifespan=lifespan,
                  docs_url="/docs" if docs else None, redoc_url=None, openapi_url="/openapi.json" if docs else None)
    app.state.rt = rt
    app.add_middleware(SecurityHeadersAndLimits, max_body=rt.settings.max_body_bytes, relax_paths=("/docs",) if docs else ())

    # ---- health ----
    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.get("/readyz")
    def readyz(response: Response):
        checks: dict = {}
        try:
            with rt.session() as db:
                db.execute(text("SELECT 1"))
                checks["database"] = {"ok": True}
                hb = db.execute(text("SELECT max(at) FROM worker_heartbeat")).scalar()
                age = (datetime.now(timezone.utc) - hb).total_seconds() if hb else None
                checks["worker"] = {"ok": age is not None and age <= rt.settings.heartbeat_max_age_seconds}
                v = audit.verify_chain(db, tail=200)
                checks["audit_chain"] = {"ok": v["ok"]}
        except Exception:  # noqa: BLE001
            checks.setdefault("database", {"ok": False})
        ok = all(c.get("ok") for c in checks.values()) and len(checks) == 3
        if not ok:
            response.status_code = 503
        return {"ready": ok, "checks": checks}

    # ---- auth ----
    @app.post(f"{API}/auth/login")
    def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)):
        token, csrf, user = auth.login(db, rt, body.username, body.password, body.totp_code, client_ip(request))
        response.set_cookie(cookie_name(rt), token, httponly=True, secure=rt.settings.cookie_secure, samesite="strict",
                            max_age=rt.settings.session_absolute_seconds, path="/")
        return {"csrf_token": csrf, "user": {"username": user.username, "role": user.role}}

    @app.post(f"{API}/auth/logout")
    def logout(request: Request, response: Response, user: User = Depends(auth.current_user), db: Session = Depends(get_db)):
        auth.logout(db, request.cookies[cookie_name(rt)], user, client_ip(request))
        response.delete_cookie(cookie_name(rt), path="/")
        return {"ok": True}

    @app.post(f"{API}/auth/logout-all")
    def logout_all(request: Request, response: Response, user: User = Depends(auth.current_user), db: Session = Depends(get_db)):
        n = auth.logout_all(db, user, client_ip(request))
        response.delete_cookie(cookie_name(rt), path="/")
        return {"ok": True, "sessions_revoked": n}

    # ---- first-login enrollment: the invited user sets their own password and TOTP (H2) ----
    @app.post(f"{API}/auth/enroll")
    def enroll(body: EnrollIn, request: Request, db: Session = Depends(get_db)):
        uri = auth.enroll_begin(db, rt, body.username, body.token, body.password, client_ip(request))
        return {"totp_provisioning_uri": uri}

    @app.post(f"{API}/auth/enroll/confirm")
    def enroll_confirm(body: EnrollConfirmIn, request: Request, db: Session = Depends(get_db)):
        auth.enroll_confirm(db, rt, body.username, body.token, body.totp_code, client_ip(request))
        return {"ok": True}

    @app.get(f"{API}/auth/me")
    def me(user: User = Depends(auth.current_user)):
        return {"username": user.username, "role": user.role, "csrf_token": user.csrf}

    @app.post(f"{API}/users", status_code=201)
    def add_user(body: UserIn, request: Request, user: User = Depends(require("admin")), db: Session = Depends(get_db)):
        """Creates an *invited* viewer/operator. No credential is chosen or returned: the enrollment token is issued on the
        host (`python -m ics.cli issue-enrollment`). approver/admin accounts need the approved `user.create` plan action."""
        if body.role not in ("viewer", "operator"):
            raise HTTPException(422, "approver/admin accounts are created via the high-risk plan action user.create (needs approval)")
        try:
            auth.create_invite(db, rt, body.username, body.role, created_by=user.id, actor=user.username)
        except ValueError as e:
            raise HTTPException(422, str(e))
        except Exception as e:  # unique violation
            db.rollback()
            raise HTTPException(409, "could not create user (duplicate username?)") from e
        return {"username": body.username, "role": body.role, "invite": True}

    # ---- plans / jobs ----
    @app.get(f"{API}/actions")
    def catalog(user: User = Depends(require("viewer"))):
        return [{"action": a.value, "risk": s["risk"], "params_schema": s["model"].model_json_schema()} for a, s in CATALOG.items()]

    @app.post(f"{API}/plans", status_code=201)
    def post_plan(body: PlanIn, request: Request, user: User = Depends(require("operator")), db: Session = Depends(get_db)):
        try:
            return create_plan(db, rt, user, body.action, body.params, client_ip(request))
        except ValidationError as e:
            db.rollback()
            raise HTTPException(422, [{"loc": list(x["loc"]), "msg": x["msg"]} for x in e.errors()])
        except PlanError as e:
            db.rollback()
            raise HTTPException(e.status, e.msg)

    def _decide(plan_id: UUID, approve: bool, request: Request, user: User, db: Session):
        try:
            return decide_plan(db, rt, user, plan_id, approve, client_ip(request))
        except PlanError as e:
            raise HTTPException(e.status, e.msg)

    @app.post(f"{API}/plans/{{plan_id}}/approve")
    def approve(plan_id: UUID, request: Request, user: User = Depends(require("approver")), db: Session = Depends(get_db)):
        return _decide(plan_id, True, request, user, db)

    @app.post(f"{API}/plans/{{plan_id}}/reject")
    def reject(plan_id: UUID, request: Request, user: User = Depends(require("approver")), db: Session = Depends(get_db)):
        return _decide(plan_id, False, request, user, db)

    @app.get(f"{API}/plans")
    def list_plans(user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        rows = db.execute(text("SELECT id, action, params, risk, status, requested_by, decided_by, decided_at, created_at "
                               "FROM plans ORDER BY created_at DESC LIMIT 200")).all()
        return [_row(r) for r in rows]

    @app.get(f"{API}/jobs")
    def list_jobs(user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        return [_row(r) for r in db.execute(text("SELECT * FROM jobs ORDER BY created_at DESC LIMIT 200")).all()]

    @app.get(f"{API}/jobs/{{job_id}}")
    def get_job(job_id: UUID, user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        r = db.execute(text("SELECT * FROM jobs WHERE id = :i"), {"i": str(job_id)}).first()
        if r is None:
            raise HTTPException(404, "job not found")
        return _row(r)

    # ---- endpoints / inventory (token secret never selected) ----
    @app.get(f"{API}/endpoints")
    def list_endpoints(user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        rows = db.execute(text("SELECT id, name, type, base_url, token_id, fingerprint_sha256, (ca_pem IS NOT NULL) AS has_ca_bundle, "
                               "created_at FROM endpoints ORDER BY name")).all()
        return [_row(r) for r in rows]

    @app.get(f"{API}/endpoints/{{endpoint_id}}/inventory")
    def latest_inventory(endpoint_id: UUID, user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        r = db.execute(text("SELECT id, collected_at, data FROM inventory_snapshots WHERE endpoint_id = :e "
                            "ORDER BY collected_at DESC LIMIT 1"), {"e": str(endpoint_id)}).first()
        if r is None:
            raise HTTPException(404, "no inventory snapshot yet; plan an inventory.refresh action")
        return {"snapshot_id": r.id, "collected_at": r.collected_at.isoformat(), "data": r.data}

    @app.get(f"{API}/endpoints/{{endpoint_id}}/inventory/snapshots")
    def snapshots(endpoint_id: UUID, user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        rows = db.execute(text("SELECT id, collected_at FROM inventory_snapshots WHERE endpoint_id = :e "
                               "ORDER BY collected_at DESC LIMIT 100"), {"e": str(endpoint_id)}).all()
        return [{"snapshot_id": r.id, "collected_at": r.collected_at.isoformat()} for r in rows]

    # ---- deployment plan preview (dry-run only) ----
    @app.post(f"{API}/plans/preview")
    def plan_preview(body: PreviewIn, request: Request, user: User = Depends(require("operator")), db: Session = Depends(get_db)):
        if len(body.blueprint_yaml) > 200_000:
            raise HTTPException(413, "blueprint too large")
        known = {r.name for r in db.execute(text("SELECT name FROM endpoints"))}
        try:
            out = preview(body.blueprint_yaml, known)
        except RecursionError:
            out = {"valid": False, "errors": [{"loc": [], "msg": "blueprint is nested too deeply"}]}
        audit.append(db, "plan.preview", actor_id=user.id, actor_name=user.username, ip=client_ip(request),
                     details={"valid": out["valid"], "sha256": hashlib.sha256(body.blueprint_yaml.encode()).hexdigest()})
        db.commit()
        return out

    # ---- audit ----
    @app.get(f"{API}/audit")
    def list_audit(limit: int = 100, user: User = Depends(require("approver")), db: Session = Depends(get_db)):
        rows = db.execute(text("SELECT seq, id, at, action, actor_name, ip, resource, resource_id, details, hash FROM audit_events "
                               "ORDER BY seq DESC LIMIT :n"), {"n": min(max(limit, 1), 500)}).all()
        return [_row(r) for r in rows]

    @app.get(f"{API}/audit/verify")
    def verify(user: User = Depends(require("approver")), db: Session = Depends(get_db)):
        return audit.verify_chain(db)

    return app
