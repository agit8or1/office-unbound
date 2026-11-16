import hashlib
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Literal
from uuid import UUID

import pyotp
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import text
from sqlalchemy.orm import Session

from . import audit, auth, epoch as epochmod, identity, standby
from .actions import CATALOG, ActionType, PlanError, create_plan, decide_plan, may_self_approve
from .auth import ROLES, User, client_ip, cookie_name, get_db, require
from .backups import ops as backup_ops
from .blueprint import preview
from . import userdir
from .config import Settings
from .deploy.api import register_routes as register_deploy_routes
from . import console_api
from .sysinfo import register as register_system_routes
from . import ratelimit
from .guest import callback as guest_callback
from .inventory import api as inventory_api
from . import version as ver
from .provisioning import service as prov_service
from .credentials import api as credentials_api, service as cred_service
from .sshonboard import api as ssh_api
from .provisioning import session_api as pve_session_api
from .tenancy import api as tenancy_api, public as tenancy_public, scope as tscope
from .tenant_admin import api as tenant_api
from .msp import api as msp_api, console as msp_console
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


class IdmEnrollIn(BaseModel):
    stack: str = Field(max_length=63)
    uid: str = Field(max_length=32)
    token: str = Field(max_length=120)
    password: str = Field(max_length=1024)


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


STATIC_DIR = Path(__file__).parent / "static"  # built operator console (frontend/ -> npm run build)
# The API's default-src 'none' would block the UI; static files get a narrow same-origin policy instead (no inline script/style, no eval).
UI_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
          "frame-ancestors 'none'; base-uri 'none'; form-action 'none'")


class UIStaticFiles(StaticFiles):
    async def get_response(self, path, scope):
        resp = await super().get_response(path, scope)
        resp.headers["Content-Security-Policy"] = UI_CSP
        return resp


WORKER_LOCK_KEY = 0x4F55574B   # 'OUWK': pg advisory-lock key of the single background-worker leader


def create_app(settings: Settings | None = None, runtime: Runtime | None = None) -> FastAPI:
    rt = runtime or Runtime(settings)
    worker = Worker(rt) if rt.settings.worker_enabled and rt.settings.role == "primary" else None

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        try:
            if rt.settings.role == "standby":
                raise RuntimeError("standby: passive, nothing to adopt")
            cred_service.adopt_all(rt)  # idempotent: moves any legacy per-endpoint secret into the credential vault
        except Exception:  # noqa: BLE001
            import logging
            if rt.settings.role != "standby":
                logging.getLogger("ics").exception("credential migration failed; endpoints keep using legacy secrets until it succeeds")
        if rt.settings.lease_standalone_override and rt.settings.role == "primary":
            try:   # review 7 H-5: running without a witness is an operator decision and is recorded
                with rt.session() as db:
                    audit.append(db, "controller.lease_standalone_override", actor_name="controller", resource="controller",
                                 details={"witness_configured": bool(rt.settings.lease_witness_url)})
                    db.commit()
            except Exception:  # noqa: BLE001
                pass
        if getattr(rt, "lease", None):
            rt.lease.start()                    # renewal thread; until the first grant no side effect is allowed
        # several uvicorn workers (ICS_WORKERS > 1): exactly one process runs the background worker (jobs, monitor, inventory, backups). Leader election
        # = a session-level advisory lock on a connection held for the process lifetime; if the leader dies, uvicorn's supervisor restarts it
        # and the new process takes the lock.
        lead = None
        if worker:
            conn = rt.engine.connect()
            if conn.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": WORKER_LOCK_KEY}).scalar():
                conn.commit()
                lead = conn
                worker.start()
            else:
                conn.close()   # not the leader: nothing was locked
        yield
        if lead is not None:
            worker.stop()
            lead.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": WORKER_LOCK_KEY})   # session lock: a pooled connection keeps it unless released
            lead.commit()
            lead.close()
        if getattr(rt, "lease", None):
            rt.lease.stop()

    docs = rt.settings.enable_docs  # off in production: Swagger UI is CDN-hosted (M6)
    app = FastAPI(title="Office Unbound ICS", version=ver.__version__, lifespan=lifespan,
                  docs_url="/docs" if docs else None, redoc_url=None, openapi_url="/openapi.json" if docs else None)
    app.state.rt = rt
    if rt.settings.role == "standby":
        app.add_middleware(standby.StandbyGuard)
    else:
        app.add_middleware(standby.FenceGuard, check=rt.assert_active)       # review 7 H-5
    app.add_middleware(SecurityHeadersAndLimits, max_body=rt.settings.max_body_bytes, relax_paths=("/docs",) if docs else ())

    # ---- health ----
    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.get("/readyz")
    def readyz(response: Response):
        checks: dict = {}
        role: dict = {"role": rt.settings.role}
        try:
            with rt.session() as db:
                db.execute(text("SELECT 1"))
                checks["database"] = {"ok": True}
                st = epochmod.get_state(db)
                role.update(epoch=st["epoch"], fenced=st["role"] != "primary")
                if rt.settings.role == "standby":
                    checks["replication"] = standby.replication_status(db, rt.settings.standby_max_lag_seconds)
                else:
                    hb = db.execute(text("SELECT max(at) FROM worker_heartbeat")).scalar()
                    age = (datetime.now(timezone.utc) - hb).total_seconds() if hb else None
                    checks["worker"] = {"ok": age is not None and age <= rt.settings.heartbeat_max_age_seconds and st["role"] == "primary"}
                v = audit.verify_chain(db, tail=200)
                checks["audit_chain"] = {"ok": v["ok"]}
        except Exception:  # noqa: BLE001
            checks.setdefault("database", {"ok": False})
        ok = all(c.get("ok") for c in checks.values()) and len(checks) == 3
        if not ok:
            response.status_code = 503
        return {"ready": ok, "version": ver.__version__.split(".")[0], **role, "checks": checks}      # review 5 L5: major only for anonymous callers

    # ---- version (ADR-0011) ----
    def _full_version(db: Session) -> dict:
        i = ver.build_info()
        try:
            db_rev = db.execute(text("SELECT version_num FROM alembic_version")).scalar()
        except Exception:  # noqa: BLE001
            db.rollback()
            db_rev = None
        return {"product": i["product"], "version": i["version"], "codename": ver.codename(i), "commit": i.get("commit"), "dirty": i.get("dirty"),
                "built_at": i.get("built_at"), "build_source": i.get("source"), "api": ver.API_VERSION,
                "schema": {"build_head": i.get("schema_head"), "database": db_rev},
                "components": {"ics": i["version"], **i.get("components", {})}, "interfaces": i.get("interfaces", {})}

    @app.get(f"{API}/version")
    def version_info(request: Request, db: Session = Depends(get_db)):
        """Review 5 L5. Anonymous and non-admin sessions: product + MAJOR version only. Full detail (exact version, commit, schema, components)
        only for an admin with the all-customers scope."""
        minimal = {"product": ver.PRODUCT, "version": ver.__version__.split(".")[0]}
        try:
            u = auth.current_user(request, db)
        except HTTPException:
            return minimal
        if auth.RANK[u.role] < auth.RANK["admin"] or getattr(u, "customer_ids", None) is not None:
            return minimal
        return _full_version(db)

    # ---- auth ----
    @app.post(f"{API}/auth/login")
    def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)):
        token, csrf, user = auth.login(db, rt, body.username, body.password, body.totp_code, client_ip(request))
        response.set_cookie(cookie_name(rt), token, httponly=True, secure=rt.settings.cookie_secure, samesite="strict",
                            max_age=rt.settings.session_absolute_seconds, path="/")
        return {"csrf_token": csrf, "user": {"id": str(user.id), "username": user.username, "role": user.role}}

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
        return {"id": str(user.id), "username": user.username, "role": user.role, "csrf_token": user.csrf}

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

    userdir.register(app, rt, API)  # GET users, users/{id}, invitations, access-policy (read-only)

    # ---- plans / jobs ----
    @app.get(f"{API}/actions")
    def catalog(user: User = Depends(require("viewer"))):
        return [{"action": a.value, "risk": s["risk"] if isinstance(s["risk"], str) else "by_runbook", "params_schema": s["model"].model_json_schema()} for a, s in CATALOG.items()]

    @app.post(f"{API}/plans", status_code=201)
    def post_plan(body: PlanIn, request: Request, user: User = Depends(require("operator")), db: Session = Depends(get_db)):
        try:
            return create_plan(db, rt, user, body.action, body.params, client_ip(request))
        except ValidationError as e:
            db.rollback()
            errs = [{"loc": list(x["loc"]), "msg": x["msg"]} for x in e.errors()]
            # field names and messages only, never the submitted values (plans can carry secrets)
            logging.getLogger("ics.plans").warning("plan rejected: action=%s user=%s status=422 errors=%s", body.action.value, user.username, errs)
            raise HTTPException(422, errs)
        except PlanError as e:
            db.rollback()
            logging.getLogger("ics.plans").warning("plan rejected: action=%s user=%s status=%s reason=%s", body.action.value, user.username, e.status, e.msg)
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
    def list_plans(status: str | None = None, limit: int = 200, include_archived: bool = False, user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        if status is not None and status not in ("pending_approval", "approved", "rejected"):
            raise HTTPException(422, "status must be pending_approval, approved or rejected")
        rows = db.execute(text(
            "SELECT p.id, p.action, p.params, p.params_hash, p.risk, p.status, p.requested_by, ru.username AS requested_by_username, "
            "p.decided_by, du.username AS decided_by_username, p.decided_at, p.created_at, "
            "(SELECT count(*) FROM plan_approvals a WHERE a.plan_id = p.id) AS approval_count, "
            "COALESCE((SELECT array_agg(u.username ORDER BY a.at) FROM plan_approvals a JOIN users u ON u.id = a.approver_id "
            "WHERE a.plan_id = p.id), ARRAY[]::text[]) AS approvers "
            "FROM plans p JOIN users ru ON ru.id = p.requested_by LEFT JOIN users du ON du.id = p.decided_by "
            f"WHERE (CAST(:s AS text) IS NULL OR p.status = :s) AND (:ia OR p.archived_at IS NULL) AND {tscope.clause(db, 'p.customer_id')} ORDER BY p.created_at DESC LIMIT :n"),
            {"s": status, "n": min(max(limit, 1), 500), "ia": include_archived}).all()
        out = []
        for r in rows:
            d = _row(r)
            d["approvals_required"] = rt.settings.required_approvals_high if r.risk == "high" else 1
            d["self_approval"] = may_self_approve(rt, user.role) and str(r.requested_by) == str(user.id)
            out.append(d)
        return out

    @app.get(f"{API}/jobs")
    def list_jobs(status: str | None = None, limit: int = 200, user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        if status is not None and status not in ("queued", "running", "succeeded", "failed"):
            raise HTTPException(422, "status must be queued, running, succeeded or failed")
        rows = db.execute(text("SELECT j.* FROM jobs j JOIN plans p ON p.id = j.plan_id WHERE (CAST(:s AS text) IS NULL OR j.status = :s) "
                               f"AND {tscope.clause(db, 'p.customer_id')} ORDER BY j.created_at DESC LIMIT :n"),
                          {"s": status, "n": min(max(limit, 1), 500)}).all()
        return [_row(r) for r in rows]

    @app.get(f"{API}/jobs/{{job_id}}")
    def get_job(job_id: UUID, user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        r = db.execute(text("SELECT j.* FROM jobs j JOIN plans p ON p.id = j.plan_id WHERE j.id = :i AND " + tscope.clause(db, "p.customer_id")),
                       {"i": str(job_id)}).first()
        if r is None:
            raise HTTPException(404, "job not found")
        return _row(r)

    # ---- endpoints / inventory (token secret never selected) ----
    inventory_api.mount(app)  # GET /endpoints[/{id}], /infra/*, /setup/*
    prov_service.mount(app, rt)  # GET /providers/{id}/permissions, /providers/{id}/provisioning/packages/{pkg}

    @app.get(f"{API}/endpoints/{{endpoint_id}}/inventory")
    def latest_inventory(endpoint_id: UUID, user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        tscope.assert_endpoint(db, user, endpoint_id)
        r = db.execute(text("SELECT id, collected_at, data FROM inventory_snapshots WHERE endpoint_id = :e "
                            "ORDER BY collected_at DESC LIMIT 1"), {"e": str(endpoint_id)}).first()
        if r is None:
            raise HTTPException(404, "no inventory snapshot yet; plan an inventory.refresh action")
        return {"snapshot_id": r.id, "collected_at": r.collected_at.isoformat(), "data": r.data}

    @app.get(f"{API}/endpoints/{{endpoint_id}}/inventory/snapshots")
    def snapshots(endpoint_id: UUID, user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        tscope.assert_endpoint(db, user, endpoint_id)
        rows = db.execute(text("SELECT id, collected_at FROM inventory_snapshots WHERE endpoint_id = :e "
                               "ORDER BY collected_at DESC LIMIT 100"), {"e": str(endpoint_id)}).all()
        return [{"snapshot_id": r.id, "collected_at": r.collected_at.isoformat()} for r in rows]

    @app.get(f"{API}/endpoints/{{endpoint_id}}/inventory/refresh-state")
    def refresh_state(endpoint_id: UUID, user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        """State of the most recent inventory.refresh job for this endpoint (none|queued|running|succeeded|failed) + last snapshot time."""
        tscope.assert_endpoint(db, user, endpoint_id)
        j = db.execute(text(
            "SELECT j.id, j.plan_id, j.status, j.created_at, j.started_at, j.finished_at, j.error FROM jobs j JOIN plans p ON p.id = j.plan_id "
            "WHERE p.action = 'inventory.refresh' AND p.params->>'endpoint_id' = :e ORDER BY j.created_at DESC LIMIT 1"),
            {"e": str(endpoint_id)}).first()
        snap = db.execute(text("SELECT max(collected_at) FROM inventory_snapshots WHERE endpoint_id = :e"), {"e": str(endpoint_id)}).scalar()
        return {"state": j.status if j else "none", "job_id": str(j.id) if j else None, "plan_id": str(j.plan_id) if j else None,
                "queued_at": _iso(j.created_at) if j else None, "started_at": _iso(j.started_at) if j else None,
                "finished_at": _iso(j.finished_at) if j else None,
                "error": (j.error or {}).get("message") if j and j.error else None, "last_snapshot_at": _iso(snap)}

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

    register_system_routes(app, rt, API, worker)  # GET system (admin): version, migration, readiness, threads, sizes, backup
    if not rt.settings.guest_callback_dedicated:
        guest_callback.register(app, rt)  # golden-image bootstrap callback (guest/callback.py): HMAC-authenticated, single use, rate limited
    console_api.register(app, rt, API)  # GET releases, GET deployments/{slug}/bootstrap (read-only console views)
    register_deploy_routes(app, rt)  # catalog, deployments, drift, change preview, job steps (deploy/api.py)

    # ---- monitoring (read-only views; every mutation is a typed plan) ----
    def _strip_cfg(cfg: dict) -> dict:
        return {k: ("[pem]" if k == "ca_pem" else v) for k, v in cfg.items()}

    @app.get(f"{API}/nodes")
    def list_nodes(user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        rows = db.execute(text("SELECT id, name, address, port, tls_fingerprint_sha256, agent_key_fp, capabilities, agent_version, status, "
                               f"last_seen_at, created_at FROM nodes WHERE {tscope.clause(db, 'customer_id')} ORDER BY name")).all()
        return [_row(r) for r in rows]

    @app.get(f"{API}/checks")
    def list_checks(user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        rows = db.execute(text(
            "SELECT c.id, c.name, c.kind, c.config, (c.secret_enc IS NOT NULL) AS has_secret, c.interval_seconds, c.fail_threshold, "
            "c.recover_threshold, c.enabled, c.state, c.consecutive_bad, c.last_run_at, c.next_run_at, c.last_state_change_at, c.last_message, "
            "c.last_latency_ms, c.remediation, c.created_at, "
            "(SELECT i.id FROM incidents i WHERE i.check_id = c.id AND i.status IN ('open','acked')) AS active_incident_id "
            f"FROM checks c WHERE {tscope.clause(db, 'c.customer_id')} ORDER BY c.name")).all()
        out = []
        for r in rows:
            d = _row(r)
            d["config"] = _strip_cfg(d["config"])
            out.append(d)
        return out

    @app.get(f"{API}/checks/{{check_id}}/results")
    def check_results(check_id: UUID, limit: int = 100, before_id: int | None = None, user: User = Depends(require("viewer")),
                      db: Session = Depends(get_db)):
        tscope.assert_row(db, user, "checks", check_id, "check")
        rows = db.execute(text("SELECT id, at, status, latency_ms, message FROM check_results WHERE check_id = :c "
                               "AND (CAST(:b AS bigint) IS NULL OR id < :b) ORDER BY id DESC LIMIT :n"),
                          {"c": str(check_id), "b": before_id, "n": min(max(limit, 1), 1000)}).all()
        return [{**_row(r), "id": r.id} for r in rows]

    @app.get(f"{API}/checks/{{check_id}}/remediation")
    def check_remediation(check_id: UUID, user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        tscope.assert_row(db, user, "checks", check_id, "check")
        rows = db.execute(text("SELECT * FROM remediation_attempts WHERE check_id = :c ORDER BY at DESC LIMIT 100"), {"c": str(check_id)}).all()
        return [{**_row(r), "id": r.id} for r in rows]

    @app.get(f"{API}/incidents")
    def list_incidents(status: str | None = None, limit: int = 100, user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        if status is not None and status not in ("open", "acked", "recovered", "active"):
            raise HTTPException(422, "status must be open, acked, recovered or active")
        rows = db.execute(text(
            "SELECT i.id, i.check_id, c.name AS check_name, i.severity, i.status, i.title, i.message, i.opened_at, i.acked_at, "
            "au.username AS acked_by_username, i.ack_note, i.recovered_at, i.escalated_at, i.notify_count FROM incidents i "
            "JOIN checks c ON c.id = i.check_id LEFT JOIN users au ON au.id = i.acked_by "
            f"WHERE {tscope.clause(db, 'c.customer_id')} AND (CAST(:s AS text) IS NULL OR i.status = :s OR (:s = 'active' AND i.status IN ('open','acked'))) "
            "ORDER BY i.opened_at DESC LIMIT :n"), {"s": status, "n": min(max(limit, 1), 500)}).all()
        return [_row(r) for r in rows]

    @app.get(f"{API}/incidents/{{incident_id}}")
    def get_incident(incident_id: UUID, user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        i = db.execute(text("SELECT i.*, c.name AS check_name, c.state AS check_state FROM incidents i JOIN checks c ON c.id = i.check_id "
                            f"WHERE i.id = :i AND {tscope.clause(db, 'c.customer_id')}"), {"i": str(incident_id)}).first()
        if i is None:
            raise HTTPException(404, "incident not found")
        notes = db.execute(text("SELECT n.id, n.event, n.status, n.attempts, n.last_error, n.detail, n.created_at, n.sent_at, ch.name AS channel, "
                                "ch.kind AS channel_kind FROM notifications n JOIN alert_channels ch ON ch.id = n.channel_id "
                                f"WHERE n.incident_id = :i AND {tscope.clause(db, 'ch.customer_id')} ORDER BY n.id"), {"i": str(incident_id)}).all()
        att = db.execute(text("SELECT * FROM remediation_attempts WHERE incident_id = :i ORDER BY at"), {"i": str(incident_id)}).all()
        return {**_row(i), "notifications": [{**_row(n), "id": n.id} for n in notes], "remediation": [{**_row(a), "id": a.id} for a in att]}

    @app.get(f"{API}/alert-channels")
    def list_channels(user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        rows = db.execute(text("SELECT id, name, kind, config, (secret_enc IS NOT NULL) AS has_secret, enabled, created_at "
                               f"FROM alert_channels WHERE {tscope.clause(db, 'customer_id')} ORDER BY name")).all()
        out = []
        for r in rows:
            d = _row(r)
            d["config"] = _strip_cfg(d["config"])
            d["delivery_available"] = r.kind not in ("pushover", "sms")
            out.append(d)
        return out

    @app.get(f"{API}/maintenance")
    def list_maintenance(user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        rows = db.execute(text("SELECT m.id, m.name, m.check_id, c.name AS check_name, m.starts_at, m.ends_at, m.reason, "
                               "(m.starts_at <= now() AND m.ends_at > now()) AS active FROM maintenance_windows m "
                               f"LEFT JOIN checks c ON c.id = m.check_id WHERE {tscope.clause(db, 'm.customer_id')} ORDER BY m.starts_at DESC LIMIT 100")).all()
        return [_row(r) for r in rows]

    # ---- identity lifecycle (mutations are typed plans idm.*; these are the one-time enrollment flow and read-only views) ----
    @app.post(f"{API}/identity/enrollments/{{plan_id}}/reveal")
    def idm_reveal(plan_id: UUID, request: Request, user: User = Depends(require("operator")), db: Session = Depends(get_db)):
        """Shows the one-time enrollment token of a user.create/user.enable plan to ITS REQUESTER, once. Hand it to the new user out of band."""
        r = identity.reveal_enrollment(db, rt, user, plan_id)
        if not r:
            raise HTTPException(404, "no unrevealed, unexpired enrollment for this plan and requester")
        return r

    @app.post(f"{API}/identity/enrollments/{{plan_id}}/deliver")
    def idm_deliver(plan_id: UUID, user: User = Depends(require("operator")), db: Session = Depends(get_db)):
        """Operator side of an organisation administrator's credential reset: the one-time link of a privileged target, once, never to the requester."""
        r = identity.reveal_enrollment_for_delivery(db, rt, user, plan_id)
        if not r:
            raise HTTPException(404, "no unrevealed, unexpired enrollment for this plan")
        return JSONResponse(r, headers={"Cache-Control": "no-store"})

    @app.post(f"{API}/identity/sip-credentials/{{plan_id}}/reveal")
    def idm_sip_reveal(plan_id: UUID, user: User = Depends(require("operator")), db: Session = Depends(get_db)):
        """Shows the one-time SIP device credential of an idm.user.issue_sip_credential plan to ITS REQUESTER, once (the PBX keeps only a digest)."""
        r = identity.reveal_sip_credential(db, rt, user, plan_id)
        if not r:
            raise HTTPException(404, "no unrevealed, unexpired SIP credential for this plan and requester")
        return JSONResponse(r, headers={"Cache-Control": "no-store"})

    @app.post(f"{API}/identity/enroll")
    def idm_enroll(body: IdmEnrollIn, request: Request, db: Session = Depends(get_db)):
        """The new user sets their OWN initial password with the one-time token (never stored, never logged). Unauthenticated by design."""
        ip = client_ip(request) or "?"
        if not ratelimit.allow(rt, "enroll-ip:" + ip, 20, 60.0):
            raise HTTPException(429, "too many attempts")
        try:
            identity.redeem_enrollment(db, rt, body.stack, body.uid, body.token, body.password, ip)
        except identity.EnrollRefused:
            raise HTTPException(403, "invalid or expired enrollment token")
        except ValueError as e:
            raise HTTPException(422, str(e))
        except identity.IdentityError:
            raise HTTPException(502, "directory unavailable; try again later")
        return {"ok": True}

    @app.get(f"{API}/identity/stacks")
    def idm_stacks(user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        rows = db.execute(text("SELECT id, name, config, last_reconcile_at, created_at FROM idm_stacks "
                               f"WHERE {tscope.clause(db, 'customer_id')} ORDER BY name")).all()   # a stack belongs to one customer (tenant isolation)
        hide = {"identity_ca_pem", "mail_ca_pem"}
        return [{**_row(r, "config"), "config": {k: v for k, v in r.config.items() if k not in hide}} for r in rows]

    @app.get(f"{API}/identity/users")
    def idm_users(stack: str | None = None, user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        rows = db.execute(text(
            "SELECT u.id, s.name AS stack, u.uid, u.entry_uuid, u.mail, u.display_name, u.groups, u.state, u.created_at, u.disabled_at, "
            "u.last_verification FROM idm_users u JOIN idm_stacks s ON s.id = u.stack_id WHERE (CAST(:s AS text) IS NULL OR s.name = :s) "
            f"AND {tscope.clause(db, 's.customer_id')} ORDER BY u.uid LIMIT 500"), {"s": stack}).all()
        return [_row(r) for r in rows]

    @app.get(f"{API}/identity/reconcile")
    def idm_reconcile_runs(stack: str | None = None, limit: int = 10, user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        rows = db.execute(text(
            "SELECT r.id, s.name AS stack, r.at, r.trigger, r.ok, r.findings FROM idm_reconcile_runs r JOIN idm_stacks s ON s.id = r.stack_id "
            "WHERE (CAST(:s AS text) IS NULL OR s.name = :s) "
            f"AND {tscope.clause(db, 's.customer_id')} ORDER BY r.at DESC LIMIT :n"), {"s": stack, "n": min(max(limit, 1), 100)}).all()
        return [{**_row(r), "id": r.id} for r in rows]

    # ---- backup product (mutations are typed plans backup.*; these are read-only views; ADR-0010) ----
    @app.get(f"{API}/backups/policies")
    def backup_policies(user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        """Policies with the four distinct states (backup_success, replication, recovery_readiness, verified_restore); no secrets."""
        return backup_ops.list_policies(db)

    @app.get(f"{API}/backups/runs")
    def backup_runs(policy: str | None = None, kind: Literal["backup", "prune"] | None = None, limit: int = 50,
                    user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        return backup_ops.list_runs(db, policy, kind, limit)

    @app.get(f"{API}/backups/verifications")
    def backup_verifications(policy: str | None = None, level: Literal["check", "restore"] | None = None, limit: int = 50,
                             user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        return backup_ops.list_verifications(db, policy, level, limit)

    # ---- audit ----
    @app.get(f"{API}/audit")
    def list_audit(limit: int = 100, before_seq: int | None = None, user: User = Depends(require("approver")),
                   db: Session = Depends(get_db)):
        """Newest first; pass the smallest `seq` you have as `before_seq` to get the next (older) page."""
        if user.customer_ids is not None:
            raise HTTPException(403, "the audit log spans all customers; it needs the all-customers scope")
        rows = db.execute(text("SELECT seq, id, at, action, actor_name, ip, resource, resource_id, details, hash FROM audit_events "
                               "WHERE (CAST(:b AS bigint) IS NULL OR seq < :b) ORDER BY seq DESC LIMIT :n"),
                          {"n": min(max(limit, 1), 500), "b": before_seq}).all()
        return [_row(r) for r in rows]

    @app.get(f"{API}/audit/verify")
    def verify(user: User = Depends(require("approver")), db: Session = Depends(get_db)):
        return audit.verify_chain(db)

    credentials_api.mount(app)
    msp_console.mount(app, API)
    msp_api.register(app)  # /api/msp/v1/* machine-to-machine API (ADR-0013)
    tenancy_api.mount(app)
    ssh_api.mount(app)
    pve_session_api.mount(app)
    tenancy_public.mount(app)
    tenant_api.mount(app)

    if STATIC_DIR.is_dir():
        @app.get("/", include_in_schema=False)
        def ui_root():
            return RedirectResponse("/ui/")

        app.mount("/ui", UIStaticFiles(directory=STATIC_DIR, html=True), name="ui")

    return app
