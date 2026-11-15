import hashlib
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from uuid import UUID

import pyotp
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, ValidationError
from sqlalchemy import text
from sqlalchemy.orm import Session

from . import audit, auth
from .actions import CATALOG, ActionType, PlanError, create_plan, decide_plan
from .auth import COOKIE, ROLES, User, client_ip, get_db, require
from .blueprint import preview
from .config import Settings
from .runtime import Runtime
from .worker import Worker

API = "/api/v1"


class LoginIn(BaseModel):
    username: str
    password: str
    totp_code: str


class UserIn(BaseModel):
    username: str
    password: str
    role: str


class PlanIn(BaseModel):
    action: ActionType
    params: dict


class PreviewIn(BaseModel):
    blueprint_yaml: str


def _iso(v):
    return v.isoformat() if isinstance(v, datetime) else v


def _row(r, *drop):
    return {k: (str(v) if v is not None and (k.endswith("id") or k == "id") else _iso(v)) for k, v in r._mapping.items() if k not in drop}


def create_app(settings: Settings | None = None) -> FastAPI:
    rt = Runtime(settings)
    worker = Worker(rt) if rt.settings.worker_enabled else None

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if worker:
            worker.start()
        yield
        if worker:
            worker.stop()

    app = FastAPI(title="Office Unbound ICS", version="0.1.0", lifespan=lifespan)
    app.state.rt = rt

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
                checks["worker"] = {"ok": age is not None and age <= rt.settings.heartbeat_max_age_seconds,
                                    "heartbeat_age_seconds": None if age is None else round(age, 1)}
                v = audit.verify_chain(db, tail=200)
                checks["audit_chain"] = {"ok": v["ok"], "head": v["head"], "checked_tail": v["checked"]}
        except Exception as e:  # noqa: BLE001
            checks.setdefault("database", {"ok": False, "error": type(e).__name__})
        ok = all(c.get("ok") for c in checks.values()) and len(checks) == 3
        if not ok:
            response.status_code = 503
        return {"ready": ok, "checks": checks}

    # ---- auth ----
    @app.post(f"{API}/auth/login")
    def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)):
        token, csrf, user = auth.login(db, rt, body.username, body.password, body.totp_code, client_ip(request))
        response.set_cookie(COOKIE, token, httponly=True, secure=rt.settings.cookie_secure, samesite="strict",
                            max_age=rt.settings.session_absolute_seconds, path="/")
        return {"csrf_token": csrf, "user": {"username": user.username, "role": user.role}}

    @app.post(f"{API}/auth/logout")
    def logout(request: Request, response: Response, user: User = Depends(auth.current_user), db: Session = Depends(get_db)):
        auth.logout(db, request.cookies[COOKIE], user, client_ip(request))
        response.delete_cookie(COOKIE, path="/")
        return {"ok": True}

    @app.get(f"{API}/auth/me")
    def me(user: User = Depends(auth.current_user)):
        return {"username": user.username, "role": user.role, "csrf_token": user.csrf}

    @app.post(f"{API}/users", status_code=201)
    def add_user(body: UserIn, request: Request, user: User = Depends(require("admin")), db: Session = Depends(get_db)):
        try:
            uri = auth.create_user(db, rt, body.username, body.password, body.role, actor=user.username)
        except ValueError as e:
            raise HTTPException(422, str(e))
        except Exception as e:  # unique violation
            db.rollback()
            raise HTTPException(409, "could not create user (duplicate username?)") from e
        return {"username": body.username, "role": body.role, "totp_provisioning_uri": uri}  # shown once

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
            return decide_plan(db, user, plan_id, approve, client_ip(request))
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
        out = preview(body.blueprint_yaml, known)
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
