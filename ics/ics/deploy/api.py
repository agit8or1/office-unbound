"""Read-only deployment API (ADR-0009 section 7). Previews have no side effects; every mutation is a typed plan via POST /plans."""
from datetime import datetime
from typing import Literal
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, ValidationError
from sqlalchemy import text
from sqlalchemy.orm import Session

from .. import audit
from ..auth import User, client_ip, get_db, require, step_up
from ..tenancy import scope as tscope
from . import appaccess, ops, sizeops, sizer, state
from .catalog import describe_component, describe_profile, get_catalog
from .plan import PlanInput

API = "/api/v1"


class ChangePreviewIn(BaseModel):
    changes: ops.ChangeSet


class RevealIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    totp_code: str
    # "directory": ou-admin (every app); "keycloak": the sign-in service's own administrator (kcadmin; setup and recovery from the identity VM
    # only: its admin console is not served on the public sign-in name). People are added in People, which also creates their mailbox.
    which: Literal["directory", "keycloak"] = "directory"


class ResizeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    window: Literal["24h", "7d", "30d"] = "7d"


def _iso(v):
    return v.isoformat() if isinstance(v, datetime) else v


def _clean(r, *drop):
    return {k: (str(v) if k.endswith("id") and v is not None else _iso(v)) for k, v in r._mapping.items() if k not in drop}


def register_routes(app: FastAPI, rt) -> None:
    @app.get(f"{API}/catalog/profiles")
    def profiles(user: User = Depends(require("viewer"))):
        c = get_catalog()
        return {"catalog_version": c.version, "catalog_digest": c.digest, "profiles": [describe_profile(p) for _, p in sorted(c.profiles.items())]}

    @app.get(f"{API}/catalog/components")
    def components(user: User = Depends(require("viewer"))):
        c = get_catalog()
        return {"catalog_version": c.version, "components": [describe_component(x) for _, x in sorted(c.components.items())],
                "os_images": [o.model_dump() for o in c.meta.os_images]}

    @app.post(f"{API}/deployments/plan")
    def plan_preview(spec: PlanInput, user: User = Depends(require("operator")), db: Session = Depends(get_db)):
        """Dry run: generate the plan against the latest inventory snapshot. Writes nothing."""
        ep = db.execute(text("SELECT id FROM endpoints WHERE name = :n"), {"n": spec.endpoint}).first()
        if ep is not None:
            tscope.assert_endpoint(db, user, ep.id)   # a scoped operator may only plan against its own customers' endpoints
        try:
            return ops.build_plan(db, spec)
        except KeyError:
            raise HTTPException(404, "endpoint not found")

    @app.post(f"{API}/deployments/size")
    def size_preview(req: sizer.SizeRequest, user: User = Depends(require("operator")), db: Session = Depends(get_db)):
        """Sizing engine dry run (docs/status/sizing-api.md). Writes nothing; `plan_input` goes to POST /deployments/plan and deployment.create."""
        ep = db.execute(text("SELECT id FROM endpoints WHERE name = :n"), {"n": req.endpoint}).first()
        if ep is None:
            raise HTTPException(404, "endpoint not found")
        tscope.assert_endpoint(db, user, ep.id)
        try:
            return sizeops.size_request(db, req)
        except KeyError:
            raise HTTPException(404, "endpoint not found")

    @app.post(f"{API}/deployments/{{slug}}/resize-plan")
    def resize_plan(slug: str, body: ResizeIn | None = None, user: User = Depends(require("operator")), db: Session = Depends(get_db)):
        """Rerun sizing against actual usage (metric_samples); proposes an approval-gated ChangeSet. Writes nothing."""
        _get(db, slug)
        try:
            return sizeops.resize_plan(db, slug, (body or ResizeIn()).window)
        except KeyError:
            raise HTTPException(404, "deployment not found")
        except LookupError as e:
            raise HTTPException(409, str(e))
        except (ValueError, ValidationError) as e:
            raise HTTPException(422, str(e)[:500])

    @app.get(f"{API}/deployments")
    def list_deployments(user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        rows = db.execute(text("SELECT id, slug, customer_id, profile, profile_version, endpoint_id, status, current_revision, created_at, updated_at "
                               f"FROM deployments WHERE {tscope.endpoint_clause(db)} ORDER BY slug")).all()
        return [_clean(r) for r in rows]

    def _get(db, slug: str):
        # operator <-> customer scope (tenant isolation): a deployment belongs to the customer that owns its endpoint
        d = db.execute(text(f"SELECT * FROM deployments WHERE slug = :s AND {tscope.endpoint_clause(db)}"), {"s": slug}).first()
        if d is None:
            raise HTTPException(404, "deployment not found")
        return d

    @app.get(f"{API}/deployments/{{slug}}")
    def get_deployment(slug: str, user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        d = _get(db, slug)
        revs = db.execute(text("SELECT revision, kind, plan_hash, risk, status, job_id, created_at, applied_at FROM deployment_revisions "
                               "WHERE deployment_id = :d ORDER BY revision, id"), {"d": str(d.id)}).all()
        counts = db.execute(text("SELECT kind, state, count(*) AS n FROM deployment_resources WHERE deployment_id = :d GROUP BY kind, state"),
                            {"d": str(d.id)}).all()
        return {**_clean(d, "desired_spec"), "desired_spec": d.desired_spec, "revisions": [_clean(r) for r in revs],
                "resource_summary": [{"kind": c.kind, "state": c.state, "count": c.n} for c in counts]}

    @app.get(f"{API}/deployments/{{slug}}/dns")
    def deployment_dns(slug: str, request: Request, refresh: bool = False, user: User = Depends(require("viewer")),
                       db: Session = Depends(get_db)):
        """The DNS records the deployment's domain needs (incl. its DKIM key) and what public DNS holds now: the tenant checker, per
        deployment (owner 2026-11-26: "dns records should be under the deployment"). Read-only; scope-checked like every deployment read."""
        from .. import tenants_api
        return tenants_api.check_deployment(db, _get(db, slug), refresh, request.app.state.rt)

    @app.get(f"{API}/deployments/{{slug}}/resources")
    def resources(slug: str, user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        d = _get(db, slug)
        rows = db.execute(text("SELECT kind, logical_name, provider_ref, desired, actual, state, updated_at FROM deployment_resources "
                               "WHERE deployment_id = :d ORDER BY kind, logical_name"), {"d": str(d.id)}).all()
        return [_clean(r) for r in rows]

    @app.get(f"{API}/dashboard/apps")
    def dashboard_apps(user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        """Every deployment's app links and service health for the dashboard (no secret)."""
        visible = {r.slug for r in db.execute(text(f"SELECT slug FROM deployments WHERE {tscope.endpoint_clause(db)}")).all()}
        return [x for x in appaccess.apps_overview(db) if x["deployment"] in visible]

    @app.get(f"{API}/deployments/{{slug}}/people")
    def deployment_people(slug: str, user: User = Depends(require("admin")), db: Session = Depends(get_db)):
        """The deployment's people, read live from its directory through the agent (no password). Changes are typed actions
        (directory.account.set / .lock / .delete)."""
        from . import accounts
        from ..gateway import GatewayError
        from ..agentclient import AgentError
        d = _get(db, slug)
        try:
            return {"available": True, "reason": None, **accounts.people(rt, db, d.slug)}
        except (GatewayError, AgentError) as e:
            # an expected state (not created yet, VM offline, older image without the runbooks): shown in the panel, not an HTTP error
            return {"available": False, "reason": f"The directory could not be read: {e}", "deployment": d.slug, "domain": None,
                    "people": [], "truncated": False}

    @app.get(f"{API}/deployments/{{slug}}/access")
    def access(slug: str, user: User = Depends(require("admin")), db: Session = Depends(get_db)):
        """Open your apps: links, hosts-file lines, client settings, the deployment CA certificate (public). No secret."""
        return appaccess.access_info(rt, db, _get(db, slug))

    @app.post(f"{API}/deployments/{{slug}}/admin-password")
    def reveal_admin_password(slug: str, body: RevealIn, request: Request, response: Response, user: User = Depends(require("admin")),
                              db: Session = Depends(get_db)):
        """The deployment administrator's directory password, after a fresh one-time code; audited, never cached (appaccess docstring)."""
        d = _get(db, slug)
        ip = client_ip(request)
        step_up(db, rt, user, body.totp_code, ip, f"deployment.admin_password:{d.slug}")
        uid, pw = ((appaccess.ADMIN_UID, appaccess.admin_password(rt, db, d)) if body.which == "directory"
                   else (appaccess.KC_ADMIN_UID, appaccess.keycloak_admin_password(rt, db, d)))
        if pw is None:
            db.commit()
            raise HTTPException(404, "this deployment has no such administrator password (it was never configured, or it was destroyed)")
        audit.append(db, "deployment.admin_password_revealed", actor_id=user.id, actor_name=user.username, ip=ip,
                     details={"deployment": d.slug, "username": uid, "which": body.which})
        db.commit()
        response.headers["Cache-Control"] = "no-store"
        return {"username": uid, "password": pw}

    @app.get(f"{API}/deployments/{{slug}}/diagnostics")
    def diagnostics_sources(slug: str, user: User = Depends(require("admin")), db: Session = Depends(get_db)):
        """What can be read: the deployment's VMs (and whether their agent offers guest.journal) and the fixed unit/file/filter lists."""
        from . import diagnostics
        return diagnostics.sources(db, _get(db, slug))

    @app.post(f"{API}/deployments/{{slug}}/diagnostics/logs")
    def diagnostics_logs(slug: str, body: dict, request: Request, response: Response, user: User = Depends(require("admin")),
                         db: Session = Depends(get_db)):
        """READ-ONLY: the last lines of an allowlisted unit journal or log file of one of this deployment's VMs, redacted on the VM.
        Audited without the content (deploy/diagnostics.py)."""
        from . import diagnostics
        d = _get(db, slug)   # scope first: an out-of-scope deployment is a 404 before the body is even looked at
        try:
            req = diagnostics.LogsIn.model_validate(body)
        except ValidationError as e:
            raise HTTPException(422, "; ".join(x.get("msg", "invalid") for x in e.errors())[:400]) from None
        response.headers["Cache-Control"] = "no-store"
        try:
            return diagnostics.read_logs(rt, db, d, req, user, client_ip(request))
        except diagnostics.DiagError as e:
            raise HTTPException(e.status, str(e)) from None

    @app.get(f"{API}/deployments/{{slug}}/events")
    def events(slug: str, limit: int = 200, user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        d = _get(db, slug)
        rows = db.execute(text("SELECT id, at, kind, message, job_id, details FROM deployment_events WHERE deployment_id = :d "
                               "ORDER BY id DESC LIMIT :n"), {"d": str(d.id), "n": min(max(limit, 1), 1000)}).all()
        return [_clean(r) for r in rows]

    @app.get(f"{API}/deployments/{{slug}}/drift")
    def drift(slug: str, user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        """Desired vs actual (latest inventory + agent reports). Report only: nothing is repaired automatically."""
        d = _get(db, slug)
        snap = db.execute(text("SELECT collected_at, data FROM inventory_snapshots WHERE endpoint_id = :e ORDER BY collected_at DESC LIMIT 1"),
                          {"e": str(d.endpoint_id)}).first() if d.endpoint_id else None
        guests = [g for n in (snap.data.get("nodes", []) if snap else []) for g in n.get("qemu", []) if isinstance(g, dict)]
        res = [{"kind": r.kind, "name": r.logical_name, "desired": r.desired, "actual": r.actual, "state": r.state, "provider_ref": r.provider_ref}
               for r in db.execute(text("SELECT * FROM deployment_resources WHERE deployment_id = :d"), {"d": str(d.id)})]
        findings = state.drift_findings(res, guests, d.slug)
        return {"deployment_id": d.slug, "status": d.status, "inventory_at": _iso(snap.collected_at) if snap else None,
                "in_sync": not findings, "findings": findings, "note": "report only; no automatic repair"}

    @app.post(f"{API}/deployments/{{slug}}/changes/preview")
    def change_preview(slug: str, body: ChangePreviewIn, user: User = Depends(require("operator")), db: Session = Depends(get_db)):
        _get(db, slug)
        try:
            return ops.change_preview(db, slug, body.changes)
        except KeyError:
            raise HTTPException(404, "deployment not found")
        except LookupError as e:
            raise HTTPException(409, str(e))
        except (ValueError, ValidationError) as e:
            raise HTTPException(422, str(e)[:500])

    @app.post(f"{API}/deployments/{{slug}}/destroy/preview")
    def destroy_preview(slug: str, user: User = Depends(require("operator")), db: Session = Depends(get_db)):
        """Dry run: the VMs a destroy would remove (applied revision + owned resources) and the plan_hash an approval binds to."""
        _get(db, slug)
        try:
            return ops.destroy_preview(db, slug)
        except KeyError:
            raise HTTPException(404, "deployment not found")
        except LookupError as e:
            raise HTTPException(409, str(e))

    @app.get(f"{API}/jobs/{{job_id}}/steps")
    def job_steps(job_id: UUID, user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        if db.execute(text("SELECT 1 FROM jobs j JOIN plans p ON p.id = j.plan_id WHERE j.id = :j AND " + tscope.clause(db, "p.customer_id")),
                      {"j": str(job_id)}).first() is None:
            raise HTTPException(404, "job not found")
        rows = db.execute(text("SELECT seq, step_key, kind, target, op, depends_on, disruptive, est_seconds, status, attempts, progress, "
                               "log_excerpt, error_message, error_explanation, started_at, finished_at, carried_from_job FROM job_steps "
                               "WHERE job_id = :j ORDER BY seq"), {"j": str(job_id)}).all()
        return [_clean(r) for r in rows]
