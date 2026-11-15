"""Read-only deployment API (ADR-0009 section 7). Previews have no side effects; every mutation is a typed plan via POST /plans."""
from datetime import datetime
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, ValidationError
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..auth import User, get_db, require
from ..tenancy import scope as tscope
from . import ops, state
from .catalog import describe_component, describe_profile, get_catalog
from .plan import PlanInput

API = "/api/v1"


class ChangePreviewIn(BaseModel):
    changes: ops.ChangeSet


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

    @app.get(f"{API}/deployments/{{slug}}/resources")
    def resources(slug: str, user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        d = _get(db, slug)
        rows = db.execute(text("SELECT kind, logical_name, provider_ref, desired, actual, state, updated_at FROM deployment_resources "
                               "WHERE deployment_id = :d ORDER BY kind, logical_name"), {"d": str(d.id)}).all()
        return [_clean(r) for r in rows]

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
