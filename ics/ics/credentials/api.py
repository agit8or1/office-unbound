"""Read-only credential API. Metadata only: no response, anywhere, contains secret material. Mutations are typed actions (POST /plans)."""
from datetime import datetime
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..auth import User, get_db, require
from ..tenancy import scope as tscope
from . import service

API = "/api/v1"
_EVENTS = ("credential.use", "credential.created", "credential.rotated", "credential.replaced", "credential.revoked", "credential.tested",
           "credential.expiring", "credential.expired", "credential.purged", "credential.migrated")


def mount(app: FastAPI) -> None:
    @app.get(f"{API}/credentials")
    def list_credentials(customer_id: UUID | None = None, provider: str | None = None, status: str | None = None, limit: int = 500,
                         user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        rows = db.execute(text(
            f"SELECT {service.PUBLIC_COLS} FROM credentials WHERE {tscope.clause(db, 'customer_id')} "
            "AND (CAST(:c AS uuid) IS NULL OR customer_id = :c) AND (CAST(:p AS text) IS NULL OR provider = :p) "
            "AND (CAST(:s AS text) IS NULL OR status = :s) ORDER BY created_at DESC LIMIT :n"),
            {"c": str(customer_id) if customer_id else None, "p": provider, "s": status, "n": min(max(limit, 1), 1000)}).all()
        return [service._pub(r) for r in rows]

    @app.get(f"{API}/credentials/access-review")
    def access_review(since: datetime | None = None, credential_id: UUID | None = None, limit: int = 500,
                      user: User = Depends(require("approver")), db: Session = Depends(get_db)):
        """Who/what used which credential and when, plus lifecycle events: derived from the hash-chained audit log."""
        rows = db.execute(text(
            "SELECT e.seq, e.at, e.action, e.actor_name, e.resource_id AS credential_id, c.label, c.provider, c.customer_id, "
            "e.details->>'purpose' AS purpose, e.details->>'use' AS use "
            "FROM audit_events e JOIN credentials c ON c.id::text = e.resource_id "
            f"WHERE e.resource = 'credential' AND e.action = ANY(:a) AND {tscope.clause(db, 'c.customer_id')} "
            "AND (CAST(:since AS timestamptz) IS NULL OR e.at >= :since) AND (CAST(:cid AS text) IS NULL OR e.resource_id = :cid) "
            "ORDER BY e.seq DESC LIMIT :n"),
            {"a": list(_EVENTS), "since": since, "cid": str(credential_id) if credential_id else None, "n": min(max(limit, 1), 2000)}).all()
        return [{"seq": r.seq, "at": r.at.isoformat(), "event": r.action, "who": r.actor_name, "credential_id": r.credential_id,
                 "label": r.label, "provider": r.provider, "customer_id": str(r.customer_id), "purpose": r.purpose, "use": r.use} for r in rows]

    @app.get(f"{API}/credentials/{{credential_id}}")
    def get_credential(credential_id: UUID, user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        r = db.execute(text(f"SELECT {service.PUBLIC_COLS} FROM credentials WHERE id = :i AND {tscope.clause(db, 'customer_id')}"),
                       {"i": str(credential_id)}).first()
        if r is None:
            raise HTTPException(404, "credential not found")
        d = service._pub(r)
        d["history"] = service.history(db, credential_id)
        d["used_by_endpoints"] = [str(e.id) for e in db.execute(text(
            "SELECT id FROM endpoints WHERE inventory_credential_id = :c OR provision_credential_id = :c"), {"c": str(credential_id)}).all()]
        return d
