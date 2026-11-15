"""Operator-console side of the MSP API: list API clients (never any key material) and let the requester of a create/rotate plan reveal the
key exactly once. Creating, changing, rotating and revoking clients are plan actions (msp.client.*)."""
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..auth import User, get_db, require
from . import actions


def mount(app: FastAPI, api: str = "/api/v1") -> None:
    rt = app.state.rt

    @app.get(f"{api}/msp/clients")
    def list_clients(user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        if user.customer_ids is not None:
            raise HTTPException(403, "API clients span customers; needs the all-customers scope")
        rows = db.execute(text(
            "SELECT c.client_id, c.name, c.permissions, c.all_customers, c.rate_limit_per_minute, c.status, c.secret_version, "
            "(c.mtls_fingerprint IS NOT NULL) AS mtls, c.created_at, c.last_used_at, c.revoked_at, "
            "COALESCE((SELECT array_agg(m.customer_id::text ORDER BY m.customer_id) FROM msp_client_customers m WHERE m.client_id = c.id), ARRAY[]::text[]) AS customer_ids "
            "FROM msp_clients c ORDER BY c.created_at")).all()
        return [{**{k: (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in r._mapping.items()}, "permissions": list(r.permissions)} for r in rows]

    @app.post(f"{api}/msp/clients/{{plan_id}}/reveal")
    def reveal(plan_id: UUID, user: User = Depends(require("operator")), db: Session = Depends(get_db)):
        r = actions.reveal(db, rt, user, plan_id)
        if not r:
            raise HTTPException(404, "no unrevealed, unexpired key for this plan and requester")
        return r
