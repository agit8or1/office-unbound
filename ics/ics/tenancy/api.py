"""Operator-side API for customers, their policies and the customer approval workflow (ICS operator RBAC + customer scope)."""
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..auth import User, client_ip, get_db, require
from . import approvals, scope as tscope

API = "/api/v1"
_APPR_COLS = ("id, customer_id, plan_id, title, status, proposal_hash, created_at, submitted_at, token_expires_at, decided_at, approver_name, "
              "approver_email, approver_ip, approver_user_agent, approver_statement, decision_note, completed_at, completion_expires_at")


class ApprovalIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    customer_id: UUID
    title: str = Field(min_length=1, max_length=200)
    params: dict = Field(default_factory=dict, description="input for the permission-plan generator (provider, summary, permissions...)")
    plan_id: UUID | None = None


class SubmitIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ttl_hours: int = Field(default=approvals.DEFAULT_TTL_HOURS, ge=1, le=approvals.MAX_TTL_HOURS)


def _iso(r):
    return {k: (v.isoformat() if hasattr(v, "isoformat") else (str(v) if isinstance(v, UUID) else v)) for k, v in r._mapping.items()}


def mount(app: FastAPI) -> None:
    @app.get(f"{API}/customers")
    def list_customers(user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        rows = db.execute(text("SELECT id, name, msp_owned, provisioning_mode, extra_approvals, contact_name, contact_email, created_at, disabled_at "
                               f"FROM customers WHERE {tscope.clause(db, 'id')} ORDER BY name")).all()
        return [_iso(r) for r in rows]

    @app.get(f"{API}/customers/{{customer_id}}")
    def get_customer(customer_id: UUID, user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        tscope.assert_customer(user, customer_id, "customer")
        r = db.execute(text("SELECT id, name, msp_owned, provisioning_mode, extra_approvals, contact_name, contact_email, created_at, disabled_at "
                            "FROM customers WHERE id = :i"), {"i": str(customer_id)}).first()
        if r is None:
            raise HTTPException(404, "customer not found")
        return _iso(r)

    @app.get(f"{API}/operators/scopes")
    def operator_scopes(user: User = Depends(require("admin")), db: Session = Depends(get_db)):
        if user.customer_ids is not None:
            raise HTTPException(403, "needs the all-customers scope")
        rows = db.execute(text("SELECT u.username, u.all_customers, COALESCE(array_agg(oc.customer_id::text) FILTER (WHERE oc.customer_id IS NOT NULL), "
                               "ARRAY[]::text[]) AS customers FROM users u LEFT JOIN operator_customers oc ON oc.user_id = u.id "
                               "GROUP BY u.username, u.all_customers ORDER BY u.username")).all()
        return [{"username": r.username, "all_customers": r.all_customers, "customer_ids": r.customers} for r in rows]

    @app.post(f"{API}/customer-approvals", status_code=201)
    def create_approval(body: ApprovalIn, request: Request, user: User = Depends(require("operator")), db: Session = Depends(get_db)):
        tscope.assert_customer(user, body.customer_id, "customer")
        if body.plan_id and not db.execute(text("SELECT 1 FROM plans WHERE id = :p AND customer_id = :c"), {"p": str(body.plan_id), "c": str(body.customer_id)}).first():
            raise HTTPException(404, "plan not found for this customer")
        try:
            out = approvals.create_draft(db, request.app.state.rt, user, body.customer_id, body.title, body.params, body.plan_id, client_ip(request))
        except approvals.ApprovalError as e:
            db.rollback()
            raise HTTPException(e.status, e.msg)
        db.commit()
        return out

    @app.get(f"{API}/customer-approvals")
    def list_approvals(status: str | None = None, user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        rows = db.execute(text(f"SELECT {_APPR_COLS} FROM customer_approvals WHERE {tscope.clause(db, 'customer_id')} "
                               "AND (CAST(:s AS text) IS NULL OR status = :s) ORDER BY created_at DESC LIMIT 500"), {"s": status}).all()
        return [_iso(r) for r in rows]

    @app.get(f"{API}/customer-approvals/{{approval_id}}")
    def get_approval(approval_id: UUID, user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        r = db.execute(text(f"SELECT {_APPR_COLS}, proposal FROM customer_approvals WHERE id = :i AND {tscope.clause(db, 'customer_id')}"),
                       {"i": str(approval_id)}).first()
        if r is None:
            raise HTTPException(404, "approval not found")
        return _iso(r)

    def _own(db, user, approval_id):
        r = db.execute(text("SELECT customer_id FROM customer_approvals WHERE id = :i"), {"i": str(approval_id)}).first()
        if r is None or not tscope.allowed(user, r.customer_id):
            raise HTTPException(404, "approval not found")

    @app.post(f"{API}/customer-approvals/{{approval_id}}/submit")
    def submit_approval(approval_id: UUID, body: SubmitIn, request: Request, user: User = Depends(require("operator")), db: Session = Depends(get_db)):
        """Returns the single-use link ONCE (not retrievable later). Deliver it to the customer out of band."""
        _own(db, user, approval_id)
        try:
            out = approvals.submit(db, request.app.state.rt, user, approval_id, body.ttl_hours, client_ip(request))
        except approvals.ApprovalError as e:
            db.rollback()
            raise HTTPException(e.status, e.msg)
        db.commit()
        return out

    @app.post(f"{API}/customer-approvals/{{approval_id}}/cancel")
    def cancel_approval(approval_id: UUID, request: Request, user: User = Depends(require("operator")), db: Session = Depends(get_db)):
        _own(db, user, approval_id)
        try:
            approvals.cancel(db, user, approval_id, client_ip(request))
        except approvals.ApprovalError as e:
            db.rollback()
            raise HTTPException(e.status, e.msg)
        db.commit()
        return {"status": "cancelled"}
