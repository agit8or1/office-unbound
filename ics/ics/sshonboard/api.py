"""Operator API for SSH onboarding sessions (ADR-0014). Credentials are accepted once, go straight into the vault and are never returned.
Everything that runs on the node is a typed action (provider.ssh.*) with plan -> approval -> job -> audit; these endpoints only handle the
credential envelope and the host-key confirmation."""
from uuid import UUID

from fastapi import Body, Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy.orm import Session

from ..auth import User, client_ip, get_db, require
from ..tenancy import scope as tscope
from . import session as S

API = "/api/v1"


class SessionIn(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    customer_id: UUID | None = None
    host: str = Field(pattern=r"^[A-Za-z0-9]([A-Za-z0-9.:-]{0,251}[A-Za-z0-9])?$")
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(pattern=r"^[a-z_][a-z0-9_.-]{0,31}$")
    password: str | None = Field(default=None, min_length=1, max_length=512)
    private_key: str | None = Field(default=None, min_length=1, max_length=16384)
    passphrase: str | None = Field(default=None, max_length=512)
    api_url: str | None = Field(default=None, pattern=r"^https://[A-Za-z0-9.:\[\]-]{1,260}$")


class ConfirmIn(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    fingerprint: str = Field(pattern=r"^SHA256:[A-Za-z0-9+/]{43}$")


def mount(app: FastAPI) -> None:
    def _guard(db, user, sid):
        try:
            return S.live(db, sid, user.id)
        except S.SessionError as e:
            raise HTTPException(e.status, e.msg) from None

    @app.post(f"{API}/ssh-sessions", status_code=201)
    def create(request: Request, body: dict = Body(...), user: User = Depends(require("operator")), db: Session = Depends(get_db)):
        try:
            b = SessionIn.model_validate(body)
        except ValidationError as e:     # never echo input (it may hold a password or key)
            raise HTTPException(422, "invalid fields: " + ", ".join(sorted({str(x["loc"][-1]) for x in e.errors()}))) from None
        cust = b.customer_id or UUID(tscope.DEFAULT_CUSTOMER)
        tscope.assert_customer(user, cust, "customer")
        if getattr(user, "customer_ids", None) is not None and b.customer_id is None:
            raise HTTPException(422, "customer_id is required")
        try:
            out = S.create(db, request.app.state.rt, user, client_ip(request), customer_id=cust, host=b.host, port=b.port, username=b.username,
                           password=b.password, private_key=b.private_key, passphrase=b.passphrase, api_url=b.api_url)
        except S.SessionError as e:
            db.rollback()
            raise HTTPException(e.status, e.msg) from None
        db.commit()
        return out

    @app.get(f"{API}/ssh-sessions/{{sid}}")
    def get(sid: UUID, user: User = Depends(require("operator")), db: Session = Depends(get_db)):
        r = S.row(db, sid)
        if r is None or str(r.created_by) != str(user.id):
            raise HTTPException(404, "SSH session not found")
        return S.view(db, sid)

    @app.post(f"{API}/ssh-sessions/{{sid}}/hostkey")
    def hostkey(sid: UUID, request: Request, user: User = Depends(require("operator")), db: Session = Depends(get_db)):
        _guard(db, user, sid)
        try:
            out = S.fetch_candidate(db, request.app.state.rt, sid)
        except S.SessionError as e:
            db.rollback()
            raise HTTPException(e.status, e.msg) from None
        db.commit()
        return out

    @app.post(f"{API}/ssh-sessions/{{sid}}/confirm")
    def confirm(sid: UUID, request: Request, body: dict = Body(...), user: User = Depends(require("operator")), db: Session = Depends(get_db)):
        _guard(db, user, sid)
        try:
            b = ConfirmIn.model_validate(body)
        except ValidationError:
            raise HTTPException(422, "fingerprint must look like SHA256:<43 characters>") from None
        try:
            out = S.confirm(db, user, client_ip(request), sid, b.fingerprint)
        except S.SessionError as e:
            db.rollback()
            raise HTTPException(e.status, e.msg) from None
        db.commit()
        return out

    @app.post(f"{API}/ssh-sessions/{{sid}}/confirm-proxy")
    def confirm_proxy(sid: UUID, request: Request, body: dict = Body(...), user: User = Depends(require("operator")), db: Session = Depends(get_db)):
        _guard(db, user, sid)
        fp = str(body.get("fingerprint", ""))[:100] if isinstance(body, dict) else ""
        try:
            out = S.confirm_proxy(db, user, client_ip(request), sid, fp)
        except S.SessionError as e:
            db.rollback()
            raise HTTPException(e.status, e.msg) from None
        db.commit()
        return out

    @app.delete(f"{API}/ssh-sessions/{{sid}}")
    def cancel(sid: UUID, request: Request, user: User = Depends(require("operator")), db: Session = Depends(get_db)):
        _guard(db, user, sid)
        S.cancel(db, user, client_ip(request), sid)
        db.commit()
        return {"status": "cancelled", "credential": "destroyed"}
