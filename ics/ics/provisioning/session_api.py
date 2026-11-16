"""Operator API for the connection wizard's Proxmox sign-in (adminsession) and its read-only discovery.

The password and the second-factor code are accepted once, used for the login request only, and never stored, logged or echoed (validation
errors name fields only). Everything that CHANGES Proxmox is still a typed action (provider.*) with plan -> approval -> job -> audit; a plan
uses a session by naming it in `admin_session`."""
from urllib.parse import urlparse
from uuid import UUID

from fastapi import Body, Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from sqlalchemy.orm import Session

from .. import audit, ratelimit
from .. import endpoint_actions as ea
from ..auth import User, client_ip, get_db, require
from ..proxmox import ProxmoxError, fetch_peer_certificate
from ..tenancy import scope as tscope
from . import adminsession as S
from . import inventory_tree

API = "/api/v1"
LOGIN_LIMIT = (10, 600.0)       # per operator and per target: 10 sign-in attempts / 10 minutes


class TlsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    base_url: str

    @field_validator("base_url")
    @classmethod
    def _u(cls, v):
        return ea._check_url(v)


class SessionIn(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    customer_id: UUID | None = None
    endpoint_id: UUID | None = None     # Manage access: address, TLS anchor and customer come from the integration itself
    base_url: str | None = None
    trust: str | None = Field(default=None, pattern=r"^(public_ca|ca|fingerprint)$")
    ca_pem: str | None = Field(default=None, max_length=100_000)
    fingerprint_sha256: str | None = Field(default=None, max_length=200)
    username: str = Field(min_length=1, max_length=64, pattern=r"^[^@\s!:/]{1,64}$")
    realm: str = Field(default="pam", pattern=r"^[A-Za-z0-9._-]{1,32}$")
    password: str = Field(min_length=1, max_length=256)

    @field_validator("base_url")
    @classmethod
    def _u(cls, v):
        return ea._check_url(v) if v is not None else v

    @field_validator("ca_pem")
    @classmethod
    def _c(cls, v):
        return ea._check_ca(v)


class TfaIn(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    method: str = Field(pattern=r"^(totp|recovery|yubico)$")
    code: str = Field(pattern=r"^[A-Za-z0-9 -]{4,80}$")


def _fields(e: ValidationError) -> str:
    return "invalid fields: " + ", ".join(sorted({str(x["loc"][-1]) for x in e.errors()}))


def mount(app: FastAPI) -> None:
    def _err(db, e: S.SessionError):
        db.rollback()
        return HTTPException(e.status, e.msg)

    @app.post(f"{API}/pve-sessions/tls")
    def tls(request: Request, body: dict = Body(...), user: User = Depends(require("admin")), db: Session = Depends(get_db)):
        """Certificate look-up before sign-in: what the server presents and whether it is publicly trusted for the host name (then nothing needs
        to be compared by hand). Only the TLS handshake is performed; no credential is sent."""
        try:
            b = TlsIn.model_validate(body)
        except ValidationError as e:
            raise HTTPException(422, _fields(e)) from None
        rt = request.app.state.rt
        out = fetch_peer_certificate(b.base_url, allow_loopback=rt.settings.allow_loopback_endpoints)
        out.pop("ok", None)
        if out.get("presented_fingerprint_sha256"):
            out.pop("error", None)          # "no trust anchor supplied" is expected here
        public = False
        if out.get("presented_fingerprint_sha256"):
            from ..sshonboard.trust import _public_root
            u = urlparse(b.base_url)
            public, _ = _public_root(u.hostname or "", u.port or 8006)
        out["public_ca"] = bool(public)
        out["verify_hint"] = ("Publicly trusted for this host name: no manual check needed." if public else
                              "Compare this fingerprint with the one Proxmox shows under <node> > System > Certificates (pveproxy-ssl.pem, or pve-ssl.pem "
                              "when no custom certificate is installed), or run `openssl x509 -noout -fingerprint -sha256 -in /etc/pve/local/pve-ssl.pem` "
                              "on the node. Alternatively paste the cluster CA (/etc/pve/pve-root-ca.pem).")
        audit.append(db, "pve.session.tls_checked", actor_id=user.id, actor_name=user.username, ip=client_ip(request), resource="pve_session",
                     details={"base_url": b.base_url, "public_ca": out["public_ca"], "fingerprint": out.get("presented_fingerprint_sha256")})
        db.commit()
        return out

    @app.post(f"{API}/pve-sessions", status_code=201)
    def create(request: Request, body: dict = Body(...), user: User = Depends(require("admin")), db: Session = Depends(get_db)):
        try:
            b = SessionIn.model_validate(body)
        except ValidationError as e:     # never echo input: it holds a password
            raise HTTPException(422, _fields(e)) from None
        rt = request.app.state.rt
        if b.endpoint_id is not None:
            if b.base_url or b.trust or b.ca_pem or b.fingerprint_sha256 or b.customer_id:
                raise HTTPException(422, "endpoint_id cannot be combined with an address, trust anchor or customer")
            from sqlalchemy import text as _t
            ep = db.execute(_t(f"SELECT * FROM endpoints e WHERE e.id = :i AND e.detached_at IS NULL AND {tscope.clause(db, 'e.customer_id')}"),
                            {"i": str(b.endpoint_id)}).first()
            if ep is None:
                raise HTTPException(404, "endpoint not found")
            b.base_url, b.customer_id = ep.base_url, ep.customer_id
            b.trust, b.ca_pem, b.fingerprint_sha256 = ("ca", ep.ca_pem, None) if ep.ca_pem else ("fingerprint", None, ep.fingerprint_sha256)
        elif not (b.base_url and b.trust):
            raise HTTPException(422, "invalid fields: base_url, trust")
        host = urlparse(b.base_url).hostname or ""
        if not (ratelimit.allow(rt, f"pve-login:u:{user.id}", *LOGIN_LIMIT) and ratelimit.allow(rt, f"pve-login:h:{host}", *LOGIN_LIMIT)):
            raise HTTPException(429, "too many Proxmox sign-in attempts; wait a few minutes")
        cust = b.customer_id or UUID(tscope.DEFAULT_CUSTOMER)
        tscope.assert_customer(user, cust, "customer")
        if getattr(user, "customer_ids", None) is not None and b.customer_id is None:
            raise HTTPException(422, "customer_id is required")
        try:
            out = S.create(db, rt, user, client_ip(request), customer_id=cust, base_url=b.base_url, trust=b.trust, ca_pem=b.ca_pem,
                           fingerprint=b.fingerprint_sha256, username=f"{b.username}@{b.realm}", password=b.password)
        except S.SessionError as e:
            raise _err(db, e) from None
        db.commit()
        return out

    @app.get(f"{API}/pve-sessions/{{sid}}")
    def get(sid: UUID, user: User = Depends(require("admin")), db: Session = Depends(get_db)):
        r = S.row(db, sid)
        if r is None or str(r.created_by) != str(user.id):
            raise HTTPException(404, "Proxmox session not found")
        return S.view(db, sid)

    @app.post(f"{API}/pve-sessions/{{sid}}/tfa")
    def tfa(sid: UUID, request: Request, body: dict = Body(...), user: User = Depends(require("admin")), db: Session = Depends(get_db)):
        try:
            b = TfaIn.model_validate(body)
        except ValidationError as e:
            raise HTTPException(422, _fields(e)) from None
        try:
            out = S.tfa(db, request.app.state.rt, user, client_ip(request), sid, b.method, b.code.replace(" ", ""))
        except S.SessionError as e:
            raise _err(db, e) from None
        db.commit()
        return out

    @app.get(f"{API}/pve-sessions/{{sid}}/inventory")
    def inventory(sid: UUID, request: Request, endpoint_id: UUID | None = None, user: User = Depends(require("admin")), db: Session = Depends(get_db)):
        """Signed-in discovery of the whole cluster. With `endpoint_id` (Manage access): annotated against that integration's approved scope and
        what the ICS has seen before; the session must be for the SAME Proxmox address."""
        rt = request.app.state.rt
        ep = None
        if endpoint_id is not None:
            from sqlalchemy import text as _t
            ep = db.execute(_t(f"SELECT * FROM endpoints e WHERE e.id = :i AND e.detached_at IS NULL AND {tscope.clause(db, 'e.customer_id')}"),
                            {"i": str(endpoint_id)}).first()
            if ep is None:
                raise HTTPException(404, "endpoint not found")
        try:
            c = S.client(db, rt, sid, user)
        except S.SessionError as e:
            raise _err(db, e) from None
        if ep is not None and ep.base_url.rstrip("/") != S.row(db, sid).base_url.rstrip("/"):
            c.discard()
            raise HTTPException(422, "this Proxmox sign-in is for a different address than the integration")
        try:
            out = inventory_tree.discover(c, c.username)
        except ProxmoxError as e:
            raise HTTPException(502, str(e)[:300]) from None
        finally:
            c.discard()
        if ep is not None:
            from sqlalchemy import text as _t
            keys = {(r.kind, r.key) for r in db.execute(_t("SELECT kind, key FROM inventory_ledger WHERE endpoint_id = :e"), {"e": str(ep.id)}).all()}
            pol = db.execute(_t("SELECT policy FROM endpoint_policy WHERE endpoint_id = :e"), {"e": str(ep.id)}).scalar()
            out = inventory_tree.annotate(out, ep, keys)
            out["approved_scope"]["preset"] = (pol or {}).get("preset")
            out["approved_scope"]["allow_migrate"] = bool((pol or {}).get("allow_migrate"))
        audit.append(db, "pve.session.discovered", actor_id=user.id, actor_name=user.username, ip=client_ip(request), resource="pve_session",
                     resource_id=str(sid), details={"nodes": out["cluster"]["nodes_total"], "guests": out["cluster"]["guests"],
                                                    "can_setup": out["account"]["ok"]})
        db.commit()
        return out

    @app.delete(f"{API}/pve-sessions/{{sid}}")
    def cancel(sid: UUID, request: Request, user: User = Depends(require("admin")), db: Session = Depends(get_db)):
        try:
            S.cancel(db, user, client_ip(request), sid)
        except S.SessionError as e:
            raise _err(db, e) from None
        db.commit()
        return {"status": "signed_out", "credential": "destroyed"}
