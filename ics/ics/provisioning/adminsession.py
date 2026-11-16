"""Proxmox administrator sessions for the connection wizard: user name + password (+ second factor) instead of a hand-made API token.

Flow: the ICS logs in to the Proxmox API itself (POST /access/ticket). An account with a second factor gets a challenge first; the TFA step
(TOTP, recovery key or Yubico OTP) completes the login. Only the resulting PVE ticket + CSRF token are kept, in the credential vault
(envelope encrypted, purpose temporary_provisioning, provider pve-admin, <= 30 minutes and never beyond the ticket's 2 h lifetime). The
password exists only for the duration of the login request and is never stored, logged or returned.

What the session is used for:
  * synchronous READ-ONLY discovery for the wizard (inventory tree, privileges of the signed-in account)
  * the plan's temporary credential: when an approved provisioning / scope / reconcile / rotate plan names `admin_session`, the ticket is copied
    into that plan's own temporary credential at plan creation; the job uses it and it is destroyed like any other temporary credential.
A session is bound to the ICS user who created it, to one Proxmox address and to its TLS trust anchor: it is never sent anywhere else.
Proxmox has no API to revoke a ticket early; the ICS destroys every copy it holds and the ticket expires on the Proxmox side within 2 hours.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from sqlalchemy import text
from sqlalchemy.orm import Session

from .. import audit
from ..credentials import service as cred_service
from ..providers.base import ProviderError
from ..providers.proxmox.admin import ProxmoxAdminClient
from ..proxmox import ProxmoxError, normalize_fingerprint
from ..runtime import Runtime

PROVIDER = "pve-admin"
TTL_SECONDS = 30 * 60
MAX_TFA_ATTEMPTS = 5
FINISHED = ("used", "cancelled", "expired", "failed")
PUBLIC = "id, customer_id, base_url, trust, username, state, tfa_methods, created_at, expires_at, finished_at"

log = logging.getLogger(__name__)


class SessionError(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status, self.msg = status, msg


def now() -> datetime:
    return datetime.now(timezone.utc)


def _kw(rt: Runtime, ca_pem, fp) -> dict:
    s = rt.settings
    return dict(ca_pem=ca_pem, fingerprint_sha256=fp, deadline=s.pve_request_deadline_seconds, max_bytes=s.pve_max_response_bytes,
                allow_loopback=s.allow_loopback_endpoints)


def resolve_trust(rt: Runtime, base_url: str, trust: str, ca_pem: str | None, fingerprint: str | None) -> tuple[str, str | None, str | None]:
    """(trust, ca_pem, fingerprint). public_ca is derived HERE from the operating system's trust store (chain + host name), never taken from the
    browser; ca and fingerprint are the operator's explicit anchors (fingerprint compared out of band in the wizard)."""
    if trust == "public_ca":
        from ..sshonboard.trust import _public_root
        u = urlparse(base_url)
        ok, root = _public_root(u.hostname or "", u.port or 8006)
        if not ok or not root:
            raise SessionError(422, "the certificate is not publicly trusted for this host name: verify its fingerprint or supply the cluster CA instead")
        return "public_ca", root, None
    if trust == "ca":
        if not ca_pem:
            raise SessionError(422, "a CA certificate is required")
        return "ca", ca_pem, None
    if trust == "fingerprint":
        try:
            return "fingerprint", None, normalize_fingerprint(fingerprint or "")
        except ValueError:
            raise SessionError(422, "fingerprint must be 64 hex characters (SHA-256)") from None
    raise SessionError(422, "unknown trust mode")


def _store(db: Session, rt: Runtime, sid, customer_id, secret: dict, identity: str, host: str, expires: datetime, user, ip, reason: str) -> str:
    return cred_service.create(db, rt, provider=PROVIDER, customer_id=customer_id, label=f"Proxmox admin session {host}", credential_type="api_token",
                               purpose="temporary_provisioning", secret=json.dumps(secret), identity=identity, host=host, expires_at=expires,
                               actor=user.username, actor_id=user.id, reason=reason, ip=ip)


def create(db: Session, rt: Runtime, user, ip, *, customer_id, base_url: str, trust: str, ca_pem: str | None, fingerprint: str | None,
           username: str, password: str) -> dict:
    trust, ca_pem, fp = resolve_trust(rt, base_url, trust, ca_pem, fingerprint)
    host = urlparse(base_url).hostname or base_url
    try:
        c = ProxmoxAdminClient(base_url, username=username, password=password, **_kw(rt, ca_pem, fp))
    except ProviderError as e:
        audit.append(db, "pve.session.login_failed", actor_id=user.id, actor_name=user.username, ip=ip, resource="pve_session",
                     details={"base_url": base_url, "username": username, "reason": "rejected"})
        db.commit()
        raise SessionError(401, e.message) from None
    except (ProxmoxError, ValueError) as e:
        raise SessionError(502 if isinstance(e, ProxmoxError) else 422, str(e)[:300]) from None
    finally:
        del password
    sid = uuid.uuid4()
    expires = now() + timedelta(seconds=TTL_SECONDS)
    try:
        if c.need_tfa:
            secret, state, methods = {"tfa_challenge": c._tfa_challenge, "username": c.username}, "need_tfa", c.tfa_methods
        else:
            secret, state, methods = c.export_ticket(), "ready", []
        uname = c.username
    finally:
        c.discard()
    cid = _store(db, rt, sid, customer_id, secret, uname, host, expires, user, ip, "Proxmox login for the connection wizard (30 minutes, never the password)")
    db.execute(text("INSERT INTO pve_admin_sessions (id, credential_id, customer_id, created_by, base_url, ca_pem, fingerprint_sha256, trust, username, state, "
                    "tfa_methods, expires_at) VALUES (:i, :cid, :c, :u, :b, :ca, :fp, :t, :n, :s, CAST(:m AS jsonb), :e)"),
               {"i": str(sid), "cid": cid, "c": str(customer_id), "u": str(user.id), "b": base_url, "ca": ca_pem, "fp": fp, "t": trust, "n": uname,
                "s": state, "m": json.dumps(methods), "e": expires})
    audit.append(db, "pve.session.created", actor_id=user.id, actor_name=user.username, ip=ip, resource="pve_session", resource_id=str(sid),
                 details={"base_url": base_url, "username": uname, "trust": trust, "state": state, "tfa_methods": methods, "expires_in_s": TTL_SECONDS})
    return view(db, sid)


def row(db: Session, sid):
    return db.execute(text("SELECT * FROM pve_admin_sessions WHERE id = :i"), {"i": str(sid)}).first()


def view(db: Session, sid) -> dict:
    r = db.execute(text(f"SELECT {PUBLIC} FROM pve_admin_sessions WHERE id = :i"), {"i": str(sid)}).first()
    d = {k: (v.isoformat() if isinstance(v, datetime) else str(v) if isinstance(v, uuid.UUID) else v) for k, v in r._mapping.items()}
    d["webauthn_only"] = r.state == "need_tfa" and set(r.tfa_methods or []) <= {"webauthn"}
    d["credential"] = "Proxmox session ticket in the vault (never shown, never the password); destroyed after use, on cancel or after 30 minutes"
    return d


def live(db: Session, sid, user_id=None, *, ready: bool = False):
    r = row(db, sid)
    if r is None or (user_id is not None and str(r.created_by) != str(user_id)):
        raise SessionError(404, "Proxmox session not found")
    if r.state in FINISHED or r.expires_at <= now():
        raise SessionError(409, "this Proxmox session is finished or expired: sign in to Proxmox again")
    if ready and r.state != "ready":
        raise SessionError(409, "the Proxmox login is not complete (second factor pending)")
    return r


def _secret(rt: Runtime, r, actor: str) -> dict:
    try:
        return json.loads(cred_service.get_secret(rt, r.credential_id, use="pve.admin_session", actor=actor))
    except cred_service.CredentialUnavailable:
        raise SessionError(409, "the Proxmox session is no longer available: sign in to Proxmox again") from None


def tfa(db: Session, rt: Runtime, user, ip, sid, method: str, code: str) -> dict:
    r = live(db, sid, user.id)
    if r.state != "need_tfa":
        raise SessionError(409, "no second factor is pending for this session")
    if method not in (r.tfa_methods or []) or method == "webauthn":
        raise SessionError(422, "this second-factor method is not available here (WebAuthn/passkeys cannot be completed outside the Proxmox web UI)")
    db.execute(text("UPDATE pve_admin_sessions SET tfa_attempts = tfa_attempts + 1 WHERE id = :i"), {"i": str(sid)})
    db.commit()
    s = _secret(rt, r, f"user:{user.username}")
    try:
        c = ProxmoxAdminClient(r.base_url, username=s["username"], tfa_challenge=s["tfa_challenge"], **_kw(rt, r.ca_pem, r.fingerprint_sha256))
    except (ProxmoxError, ValueError) as e:
        raise SessionError(502, str(e)[:200]) from None
    try:
        c.complete_tfa(method, code)
        ticket = c.export_ticket()
    except ProviderError as e:
        c.discard()
        attempts = r.tfa_attempts + 1
        audit.append(db, "pve.session.tfa_failed", actor_id=user.id, actor_name=user.username, ip=ip, resource="pve_session", resource_id=str(sid),
                     details={"method": method, "attempt": attempts})
        if attempts >= MAX_TFA_ATTEMPTS:
            wipe(db, sid, "failed", user.username, f"{MAX_TFA_ATTEMPTS} wrong second-factor codes")
            db.commit()
            raise SessionError(401, "too many wrong codes: sign in to Proxmox again") from None
        db.commit()
        raise SessionError(401, e.message) from None
    except ProxmoxError as e:
        c.discard()
        raise SessionError(502, str(e)[:200]) from None
    c.discard()
    old = r.credential_id
    cid = _store(db, rt, sid, r.customer_id, ticket, ticket["admin_ticket_user"], urlparse(r.base_url).hostname or r.base_url, r.expires_at, user, ip,
                 "Proxmox login completed with a second factor")
    cred_service.revoke(db, old, actor=user.username, reason="second-factor challenge used")
    db.execute(text("UPDATE pve_admin_sessions SET credential_id = :c, state = 'ready' WHERE id = :i"), {"c": cid, "i": str(sid)})
    audit.append(db, "pve.session.tfa_completed", actor_id=user.id, actor_name=user.username, ip=ip, resource="pve_session", resource_id=str(sid),
                 details={"method": method})
    return view(db, sid)


def client(db: Session, rt: Runtime, sid, user, known: list[str] | None = None) -> ProxmoxAdminClient:
    """A signed-in client for synchronous READ-ONLY use by the wizard (mutations stay job-only in ProxmoxAdminClient)."""
    r = live(db, sid, user.id, ready=True)
    s = _secret(rt, r, f"user:{user.username}")
    if known is not None:
        known += [s["admin_ticket"], s["admin_csrf"]]
    return ProxmoxAdminClient(r.base_url, username=s["admin_ticket_user"], ticket=s["admin_ticket"], csrf=s["admin_csrf"],
                              **_kw(rt, r.ca_pem, r.fingerprint_sha256))


def for_plan(db: Session, rt: Runtime, user, sid, base_url: str, ca_pem: str | None, fp: str | None) -> tuple[dict, datetime]:
    """The ticket for a plan's temporary credential. Refused unless the session belongs to the requester and targets EXACTLY this cluster with
    EXACTLY this trust anchor (a ticket is never sent to any other server)."""
    r = live(db, sid, user.id, ready=True)
    same_ca = (r.ca_pem or "").strip() == (ca_pem or "").strip()
    same_fp = (r.fingerprint_sha256 or "") == (normalize_fingerprint(fp) if fp else "")
    if r.base_url.rstrip("/") != (base_url or "").rstrip("/") or not (same_ca and same_fp):
        raise SessionError(422, "this Proxmox session was opened for a different address or certificate than the plan targets")
    s = _secret(rt, r, f"user:{user.username}")
    return {k: s[k] for k in ("admin_ticket", "admin_csrf", "admin_ticket_user")}, r.expires_at


def wipe(db: Session, sid, state: str, actor: str, reason: str) -> None:
    r = row(db, sid)
    if r is None:
        return
    if r.credential_id is not None:
        c = cred_service.get_row(db, r.credential_id)
        if c is not None and c.purged_at is None:
            cred_service.revoke(db, r.credential_id, actor=actor, reason=reason)
    db.execute(text("UPDATE pve_admin_sessions SET state = :s, finished_at = COALESCE(finished_at, now()) WHERE id = :i AND state NOT IN "
                    "('used','cancelled','expired','failed')"), {"s": state, "i": str(sid)})
    audit.append(db, "pve.session.wiped", actor_name=actor, resource="pve_session", resource_id=str(sid), details={"state": state, "reason": reason})


def cancel(db: Session, user, ip, sid) -> None:
    live(db, sid, user.id)
    wipe(db, sid, "cancelled", user.username, "signed out by the operator")


def sweep(db: Session) -> int:
    n = 0
    for r in db.execute(text("SELECT id FROM pve_admin_sessions WHERE state NOT IN ('used','cancelled','expired','failed') AND expires_at <= now() FOR UPDATE")).all():
        wipe(db, r.id, "expired", "system", "Proxmox session expired (30 minutes)")
        n += 1
    for r in db.execute(text("SELECT c.id FROM credentials c WHERE c.provider = :p AND c.purged_at IS NULL AND c.expires_at IS NOT NULL AND c.expires_at <= now() "
                             "FOR UPDATE OF c"), {"p": PROVIDER}).all():
        cred_service.revoke(db, r.id, actor="system", reason="Proxmox admin session expired")
        n += 1
    return n

