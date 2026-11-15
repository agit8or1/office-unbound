"""Operator authentication: argon2id + mandatory TOTP, server-side sessions, CSRF, rate limiting, roles."""
import hashlib
import hmac
import re
import secrets
import time
from datetime import datetime, timedelta, timezone
from uuid import UUID

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import Depends, HTTPException, Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from . import audit
from .runtime import Runtime
from .tenancy import scope as tscope

ROLES = ("viewer", "operator", "approver", "admin")
RANK = {r: i for i, r in enumerate(ROLES)}
COOKIE = "ics_session"
ph = PasswordHasher()  # argon2id defaults
_DUMMY_HASH = ph.hash("dummy-password-for-timing")
ISSUER = "Office Unbound ICS"


class User:
    def __init__(self, row, csrf: str | None = None):
        self.id: UUID = row.id
        self.username: str = row.username
        self.role: str = row.role
        self.created_by = getattr(row, "created_by", None)
        self.role_set_by = getattr(row, "role_set_by", None)
        self.csrf = csrf
        self.customer_ids = None  # None = MSP all-customers scope; set by current_user from operator_customers


def hash_token(t: str) -> str:
    return hashlib.sha256(t.encode()).hexdigest()


_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$")
_TOTP_RE = re.compile(r"^[0-9]{6}$")
MAX_PASSWORD = 1024


def cookie_name(rt: Runtime) -> str:
    # __Host- prefix forces Secure + Path=/ + no Domain; only usable when the cookie is Secure
    return "__Host-ics_session" if rt.settings.cookie_secure else COOKIE


def _check_username(username: str) -> None:
    if not _USERNAME_RE.match(username or ""):
        raise ValueError("username must be 1-64 chars of letters, digits, . _ @ -")


def _new_enrollment(rt: Runtime) -> tuple[str, str, datetime]:
    token = secrets.token_urlsafe(32)
    return token, hash_token(token), datetime.now(timezone.utc) + timedelta(seconds=rt.settings.enrollment_ttl_seconds)


def create_invite(db: Session, rt: Runtime, username: str, role: str, *, created_by=None, actor: str = "cli", commit: bool = True,
                  extra: dict | None = None) -> str:
    """Creates an account in the 'invited' state (no password, no TOTP, cannot log in). Returns the user id.
    Credentials are never chosen or seen by the creator; the enrollment token is issued separately on the host (CLI)."""
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}")
    _check_username(username)
    uid = db.execute(text(
        "INSERT INTO users (username, role, enrolled, created_by, role_set_by, role_set_at) "
        "VALUES (:u, :r, false, :cb, :cb, now()) RETURNING id"),
        {"u": username, "r": role, "cb": str(created_by) if created_by else None}).scalar()
    audit.append(db, "user.invite", actor_id=created_by, actor_name=actor, resource="user", resource_id=str(uid),
                 details={"username": username, "role": role, **(extra or {})})
    if commit:
        db.commit()
    return str(uid)


def issue_enrollment_token(db: Session, rt: Runtime, username: str, *, actor: str = "cli") -> str:
    """Host-side only (CLI). Resets the account to 'invited' (drops password, TOTP and sessions) and returns a one-time token.
    Also the break-glass recovery path: it is never rate limited and clears login throttling."""
    row = db.execute(text("SELECT id FROM users WHERE username = :u FOR UPDATE"), {"u": username}).first()
    if row is None:
        raise ValueError("no such user")
    token, h, exp = _new_enrollment(rt)
    db.execute(text("UPDATE users SET enrolled = false, password_hash = NULL, totp_secret_enc = NULL, last_totp_step = 0, "
                    "enrollment_token_hash = :h, enrollment_expires_at = :e WHERE id = :i"), {"h": h, "e": exp, "i": row.id})
    db.execute(text("DELETE FROM sessions WHERE user_id = :i"), {"i": row.id})
    db.execute(text("DELETE FROM login_attempts WHERE username = :u"), {"u": username})
    audit.append(db, "user.enrollment_issued", actor_name=actor, resource="user", resource_id=str(row.id), details={"username": username})
    db.commit()
    return token


def create_account_cli(db: Session, rt: Runtime, username: str, role: str) -> str:
    """Bootstrap from the host: invite + enrollment token (printed once by the CLI, never returned over the API)."""
    create_invite(db, rt, username, role, created_by=None, actor="cli")
    return issue_enrollment_token(db, rt, username, actor="cli")


def _enrollment_row(db: Session, username: str, token: str):
    row = db.execute(text("SELECT * FROM users WHERE username = :u FOR UPDATE"), {"u": username}).first()
    ok = (row is not None and not row.enrolled and not row.disabled and row.enrollment_token_hash is not None
          and row.enrollment_expires_at > datetime.now(timezone.utc)
          and hmac.compare_digest(row.enrollment_token_hash, hash_token(token or "")))
    return row if ok else None


def _enroll_fail(db: Session, username: str, ip: str | None, reason: str):
    db.rollback()
    db.execute(text("INSERT INTO login_attempts (username, ip, success) VALUES (:u, :i, false)"), {"u": ("enroll:" + username)[:64], "i": ip})
    audit.append(db, "auth.enroll_failed", actor_name=username[:64], ip=ip, details={"reason": reason})
    db.commit()
    raise HTTPException(401, "invalid enrollment")


def enroll_begin(db: Session, rt: Runtime, username: str, token: str, password: str, ip: str | None) -> str:
    """The invited user sets their own password; the server creates their TOTP secret. Returns the provisioning URI."""
    if throttle_remaining(db, rt, "enroll:" + username, ip) > 0:
        raise HTTPException(429, "too many attempts")
    row = _enrollment_row(db, username, token)
    if row is None:
        _enroll_fail(db, username, ip, "bad_token")
    if not (12 <= len(password) <= MAX_PASSWORD):
        raise HTTPException(422, "password must be 12-1024 characters")
    secret = pyotp.random_base32()
    db.execute(text("UPDATE users SET password_hash = :p, totp_secret_enc = :t WHERE id = :i"),
               {"p": ph.hash(password), "t": rt.vault.encrypt(secret.encode(), f"user-totp:{row.username}"), "i": row.id})
    audit.append(db, "user.enroll_started", actor_id=row.id, actor_name=row.username, ip=ip)
    db.commit()
    return pyotp.TOTP(secret).provisioning_uri(name=row.username, issuer_name=ISSUER)


def _consume_totp(db: Session, row, secret: str, code: str) -> bool:
    if not _TOTP_RE.match(code or ""):
        return False
    step = int(time.time() // 30)
    totp = pyotp.TOTP(secret)
    for s in (step - 1, step, step + 1):  # one step of clock skew
        if hmac.compare_digest(totp.at(s * 30), code):
            # atomic: a concurrent login with the same code updates 0 rows (M1)
            res = db.execute(text("UPDATE users SET last_totp_step = :s WHERE id = :id AND last_totp_step < :s"), {"s": s, "id": row.id})
            return res.rowcount == 1
    return False


def enroll_confirm(db: Session, rt: Runtime, username: str, token: str, totp_code: str, ip: str | None) -> None:
    if throttle_remaining(db, rt, "enroll:" + username, ip) > 0:
        raise HTTPException(429, "too many attempts")
    row = _enrollment_row(db, username, token)
    if row is None or row.password_hash is None or row.totp_secret_enc is None:
        _enroll_fail(db, username, ip, "bad_token_or_not_started")
    secret = rt.vault.decrypt(row.totp_secret_enc, f"user-totp:{row.username}").decode()
    if not _consume_totp(db, row, secret, totp_code):
        _enroll_fail(db, username, ip, "bad_totp")
    db.execute(text("UPDATE users SET enrolled = true, enrollment_token_hash = NULL, enrollment_expires_at = NULL WHERE id = :i"), {"i": row.id})
    audit.append(db, "user.enrolled", actor_id=row.id, actor_name=row.username, ip=ip, details={"role": row.role})
    db.commit()


def throttle_remaining(db: Session, rt: Runtime, username: str, ip: str | None) -> float:
    """Seconds until another attempt is allowed for this (username, ip); 0 = allowed. Exponential backoff with a cap.
    Only real failures count (429 responses are not recorded), so an attacker cannot extend a lock by hammering it,
    and failures from other source IPs do not lock out the legitimate user (M3)."""
    s = rt.settings
    now = datetime.now(timezone.utc)
    since = now - timedelta(seconds=s.login_window_seconds)
    last_ok = db.execute(text("SELECT max(at) FROM login_attempts WHERE success AND username = :u AND ip IS NOT DISTINCT FROM :i"),
                         {"u": username, "i": ip}).scalar()
    if last_ok and last_ok > since:
        since = last_ok
    n, last = db.execute(text("SELECT count(*), max(at) FROM login_attempts WHERE NOT success AND at > :s AND username = :u "
                              "AND ip IS NOT DISTINCT FROM :i"), {"s": since, "u": username, "i": ip}).one()
    remaining = 0.0
    if n >= s.login_max_failures:
        delay = min(s.login_backoff_base_seconds * 2 ** min(n - s.login_max_failures, 20), s.login_backoff_cap_seconds)
        remaining = (last + timedelta(seconds=delay) - now).total_seconds()
    if ip is not None:
        n2, last2 = db.execute(text("SELECT count(*), max(at) FROM login_attempts WHERE NOT success AND at > :s AND ip = :i"),
                               {"s": since, "i": ip}).one()
        if n2 >= s.login_ip_max_failures:
            delay = min(s.login_backoff_base_seconds * 2 ** min(n2 - s.login_ip_max_failures, 20), s.login_backoff_cap_seconds)
            remaining = max(remaining, (last2 + timedelta(seconds=delay) - now).total_seconds())
    return max(remaining, 0.0)


def login(db: Session, rt: Runtime, username: str, password: str, totp_code: str, ip: str | None) -> tuple[str, str, User]:
    """Returns (session_token, csrf_token, user). Raises HTTPException 401/429; failures are audited+recorded."""
    def fail(reason: str):
        db.execute(text("INSERT INTO login_attempts (username, ip, success) VALUES (:u, :i, false)"), {"u": username[:64], "i": ip})
        audit.append(db, "auth.login_failed", actor_name=username[:64], ip=ip, details={"reason": reason})
        db.commit()
        raise HTTPException(401, "invalid credentials")

    wait = throttle_remaining(db, rt, username[:64], ip)
    if wait > 0:  # not recorded as a failure and not audited (an attacker must not be able to grow the audit log or extend the lock)
        raise HTTPException(429, "too many attempts", headers={"Retry-After": str(int(wait) + 1)})
    row = db.execute(text("SELECT * FROM users WHERE username = :u"), {"u": username}).first()
    if row is None or row.disabled or not row.enrolled or row.password_hash is None:
        try:
            ph.verify(_DUMMY_HASH, password[:MAX_PASSWORD])
        except (VerifyMismatchError, InvalidHashError):
            pass
        fail("unknown_or_disabled")
    try:
        ph.verify(row.password_hash, password[:MAX_PASSWORD])
    except (VerifyMismatchError, InvalidHashError):
        fail("bad_password")
    secret = rt.vault.decrypt(row.totp_secret_enc, f"user-totp:{row.username}").decode()
    if not _consume_totp(db, row, secret, totp_code):
        db.rollback()
        fail("bad_totp")
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    db.execute(text("INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at) VALUES (:h, :u, :c, :e)"),
               {"h": hash_token(token), "u": row.id, "c": csrf, "e": now + timedelta(seconds=rt.settings.session_absolute_seconds)})
    db.execute(text("DELETE FROM sessions WHERE user_id = :u AND id NOT IN "
                    "(SELECT id FROM sessions WHERE user_id = :u ORDER BY created_at DESC LIMIT :n)"),
               {"u": row.id, "n": rt.settings.max_sessions_per_user})
    db.execute(text("INSERT INTO login_attempts (username, ip, success) VALUES (:u, :i, true)"), {"u": username, "i": ip})
    audit.append(db, "auth.login", actor_id=row.id, actor_name=row.username, ip=ip)
    db.commit()
    return token, csrf, User(row, csrf)


def logout_all(db: Session, user: User, ip: str | None) -> int:
    n = db.execute(text("DELETE FROM sessions WHERE user_id = :u"), {"u": user.id}).rowcount
    audit.append(db, "auth.logout_all", actor_id=user.id, actor_name=user.username, ip=ip, details={"sessions": n})
    db.commit()
    return n


def logout(db: Session, token: str, user: User, ip: str | None) -> None:
    db.execute(text("DELETE FROM sessions WHERE token_hash = :h"), {"h": hash_token(token)})
    audit.append(db, "auth.logout", actor_id=user.id, actor_name=user.username, ip=ip)
    db.commit()


# ---- FastAPI dependencies -------------------------------------------------

def get_db(request: Request):
    rt: Runtime = request.app.state.rt
    db = rt.session()
    try:
        yield db
    finally:
        db.close()


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    rt: Runtime = request.app.state.rt
    token = request.cookies.get(cookie_name(rt))
    if not token:
        raise HTTPException(401, "not authenticated")
    now = datetime.now(timezone.utc)
    row = db.execute(text(
        "SELECT s.id AS sid, s.csrf_token, s.last_seen, s.expires_at, u.* FROM sessions s JOIN users u ON u.id = s.user_id "
        "WHERE s.token_hash = :h"), {"h": hash_token(token)}).first()
    if row is None or row.disabled or not row.enrolled or row.expires_at < now or (now - row.last_seen).total_seconds() > rt.settings.session_idle_seconds:
        raise HTTPException(401, "not authenticated")
    if (now - row.last_seen).total_seconds() > 60:
        db.execute(text("UPDATE sessions SET last_seen = :n WHERE id = :i"), {"n": now, "i": row.sid})
        db.commit()
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        sent = request.headers.get("x-csrf-token", "")
        if not hmac.compare_digest(sent.encode("utf-8", "replace"), row.csrf_token.encode()):
            audit.append(db, "auth.csrf_rejected", actor_id=row.id, actor_name=row.username, ip=client_ip(request),
                         details={"path": request.scope["path"]})
            db.commit()
            raise HTTPException(403, "CSRF token missing or invalid")
    user = User(row, row.csrf_token)
    tscope.attach(db, user, row)
    return user


def require(min_role: str):
    def dep(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)) -> User:
        if RANK[user.role] < RANK[min_role]:
            audit.append(db, "auth.forbidden", actor_id=user.id, actor_name=user.username, ip=client_ip(request),
                         details={"path": request.scope["path"], "needs": min_role})
            db.commit()
            raise HTTPException(403, f"requires role {min_role}")
        return user
    return dep
