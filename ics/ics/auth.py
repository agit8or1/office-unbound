"""Operator authentication: argon2id + mandatory TOTP, server-side sessions, CSRF, rate limiting, roles."""
import hashlib
import hmac
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
        self.csrf = csrf


def hash_token(t: str) -> str:
    return hashlib.sha256(t.encode()).hexdigest()


def create_user(db: Session, rt: Runtime, username: str, password: str, role: str, *, actor: str = "cli") -> str:
    """Creates an account with a fresh TOTP secret; returns the provisioning URI (shown once)."""
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}")
    if len(password) < 12:
        raise ValueError("password must be at least 12 characters")
    if not username or len(username) > 64:
        raise ValueError("bad username")
    secret = pyotp.random_base32()
    uid = db.execute(text(
        "INSERT INTO users (username, password_hash, totp_secret_enc, role) VALUES (:u, :p, :t, :r) RETURNING id"),
        {"u": username, "p": ph.hash(password), "t": rt.vault.encrypt(secret.encode(), f"user-totp:{username}"), "r": role}).scalar()
    audit.append(db, "user.create", actor_name=actor, resource="user", resource_id=str(uid), details={"username": username, "role": role})
    db.commit()
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=ISSUER)


def _rate_limited(db: Session, rt: Runtime, username: str, ip: str | None) -> bool:
    s = rt.settings
    since = datetime.now(timezone.utc) - timedelta(seconds=s.login_window_seconds)
    q = "SELECT count(*) FROM login_attempts WHERE success = false AND at > :since AND {}"
    n_user = db.execute(text(q.format("username = :v")), {"since": since, "v": username}).scalar()
    n_ip = db.execute(text(q.format("ip = :v")), {"since": since, "v": ip or ""}).scalar() if ip else 0
    return n_user >= s.login_max_failures or n_ip >= s.login_max_failures * 4


def login(db: Session, rt: Runtime, username: str, password: str, totp_code: str, ip: str | None) -> tuple[str, str, User]:
    """Returns (session_token, csrf_token, user). Raises HTTPException 401/429; failures are audited+recorded."""
    def fail(reason: str, status: int = 401):
        db.execute(text("INSERT INTO login_attempts (username, ip, success) VALUES (:u, :i, false)"), {"u": username[:64], "i": ip})
        audit.append(db, "auth.login_failed", actor_name=username[:64], ip=ip, details={"reason": reason})
        db.commit()
        raise HTTPException(status, "invalid credentials" if status == 401 else "too many attempts")

    if _rate_limited(db, rt, username, ip):
        fail("rate_limited", 429)
    row = db.execute(text("SELECT * FROM users WHERE username = :u"), {"u": username}).first()
    if row is None or row.disabled:
        try:
            ph.verify(_DUMMY_HASH, password)
        except VerifyMismatchError:
            pass
        fail("unknown_or_disabled")
    try:
        ph.verify(row.password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        fail("bad_password")
    secret = rt.vault.decrypt(row.totp_secret_enc, f"user-totp:{row.username}").decode()
    step = int(time.time() // 30)
    totp = pyotp.TOTP(secret)
    ok = False
    for s in (step - 1, step, step + 1):  # one step of clock skew
        if hmac.compare_digest(totp.at(s * 30), totp_code or "") and s > row.last_totp_step:
            db.execute(text("UPDATE users SET last_totp_step = :s WHERE id = :id"), {"s": s, "id": row.id})
            ok = True
            break
    if not ok:
        fail("bad_totp")
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    db.execute(text("INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at) VALUES (:h, :u, :c, :e)"),
               {"h": hash_token(token), "u": row.id, "c": csrf, "e": now + timedelta(seconds=rt.settings.session_absolute_seconds)})
    db.execute(text("INSERT INTO login_attempts (username, ip, success) VALUES (:u, :i, true)"), {"u": username, "i": ip})
    audit.append(db, "auth.login", actor_id=row.id, actor_name=row.username, ip=ip)
    db.commit()
    return token, csrf, User(row, csrf)


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
    token = request.cookies.get(COOKIE)
    if not token:
        raise HTTPException(401, "not authenticated")
    now = datetime.now(timezone.utc)
    row = db.execute(text(
        "SELECT s.id AS sid, s.csrf_token, s.last_seen, s.expires_at, u.* FROM sessions s JOIN users u ON u.id = s.user_id "
        "WHERE s.token_hash = :h"), {"h": hash_token(token)}).first()
    if row is None or row.disabled or row.expires_at < now or (now - row.last_seen).total_seconds() > rt.settings.session_idle_seconds:
        raise HTTPException(401, "not authenticated")
    if (now - row.last_seen).total_seconds() > 60:
        db.execute(text("UPDATE sessions SET last_seen = :n WHERE id = :i"), {"n": now, "i": row.sid})
        db.commit()
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        sent = request.headers.get("x-csrf-token", "")
        if not hmac.compare_digest(sent, row.csrf_token):
            audit.append(db, "auth.csrf_rejected", actor_id=row.id, actor_name=row.username, ip=client_ip(request),
                         details={"path": request.url.path})
            db.commit()
            raise HTTPException(403, "CSRF token missing or invalid")
    return User(row, row.csrf_token)


def require(min_role: str):
    def dep(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)) -> User:
        if RANK[user.role] < RANK[min_role]:
            audit.append(db, "auth.forbidden", actor_id=user.id, actor_name=user.username, ip=client_ip(request),
                         details={"path": request.url.path, "needs": min_role})
            db.commit()
            raise HTTPException(403, f"requires role {min_role}")
        return user
    return dep
