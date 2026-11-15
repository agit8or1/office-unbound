"""Operator user directory, invitations and the effective access policy (read-only API).

Every mutation of accounts stays a typed plan action (user.invite / revoke_invite / disable / enable / revoke_sessions /
set_role -> POST /plans, see actions.py); nothing here writes. Directory reads are viewer+; the last sign-in address and
live session details are admin only. Enrollment tokens are never exposed over the API (host CLI only).
"""
from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from . import auth
from .auth import RANK, User, get_db, require
from .runtime import Runtime

PRIVILEGED = ("approver", "admin")

ROLE_INFO = [
    {"role": "viewer", "summary": "Read-only access to the console, inventory, plans, jobs and the user directory."},
    {"role": "operator", "summary": "Everything a viewer can do, plus requesting operational plans (other people approve them)."},
    {"role": "approver", "summary": "Everything an operator can do, plus approving or rejecting plans and reading the audit log. Privileged."},
    {"role": "admin", "summary": "Everything an approver can do, plus user management plans and seeing sign-in addresses. Privileged."},
]
# capability -> minimum role (the matrix is derived from this; keep in step with the require() guards in main.py / actions.py)
CAPABILITIES = [
    ("Browse infrastructure, plans, jobs, checks and incidents", "viewer"),
    ("View the user directory, invitations and access policies", "viewer"),
    ("Request operational plans (low, normal and high risk)", "operator"),
    ("Preview deployment blueprints", "operator"),
    ("Approve or reject plans (never your own, never a requester who created or elevated you)", "approver"),
    ("Read the audit log and verify the audit chain", "approver"),
    ("Request user-management plans (invite, disable, enable, revoke sessions, role change)", "admin"),
    ("Invite viewers and operators directly", "admin"),
    ("See last sign-in address and live session details", "admin"),
]


def _iso(v):
    return v.isoformat() if isinstance(v, datetime) else v


def _status(r, locked: bool) -> str:
    if not r.enrolled:
        return "revoked" if r.disabled else "invited"
    if r.disabled:
        return "disabled"
    return "locked" if locked else "active"


def _locked_set(db: Session, rt: Runtime, usernames: list[str]) -> set[str]:
    """Usernames currently throttled from some source address (same rule as login)."""
    s = rt.settings
    since = datetime.now(timezone.utc) - timedelta(seconds=s.login_window_seconds)
    rows = db.execute(text("SELECT DISTINCT username, ip FROM login_attempts WHERE NOT success AND at > :s AND username = ANY(:u)"),
                      {"s": since, "u": usernames}).all()
    out = set()
    for r in rows:
        if r.username not in out and auth.throttle_remaining(db, rt, r.username, r.ip) > 0:
            out.add(r.username)
    return out


_BASE = (
    "SELECT u.id, u.username, u.role, u.enrolled, u.disabled, u.created_at, u.role_set_at, u.enrollment_expires_at, "
    "u.enrollment_token_hash IS NOT NULL AS has_token, (u.totp_secret_enc IS NOT NULL AND u.enrolled) AS mfa_enrolled, "
    "cu.username AS created_by, ru.username AS role_set_by, "
    "(SELECT max(a.at) FROM audit_events a WHERE a.action = 'auth.login' AND a.actor_id = u.id) AS last_login_at, "
    "(SELECT a.ip FROM audit_events a WHERE a.action = 'auth.login' AND a.actor_id = u.id ORDER BY a.seq DESC LIMIT 1) AS last_login_ip, "
    "(SELECT count(*) FROM sessions s WHERE s.user_id = u.id AND s.expires_at > now() "
    " AND s.last_seen > now() - make_interval(secs => :idle)) AS active_sessions, "
    "(SELECT count(*) FROM plans p WHERE p.status = 'pending_approval' AND p.action LIKE 'user.%' "
    " AND p.params->>'username' = u.username) AS pending_plans "
    "FROM users u LEFT JOIN users cu ON cu.id = u.created_by LEFT JOIN users ru ON ru.id = u.role_set_by "
)


def _shape(r, is_admin: bool, locked: bool) -> dict:
    d = {
        "id": str(r.id), "username": r.username, "role": r.role, "privileged": r.role in PRIVILEGED,
        "status": _status(r, locked), "created_by": r.created_by, "created_at": _iso(r.created_at),
        "role_set_by": r.role_set_by, "role_set_at": _iso(r.role_set_at),
        "last_login_at": _iso(r.last_login_at), "mfa_enrolled": bool(r.mfa_enrolled),
        "active_sessions": int(r.active_sessions), "pending_plans": int(r.pending_plans),
    }
    if is_admin:
        d["last_login_ip"] = r.last_login_ip
    return d


def register(app: FastAPI, rt: Runtime, API: str) -> None:
    def idle() -> int:
        return rt.settings.session_idle_seconds

    @app.get(f"{API}/users")
    def list_users(status: str | None = None, role: str | None = None, q: str | None = None,
                   user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        """Directory. status: active|disabled|invited|locked|revoked. last_login_ip is admin-only."""
        if role is not None and role not in auth.ROLES:
            raise HTTPException(422, "unknown role")
        rows = db.execute(text(_BASE + "WHERE (CAST(:r AS text) IS NULL OR u.role = :r) AND "
                                       "(CAST(:q AS text) IS NULL OR u.username ILIKE '%' || :q || '%') ORDER BY u.username"),
                          {"r": role, "q": (q or "")[:64] or None, "idle": idle()}).all()
        locked = _locked_set(db, rt, [r.username for r in rows])
        is_admin = RANK[user.role] >= RANK["admin"]
        out = [_shape(r, is_admin, r.username in locked) for r in rows]
        if status:
            out = [u for u in out if u["status"] == status]
        return out

    @app.get(f"{API}/users/{{user_id}}")
    def get_user(user_id: UUID, user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        r = db.execute(text(_BASE + "WHERE u.id = :i"), {"i": str(user_id), "idle": idle()}).first()
        if r is None:
            raise HTTPException(404, "user not found")
        is_admin = RANK[user.role] >= RANK["admin"]
        d = _shape(r, is_admin, r.username in _locked_set(db, rt, [r.username]))
        d["enrollment_expires_at"] = _iso(r.enrollment_expires_at) if r.enrolled is False else None
        ev = db.execute(text(
            "SELECT at, action, ip, details FROM audit_events WHERE (actor_id = :i OR (resource = 'user' AND resource_id = :s)) "
            "AND (action LIKE 'auth.%' OR action LIKE 'user.%') ORDER BY seq DESC LIMIT 25"), {"i": str(user_id), "s": str(user_id)}).all()
        d["recent_events"] = [{"at": _iso(e.at), "action": e.action, **({"ip": e.ip} if is_admin else {}),
                               "reason": (e.details or {}).get("reason") if e.action.startswith("auth.") else None} for e in ev]
        hist = db.execute(text(
            "SELECT at, action, details FROM audit_events WHERE resource = 'user' AND resource_id = :s "
            "AND action IN ('user.invite', 'user.role_set') ORDER BY seq"), {"s": str(user_id)}).all()
        ids = {x.details.get("requested_by") for x in hist if x.details and x.details.get("requested_by")}
        names = {str(i.id): i.username for i in db.execute(text("SELECT id, username FROM users WHERE id = ANY(CAST(:i AS uuid[]))"),
                                                           {"i": list(ids)}).all()} if ids else {}
        d["role_history"] = [{
            "at": _iso(h.at), "role": h.details.get("role"), "previous_role": h.details.get("previous_role"),
            "kind": "invited" if h.action == "user.invite" else "role_change",
            "by": names.get(h.details.get("requested_by")) or (d["created_by"] if h.action == "user.invite" else None),
            "plan_id": h.details.get("plan_id"), "justification": h.details.get("justification"),
        } for h in hist]
        if is_admin:
            ss = db.execute(text("SELECT created_at, last_seen, expires_at FROM sessions WHERE user_id = :i AND expires_at > now() "
                                 "ORDER BY last_seen DESC"), {"i": str(user_id)}).all()
            d["sessions"] = [{"created_at": _iso(s.created_at), "last_seen": _iso(s.last_seen), "expires_at": _iso(s.expires_at)} for s in ss]
        pl = db.execute(text("SELECT id, action, risk, created_at FROM plans WHERE status = 'pending_approval' AND action LIKE 'user.%' "
                             "AND params->>'username' = :u ORDER BY created_at DESC"), {"u": r.username}).all()
        d["pending_plans_detail"] = [{"id": str(p.id), "action": p.action, "risk": p.risk, "created_at": _iso(p.created_at)} for p in pl]
        return d

    @app.get(f"{API}/invitations")
    def invitations(status: str | None = None, user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        """Accounts that never completed enrollment. status: pending|expired|revoked. Tokens are never returned."""
        if status not in (None, "pending", "expired", "revoked"):
            raise HTTPException(422, "status must be pending, expired or revoked")
        rows = db.execute(text(
            "SELECT u.id, u.username, u.role, u.disabled, u.created_at, u.enrollment_expires_at, u.enrollment_token_hash IS NOT NULL AS has_token, "
            "cu.username AS invited_by FROM users u LEFT JOIN users cu ON cu.id = u.created_by WHERE NOT u.enrolled ORDER BY u.created_at DESC")).all()
        now = datetime.now(timezone.utc)
        out = []
        for r in rows:
            if r.disabled:
                st, tok = "revoked", "none"
            elif r.has_token and r.enrollment_expires_at and r.enrollment_expires_at > now:
                st, tok = "pending", "issued"
            elif r.has_token:
                st, tok = "expired", "expired"
            else:
                st, tok = "pending", "not_issued"  # waiting for a host operator to issue the one-time token
            if status and st != status:
                continue
            out.append({"id": str(r.id), "username": r.username, "role": r.role, "privileged": r.role in PRIVILEGED, "status": st,
                        "token": tok, "invited_by": r.invited_by, "invited_at": _iso(r.created_at),
                        "token_expires_at": _iso(r.enrollment_expires_at) if r.has_token else None})
        return out

    @app.get(f"{API}/access-policy")
    def access_policy(user: User = Depends(require("viewer"))):
        """The effective policy, read from the running settings (read-only; changing it is a deployment/host decision)."""
        s = rt.settings
        n = s.required_approvals_high
        return {
            "approvals": [
                {"risk": "low", "required": 0, "text": "Policy auto-approval: runs immediately, recorded like an approval."},
                {"risk": "normal", "required": 1, "text": "One approver who is not the requester."},
                {"risk": "high", "required": n, "text": f"{n} distinct approvers, none of them the requester, and none created or elevated by the requester."},
            ],
            "sessions": {"absolute_seconds": s.session_absolute_seconds, "idle_seconds": s.session_idle_seconds, "max_per_user": s.max_sessions_per_user},
            "lockout": {"max_failures": s.login_max_failures, "window_seconds": s.login_window_seconds,
                        "backoff_base_seconds": s.login_backoff_base_seconds, "backoff_cap_seconds": s.login_backoff_cap_seconds,
                        "per_ip_max_failures": s.login_ip_max_failures},
            "mfa": {"mandatory": True, "method": "TOTP (RFC 6238), one use per time step"},
            "enrollment": {"token_ttl_seconds": s.enrollment_ttl_seconds, "token_channel": "host CLI only (never returned by the API)",
                           "password_min_length": 12},
            "plan_expiry_seconds": s.plan_expiry_seconds,
            "rules": [
                {"id": "invites-no-credentials", "title": "Invitations carry no credentials",
                 "text": "The inviter never sees or chooses a password or authenticator secret. The invited person sets their own with a one-time token handed over out of band."},
                {"id": "privileged-high-risk", "title": "Privileged access is high risk",
                 "text": "Creating or elevating an approver or admin needs the full high-risk approval, a written justification, and is always recorded with who requested it."},
                {"id": "provenance", "title": "Provenance rule",
                 "text": "An approver created or elevated by someone cannot approve that person's plans, so one admin cannot mint their own approvers."},
                {"id": "self", "title": "No self-service",
                 "text": "Nobody can approve their own plan or a plan that changes, disables or revokes their own account."},
                {"id": "last-admin", "title": "Last admin protected",
                 "text": "The last active admin cannot be disabled or demoted."},
            ],
            "roles": ROLE_INFO,
            "capabilities": [{"capability": c, "min_role": m, "roles": {r: RANK[r] >= RANK[m] for r in auth.ROLES}} for c, m in CAPABILITIES],
        }
