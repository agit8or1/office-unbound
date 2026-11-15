"""Customer approval workflow. The customer has NO ICS account: an MSP operator prepares a request, submits it, and delivers a
single-use signed link out of band (shown once). The link authorises exactly: view the proposal, download the instructions,
record ONE decision, and (after approval) a separate single-use completion link confirms provisioning is done.

Token format  <kind>.<approval-id>.<nonce>.<hmac>   kind a = decision link, c = completion link.
Only sha256(token) is stored; the HMAC (key derived from the audit key file) makes forged/tampered tokens fail before any lookup.
Tokens are never logged or audited. Approver identity (name, email, IP, user agent, time, statement) goes into the audit chain."""
import hashlib
import hmac
import json
import re
import secrets
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from .. import audit
from ..runtime import Runtime
from ..vault import read_key_file
from . import plan_provider

MAX_TTL_HOURS = 24 * 7
DEFAULT_TTL_HOURS = 72
COMPLETION_TTL_DAYS = 30
GATE_OK = ("approved", "provisioned")
_EMAIL = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,}$")
SYSTEM = SimpleNamespace(id=None, username="customer-approval")


class ApprovalError(Exception):
    def __init__(self, status: int, msg: str):
        self.status, self.msg = status, msg


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _hmac_key(rt: Runtime) -> bytes:
    k = getattr(rt, "_approval_hmac_key", None)
    if k is None:
        k = hashlib.sha256(b"ics-customer-approval-link:" + read_key_file(rt.settings.audit_key_file, "audit key")).digest()
        rt._approval_hmac_key = k
    return k


def _sign(rt: Runtime, body: str) -> str:
    return hmac.new(_hmac_key(rt), body.encode(), hashlib.sha256).hexdigest()[:40]


def _mint(rt: Runtime, kind: str, approval_id) -> str:
    body = f"{kind}.{approval_id}.{secrets.token_urlsafe(24)}"
    return f"{body}.{_sign(rt, body)}"


def _hash(t: str) -> str:
    return hashlib.sha256(t.encode()).hexdigest()


def _parse(rt: Runtime, token: str, kind: str) -> UUID:
    """Signature check first (constant time); any malformed/tampered token is indistinguishable from an unknown one."""
    try:
        k, aid, nonce, sig = (token or "").split(".")
        body = f"{k}.{aid}.{nonce}"
        if k != kind or len(token) > 200 or not hmac.compare_digest(sig, _sign(rt, body)):
            raise ValueError
        return UUID(aid)
    except ValueError:
        raise ApprovalError(404, "this link is invalid or has expired") from None


def proposal_hash(proposal: dict) -> str:
    return hashlib.sha256(audit.canon(proposal).encode()).hexdigest()


# ---- operator side ----------------------------------------------------------------------------------------------------

def create_draft(db: Session, rt: Runtime, user, customer_id, title: str, params: dict, plan_id=None, ip=None) -> dict:
    c = db.execute(text("SELECT * FROM customers WHERE id = :i"), {"i": str(customer_id)}).first()
    if c is None or c.disabled_at is not None:
        raise ApprovalError(404, "customer not found")
    cust = {"id": str(c.id), "name": c.name}
    pp = plan_provider.build(db, rt, cust, params)
    proposal = audit.sanitize({"customer": c.name, "title": title, "summary": pp.summary, "permissions": pp.permissions,
                               "instructions_md": pp.instructions_md, "stub_plan": pp.stub, "provider": params.get("provider", "proxmox")})
    if pp.package_files:
        proposal["package_files"] = {str(k)[:100]: str(v) for k, v in list(pp.package_files.items())[:20]}   # part of the hashed proposal
    aid = db.execute(text("INSERT INTO customer_approvals (customer_id, plan_id, title, proposal, proposal_hash, created_by) "
                          "VALUES (:c, :p, :t, CAST(:pr AS jsonb), :h, :u) RETURNING id"),
                     {"c": str(c.id), "p": str(plan_id) if plan_id else None, "t": title[:200], "pr": audit.canon(proposal),
                      "h": proposal_hash(proposal), "u": str(user.id) if user.id else None}).scalar()
    audit.append(db, "customer_approval.created", actor_id=user.id, actor_name=user.username, ip=ip, resource="customer_approval",
                 resource_id=str(aid), details={"customer_id": str(c.id), "title": title[:200], "plan_id": str(plan_id) if plan_id else None,
                                                "proposal_hash": proposal_hash(proposal), "permissions": len(pp.permissions)})
    return {"id": str(aid), "status": "draft", "proposal_hash": proposal_hash(proposal)}


def submit(db: Session, rt: Runtime, user, approval_id, ttl_hours: int = DEFAULT_TTL_HOURS, ip=None) -> dict:
    """Returns the one-time link path. It is not stored in recoverable form: if lost, cancel and resubmit."""
    a = db.execute(text("SELECT * FROM customer_approvals WHERE id = :i FOR UPDATE"), {"i": str(approval_id)}).first()
    if a is None:
        raise ApprovalError(404, "approval not found")
    if a.status not in ("draft", "pending", "changes_requested"):
        raise ApprovalError(409, f"approval is {a.status}")
    if not 1 <= ttl_hours <= MAX_TTL_HOURS:
        raise ApprovalError(422, f"ttl_hours must be 1-{MAX_TTL_HOURS}")
    token = _mint(rt, "a", a.id)
    exp = _now() + timedelta(hours=ttl_hours)
    db.execute(text("UPDATE customer_approvals SET status = 'pending', token_hash = :h, token_expires_at = :e, submitted_at = now(), "
                    "decided_at = NULL WHERE id = :i"), {"h": _hash(token), "e": exp, "i": str(a.id)})
    audit.append(db, "customer_approval.submitted", actor_id=user.id, actor_name=user.username, ip=ip, resource="customer_approval",
                 resource_id=str(a.id), details={"customer_id": str(a.customer_id), "expires_at": exp.isoformat(), "proposal_hash": a.proposal_hash})
    return {"id": str(a.id), "link_path": f"/approve#t={token}", "expires_at": exp.isoformat(),
            "note": "shown once; deliver to the customer out of band"}


def cancel(db: Session, user, approval_id, ip=None) -> None:
    n = db.execute(text("UPDATE customer_approvals SET status = 'cancelled', token_hash = NULL, completion_token_hash = NULL "
                        "WHERE id = :i AND status IN ('draft','pending','changes_requested','approved') RETURNING id"), {"i": str(approval_id)}).first()
    if n is None:
        raise ApprovalError(409, "approval cannot be cancelled")
    audit.append(db, "customer_approval.cancelled", actor_id=user.id, actor_name=user.username, ip=ip, resource="customer_approval",
                 resource_id=str(approval_id))


def gate_ok(db: Session, approval_id) -> bool:
    r = db.execute(text("SELECT status FROM customer_approvals WHERE id = :i"), {"i": str(approval_id)}).first()
    return bool(r and r.status in GATE_OK)


def release_plan(db: Session, rt: Runtime, plan_id) -> str | None:
    """After the customer approved: if ICS-side approvals are already complete, enqueue the job. Returns job id or None."""
    from ..actions import _enqueue
    plan = db.execute(text("SELECT * FROM plans WHERE id = :i FOR UPDATE"), {"i": str(plan_id)}).first()
    if plan is None or plan.status != "pending_approval":
        return None
    from .. import actions
    # same threshold decide_plan uses
    need = actions.needed_approvals(rt, plan)
    n = db.execute(text("SELECT count(*) FROM plan_approvals WHERE plan_id = :p"), {"p": str(plan.id)}).scalar()
    if n < need:
        return None
    last = db.execute(text("SELECT approver_id FROM plan_approvals WHERE plan_id = :p ORDER BY at DESC LIMIT 1"), {"p": str(plan.id)}).scalar()
    db.execute(text("UPDATE plans SET status = 'approved', decided_by = :u, decided_at = now() WHERE id = :i"), {"u": last, "i": str(plan.id)})
    return _enqueue(db, plan.id, plan.action, SYSTEM, None)


# ---- customer side (no account) ----------------------------------------------------------------------------------------------

def _load(db: Session, rt: Runtime, token: str, kind: str, lock: bool = False):
    aid = _parse(rt, token, kind)
    a = db.execute(text("SELECT * FROM customer_approvals WHERE id = :i" + (" FOR UPDATE" if lock else "")), {"i": str(aid)}).first()
    col_h, col_e = ("token_hash", "token_expires_at") if kind == "a" else ("completion_token_hash", "completion_expires_at")
    stored, exp = (getattr(a, col_h), getattr(a, col_e)) if a else (None, None)
    if a is None or not stored or not hmac.compare_digest(stored, _hash(token)):
        raise ApprovalError(404, "this link is invalid or has expired")
    if exp is None or exp <= _now():
        if a.status == "pending":
            db.execute(text("UPDATE customer_approvals SET status = 'expired', token_hash = NULL WHERE id = :i"), {"i": str(a.id)})
            audit.append(db, "customer_approval.expired", actor_name="system", resource="customer_approval", resource_id=str(a.id))
            db.commit()
        raise ApprovalError(404, "this link is invalid or has expired")
    return a


def view(db: Session, rt: Runtime, token: str, kind: str = "a") -> dict:
    a = _load(db, rt, token, kind)
    p = a.proposal
    return {"customer": p.get("customer"), "title": a.title, "summary": p.get("summary"), "permissions": p.get("permissions", []),
            "stub_plan": p.get("stub_plan", False), "package_available": bool(p.get("package_files")), "status": a.status, "proposal_hash": a.proposal_hash,
            "expires_at": (a.token_expires_at if kind == "a" else a.completion_expires_at).isoformat(), "kind": kind}


def instructions(db: Session, rt: Runtime, token: str, kind: str = "a") -> str:
    return _load(db, rt, token, kind).proposal.get("instructions_md", "")


def package(db: Session, rt: Runtime, token: str, kind: str = "a") -> dict:
    """The real generated package (the exact files the customer approves) as {filename: text}."""
    files = _load(db, rt, token, kind).proposal.get("package_files")
    if not files:
        raise ApprovalError(404, "no package is attached to this request")
    return files


def _identity(name: str, email: str) -> tuple[str, str]:
    name, email = (name or "").strip(), (email or "").strip()
    if not 2 <= len(name) <= 100 or re.search(r"[\x00-\x1f]", name):
        raise ApprovalError(422, "name is required (2-100 characters)")
    if not _EMAIL.match(email):
        raise ApprovalError(422, "a valid email address is required")
    return name, email


def decide(db: Session, rt: Runtime, token: str, *, decision: str, name: str, email: str, statement: str, note: str,
           shown_hash: str, ip: str | None, user_agent: str | None) -> dict:
    if decision not in ("approve", "reject", "request_changes"):
        raise ApprovalError(422, "decision must be approve, reject or request_changes")
    a = _load(db, rt, token, "a", lock=True)
    if a.status != "pending":
        raise ApprovalError(409, f"this request is already {a.status}")
    name, email = _identity(name, email)
    statement, note = (statement or "").strip(), (note or "").strip()
    if decision == "approve" and not 10 <= len(statement) <= 1000:
        raise ApprovalError(422, "an approval statement of 10-1000 characters is required")
    if len(note) > 1000:
        raise ApprovalError(422, "note too long")
    if decision == "approve" and not hmac.compare_digest(shown_hash or "", a.proposal_hash):
        raise ApprovalError(409, "the proposal changed since you opened it; reload and review it again")
    status = {"approve": "approved", "reject": "rejected", "request_changes": "changes_requested"}[decision]
    completion = _mint(rt, "c", a.id) if status == "approved" else None
    db.execute(text(
        "UPDATE customer_approvals SET status = :s, token_hash = NULL, decided_at = now(), approver_name = :n, approver_email = :e, "
        "approver_ip = :ip, approver_user_agent = :ua, approver_statement = :st, decision_note = :no, completion_token_hash = :ch, "
        "completion_expires_at = :ce WHERE id = :i"),
        {"s": status, "n": name, "e": email, "ip": ip, "ua": (user_agent or "")[:300], "st": statement or None, "no": note or None,
         "ch": _hash(completion) if completion else None, "ce": _now() + timedelta(days=COMPLETION_TTL_DAYS) if completion else None,
         "i": str(a.id)})
    audit.append(db, f"customer_approval.{status}", actor_name=f"customer:{name}"[:200], ip=ip, resource="customer_approval", resource_id=str(a.id),
                 details={"customer_id": str(a.customer_id), "approver_name": name, "approver_email": email, "approver_ip": ip,
                          "approver_user_agent": (user_agent or "")[:300], "statement": statement, "note": note,
                          "proposal_hash": a.proposal_hash, "decided_at": _now().isoformat()})
    job = None
    if status == "approved" and a.plan_id:
        job = release_plan(db, rt, a.plan_id)
    elif status in ("rejected",) and a.plan_id:
        db.execute(text("UPDATE plans SET status = 'rejected', decided_at = now(), secret_enc = NULL WHERE id = :p AND status = 'pending_approval'"),
                   {"p": str(a.plan_id)})
        from ..provisioning import actions as prov_actions   # discard any temporary provisioning credential of the rejected plan
        prov_actions.scrub_expired_credentials(db)
        audit.append(db, "plan.reject", actor_name=f"customer:{name}"[:200], resource="plan", resource_id=str(a.plan_id),
                     details={"reason": "customer rejected"})
    out = {"status": status, "job_released": bool(job)}
    if completion:
        out["completion_link_path"] = f"/approve#c={completion}"
    return out


def complete(db: Session, rt: Runtime, token: str, *, name: str, email: str, note: str, ip: str | None, user_agent: str | None) -> dict:
    a = _load(db, rt, token, "c", lock=True)
    if a.status != "approved":
        raise ApprovalError(409, f"this request is {a.status}")
    name, email = _identity(name, email)
    db.execute(text("UPDATE customer_approvals SET status = 'provisioned', completion_token_hash = NULL, completed_at = now() WHERE id = :i"),
               {"i": str(a.id)})
    audit.append(db, "customer_approval.provisioned", actor_name=f"customer:{name}"[:200], ip=ip, resource="customer_approval",
                 resource_id=str(a.id), details={"customer_id": str(a.customer_id), "approver_name": name, "approver_email": email,
                                                 "approver_ip": ip, "approver_user_agent": (user_agent or "")[:300],
                                                 "note": (note or "")[:1000]})
    return {"status": "provisioned"}


def expire_due(rt: Runtime) -> int:
    with rt.session() as db:
        rows = db.execute(text("UPDATE customer_approvals SET status = 'expired', token_hash = NULL WHERE status = 'pending' "
                               "AND token_expires_at < now() RETURNING id")).all()
        for r in rows:
            audit.append(db, "customer_approval.expired", actor_name="system", resource="customer_approval", resource_id=str(r.id))
        db.commit()
    return len(rows)
