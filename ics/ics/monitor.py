"""Monitoring engine: scheduler, check state machine with flap damping, incidents, notification outbox, remediation policy.

All deterministic; no LLM anywhere. Called from the worker loop (`tick`), so everything is serialised with job execution.
State machine per check: unknown -> ok | warning | critical. A non-ok state needs `fail_threshold` consecutive identical bad
results (flap damping); returning to ok needs `recover_threshold` consecutive ok results (first result from unknown is ok at once).
"""
import hashlib
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import text
from sqlalchemy.orm import Session

from . import alerts, audit, checks
from .runtime import Runtime
from .vault import VaultError

log = logging.getLogger("ics.monitor")

RUNBOOKS = ("service.restart", "service.status", "disk.usage")
HIGH_RISK_UNITS = {"mariadb"}   # restarting the datastore interrupts every service: needs two approvers, never auto-executed
UNIT_RE = r"^[a-z0-9][a-z0-9_.@-]{0,62}$"
_last_retention = 0.0


def runbook_risk(runbook: str, unit: str | None) -> str:
    return "high" if runbook == "service.restart" and unit in HIGH_RISK_UNITS else "low"


class Remediation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    node_id: UUID
    runbook: Literal["service.restart", "service.status", "disk.usage"]
    unit: str | None = Field(default=None, pattern=UNIT_RE)
    path: str | None = Field(default=None, pattern=r"^/[A-Za-z0-9_./-]{0,200}$")
    mode: Literal["auto", "approval"] = "auto"
    max_attempts: int = Field(default=3, ge=1, le=10)
    window_seconds: int = Field(default=3600, ge=60, le=86400)
    backoff_seconds: int = Field(default=60, ge=0, le=3600)
    verify_timeout_seconds: int = Field(default=30, ge=0, le=90)

    @model_validator(mode="after")
    def _chk(self):
        if self.runbook.startswith("service.") and (not self.unit or self.path):
            raise ValueError("service runbooks need `unit` (and no path)")
        if self.runbook == "disk.usage" and (not self.path or self.unit):
            raise ValueError("disk.usage needs `path` (and no unit)")
        if self.mode == "auto" and self.risk == "high":
            raise ValueError("high-risk runbooks cannot be auto-executed: use mode=approval")
        return self

    @property
    def risk(self) -> str:
        return runbook_risk(self.runbook, self.unit)


def canon_hash(cfg: dict) -> str:
    return hashlib.sha256(audit.canon(cfg).encode()).hexdigest()


def check_aad(check_id, cfg: dict) -> str:
    return f"check-secret:{check_id}:{canon_hash(cfg)}"


def channel_aad(ch_id, cfg: dict) -> str:
    return f"alert-channel:{ch_id}:{canon_hash(cfg)}"


def in_maintenance(db: Session, check_id) -> bool:
    return bool(db.execute(text(
        "SELECT 1 FROM maintenance_windows WHERE starts_at <= now() AND ends_at > now() AND (check_id IS NULL OR check_id = :c) LIMIT 1"),
        {"c": str(check_id)}).first())


# ---- notifications ----------------------------------------------------------------------------

def enqueue_notifications(db: Session, check, incident_id, event: str, detail: str | None = None) -> int:
    chans = db.execute(text("SELECT id FROM alert_channels WHERE enabled")).all()
    supp = in_maintenance(db, check.id)
    for c in chans:
        db.execute(text("INSERT INTO notifications (incident_id, channel_id, event, status, detail) VALUES (:i, :c, :e, :s, :d)"),
                   {"i": str(incident_id) if incident_id else None, "c": str(c.id), "e": event,
                    "s": "suppressed" if supp else "pending", "d": "maintenance window" if supp else detail})
    if incident_id:
        db.execute(text("UPDATE incidents SET last_notified_at = now(), notify_count = notify_count + 1 WHERE id = :i"), {"i": str(incident_id)})
    return len(chans)


def build_message(db: Session, n) -> alerts.Message:
    r = db.execute(text(
        "SELECT i.id AS iid, i.status AS istatus, i.severity, i.title, i.opened_at, i.recovered_at, i.escalated_at, c.name, c.kind, c.state, "
        "c.last_message FROM incidents i JOIN checks c ON c.id = i.check_id WHERE i.id = :i"), {"i": str(n.incident_id)}).first() \
        if n.incident_id else None
    ev = n.event
    if r is None and ev.startswith("credential."):  # credential expiry alerts carry their text in `detail` (no secrets)
        return alerts.Message(ev, f"[OU-ICS] {ev}", (n.detail or ev) + "\n", {"event": ev, "at": int(time.time()), "message": n.detail})
    if r is None:
        return alerts.Message(ev, "[OU-ICS] test notification", "This is a test notification from Office Unbound ICS.",
                              {"event": ev, "test": True, "at": int(time.time())})
    word = {"opened": "opened", "recovered": "RECOVERED", "severity_changed": "severity changed", "escalated": "ESCALATED",
            "reminder": "still open"}.get(ev, ev)
    subj = f"[OU-ICS] {r.severity.upper() if ev != 'recovered' else 'OK'}: {r.name} {word}"
    lines = [f"Check:     {r.name} ({r.kind})", f"Incident:  {r.iid}", f"State:     {r.state}", f"Severity:  {r.severity}",
             f"Opened:    {r.opened_at.isoformat()}"]
    if r.recovered_at:
        lines.append(f"Recovered: {r.recovered_at.isoformat()}  (down {int((r.recovered_at - r.opened_at).total_seconds())} s)")
    if ev == "escalated":
        lines.append("Automatic remediation is exhausted (attempt limit reached while the check is still failing). Manual action needed.")
    if n.detail and ev == "escalated":
        lines.append(f"Detail:    {n.detail}")
    lines.append(f"Last result: {r.last_message}")
    payload = {"event": ev, "at": int(time.time()), "incident": {"id": str(r.iid), "status": r.istatus, "severity": r.severity,
                                                                   "opened_at": r.opened_at.isoformat(),
                                                                   "recovered_at": r.recovered_at.isoformat() if r.recovered_at else None},
               "check": {"name": r.name, "kind": r.kind, "state": r.state}, "message": r.last_message}
    return alerts.Message(ev, subj, "\n".join(lines) + "\n", audit.sanitize(payload))


def dispatch_notifications(rt: Runtime, limit: int = 20) -> int:
    sent = 0
    with rt.session() as db:
        rows = db.execute(text("SELECT * FROM notifications WHERE status = 'pending' AND next_attempt_at <= now() "
                               "ORDER BY id LIMIT :n FOR UPDATE SKIP LOCKED"), {"n": limit}).all()
        for n in rows:
            ch = db.execute(text("SELECT * FROM alert_channels WHERE id = :c"), {"c": str(n.channel_id)}).first()
            if ch is None or not ch.enabled:
                db.execute(text("UPDATE notifications SET status = 'suppressed', detail = 'channel disabled' WHERE id = :i"), {"i": n.id})
                continue
            err = None
            secret = None
            try:
                if ch.secret_enc is not None:
                    secret = rt.vault.decrypt(ch.secret_enc, channel_aad(ch.id, ch.config)).decode()
                alerts.send(ch.kind, ch.config, secret, build_message(db, n), allow_loopback=rt.settings.allow_loopback_endpoints)
            except alerts.ChannelDisabled as e:
                db.execute(text("UPDATE notifications SET status = 'suppressed', detail = :d WHERE id = :i"), {"i": n.id, "d": str(e)[:200]})
                continue
            except (alerts.ChannelError, VaultError) as e:
                err = str(e)
            except Exception as e:  # noqa: BLE001
                err = f"delivery error: {type(e).__name__}"
            if err is None:
                db.execute(text("UPDATE notifications SET status = 'sent', sent_at = now(), attempts = attempts + 1, last_error = NULL WHERE id = :i"),
                           {"i": n.id})
                audit.append(db, "notification.sent", actor_name="monitor", resource="notification", resource_id=str(n.id),
                             details={"event": n.event, "channel": ch.name, "kind": ch.kind})
                sent += 1
            else:
                err = audit.redact(err, [secret] if secret else [])[:300]
                final = n.attempts + 1 >= rt.settings.notify_max_attempts
                db.execute(text("UPDATE notifications SET attempts = attempts + 1, last_error = :e, status = :s, "
                                "next_attempt_at = now() + make_interval(secs => :b) WHERE id = :i"),
                           {"i": n.id, "e": err, "s": "failed" if final else "pending", "b": min(30 * 2 ** n.attempts, 900)})
                audit.append(db, "notification.failed" if final else "notification.retry", actor_name="monitor", resource="notification",
                             resource_id=str(n.id), details={"event": n.event, "channel": ch.name, "error": err})
        db.commit()
    return sent


# ---- state machine ----------------------------------------------------------------------------

def _active_incident(db, check_id):
    return db.execute(text("SELECT * FROM incidents WHERE check_id = :c AND status IN ('open','acked')"), {"c": str(check_id)}).first()


def _transition(db: Session, check, old: str, new: str, msg: str) -> None:
    audit.append(db, "check.state_changed", actor_name="monitor", resource="check", resource_id=str(check.id),
                 details={"name": check.name, "from": old, "to": new, "message": msg})
    inc = _active_incident(db, check.id)
    if new in ("warning", "critical"):
        if inc is None:
            iid = db.execute(text(
                "INSERT INTO incidents (check_id, severity, status, title, message) VALUES (:c, :s, 'open', :t, :m) "
                "ON CONFLICT (check_id) WHERE status IN ('open','acked') DO NOTHING RETURNING id"),
                {"c": str(check.id), "s": new, "t": f"{check.name}: {new}", "m": msg}).scalar()
            if iid:
                audit.append(db, "incident.opened", actor_name="monitor", resource="incident", resource_id=str(iid),
                             details={"check": check.name, "severity": new, "message": msg})
                enqueue_notifications(db, check, iid, "opened")
        elif inc.severity != new:
            db.execute(text("UPDATE incidents SET severity = :s, title = :t WHERE id = :i"),
                       {"s": new, "t": f"{check.name}: {new}", "i": str(inc.id)})
            audit.append(db, "incident.severity_changed", actor_name="monitor", resource="incident", resource_id=str(inc.id),
                         details={"check": check.name, "from": inc.severity, "to": new})
            enqueue_notifications(db, check, inc.id, "severity_changed")
    elif new == "ok" and inc is not None:
        db.execute(text("UPDATE incidents SET status = 'recovered', recovered_at = now() WHERE id = :i"), {"i": str(inc.id)})
        audit.append(db, "incident.recovered", actor_name="monitor", resource="incident", resource_id=str(inc.id),
                     details={"check": check.name})
        enqueue_notifications(db, check, inc.id, "recovered")


def apply_result(db: Session, rt: Runtime, check_id, o: checks.Outcome, *, remediate: bool = True) -> str:
    """Record one result, advance the state machine, open/close incidents, maybe start remediation. Returns the new state."""
    check = db.execute(text("SELECT * FROM checks WHERE id = :i FOR UPDATE"), {"i": str(check_id)}).first()
    if check is None:
        return "unknown"
    msg = audit.redact(str(audit.sanitize(o.message)), [])[:300]
    db.execute(text("INSERT INTO check_results (check_id, status, latency_ms, message, details) VALUES (:c, :s, :l, :m, CAST(:d AS jsonb))"),
               {"c": str(check.id), "s": o.status, "l": o.latency_ms, "m": msg, "d": audit.canon(audit.sanitize(o.details))})
    bad = o.status != "ok"
    cb = (check.consecutive_bad + 1 if check.last_raw == o.status else 1) if bad else 0
    co = 0 if bad else check.consecutive_ok + 1
    new = check.state
    if not bad:
        if check.state == "unknown" or co >= check.recover_threshold:
            new = "ok"
    elif cb >= check.fail_threshold:
        new = o.status
    db.execute(text(
        "UPDATE checks SET state = :s, last_raw = :r, consecutive_bad = :cb, consecutive_ok = :co, last_run_at = now(), last_message = :m, "
        "last_latency_ms = :l, last_state_change_at = CASE WHEN :s <> state THEN now() ELSE last_state_change_at END WHERE id = :i"),
        {"s": new, "r": o.status, "cb": cb, "co": co, "m": msg, "l": o.latency_ms, "i": str(check.id)})
    if new != check.state:
        _transition(db, check, check.state, new, msg)
    db.commit()
    if remediate and new == "critical":
        maybe_remediate(db, rt, check.id)
    return new


# ---- remediation ------------------------------------------------------------------------------

def _escalate(db, check, inc, n: int) -> None:
    if inc is None or inc.escalated_at is not None:
        return
    db.execute(text("UPDATE incidents SET escalated_at = now() WHERE id = :i"), {"i": str(inc.id)})
    audit.append(db, "remediation.escalated", actor_name="monitor", resource="incident", resource_id=str(inc.id),
                 details={"check": check.name, "attempts_in_window": n, "max_attempts": check.remediation["max_attempts"]})
    enqueue_notifications(db, check, inc.id, "escalated", detail=f"{n} remediation attempt(s) within the window, check still {check.state}")
    db.commit()


def maybe_remediate(db: Session, rt: Runtime, check_id) -> str | None:
    """Policy engine. Never loops: at most `max_attempts` attempts per sliding window, exponential backoff between them,
    one attempt in flight at a time, nothing during maintenance; when exhausted it escalates (notification) and stops."""
    from . import actions  # local import: actions imports this module
    check = db.execute(text("SELECT * FROM checks WHERE id = :i"), {"i": str(check_id)}).first()
    pol = check.remediation if check else None
    if not pol or check.state != "critical" or not check.enabled or in_maintenance(db, check.id):
        return None
    pol = Remediation.model_validate(pol)
    rows = db.execute(text("SELECT status, at, finished_at FROM remediation_attempts WHERE check_id = :c "
                           "AND at > now() - make_interval(secs => :w) ORDER BY at DESC"), {"c": str(check.id), "w": pol.window_seconds}).all()
    if any(r.status in ("queued", "pending_approval", "running") for r in rows):
        return None
    inc = _active_incident(db, check.id)
    n = len(rows)
    if n >= pol.max_attempts:
        _escalate(db, check, inc, n)
        return "escalated"
    if n >= 1:
        last = rows[0]
        ready_in = db.execute(text("SELECT EXTRACT(EPOCH FROM (COALESCE(CAST(:f AS timestamptz), CAST(:a AS timestamptz)) + make_interval(secs => :b) - now()))"),
                              {"f": last.finished_at, "a": last.at, "b": pol.backoff_seconds * 2 ** (n - 1)}).scalar()
        if ready_in and ready_in > 0:
            return None
    owner = db.execute(text("SELECT id, username, role FROM users WHERE id = :u AND NOT disabled"), {"u": str(check.created_by)}).first()
    if owner is None:
        return None
    aid = db.execute(text("INSERT INTO remediation_attempts (check_id, incident_id, runbook, attempt_no, status) "
                          "VALUES (:c, :i, :r, :n, 'queued') RETURNING id"),
                     {"c": str(check.id), "i": str(inc.id) if inc else None, "r": pol.runbook, "n": n + 1}).scalar()
    params = {"node_id": str(pol.node_id), "runbook": pol.runbook, "check_id": str(check.id), "attempt_id": aid,
              "verify_timeout_seconds": pol.verify_timeout_seconds, "require_approval": pol.mode == "approval"}
    params.update({"unit": pol.unit} if pol.unit else {"path": pol.path})
    user = SimpleNamespace(id=owner.id, username=f"{owner.username}(remediation)", role=owner.role)
    try:
        res = actions.create_plan(db, rt, user, actions.ActionType.runbook_execute, params, None)
    except Exception as e:  # noqa: BLE001
        db.rollback()
        log.warning("remediation plan failed: %s", type(e).__name__)
        db.execute(text("INSERT INTO remediation_attempts (check_id, incident_id, runbook, attempt_no, status, message, finished_at) "
                        "VALUES (:c, :i, :r, :n, 'failed', :m, now())"),
                   {"c": str(check.id), "i": str(inc.id) if inc else None, "r": pol.runbook, "n": n + 1, "m": f"plan rejected: {type(e).__name__}"})
        db.commit()
        return None
    db.execute(text("UPDATE remediation_attempts SET plan_id = :p, job_id = :j, status = :s WHERE id = :i"),
               {"p": res["plan_id"], "j": res["job_id"], "s": "queued" if res["job_id"] else "pending_approval", "i": aid})
    audit.append(db, "remediation.attempt", actor_name="monitor", resource="check", resource_id=str(check.id),
                 details={"attempt": n + 1, "of": pol.max_attempts, "runbook": pol.runbook, "plan_id": res["plan_id"], "job_id": res["job_id"],
                          "status": res["status"]})
    db.commit()
    return "attempt"


def sync_attempts(db: Session) -> int:
    """Move in-flight attempts forward from their job state; mark lost ones failed."""
    rows = db.execute(text(
        "SELECT a.id, a.status AS astatus, a.at, p.status AS pstatus, j.id AS jid, j.status AS jstatus, j.result, j.error "
        "FROM remediation_attempts a LEFT JOIN plans p ON p.id = a.plan_id LEFT JOIN jobs j ON j.plan_id = a.plan_id "
        "WHERE a.status IN ('queued','pending_approval','running')")).all()
    n = 0
    for r in rows:
        new = msg = verified = None
        fin = False
        if r.pstatus is None:
            if db.execute(text("SELECT now() - CAST(:a AS timestamptz) > interval '10 minutes'"), {"a": r.at}).scalar():
                new, msg, fin, verified = "failed", "attempt lost before a job was created", True, False
        elif r.pstatus == "rejected":
            new, msg, fin, verified = "failed", "plan rejected or expired", True, False
        elif r.jid is None:
            new = "pending_approval"
        elif r.jstatus in ("queued", "running"):
            new = "queued" if r.jstatus == "queued" else "running"
        elif r.jstatus == "failed":
            new, fin, verified = "failed", True, False
            msg = (r.error or {}).get("message", "job failed")[:300]
        else:
            ok = bool((r.result or {}).get("verified"))
            new, fin, verified = ("verified" if ok else "failed"), True, ok
            msg = (r.result or {}).get("verification", "")[:300]
        if new and (new != r.astatus or fin):
            db.execute(text("UPDATE remediation_attempts SET status = :s, job_id = :j, verified = :v, message = COALESCE(:m, message), "
                            "finished_at = CASE WHEN :f THEN now() ELSE finished_at END WHERE id = :i"),
                       {"s": new, "j": str(r.jid) if r.jid else None, "v": verified, "m": msg, "f": fin, "i": r.id})
            n += 1
    db.commit()
    return n


# ---- scheduler --------------------------------------------------------------------------------

def _run_one(rt: Runtime, row, password: str | None) -> checks.Outcome:
    return checks.run_check(row.kind, row.config, password, rt.settings.allow_loopback_endpoints)


def check_password(rt: Runtime, row) -> str | None:
    if row.secret_enc is None:
        return None
    return rt.vault.decrypt(row.secret_enc, check_aad(row.id, row.config)).decode()


def run_and_record(rt: Runtime, check_id, *, remediate: bool = False) -> tuple[str, checks.Outcome]:
    """Run one check now and record the result (used by remediation verification and tests)."""
    with rt.session() as db:
        row = db.execute(text("SELECT * FROM checks WHERE id = :i"), {"i": str(check_id)}).first()
        try:
            pw = check_password(rt, row)
            o = _run_one(rt, row, pw)
        except VaultError:
            o = checks.Outcome("critical", "stored check secret cannot be decrypted", None, {})
        return apply_result(db, rt, check_id, o, remediate=remediate), o


def run_due_checks(rt: Runtime) -> int:
    with rt.session() as db:
        due = db.execute(text("SELECT * FROM checks WHERE enabled AND next_run_at <= now() ORDER BY next_run_at LIMIT 100 FOR UPDATE SKIP LOCKED")).all()
        if not due:
            return 0
        db.execute(text("UPDATE checks SET next_run_at = now() + make_interval(secs => interval_seconds) WHERE id = ANY(CAST(:ids AS uuid[]))"),
                   {"ids": [str(d.id) for d in due]})
        db.commit()
    jobs = []
    for d in due:
        try:
            jobs.append((d, check_password(rt, d), None))
        except VaultError:
            jobs.append((d, None, checks.Outcome("critical", "stored check secret cannot be decrypted", None, {})))
    with ThreadPoolExecutor(max_workers=rt.settings.monitor_parallelism) as ex:
        futs = [(d, o or ex.submit(_run_one, rt, d, pw)) for d, pw, o in jobs]
        results = [(d, f if isinstance(f, checks.Outcome) else f.result()) for d, f in futs]
    for d, o in results:
        with rt.session() as db:
            try:
                apply_result(db, rt, d.id, o)
            except Exception:  # noqa: BLE001
                db.rollback()
                log.exception("applying check result failed")
    return len(results)


def renotify(db: Session, rt: Runtime) -> int:
    s = rt.settings.incident_renotify_seconds
    if s <= 0:
        return 0
    rows = db.execute(text("SELECT i.id, c.id AS cid, c.name FROM incidents i JOIN checks c ON c.id = i.check_id WHERE i.status = 'open' "
                           "AND i.last_notified_at < now() - make_interval(secs => :s)"), {"s": s}).all()
    for r in rows:
        enqueue_notifications(db, SimpleNamespace(id=r.cid), r.id, "reminder")
    db.commit()
    return len(rows)


def retention(rt: Runtime) -> int:
    global _last_retention
    if time.monotonic() - _last_retention < 600:
        return 0
    _last_retention = time.monotonic()
    with rt.session() as db:
        n = db.execute(text("DELETE FROM check_results WHERE at < now() - make_interval(days => :d)"),
                       {"d": rt.settings.check_result_retention_days}).rowcount
        db.execute(text("DELETE FROM maintenance_windows WHERE ends_at < now() - interval '30 days'"))
        db.execute(text("DELETE FROM agent_requests WHERE issued_at < now() - interval '30 days'"))
        db.commit()
        return n


def tick(rt: Runtime) -> dict:
    """One scheduler pass: run due checks, advance remediation attempts, deliver notifications, retention."""
    out = {"checks": run_due_checks(rt)}
    with rt.session() as db:
        out["attempts_synced"] = sync_attempts(db)
        # attempts may have just finished: let the policy engine look at still-critical checks (backoff / escalation)
        for r in db.execute(text("SELECT id FROM checks WHERE state = 'critical' AND remediation IS NOT NULL AND enabled")).all():
            maybe_remediate(db, rt, r.id)
        out["reminders"] = renotify(db, rt)
    out["notified"] = dispatch_notifications(rt)
    out["pruned"] = retention(rt)
    return out
