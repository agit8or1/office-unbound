"""Backup product, DB + agent part (ADR-0010): typed actions, executors, scheduler, monitoring evaluation, read models.

Actions (all plans -> approval -> durable job -> hash-chained audit; the catalog lives in actions.py):
  backup.policy.create  normal   registers a policy; the restic repository password is generated here (256 bit), vault-encrypted, never returned
  backup.policy.update  normal   (high when the retention shrinks: pruning is irreversible)
  backup.run            low      runbook backup.run {tier} on the policy's runner node (online backup hook + restic snapshot)
  backup.verify         low      runbook backup.verify {tier, level=check|restore[, percent][, snapshot]}
  backup.prune          low      runbook backup.prune {tier, retention from the POLICY}: the caller cannot choose a retention
Secrets never travel in a runbook: the node holds the repository password / REST credentials in root-only files (provisioned from the vault with
`ics.cli backup-node-secret`, see docs/admin/backup-and-restore.md). The runner returns counts, durations and the canary comparison only.
"""
import json
import re
import logging
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import text

from .. import agentclient, audit
from ..agentclient import AgentError
from ..proxmox import ProxmoxError, check_destination
from ..runtime import Runtime
from ..tenancy import scope as tscope
from . import policy as pol

log = logging.getLogger("ics.backups")

ACTIONS = ("backup.policy.create", "backup.policy.update", "backup.run", "backup.verify", "backup.prune")
PRUNE_INTERVAL_SECONDS = 86400
RETRY_AFTER_FAILURE_SECONDS = 900
NAME = pol.NAME_RE


class BackupError(Exception):
    """Message is safe to store and show."""


class PolicyUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    policy: str = Field(pattern=NAME)
    schedule: pol.Schedule | None = None
    retention: pol.Retention | None = None
    rpo_seconds: int | None = Field(default=None, ge=pol.MIN_RPO_SECONDS, le=30 * 86400)
    rto_seconds: int | None = Field(default=None, ge=60, le=7 * 86400)
    verify: pol.VerifyPolicy | None = None
    enabled: bool | None = None

    @model_validator(mode="after")
    def _any(self) -> Self:
        if all(getattr(self, k) is None for k in ("schedule", "retention", "rpo_seconds", "rto_seconds", "verify", "enabled")):
            raise ValueError("nothing to change")
        return self


class BackupRun(BaseModel):
    model_config = ConfigDict(extra="forbid")
    policy: str = Field(pattern=NAME)
    trigger: Literal["manual", "schedule"] = "manual"


class BackupVerify(BaseModel):
    model_config = ConfigDict(extra="forbid")
    policy: str = Field(pattern=NAME)
    level: Literal["check", "restore"]
    snapshot: str | None = Field(default=None, pattern=r"^[0-9a-f]{8,64}$", description="restore only: a specific snapshot (default: the newest)")
    trigger: Literal["manual", "schedule"] = "manual"


class BackupPrune(BaseModel):
    model_config = ConfigDict(extra="forbid")
    policy: str = Field(pattern=NAME)
    trigger: Literal["manual", "schedule"] = "manual"


MODELS = {"backup.policy.create": pol.PolicyCreate, "backup.policy.update": PolicyUpdate, "backup.run": BackupRun,
          "backup.verify": BackupVerify, "backup.prune": BackupPrune}
SECRETS = {"backup.policy.create": ("repo_password",)}


def repo_aad(policy_id, repo_url: str, customer_id=None) -> str:
    """The repository password only decrypts for this policy, this repository URL AND (customer policies) this customer: re-pointing the policy
    or relabelling its row to another customer voids it (like endpoint tokens / agent M's credential AAD)."""
    import hashlib
    c = f":{customer_id}" if customer_id else ""
    return f"backup-repo:{policy_id}{c}:{hashlib.sha256(repo_url.encode()).hexdigest()[:16]}"


def policy_customer(db, name: str) -> str | None:
    """Owning customer id (str) of the named policy (every policy has one since migration 0010; used for operator scope). KeyError when it does not exist."""
    r = _policy(db, name)
    return str(r.customer_id) if r.customer_id else None


def _isolated(row) -> str | None:
    """One model for review 5 M5 (scope: backup_policies.customer_id, always set) and per-customer backup isolation (agent AU): a policy is a
    customer-ISOLATED one (own runner profile, repository user/path, vault AAD) exactly when its repository path starts with that customer's own
    namespace, which PolicyCreate enforces for an explicit customer_id. Policies that merely inherited a customer for scoping stay on the shared runner profile."""
    if not row.customer_id:
        return None
    try:
        # any customer namespace counts (fail closed): a row relabelled to another customer stays isolated and then fails the plan/AAD binding
        return str(row.customer_id) if re.fullmatch(r"c-[0-9a-f]{32}", pol.repo_first_segment(row.repo["url"])) else None
    except (TypeError, KeyError):
        return None


def _profile(row) -> dict:
    """Runbook parameter that selects the customer's runner profile (/etc/ou-backup/<profile>/<tier>.json): derived from the policy row, never from a caller."""
    c = _isolated(row)
    return {"customer": pol.customer_profile(c)} if c else {}


def _own_plan(row, plan) -> None:
    """Defence in depth under the plan-time scope check: a job may only act on a policy of the customer its plan was made for."""
    if _isolated(row) is not None and str(getattr(plan, "customer_id", None)) != str(row.customer_id):
        raise BackupError("plan and backup policy belong to different customers")


def _policy(db, name: str):
    row = db.execute(text("SELECT * FROM backup_policies WHERE name = :n"), {"n": name}).first()
    if row is None:
        raise KeyError("backup policy not found")
    return row


def _node_has(db, node_id, runbook: str, tier: str, customer_id=None) -> bool:
    n = db.execute(text("SELECT capabilities FROM nodes WHERE id = :i"), {"i": str(node_id)}).first()
    spec = ((n.capabilities or {}).get(runbook) or {}) if n else {}
    return bool(n and tier in spec.get("tiers", []) and (customer_id is None or pol.customer_profile(customer_id) in spec.get("customers", [])))


# ---- plan-time ----------------------------------------------------------------------------------------------------------------------------
def risk_for(db, action: str, p) -> str:
    if action == "backup.policy.update" and p.retention is not None:
        cur = _policy(db, p.policy).retention
        if any(getattr(p.retention, k) < cur.get(k, 0) for k in ("last", "daily", "weekly", "monthly")):
            return "high"   # shrinking retention makes the next prune delete history for good: two people
    if action in ("backup.policy.create", "backup.policy.update"):
        return "normal"
    return "low"


def precheck(db, rt: Runtime, action: str, p) -> dict:
    """Raises KeyError (404), LookupError (409) or ValueError (422)."""
    if action == "backup.policy.create":
        if db.execute(text("SELECT 1 FROM backup_policies WHERE name = :n"), {"n": p.name}).first():
            raise LookupError("backup policy name already exists")
        if db.execute(text("SELECT 1 FROM nodes WHERE id = :i"), {"i": p.runner_node_id}).first() is None:
            raise KeyError("runner node not found (enroll it first)")
        if p.customer_id:
            c = db.execute(text("SELECT disabled_at FROM customers WHERE id = :i"), {"i": p.customer_id}).first()
            if c is None or c.disabled_at is not None:
                raise KeyError("customer not found")
        if db.execute(text("SELECT 1 FROM backup_policies WHERE repo->>'url' = :u"), {"u": p.repo.url}).first():
            raise LookupError("another policy already uses this repository (a repository belongs to exactly one policy)")
        for rb in ("backup.run", "backup.verify", "backup.prune"):
            if not _node_has(db, p.runner_node_id, rb, p.tier, p.customer_id):
                raise ValueError(f"the node's agent does not allow {rb} for tier {p.tier}" + (" and this customer" if p.customer_id else ""))
        try:
            return {"resolved_ips": check_destination(p.repo.host, rt.settings.allow_loopback_endpoints)}
        except ProxmoxError as e:
            raise ValueError(str(e)) from None
    row = _policy(db, p.policy)
    if action == "backup.policy.update":
        return {}
    if not row.enabled:
        raise LookupError("policy is disabled")
    need = {"backup.run": "backup.run", "backup.prune": "backup.prune", "backup.verify": "backup.verify"}[action]
    if not _node_has(db, row.runner_node_id, need, row.tier, _isolated(row)):
        raise ValueError(f"the runner node's agent does not allow {need} for tier {row.tier}")
    if action == "backup.verify" and p.snapshot and p.level != "restore":
        raise ValueError("snapshot is only meaningful for a restore verification")
    return {"tier": row.tier}


# ---- executors ----------------------------------------------------------------------------------------------------------------------------
def exec_policy_create(rt: Runtime, db, m: pol.PolicyCreate, plan, known: list[str]) -> dict:
    pid = uuid.uuid4()
    pw = m.repo_password.get_secret_value() if m.repo_password else secrets.token_urlsafe(32)
    known.append(pw)
    enc = rt.vault.encrypt(json.dumps({"repo_password": pw}).encode(), repo_aad(pid, m.repo.url, m.customer_id))
    creator = db.execute(text("SELECT requested_by FROM plans WHERE id = :i"), {"i": str(plan.id)}).scalar()
    db.execute(text(
        "INSERT INTO backup_policies (id, name, tier, deployment, runner_node_id, schedule, retention, rpo_seconds, rto_seconds, repo, "
        "copies_required, verify, repo_secret_enc, created_by, customer_id) VALUES (:id, :n, :t, :d, :node, CAST(:s AS jsonb), CAST(:r AS jsonb), :rpo, :rto, "
        "CAST(:repo AS jsonb), :c, CAST(:v AS jsonb), :e, :u, COALESCE(:cu, (SELECT customer_id FROM nodes WHERE id = :node)))"),
        {"id": str(pid), "n": m.name, "t": m.tier, "d": m.deployment, "node": m.runner_node_id, "s": audit.canon(m.schedule.model_dump(exclude_none=True)),
         "r": audit.canon(m.retention.model_dump()), "rpo": m.rpo_seconds, "rto": m.rto_seconds, "repo": audit.canon(m.repo.model_dump()),
         "c": m.copies_required, "v": audit.canon(m.verify.model_dump()), "e": enc, "u": creator, "cu": m.customer_id})
    return {"policy_id": str(pid), "name": m.name, "tier": m.tier, "customer_id": m.customer_id, "repository_password": "stored in the vault (never shown); "
            "provision it on the node with `ics.cli backup-node-secret`", "next": "init the repository and export the offline recovery key (docs/admin/backup-and-restore.md)"}


def exec_policy_update(rt: Runtime, db, m: PolicyUpdate, plan, known: list[str]) -> dict:
    row = _policy(db, m.policy)
    sets, args = [], {"i": str(row.id)}
    for k in ("schedule", "retention", "verify"):
        v = getattr(m, k)
        if v is not None:
            sets.append(f"{k} = CAST(:{k} AS jsonb)")
            args[k] = audit.canon(v.model_dump(exclude_none=True))
    for k in ("rpo_seconds", "rto_seconds", "enabled"):
        v = getattr(m, k)
        if v is not None:
            sets.append(f"{k} = :{k}")
            args[k] = v
    # the merged policy must still be coherent (schedule vs RPO)
    sched = pol.Schedule(**(m.schedule.model_dump(exclude_none=True) if m.schedule else row.schedule))
    rpo = m.rpo_seconds or row.rpo_seconds
    if sched.every_hours is not None and sched.every_hours * 3600 > rpo or sched.daily_at is not None and 86400 > rpo:
        raise BackupError("schedule is incompatible with the RPO target")
    db.execute(text(f"UPDATE backup_policies SET {', '.join(sets)} WHERE id = :i"), args)
    return {"policy": m.policy, "changed": [k for k in ("schedule", "retention", "rpo_seconds", "rto_seconds", "verify", "enabled")
                                           if getattr(m, k) is not None]}


def _node(rt: Runtime, row):
    with rt.session() as d:
        n = d.execute(text("SELECT * FROM nodes WHERE id = :i"), {"i": str(row.runner_node_id)}).first()
    if n is None:
        raise BackupError("runner node not found")
    return n


_SCALAR = (bool, int, float, str, type(None))
_RUN_KEYS = ("snapshot", "bytes_added", "bytes_added_packed", "bytes_processed", "files_new", "files_changed", "files_unmodified", "archive_bytes",
             "repo_confirmed", "snapshots_total", "repo_id", "canary_recorded", "canary_error", "consistency", "repo_bytes", "repo_blobs", "seconds",
             "kept", "removed", "passed", "read_data_percent", "output_tail", "match", "problems", "canary_expected", "canary_observed", "scratch",
             "services_checked", "rto_seconds", "rto_seconds_incl_poweron", "restic_restore_bytes", "level", "tier", "run_tag",
             "chain_checked", "passive", "operator_login")


def _clean(v, depth: int = 0):
    """Runner output is data, not instructions: keep only plain JSON, bounded depth/size/strings."""
    if depth > 5:
        return None
    if isinstance(v, str):
        return "".join(c if 32 <= ord(c) < 127 or c == "\n" else "?" for c in v[:500])
    if isinstance(v, bool) or v is None:
        return v
    if isinstance(v, int):
        return v if abs(v) < 2**53 else str(v)
    if isinstance(v, float):
        return round(v, 3) if v == v and abs(v) < 1e12 else None
    if isinstance(v, list):
        return [_clean(x, depth + 1) for x in v[:50]]
    if isinstance(v, dict):
        return {str(k)[:80]: _clean(x, depth + 1) for k, x in list(v.items())[:50]}
    return str(v)[:100]


def _detail(res: dict) -> dict:
    d = {k: _clean(res[k]) for k in _RUN_KEYS if k in res}
    return d if len(json.dumps(d)) < 16000 else {k: v for k, v in d.items() if k not in ("canary_expected", "canary_observed")}


def _call(rt: Runtime, row, node, runbook: str, params: dict, plan) -> dict:
    """One signed agent request (same evidence trail as runbook.execute: agent_requests row first, audit entry after)."""
    pol.runbook_params(runbook, params)   # ICS-side shape check; the agent and the root helper check again
    jid = str(rt_job_id(rt, plan))
    priv = agentclient.load_signing_key(rt.settings.signing_key_file)
    body = agentclient.build_request(priv, action=runbook, params=params, node_id=str(node.id), job_id=jid, ttl=rt.settings.agent_request_ttl_seconds, epoch=rt.agent_epoch())
    req = body["req"]
    with rt.session() as d2:
        d2.execute(text("INSERT INTO agent_requests (node_id, job_id, nonce, action, issued_at, expires_at) "
                        "VALUES (:n, :j, :nc, :a, to_timestamp(:i), to_timestamp(:e))"),
                   {"n": str(node.id), "j": jid, "nc": req["nonce"], "a": runbook, "i": req["issued_at"], "e": req["expires_at"]})
        d2.commit()
    code, resp = "error", {}
    try:
        _, resp = agentclient.call(node, priv, action=runbook, params=params, job_id=jid, deadline=float(rt.settings.backup_job_timeout_seconds) - 60,
                                   allow_loopback=rt.settings.allow_loopback_endpoints, req_override=body)
        code = str(resp.get("code"))[:60]
    except AgentError:
        code = "transport_or_signature_error"
        raise
    finally:
        with rt.session() as d2:
            d2.execute(text("UPDATE agent_requests SET status = :s, response_code = :c, finished_at = now() WHERE job_id = :j"),
                       {"s": "done" if code == "ok" else "failed", "c": code, "j": jid})
            if code != "transport_or_signature_error":
                d2.execute(text("UPDATE nodes SET last_seen_at = now() WHERE id = :i"), {"i": str(node.id)})
            audit.append(d2, "backup.runbook", actor_name="worker", resource="node", resource_id=str(node.id),
                         details={"runbook": runbook, "params": params, "policy": row.name, "agent_status": resp.get("status", "error"),
                                  "agent_code": code, "job_id": jid})
            d2.commit()
    if resp.get("status") != "ok":
        raise BackupError(f"agent {resp.get('status')}: {code}")
    r = resp.get("result") or {}
    if r.get("error"):
        raise BackupError("runner: " + str(r["error"])[:300])
    if not isinstance(r.get("result"), dict):
        raise BackupError("runner returned no result")
    return r["result"]


def rt_job_id(rt: Runtime, plan):
    with rt.session() as d:
        return d.execute(text("SELECT id FROM jobs WHERE plan_id = :p"), {"p": str(plan.id)}).scalar()


def _pin_repo(rt: Runtime, row, repo_id: str | None) -> None:
    """First successful contact pins the restic repository id; a later different id means the node points at another repository."""
    if not repo_id:
        return
    with rt.session() as d:
        cur = d.execute(text("SELECT repo_id FROM backup_policies WHERE id = :i FOR UPDATE"), {"i": str(row.id)}).scalar()
        if cur is None:
            d.execute(text("UPDATE backup_policies SET repo_id = :r WHERE id = :i"), {"r": repo_id, "i": str(row.id)})
            d.commit()
        elif cur != repo_id:
            raise BackupError("the repository id changed: the runner points at a different repository than the one this policy was pinned to")


def _start(rt: Runtime, table: str, row, fields: dict, job_id) -> str:
    rid = str(uuid.uuid4())
    cols = ", ".join(["id", "policy_id", "job_id", *fields])
    vals = ", ".join([":id", ":p", ":j", *(f":{k}" for k in fields)])
    with rt.session() as d:
        d.execute(text(f"INSERT INTO {table} ({cols}) VALUES ({vals})"), {"id": rid, "p": str(row.id), "j": str(job_id), **fields})
        d.commit()
    return rid


def _finish_run(rt: Runtime, rid: str, status: str, res: dict | None, err: str | None, t0: float) -> None:
    res = res or {}
    with rt.session() as d:
        d.execute(text(
            "UPDATE backup_runs SET status = :s, finished_at = now(), snapshot_id = :sn, bytes_added = :ba, bytes_processed = :bp, repo_bytes = :rb, "
            "snapshots_total = :st, duration_ms = :dm, repo_confirmed = :rc, canary_recorded = :cr, detail = CAST(:d AS jsonb), error = :e WHERE id = :i"),
            {"s": status, "sn": res.get("snapshot"), "ba": res.get("bytes_added"), "bp": res.get("bytes_processed"), "rb": res.get("repo_bytes"),
             "st": res.get("snapshots_total"), "dm": int((time.monotonic() - t0) * 1000), "rc": res.get("repo_confirmed"), "cr": res.get("canary_recorded"),
             "d": audit.canon(_detail(res)) if res else None, "e": err[:400] if err else None, "i": rid})
        d.commit()


def exec_run(rt: Runtime, db, m: BackupRun, plan, known: list[str]) -> dict:
    row = _policy(db, m.policy)
    _own_plan(row, plan)
    node = _node(rt, row)
    jid = rt_job_id(rt, plan)
    rid = _start(rt, "backup_runs", row, {"kind": "backup", "trigger": m.trigger, "status": "running"}, jid)
    t0 = time.monotonic()
    try:
        res = _call(rt, row, node, "backup.run", {"tier": row.tier, **_profile(row)}, plan)
        _pin_repo(rt, row, res.get("repo_id"))
        if res.get("repo_confirmed") is not True:
            raise BackupError("the snapshot was not confirmed in the repository")
    except (BackupError, AgentError) as e:
        _finish_run(rt, rid, "failed", None, str(e), t0)
        raise
    except Exception as e:  # noqa: BLE001
        _finish_run(rt, rid, "failed", None, type(e).__name__, t0)
        raise
    _finish_run(rt, rid, "succeeded", res, None, t0)
    return {"run_id": rid, **{k: _clean(res.get(k)) for k in ("snapshot", "bytes_added", "bytes_processed", "repo_bytes", "snapshots_total", "repo_confirmed", "canary_recorded", "seconds")}}


def exec_prune(rt: Runtime, db, m: BackupPrune, plan, known: list[str]) -> dict:
    row = _policy(db, m.policy)
    _own_plan(row, plan)
    node = _node(rt, row)
    jid = rt_job_id(rt, plan)
    rid = _start(rt, "backup_runs", row, {"kind": "prune", "trigger": m.trigger, "status": "running"}, jid)
    t0 = time.monotonic()
    params = {"tier": row.tier, **_profile(row), **{k: int(row.retention.get(k, 0)) for k in ("last", "daily", "weekly", "monthly")}}
    try:
        res = _call(rt, row, node, "backup.prune", params, plan)
    except Exception as e:  # noqa: BLE001
        _finish_run(rt, rid, "failed", None, str(e) if isinstance(e, (BackupError, AgentError)) else type(e).__name__, t0)
        raise
    _finish_run(rt, rid, "succeeded", res, None, t0)
    return {"run_id": rid, "kept": res.get("kept"), "removed": res.get("removed"), "repo_bytes": res.get("repo_bytes")}


def exec_verify(rt: Runtime, db, m: BackupVerify, plan, known: list[str]) -> dict:
    """Verification state machine: pending -> running -> passed | failed | error. 'failed' = the check/restore ran and the result was bad
    (corrupt pack, canary mismatch); 'error' = it could not run (agent/runner/scratch problem)."""
    row = _policy(db, m.policy)
    _own_plan(row, plan)
    node = _node(rt, row)
    jid = rt_job_id(rt, plan)
    vid = _start(rt, "backup_verifications", row, {"level": m.level, "state": "pending", "trigger": m.trigger}, jid)

    def move(new: str, **cols) -> None:
        with rt.session() as d:
            cur = d.execute(text("SELECT state FROM backup_verifications WHERE id = :i FOR UPDATE"), {"i": vid}).scalar()
            pol.verif_transition(cur, new)
            sets = ", ".join(["state = :s", *(f"{k} = CAST(:{k} AS jsonb)" if k == "detail" else f"{k} = :{k}" for k in cols)]
                             + (["finished_at = now()"] if new in pol.TERMINAL else []))
            d.execute(text(f"UPDATE backup_verifications SET {sets} WHERE id = :i"), {"s": new, "i": vid, **cols})
            d.commit()
    move("running")
    params: dict = {"tier": row.tier, **_profile(row), "level": m.level}
    if m.level == "check":
        params["percent"] = int(row.verify.get("check_read_data_percent", 10))
    elif m.snapshot:
        params["snapshot"] = m.snapshot
    try:
        res = _call(rt, row, node, "backup.verify", params, plan)
        _pin_repo(rt, row, res.get("repo_id"))
    except Exception as e:  # noqa: BLE001
        move("error", error=(str(e) if isinstance(e, (BackupError, AgentError)) else type(e).__name__)[:400])
        raise
    passed = bool(res.get("passed")) if m.level == "check" else bool(res.get("match"))
    rto = res.get("rto_seconds") if m.level == "restore" else None
    move("passed" if passed else "failed", snapshot_id=res.get("snapshot"), rto_seconds=rto if isinstance(rto, (int, float)) else None,
         detail=audit.canon(_detail(res)), error=None if passed else "; ".join(map(str, (res.get("problems") or ["repository check reported errors"])))[:400])
    out = {"verification_id": vid, "level": m.level, "passed": passed, "snapshot": res.get("snapshot"), "rto_seconds": rto}
    if not passed:
        raise BackupError(f"{m.level} verification FAILED: " + "; ".join(map(str, res.get("problems") or ["see verification detail"]))[:300])
    return out


EXECUTORS = {"backup.policy.create": exec_policy_create, "backup.policy.update": exec_policy_update, "backup.run": exec_run,
             "backup.verify": exec_verify, "backup.prune": exec_prune}


# ---- read models ---------------------------------------------------------------------------------------------------------------------------
def _ts(v) -> str | None:
    return v.isoformat() if v else None


def policy_view(db, r, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    last_ok = db.execute(text("SELECT finished_at, snapshot_id, repo_bytes, bytes_added FROM backup_runs WHERE policy_id = :p AND kind = 'backup' "
                              "AND status = 'succeeded' AND repo_confirmed ORDER BY finished_at DESC LIMIT 1"), {"p": str(r.id)}).first()
    last_any = db.execute(text("SELECT status, started_at, finished_at, error FROM backup_runs WHERE policy_id = :p AND kind = 'backup' "
                               "ORDER BY started_at DESC LIMIT 1"), {"p": str(r.id)}).first()
    chk = db.execute(text("SELECT finished_at, state = 'passed' AS passed, snapshot_id FROM backup_verifications WHERE policy_id = :p AND level = 'check' "
                          "AND state IN ('passed','failed') ORDER BY finished_at DESC LIMIT 1"), {"p": str(r.id)}).first()
    rst = db.execute(text("SELECT finished_at, state = 'passed' AS passed, snapshot_id, rto_seconds FROM backup_verifications WHERE policy_id = :p "
                          "AND level = 'restore' AND state IN ('passed','failed') ORDER BY finished_at DESC LIMIT 1"), {"p": str(r.id)}).first()
    ver = r.verify
    states = pol.four_states(
        now=now, rpo_seconds=r.rpo_seconds, rto_seconds=r.rto_seconds, copies_required=r.copies_required, copies_present=1 if last_ok else 0,
        last_success=last_ok.finished_at if last_ok else None, last_snapshot_id=last_ok.snapshot_id if last_ok else None,
        last_check={"finished_at": chk.finished_at, "passed": chk.passed} if chk else None, recovery_key_exported=r.recovery_exported_at is not None,
        last_restore={"finished_at": rst.finished_at, "passed": rst.passed, "snapshot_id": rst.snapshot_id,
                      "rto_seconds": float(rst.rto_seconds) if rst.rto_seconds is not None else None} if rst else None,
        check_max_age=int(ver["check_every_seconds"] * 2), restore_max_age=int(ver["restore_every_seconds"] * 1.5),
        last_run_failed=bool(last_any and last_any.status == "failed" and (not last_ok or last_any.started_at > last_ok.finished_at)))
    return {"id": str(r.id), "name": r.name, "tier": r.tier, "deployment": r.deployment, "customer_id": str(r.customer_id) if r.customer_id else None, "runner_node_id": str(r.runner_node_id),
            "schedule": r.schedule, "retention": r.retention, "rpo_seconds": r.rpo_seconds, "rto_seconds": r.rto_seconds, "repo": r.repo,
            "copies_required": r.copies_required, "verify": r.verify, "enabled": r.enabled, "repo_id": r.repo_id,
            "recovery_key": {"exported": r.recovery_exported_at is not None, "fingerprint": r.recovery_fp, "exported_at": _ts(r.recovery_exported_at)},
            "created_at": _ts(r.created_at), "last_success_at": _ts(last_ok.finished_at) if last_ok else None,
            "last_run": {"status": last_any.status, "started_at": _ts(last_any.started_at), "error": last_any.error} if last_any else None,
            "repo_bytes": last_ok.repo_bytes if last_ok else None, "states": states,
            "next_backup_due_at": _ts(pol.next_due(pol.Schedule(**r.schedule), last_any.started_at if last_any else None, now))}


def list_policies(db) -> list[dict]:
    from ..tenancy import scope as tscope
    return [policy_view(db, r) for r in db.execute(text(f"SELECT * FROM backup_policies WHERE {tscope.clause(db, 'customer_id')} ORDER BY name")).all()]


def list_runs(db, policy: str | None = None, kind: str | None = None, limit: int = 50) -> list[dict]:
    from ..tenancy import scope as tscope
    rows = db.execute(text(
        "SELECT r.*, p.name AS policy_name, p.tier FROM backup_runs r JOIN backup_policies p ON p.id = r.policy_id "
        f"WHERE {tscope.clause(db, 'p.customer_id')} AND (CAST(:p AS text) IS NULL OR p.name = :p) AND (CAST(:k AS text) IS NULL OR r.kind = :k) ORDER BY r.started_at DESC LIMIT :n"),
        {"p": policy, "k": kind, "n": max(1, min(limit, 500))}).all()
    return [{"id": str(r.id), "policy": r.policy_name, "tier": r.tier, "kind": r.kind, "trigger": r.trigger, "status": r.status,
             "started_at": _ts(r.started_at), "finished_at": _ts(r.finished_at), "duration_ms": r.duration_ms, "snapshot": r.snapshot_id,
             "bytes_added": r.bytes_added, "bytes_processed": r.bytes_processed, "repo_bytes": r.repo_bytes, "snapshots_total": r.snapshots_total,
             "repo_confirmed": r.repo_confirmed, "canary_recorded": r.canary_recorded, "error": r.error, "detail": r.detail, "job_id": str(r.job_id) if r.job_id else None}
            for r in rows]


def list_verifications(db, policy: str | None = None, level: str | None = None, limit: int = 50) -> list[dict]:
    from ..tenancy import scope as tscope
    rows = db.execute(text(
        "SELECT v.*, p.name AS policy_name, p.tier, p.rto_seconds AS rto_target FROM backup_verifications v JOIN backup_policies p ON p.id = v.policy_id "
        f"WHERE {tscope.clause(db, 'p.customer_id')} AND (CAST(:p AS text) IS NULL OR p.name = :p) AND (CAST(:l AS text) IS NULL OR v.level = :l) ORDER BY v.started_at DESC LIMIT :n"),
        {"p": policy, "l": level, "n": max(1, min(limit, 500))}).all()
    return [{"id": str(r.id), "policy": r.policy_name, "tier": r.tier, "level": r.level, "state": r.state, "trigger": r.trigger,
             "snapshot": r.snapshot_id, "started_at": _ts(r.started_at), "finished_at": _ts(r.finished_at),
             "rto_seconds": float(r.rto_seconds) if r.rto_seconds is not None else None, "rto_target_seconds": r.rto_target,
             "rto_within_target": None if r.rto_seconds is None else float(r.rto_seconds) <= r.rto_target, "error": r.error, "detail": r.detail,
             "job_id": str(r.job_id) if r.job_id else None} for r in rows]


# ---- monitoring (check kind "backup") -----------------------------------------------------------------------------------------------------
class BackupCheckConfig(BaseModel):
    """Evaluated from the recorded runs/verifications (no network): age vs RPO, repository check freshness/result, restore-verification
    freshness/result/RTO, repository growth vs a size ceiling."""
    model_config = ConfigDict(extra="forbid")
    policy: str = Field(pattern=NAME)
    aspect: Literal["age", "repo_check", "restore", "growth"]
    max_repo_bytes: int | None = Field(default=None, ge=1)
    timeout_seconds: int = Field(default=10, ge=1, le=30)

    @model_validator(mode="after")
    def _g(self) -> Self:
        if (self.aspect == "growth") != (self.max_repo_bytes is not None):
            raise ValueError("max_repo_bytes is required for (and only for) aspect=growth")
        return self


def evaluate(rt: Runtime, cfg: dict, now: datetime | None = None):
    from .. import checks
    now = now or datetime.now(timezone.utc)
    t0 = time.monotonic()
    try:
        c = BackupCheckConfig.model_validate(cfg)
        with rt.session() as db:
            r = db.execute(text("SELECT * FROM backup_policies WHERE name = :n"), {"n": c.policy}).first()
            if r is None:
                return checks.Outcome("critical", "backup policy does not exist", None, {"cause": "config"})
            v = policy_view(db, r, now)
            samples = db.execute(text("SELECT finished_at, repo_bytes FROM backup_runs WHERE policy_id = :p AND status = 'succeeded' AND repo_bytes IS NOT NULL "
                                      "ORDER BY finished_at DESC LIMIT 60"), {"p": str(r.id)}).all()
        s = v["states"]
        if not v["enabled"]:
            return checks.Outcome("ok", "policy is disabled (no backups expected)", None, {"policy": c.policy})
        if c.aspect == "age":
            st, age = pol.rpo_state(datetime.fromisoformat(v["last_success_at"]) if v["last_success_at"] else None, now, v["rpo_seconds"])
            msg = ("no successful backup yet" if age is None else f"last good snapshot {age // 60} min old (RPO {v['rpo_seconds'] // 60} min)")
            if v["last_run"] and v["last_run"]["status"] == "failed" and st == "ok":
                st, msg = "warning", msg + "; the latest run FAILED: " + (v["last_run"]["error"] or "")[:120]
            return checks.Outcome(st, msg, int((time.monotonic() - t0) * 1000), {"age_seconds": age, "rpo_seconds": v["rpo_seconds"]})
        if c.aspect == "repo_check":
            rc = s["recovery_readiness"]
            bad = [x for x in rc["reasons"] if "check" in x]
            st = "ok" if not bad else "critical" if "has not passed" in " ".join(bad) else "warning"
            return checks.Outcome(st, "repository check ok" if not bad else "; ".join(bad), None, {"last_check_age_seconds": rc["last_check_age_seconds"]})
        if c.aspect == "restore":
            vr = s["verified_restore"]
            st = {"verified": "ok", "never_verified": "warning", "stale": "warning", "verified_rto_exceeded": "warning", "failed": "critical"}[vr["state"]]
            return checks.Outcome(st, f"restore verification: {vr['state']}" + (f", RTO {vr['rto_seconds']:.0f}s (target {vr.get('rto_target_seconds')}s)" if vr.get("rto_seconds") else ""),
                                  None, {k: vr.get(k) for k in ("age_seconds", "rto_seconds")})
        size = samples[0].repo_bytes if samples else None
        if size is None:
            return checks.Outcome("warning", "no repository size recorded yet", None, {})
        per_day = pol.growth_per_day([(x.finished_at, x.repo_bytes) for x in reversed(samples)])
        left = pol.days_until_full(c.max_repo_bytes - size, per_day)  # type: ignore[operator]
        st = "critical" if size >= c.max_repo_bytes else "warning" if size >= 0.8 * c.max_repo_bytes or (left is not None and left < 14) else "ok"  # type: ignore[operator]
        return checks.Outcome(st, f"repository {size} bytes of {c.max_repo_bytes} ceiling" + ("" if per_day is None else f", growth {per_day / 1e6:.2f} MB/day"),
                              None, {"repo_bytes": size, "growth_bytes_per_day": per_day, "days_to_ceiling": left})
    except Exception as e:  # noqa: BLE001
        return checks.Outcome("critical", f"backup check error: {type(e).__name__}", None, {"cause": "config"})


# ---- scheduler (backup lane thread) ---------------------------------------------------------------------------------------------------------
def _inflight(db, policy: str, action: str) -> bool:
    return bool(db.execute(text(
        "SELECT 1 FROM jobs j JOIN plans p ON p.id = j.plan_id WHERE j.status IN ('queued','running') AND p.action = :a AND p.params->>'policy' = :n LIMIT 1"),
        {"a": action, "n": policy}).first() or db.execute(text(
            "SELECT 1 FROM plans WHERE action = :a AND params->>'policy' = :n AND status = 'pending_approval' LIMIT 1"), {"a": action, "n": policy}).first())


def tick(rt: Runtime, now: datetime | None = None) -> list[str]:
    """Creates the plans that are due. Plans are made as the policy's creator (auditable owner); low-risk ones auto-approve like any other.
    A runner that is down produces failed runs (retried after 15 min), never a pile of queued jobs (one in-flight plan per policy+action)."""
    from .. import actions
    now = now or datetime.now(timezone.utc)
    made = []
    with rt.session() as db:
        for r in db.execute(text("SELECT * FROM backup_policies WHERE enabled ORDER BY name")).all():
            u = db.execute(text("SELECT id, username, role FROM users WHERE id = :i AND NOT disabled"), {"i": str(r.created_by)}).first() if r.created_by else None
            if u is None:
                continue
            ver = r.verify
            last_b = db.execute(text("SELECT started_at, status FROM backup_runs WHERE policy_id = :p AND kind = 'backup' ORDER BY started_at DESC LIMIT 1"),
                                {"p": str(r.id)}).first()
            last_ok = db.execute(text("SELECT max(finished_at) FROM backup_runs WHERE policy_id = :p AND kind = 'backup' AND status = 'succeeded'"), {"p": str(r.id)}).scalar()
            last_chk = db.execute(text("SELECT max(started_at) FROM backup_verifications WHERE policy_id = :p AND level = 'check'"), {"p": str(r.id)}).scalar()
            last_rst = db.execute(text("SELECT max(started_at) FROM backup_verifications WHERE policy_id = :p AND level = 'restore'"), {"p": str(r.id)}).scalar()
            last_pr = db.execute(text("SELECT max(started_at) FROM backup_runs WHERE policy_id = :p AND kind = 'prune'"), {"p": str(r.id)}).scalar()
            want = []
            if last_b and last_b.status == "failed":
                due = now - last_b.started_at >= timedelta(seconds=RETRY_AFTER_FAILURE_SECONDS) and pol.is_due(pol.Schedule(**r.schedule), last_ok, now)
            else:
                due = pol.is_due(pol.Schedule(**r.schedule), last_b.started_at if last_b else None, now)
            if due and not (last_b and last_b.status == "running"):
                want.append(("backup.run", {"policy": r.name, "trigger": "schedule"}))
            if last_ok and (last_chk is None or now - last_chk >= timedelta(seconds=ver["check_every_seconds"])):
                want.append(("backup.verify", {"policy": r.name, "level": "check", "trigger": "schedule"}))
            if last_ok and (last_rst is None or now - last_rst >= timedelta(seconds=ver["restore_every_seconds"])):
                want.append(("backup.verify", {"policy": r.name, "level": "restore", "trigger": "schedule"}))
            if last_ok and (last_pr is None or now - last_pr >= timedelta(seconds=PRUNE_INTERVAL_SECONDS)):
                want.append(("backup.prune", {"policy": r.name, "trigger": "schedule"}))
            for action, params in want[:1]:   # one plan per policy per tick: backups first, then verification, then prune
                if _inflight(db, r.name, action):
                    continue
                if action == "backup.verify" and (_inflight(db, r.name, "backup.run")):
                    continue
                try:
                    actions.create_plan(db, rt, u, actions.ActionType(action), params, None)
                    made.append(f"{action}:{r.name}")
                except Exception as e:  # noqa: BLE001
                    db.rollback()
                    log.error("scheduling %s for %s failed: %s", action, r.name, type(e).__name__)
    return made


# ---- break-glass CLI helpers --------------------------------------------------------------------------------------------------------------------
def node_secret(rt: Runtime, db, name: str) -> dict:
    """Decrypts the repository password for the node provisioning step (host root only; audited; never logged)."""
    r = _policy(db, name)
    data = json.loads(rt.vault.decrypt(r.repo_secret_enc, repo_aad(r.id, r.repo["url"], _isolated(r))))
    audit.append(db, "backup.key.exported", actor_name="cli", resource="backup_policy", resource_id=str(r.id),
                 details={"policy": name, "purpose": "node provisioning", "fingerprint": pol.key_fingerprint(data["repo_password"])})
    db.commit()
    return {"repo_password": data["repo_password"]}


def recovery_ack(db, name: str, fingerprint: str) -> None:
    import re
    if not re.fullmatch(r"[0-9a-f]{16}", fingerprint):
        raise BackupError("fingerprint must be 16 hex characters")
    r = _policy(db, name)
    db.execute(text("UPDATE backup_policies SET recovery_fp = :f, recovery_exported_at = now() WHERE id = :i"), {"f": fingerprint, "i": str(r.id)})
    audit.append(db, "backup.recovery_key.recorded", actor_name="cli", resource="backup_policy", resource_id=str(r.id),
                 details={"policy": name, "recovery_fp": fingerprint})
    db.commit()
