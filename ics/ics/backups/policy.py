"""Backup product, pure part (no DB, no I/O): policy shapes, retention math, RPO/RTO evaluation, the owner's four states and the
verification state machine. ADR-0010. Everything here is deterministic so it can be tested without a repository.

Four distinct states (owner requirement: "backups are not complete until recovery is tested"). They are never collapsed into one flag:
  backup_success      the last scheduled run finished and the snapshot is within the RPO target
  replication         the latest snapshot is confirmed present on N independent repositories (N >= copies_required)
  recovery_readiness  the repository was integrity-checked recently, the offline recovery key was exported, and the snapshot is fresh
  verified_restore    a restore of the latest-or-newer snapshot into a scratch machine passed the canary comparison, within its max age
"""
import hashlib
import re
from datetime import datetime, time, timedelta, timezone
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

TIERS = ("files", "identity", "groupware", "ics")
NAME_RE = r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$"
LABEL_RE = r"^[A-Za-z0-9][A-Za-z0-9 _.:/-]{0,62}$"
SNAPSHOT_RE = re.compile(r"^[0-9a-f]{8,64}$")
REPO_URL_RE = re.compile(r"^https://(?P<host>[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)(:(?P<port>[0-9]{1,5}))?(?P<path>/[A-Za-z0-9_.-]{1,64}/?)$")
SHA256_RE = r"^[0-9a-fA-F]{64}$"
MIN_RPO_SECONDS = 300
VERIFY_LEVELS = ("check", "restore")


class Retention(BaseModel):
    """Mirrors `restic forget --keep-last/--keep-daily/--keep-weekly/--keep-monthly`: the newest snapshot of each of the last N days /
    ISO weeks / months *that have snapshots* is kept."""
    model_config = ConfigDict(extra="forbid")
    last: int = Field(default=2, ge=0, le=100)
    daily: int = Field(default=7, ge=0, le=366)
    weekly: int = Field(default=4, ge=0, le=260)
    monthly: int = Field(default=6, ge=0, le=240)

    @model_validator(mode="after")
    def _some(self) -> Self:
        if self.last + self.daily + self.weekly + self.monthly < 1:
            raise ValueError("retention must keep something (a policy that keeps nothing would delete every backup)")
        return self


class Schedule(BaseModel):
    """Exactly one of: every_hours (1..168, anchored on the last start) or daily_at 'HH:MM' (UTC)."""
    model_config = ConfigDict(extra="forbid")
    every_hours: int | None = Field(default=None, ge=1, le=168)
    daily_at: str | None = Field(default=None, pattern=r"^([01]\d|2[0-3]):[0-5]\d$")

    @model_validator(mode="after")
    def _one(self) -> Self:
        if (self.every_hours is None) == (self.daily_at is None):
            raise ValueError("exactly one of every_hours / daily_at is required")
        return self


class RepoRef(BaseModel):
    """restic REST server (restic/rest-server, HTTPS). No credential here: the repository password lives in the vault, the REST user's
    credentials in the node's root-only config. `ca_sha256` pins the server certificate (same trust-anchor rule as agents/endpoints)."""
    model_config = ConfigDict(extra="forbid")
    backend: Literal["rest"] = "rest"
    url: str
    ca_sha256: str = Field(pattern=SHA256_RE)

    @field_validator("url")
    @classmethod
    def _url(cls, v: str) -> str:
        m = REPO_URL_RE.match(v)
        if not m or (m["port"] and not 1 <= int(m["port"]) <= 65535):
            raise ValueError("repository url must be https://host[:port]/name (no userinfo, no query)")
        return v

    @field_validator("ca_sha256")
    @classmethod
    def _fp(cls, v: str) -> str:
        return v.lower()

    @property
    def host(self) -> str:
        return REPO_URL_RE.match(self.url)["host"]  # type: ignore[index]


class VerifyPolicy(BaseModel):
    """check = `restic check --read-data-subset=<percent>%`; restore = canary restore into a scratch machine."""
    model_config = ConfigDict(extra="forbid")
    check_every_seconds: int = Field(default=86400, ge=3600, le=30 * 86400)
    check_read_data_percent: int = Field(default=10, ge=1, le=100)
    restore_every_seconds: int = Field(default=7 * 86400, ge=3600, le=90 * 86400)


class PolicyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=NAME_RE)
    tier: Literal["files", "identity", "groupware", "ics"]
    deployment: str = Field(pattern=LABEL_RE, description="customer stack / deployment label this policy protects")
    runner_node_id: str = Field(pattern=r"^[0-9a-fA-F-]{36}$", description="enrolled node whose agent runs backup.run/backup.verify")
    schedule: Schedule
    retention: Retention = Field(default_factory=Retention)
    rpo_seconds: int = Field(ge=MIN_RPO_SECONDS, le=30 * 86400)
    rto_seconds: int = Field(ge=60, le=7 * 86400)
    repo: RepoRef
    copies_required: int = Field(default=1, ge=1, le=3)
    verify: VerifyPolicy = Field(default_factory=VerifyPolicy)
    repo_password: SecretStr | None = Field(default=None, description="optional; generated server-side (256 bit) when absent and NEVER returned")

    @field_validator("repo_password", mode="before")
    @classmethod
    def _pw(cls, v):
        raw = v.get_secret_value() if isinstance(v, SecretStr) else v
        if raw is not None and (not isinstance(raw, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", raw)):
            raise ValueError("repo_password: 32-128 chars of [A-Za-z0-9_-]")
        return raw

    @model_validator(mode="after")
    def _sane(self) -> Self:
        if self.schedule.every_hours is not None and self.schedule.every_hours * 3600 > self.rpo_seconds:
            raise ValueError("schedule interval is longer than the RPO target: the RPO could never be met")
        if self.schedule.daily_at is not None and 86400 > self.rpo_seconds:
            raise ValueError("a daily schedule cannot meet an RPO below 24 h")
        return self


# ---- runbook parameters (what may travel to the node agent) ------------------------------------------------------------------------------
def runbook_params(action: str, p: dict) -> dict:
    """Closed shapes; the agent validates the same shapes again (agent/ou_agent/backupspec.py). Anything else is refused."""
    def exact(keys, required=None):
        if set(p) - set(keys) or set(required if required is not None else keys) - set(p):
            raise ValueError("unexpected or missing runbook parameters")
    if action == "backup.run":
        exact(("tier",))
    elif action == "backup.verify":
        exact(("tier", "level", "percent", "snapshot"), ("tier", "level"))
        if p["level"] not in VERIFY_LEVELS:
            raise ValueError("level must be check or restore")
        if "percent" in p and (type(p["percent"]) is not int or not 1 <= p["percent"] <= 100):
            raise ValueError("percent must be 1..100")
        if "snapshot" in p and not (isinstance(p["snapshot"], str) and SNAPSHOT_RE.match(p["snapshot"])):
            raise ValueError("snapshot must be a hex id")
    elif action == "backup.prune":
        exact(("tier", "last", "daily", "weekly", "monthly"))
        for k, hi in (("last", 100), ("daily", 366), ("weekly", 260), ("monthly", 240)):
            if type(p[k]) is not int or not 0 <= p[k] <= hi:
                raise ValueError(f"{k} out of range")
        if p["last"] + p["daily"] + p["weekly"] + p["monthly"] < 1:
            raise ValueError("retention keeps nothing")
    else:
        raise ValueError("not a backup runbook")
    if p["tier"] not in TIERS:
        raise ValueError("unknown tier")
    return dict(p)


# ---- retention math ----------------------------------------------------------------------------------------------------------------------
def retention_keep(snaps: list[tuple[str, datetime]], r: Retention) -> dict[str, list[str]]:
    """Which snapshots restic would keep, and why. Same bucket semantics as `restic forget --keep-*` (UTC buckets): walk snapshots newest
    first; for each rule, the first snapshot seen in a not-yet-counted bucket is kept until N distinct buckets were counted.
    Returns {snapshot_id: [reasons]} for the KEPT snapshots only."""
    ordered = sorted(snaps, key=lambda s: s[1], reverse=True)
    kept: dict[str, list[str]] = {}

    def keep(sid: str, why: str) -> None:
        kept.setdefault(sid, []).append(why)

    def utc(t: datetime) -> datetime:
        return t.astimezone(timezone.utc)
    for sid, _ in ordered[: r.last]:
        keep(sid, "last")
    for rule, n, key in (("daily", r.daily, lambda t: utc(t).date()),
                         ("weekly", r.weekly, lambda t: tuple(utc(t).isocalendar()[:2])),
                         ("monthly", r.monthly, lambda t: (utc(t).year, utc(t).month))):
        seen: set = set()
        for sid, t in ordered:
            if len(seen) >= n:
                break
            b = key(t)
            if b not in seen:
                seen.add(b)
                keep(sid, rule)
        if 0 < n and len(seen) < n and ordered:   # restic >= 0.17: the rule was not used up -> the oldest snapshot is kept as well (cross-checked against restic 0.19.1)
            keep(ordered[-1][0], "oldest " + rule)
    return kept


def retention_prune_candidates(snaps: list[tuple[str, datetime]], r: Retention) -> list[str]:
    keep = retention_keep(snaps, r)
    return [sid for sid, _ in snaps if sid not in keep]


def retention_horizon(r: Retention) -> timedelta:
    """Oldest point in time the policy can restore to (upper bound, assuming one snapshot per bucket)."""
    return max(timedelta(days=r.daily), timedelta(weeks=r.weekly), timedelta(days=31 * r.monthly))


# ---- schedule ----------------------------------------------------------------------------------------------------------------------------
def next_due(s: Schedule, last_started: datetime | None, now: datetime) -> datetime:
    if last_started is None:
        return now        # never ran: due immediately
    if s.every_hours is not None:
        return last_started + timedelta(hours=s.every_hours)
    hh, mm = map(int, s.daily_at.split(":"))  # type: ignore[union-attr]
    t = datetime.combine(last_started.astimezone(timezone.utc).date(), time(hh, mm), tzinfo=timezone.utc)
    return t + timedelta(days=1) if t <= last_started else t


def is_due(s: Schedule, last_started: datetime | None, now: datetime) -> bool:
    return next_due(s, last_started, now) <= now


# ---- RPO / size ---------------------------------------------------------------------------------------------------------------------------
def rpo_state(last_success: datetime | None, now: datetime, rpo_seconds: int) -> tuple[Literal["ok", "warning", "critical"], int | None]:
    """Age of the newest good snapshot against the RPO target: <= RPO ok, <= 1.5x warning, beyond (or no backup at all) critical."""
    if last_success is None:
        return "critical", None
    age = int((now - last_success).total_seconds())
    return ("ok" if age <= rpo_seconds else "warning" if age <= rpo_seconds * 1.5 else "critical"), age


MIN_GROWTH_SPAN = timedelta(hours=6)


def growth_per_day(points: list[tuple[datetime, int]]) -> float | None:
    """Least-squares slope of repository size over time, bytes/day. None with < 2 points or less than 6 h between the first and the last
    sample (extrapolating minutes to days produced absurd rates in the lab run)."""
    if len(points) < 2 or max(t for t, _ in points) - min(t for t, _ in points) < MIN_GROWTH_SPAN:
        return None
    t0 = points[0][0]
    xs = [(t - t0).total_seconds() / 86400 for t, _ in points]
    ys = [float(v) for _, v in points]
    mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
    den = sum((x - mx) ** 2 for x in xs)
    return None if den == 0 else sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / den


def days_until_full(free_bytes: int, per_day: float | None) -> float | None:
    return None if per_day is None or per_day <= 0 else free_bytes / per_day


# ---- verification state machine ---------------------------------------------------------------------------------------------------------
VERIF_STATES = ("pending", "running", "passed", "failed", "error", "cancelled")
VERIF_TRANSITIONS = {"pending": {"running", "cancelled"}, "running": {"passed", "failed", "error"},
                     "passed": set(), "failed": set(), "error": set(), "cancelled": set()}
TERMINAL = {"passed", "failed", "error", "cancelled"}


class BadTransition(Exception):
    pass


def verif_transition(cur: str, new: str) -> str:
    if cur not in VERIF_TRANSITIONS or new not in VERIF_TRANSITIONS:
        raise BadTransition(f"unknown state {cur!r} -> {new!r}")
    if new not in VERIF_TRANSITIONS[cur]:
        raise BadTransition(f"{cur} -> {new} is not allowed")
    return new


def judge_canary(expected: dict | None, observed: dict | None) -> tuple[bool, list[str]]:
    """Restore verification compares what the live source showed at backup time (`expected`, recorded inside the backup run) with what the
    scratch machine shows after the restore (`observed`). Equal means every item of every canary key matched; anything missing fails."""
    if not expected:
        return False, ["no canary was recorded at backup time: nothing to compare (a restore without a canary is not verified)"]
    if not observed:
        return False, ["no canary observed on the restored machine"]
    problems = []
    for k in sorted(set(expected) | set(observed)):
        if expected.get(k) != observed.get(k):
            problems.append(f"canary {k}: expected {_brief(expected.get(k))}, observed {_brief(observed.get(k))}")
    return not problems, problems


def _brief(v) -> str:
    s = str(v)
    return s if len(s) <= 80 else s[:77] + "..."


def four_states(*, now: datetime, rpo_seconds: int, rto_seconds: int, copies_required: int, copies_present: int,
                last_success: datetime | None, last_snapshot_id: str | None, last_check: dict | None, recovery_key_exported: bool,
                last_restore: dict | None, check_max_age: int, restore_max_age: int, last_run_failed: bool = False) -> dict:
    """The four states for one policy. last_check / last_restore: {finished_at, passed, snapshot_id, rto_seconds?} or None."""
    rs, age = rpo_state(last_success, now, rpo_seconds)
    bs = {"state": "failed" if last_success is None or last_run_failed else rs, "age_seconds": age, "rpo_seconds": rpo_seconds,
          "snapshot": last_snapshot_id}
    rep_ok = last_success is not None and copies_present >= copies_required
    rep = {"state": "ok" if rep_ok else "unprotected" if last_success is None else "degraded", "copies": copies_present, "required": copies_required}
    chk_age = None if not last_check else int((now - last_check["finished_at"]).total_seconds())
    ready_reasons = []
    if last_success is None or rs != "ok":
        ready_reasons.append("no snapshot within the RPO")
    if not last_check:
        ready_reasons.append("repository was never checked")
    elif not last_check["passed"]:
        ready_reasons.append("repository check has not passed")
    elif chk_age is not None and chk_age > check_max_age:
        ready_reasons.append("repository check is stale")
    if not recovery_key_exported:
        ready_reasons.append("offline recovery key not exported")
    ready = {"state": "ready" if not ready_reasons else "not_ready", "reasons": ready_reasons, "last_check_age_seconds": chk_age}
    vr_age = None if not last_restore else int((now - last_restore["finished_at"]).total_seconds())
    if not last_restore:
        vr = {"state": "never_verified", "age_seconds": None}
    elif not last_restore["passed"]:
        vr = {"state": "failed", "age_seconds": vr_age, "snapshot": last_restore.get("snapshot_id")}
    elif vr_age is not None and vr_age > restore_max_age:
        vr = {"state": "stale", "age_seconds": vr_age, "snapshot": last_restore.get("snapshot_id"), "rto_seconds": last_restore.get("rto_seconds")}
    else:
        rto = last_restore.get("rto_seconds")
        vr = {"state": "verified" if rto is None or rto <= rto_seconds else "verified_rto_exceeded", "age_seconds": vr_age,
              "snapshot": last_restore.get("snapshot_id"), "rto_seconds": rto, "rto_target_seconds": rto_seconds}
    return {"backup_success": bs, "replication": rep, "recovery_readiness": ready, "verified_restore": vr}


def key_fingerprint(secret: str) -> str:
    """Non-reversible short identifier that lets the owner match a printed recovery key to a repository without ever storing the key."""
    return hashlib.sha256(b"ou-backup-key-fp-v1\n" + secret.encode()).hexdigest()[:16]
