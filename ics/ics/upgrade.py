"""Pre-upgrade checks for the packaged ICS (`python -m ics.cli upgrade-preflight`).

Pure decision logic (`evaluate`) is separated from fact gathering (`gather`) so it can be tested without a host.
Levels: FAIL blocks the upgrade (exit 1), WARN is reported, OK/INFO are informational.
A stale or missing backup is only a WARN: the ou-ics package takes its own pre-upgrade backup before it touches anything and refuses
to continue when that fails. What FAILs here is what the package cannot fix by itself: no room for that backup, a job in flight,
a database that cannot be read, or a database schema newer than the code (a downgrade needs the restore path, docs/runbooks/ics-upgrade-rollback.md).
"""
from __future__ import annotations

import os
import re
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_BACKUP_DIR = "/var/backups/office-unbound/ics"
MAX_BACKUP_AGE_S = 24 * 3600
MIN_FREE_FACTOR = 3.0            # free space on the backup volume must be >= 3x the database size (dump + tar + copy of etc/release)
MIN_FREE_BYTES = 512 * 1024 * 1024
MIN_FREE_OPT = 300 * 1024 * 1024   # new code + venv are unpacked next to the old ones


@dataclass
class Facts:
    db_ok: bool = True
    db_size_bytes: int = 0
    free_backup_bytes: int = 0
    free_opt_bytes: int = 0
    last_backup_epoch: float | None = None
    last_backup_head: str | None = None
    db_head: str | None = None
    code_heads: list[str] = field(default_factory=list)       # alembic heads of the code that is about to be installed (or is installed)
    code_revisions: set[str] = field(default_factory=set)
    queued_jobs: int = 0
    running_jobs: int = 0
    running_deployments: int = 0
    worker_enabled: bool = True
    monitor_enabled: bool = True
    now: float = field(default_factory=time.time)


@dataclass
class Check:
    name: str
    level: str          # OK | INFO | WARN | FAIL
    detail: str


def _mb(n: int) -> str:
    return f"{n / 1048576:.0f} MiB"


def evaluate(f: Facts, max_backup_age_s: int = MAX_BACKUP_AGE_S) -> list[Check]:
    out: list[Check] = []
    add = lambda n, lv, d: out.append(Check(n, lv, d))    # noqa: E731
    # database
    if not f.db_ok:
        add("database", "FAIL", "the database cannot be read with the ICS credentials; fix that first, no backup is possible without it")
    else:
        add("database", "OK", f"reachable, {_mb(f.db_size_bytes)}")
    # disk
    need = max(MIN_FREE_BYTES, int(f.db_size_bytes * MIN_FREE_FACTOR))
    if f.free_backup_bytes < need:
        add("disk.backup", "FAIL", f"{_mb(f.free_backup_bytes)} free on the backup volume, need >= {_mb(need)} (3x database size, min 512 MiB)")
    else:
        add("disk.backup", "OK", f"{_mb(f.free_backup_bytes)} free (need {_mb(need)})")
    if f.free_opt_bytes < MIN_FREE_OPT:
        add("disk.opt", "FAIL", f"{_mb(f.free_opt_bytes)} free under /opt, need >= {_mb(MIN_FREE_OPT)} for the new code and virtualenv")
    else:
        add("disk.opt", "OK", f"{_mb(f.free_opt_bytes)} free")
    # backup freshness
    if f.last_backup_epoch is None:
        add("backup", "WARN", "no ICS backup found; the package takes one automatically before migrating and aborts if that fails")
    else:
        age = f.now - f.last_backup_epoch
        if age > max_backup_age_s:
            add("backup", "WARN", f"newest backup is {age / 3600:.1f} h old (> {max_backup_age_s / 3600:.0f} h); a fresh one is taken automatically before migrating")
        else:
            add("backup", "OK", f"newest backup is {age / 60:.0f} min old")
    # jobs
    if f.running_jobs or f.running_deployments:
        add("jobs.running", "FAIL", f"{f.running_jobs} job(s) and {f.running_deployments} deployment(s) are running; an upgrade restarts the worker and would orphan them. Wait or cancel")
    else:
        add("jobs.running", "OK", "no job or deployment is running")
    if f.queued_jobs:
        add("jobs.queued", "WARN", f"{f.queued_jobs} queued job(s) will start after the upgrade (the worker restarts)")
    else:
        add("jobs.queued", "OK", "no queued jobs")
    # standby / passive controller
    if not f.worker_enabled or not f.monitor_enabled:
        add("standby", "WARN", "this controller is PASSIVE (ICS_WORKER_ENABLED/ICS_MONITOR_ENABLED=false: a restored or standby copy). The upgrade keeps that setting; "
            "do not upgrade a standby that is out of step with the active controller's schema/version")
    else:
        add("standby", "OK", "active controller (worker and monitor enabled)")
    # schema
    if f.db_ok and not f.db_head:
        add("schema", "WARN", "database schema revision could not be read (run the preflight as root so the owner role can read alembic_version)")
    elif f.db_ok and f.code_revisions:
        if f.db_head in f.code_heads:
            add("schema", "OK", f"database schema {f.db_head} is the head of the installed code")
        elif f.db_head in f.code_revisions:
            add("schema", "INFO", f"database schema {f.db_head} is behind the code heads {','.join(f.code_heads)}: migrations will run")
        else:
            add("schema", "FAIL", f"database schema {f.db_head} is unknown to this code: it was migrated by a NEWER version. Roll back with the pre-upgrade backup restore, not alembic downgrade")
    return out


def verdict(checks: list[Check]) -> int:
    return 1 if any(c.level == "FAIL" for c in checks) else 0


def _newest_backup(backup_dir: str) -> tuple[float | None, str | None]:
    best: tuple[float, str | None] | None = None
    p = Path(backup_dir)
    try:
        entries = list(p.iterdir())
    except OSError:
        return None, None
    for d in entries:
        m = d / "MANIFEST"
        try:
            kv = dict(l.split("=", 1) for l in m.read_text().splitlines() if "=" in l)
            ts = time.mktime(time.strptime(kv["created_utc"], "%Y%m%dT%H%M%SZ")) - time.timezone
            if not (d / "ics-backup.tar").is_file():
                continue
        except (OSError, KeyError, ValueError):
            continue
        if best is None or ts > best[0]:
            best = (ts, kv.get("alembic_head"))
    return (best[0], best[1]) if best else (None, None)


def _code_revisions(versions_dir: Path) -> tuple[list[str], set[str]]:
    revs: dict[str, str | None] = {}
    for f in versions_dir.glob("*.py"):
        t = f.read_text()
        m = re.search(r"^revision\s*(?::\s*\w+)?\s*=\s*['\"]([^'\"]+)['\"]", t, re.M)
        d = re.search(r"^down_revision\s*(?::[^=]+)?=\s*(?:['\"]([^'\"]+)['\"]|None)", t, re.M)
        if m:
            revs[m.group(1)] = d.group(1) if d else None
    downs = {v for v in revs.values() if v}
    return sorted(set(revs) - downs), set(revs)


def _owner_head() -> str | None:
    try:
        from sqlalchemy import create_engine, text

        from .config import load_migrate_url
        eng = create_engine(load_migrate_url())
        try:
            with eng.connect() as c:
                return c.execute(text("SELECT version_num FROM alembic_version")).scalar()
        finally:
            eng.dispose()
    except Exception:  # noqa: BLE001  (not root / no owner file: schema check is skipped, reported as unknown)
        return None


def gather(db, settings, backup_dir: str = DEFAULT_BACKUP_DIR, opt_dir: str = "/opt/office-unbound",
           versions_dir: str | None = None) -> Facts:
    from sqlalchemy import text
    f = Facts(worker_enabled=settings.worker_enabled, monitor_enabled=settings.monitor_enabled)
    vd = Path(versions_dir or Path(__file__).resolve().parent.parent / "migrations" / "versions")
    f.code_heads, f.code_revisions = _code_revisions(vd)
    def one(sql):
        try:
            return db.execute(text(sql)).scalar()
        except Exception:  # noqa: BLE001
            db.rollback()
            raise

    try:
        f.db_size_bytes = int(one("SELECT pg_database_size(current_database())") or 0)
        f.queued_jobs = int(one("SELECT count(*) FROM jobs WHERE status = 'queued'") or 0)
        f.running_jobs = int(one("SELECT count(*) FROM jobs WHERE status = 'running'") or 0)
    except Exception:  # noqa: BLE001
        f.db_ok = False
    try:
        f.running_deployments = int(one("SELECT count(*) FROM deployments WHERE status IN ('provisioning','changing','destroying')") or 0)
    except Exception:  # noqa: BLE001  (an older schema may differ: the jobs count still covers it)
        pass
    # alembic_version is not granted to the runtime role: read it with the owner URL (root-only file) when the app role cannot
    try:
        f.db_head = one("SELECT version_num FROM alembic_version")
    except Exception:  # noqa: BLE001
        f.db_head = _owner_head()
    probe = backup_dir
    while not os.path.isdir(probe) and probe != "/":
        probe = os.path.dirname(probe)
    f.free_backup_bytes = shutil.disk_usage(probe).free
    probe = opt_dir
    while not os.path.isdir(probe) and probe != "/":
        probe = os.path.dirname(probe)
    f.free_opt_bytes = shutil.disk_usage(probe).free
    f.last_backup_epoch, f.last_backup_head = _newest_backup(backup_dir)
    return f


def render(checks: list[Check]) -> str:
    lines = [f"{c.level:<5} {c.name:<14} {c.detail}" for c in checks]
    lines.append("RESULT: " + ("NOT READY (fix the FAIL lines)" if verdict(checks) else "ready to upgrade"))
    return "\n".join(lines)
