"""Read-only system information for Administration > System (admin only): version, schema state, readiness, background threads,
database and disk size, last backup. Nothing here returns secrets, key paths or connection strings."""
import os
import shutil
import time
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from . import audit, epoch, standby
from . import version as ver
from .auth import User, get_db, require

BACKUP_DIR = os.environ.get("ICS_BACKUP_DIR", "/var/backups/office-unbound/ics")


def _last_backup() -> dict:
    """Backups are timestamped directories (YYYYmmddTHHMMSSZ, see deploy/backup/ics-backup.sh). Unreadable or absent -> unknown."""
    try:
        names = sorted(n for n in os.listdir(BACKUP_DIR) if len(n) == 16 and n.endswith("Z") and n[8] == "T")
    except OSError:
        return {"known": False, "at": None}
    if not names:
        return {"known": True, "at": None}
    try:
        at = datetime.strptime(names[-1], "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return {"known": False, "at": None}
    return {"known": True, "at": at.isoformat()}


def register(app: FastAPI, rt, API: str, worker) -> None:
    @app.get(f"{API}/system")
    def system(user: User = Depends(require("admin")), db: Session = Depends(get_db)):
        if getattr(user, "customer_ids", None) is not None:
            raise HTTPException(404, "not found")     # review 5 L5 / review 7: exact version, commit and schema of the ICS host are for all-customers admins only
        s = rt.settings
        checks: dict = {}
        head = size = hb_age = None
        try:
            db.execute(text("SELECT 1"))
            checks["database"] = True
            size = db.execute(text("SELECT pg_database_size(current_database())")).scalar()
            hb = db.execute(text("SELECT max(at) FROM worker_heartbeat")).scalar()
            hb_age = (datetime.now(timezone.utc) - hb).total_seconds() if hb else None
            checks["worker"] = hb_age is not None and hb_age <= s.heartbeat_max_age_seconds
            checks["audit_chain"] = bool(audit.verify_chain(db, tail=200)["ok"])
        except Exception:  # noqa: BLE001
            db.rollback()
            checks.setdefault("database", False)
        try:  # the service role may not be allowed to read the schema-version table; then the head is simply unknown
            head = db.execute(text("SELECT version_num FROM alembic_version")).scalar()
        except Exception:  # noqa: BLE001
            db.rollback()
        now = time.monotonic()
        threads = []
        if worker is not None:
            stall = {"jobs": worker.job_stall_seconds, "monitor": worker.monitor_stall_seconds, "inventory": worker.monitor_stall_seconds}
            for name in ("jobs", "monitor", "inventory", "heartbeat"):
                t = worker.threads.get(name)
                if t is None:
                    threads.append({"name": name, "state": "off", "last_progress_seconds": None})
                    continue
                age = now - worker.progress[name] if name in worker.progress else None
                ok = t.is_alive() and (age is None or age <= stall[name])
                threads.append({"name": name, "state": "ok" if ok else "stalled", "last_progress_seconds": round(age) if age is not None else None})
        try:
            du = shutil.disk_usage("/var/lib" if os.path.isdir("/var/lib") else "/")
            disk = {"total": du.total, "free": du.free}
        except OSError:
            disk = None
        controller = {"role": s.role, "epoch": None, "fenced": None, "node_name": None, "changed_at": None, "replication": None, "last_promotion": None,
                      "max_lag_seconds": s.standby_max_lag_seconds}
        try:
            st = epoch.get_state(db)
            controller.update(epoch=st["epoch"], fenced=st["role"] != "primary", node_name=st["node_name"], changed_at=st["changed_at"])
            if s.role == "standby":
                controller["replication"] = standby.replication_status(db, s.standby_max_lag_seconds)
            lp = db.execute(text("SELECT at, actor_name, resource_id, details FROM audit_events WHERE action = 'controller.promoted' ORDER BY seq DESC LIMIT 1")).first()
            if lp is not None:
                d = lp.details or {}
                controller["last_promotion"] = {"at": lp.at.isoformat(), "by": lp.actor_name, "host": lp.resource_id, "old_epoch": d.get("old_epoch"), "new_epoch": d.get("new_epoch"),
                                                "last_replayed_commit": d.get("last_replayed_commit")}
        except Exception:  # noqa: BLE001
            db.rollback()
        bi = ver.build_info()
        return {"product": bi["product"], "version": ver.__version__, "commit": bi.get("commit"), "dirty": bi.get("dirty"), "built_at": bi.get("built_at"),
                "build_source": bi.get("source"), "api": ver.API_VERSION, "schema": {"build_head": bi.get("schema_head"), "database": head},
                "components": {"ics": ver.__version__, **bi.get("components", {})}, "interfaces": bi.get("interfaces", {}),
                "updates": ver.update_status(),   # read-only comparison with the bundled release list; no network
                "migration_head": head, "ready": len(checks) == 3 and all(checks.values()), "checks": checks,
                "heartbeat_age_seconds": round(hb_age) if hb_age is not None else None, "worker_enabled": worker is not None,
                "threads": threads, "database_bytes": size, "disk": disk, "backup": _last_backup(), "controller": controller}
