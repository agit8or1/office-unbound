"""The installation's tenancy mode (owner 2026-11-20: "system should have two modes; single tenant mode and multi tenant mode").

* single: one organisation. No customer / MSP screens; deployments are the organisation's own; accounts are its people.
* multi:  an MSP hosting separate customers, each with its own isolated stack, domains and administrators (the existing per-customer
          isolation: customers, tenant scopes, per-tenant CAs and secrets).
Chosen once (setup or Settings) and shown afterwards. While any deployment exists, a different mode is refused: converting live
deployments needs a migration plan that does not exist yet, so it is reported as unavailable instead of being half-done."""
from __future__ import annotations

import json
from typing import Literal

from fastapi import Depends
from pydantic import BaseModel, ConfigDict
from sqlalchemy import text
from sqlalchemy.orm import Session

KEY = "system.tenancy"


class TenancyMode(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["single", "multi"]


class ModeLocked(Exception):
    pass


def get(db) -> str | None:
    row = db.execute(text("SELECT value FROM system_settings WHERE key = :k"), {"k": KEY}).first()
    return (row.value or {}).get("mode") if row else None


def live_deployments(db) -> int:
    return int(db.execute(text("SELECT count(*) FROM deployments WHERE status NOT IN ('destroyed')")).scalar() or 0)


def exec_set(rt, db, m: TenancyMode, plan, known) -> dict:
    from . import audit
    old = get(db)
    n = live_deployments(db)
    if old is not None and old != m.mode and n:
        raise ModeLocked(f"the installation runs {n} deployment(s) in {old}-tenant mode: converting them is not available yet "
                         "(it needs a migration plan with backup and approval); destroy them first or keep the mode")
    db.execute(text("INSERT INTO system_settings (key, value, updated_at, updated_by) VALUES (:k, CAST(:v AS jsonb), now(), :b) "
                    "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now(), updated_by = EXCLUDED.updated_by"),
               {"k": KEY, "v": json.dumps({"mode": m.mode}), "b": f"plan:{plan.id}"})
    audit.append(db, "settings.tenancy_set", actor_name="worker", resource="settings", resource_id=KEY,
                 details={"old": old, "new": m.mode, "deployments": n, "requested_by": str(plan.requested_by), "plan_id": str(plan.id)})
    return {"mode": m.mode}


def register_routes(app, rt) -> None:
    from .auth import User, get_db, require

    @app.get("/api/v1/settings/tenancy")
    def tenancy(user: User = Depends(require("viewer")), db: Session = Depends(get_db)):
        n = live_deployments(db)
        mode = get(db)
        return {"mode": mode, "deployments": n, "can_change": mode is None or n == 0,
                "note": None if (mode is None or n == 0) else "Changing the mode with deployments present is not available yet (needs a migration plan)."}
