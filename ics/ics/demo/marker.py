"""The ICS-side demo marker: typed action demo.deployment.mark {deployment, demo, confirm}. Admin only, high risk, approved like any
plan and recorded in the hash-chained audit log. It is the only way a deployment becomes a target of the demo seeding tool
(guard.check_marker), and it is refused for a deployment whose slug or domain carries no demo label or that is a production
deployment (guard.check_names), so marking can never reach officeunbound8. The marker (system_settings 'deployment.demo') is bound to the
deployment's id and domain. demo=false removes it."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import text

from .. import audit
from . import guard

ACTION = "demo.deployment.mark"


class DemoMark(BaseModel):
    model_config = ConfigDict(extra="forbid")
    deployment: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,30}$")
    demo: bool = True
    confirm: str = Field(description="the deployment slug typed again")

    @model_validator(mode="after")
    def _confirm(self):
        if self.confirm != self.deployment:
            raise ValueError("confirm must repeat the deployment slug exactly")
        return self


def _target(db, slug: str):
    from ..deploy import appaccess, configure
    d = db.execute(text("SELECT * FROM deployments WHERE slug = :s AND status NOT IN ('destroyed', 'destroying')"), {"s": slug}).first()
    if d is None:
        return None, None
    plan = appaccess._applied_plan(db, d)
    domain = configure.scope(plan, None)["domain"] if plan else (d.desired_spec or {}).get("domain")
    return d, domain


def precheck(db, rt, p: DemoMark) -> dict:
    from ..actions import PlanError
    d, domain = _target(db, p.deployment)
    if d is None:
        raise PlanError(404, f"deployment {p.deployment} not found")
    if p.demo:
        if not domain:
            raise PlanError(422, "the deployment has no domain yet")
        try:
            guard.check_names(p.deployment, domain)
        except guard.DemoRefused as e:
            raise PlanError(422, str(e)) from None
    return {"domain": domain}


def _store(db, value: dict) -> None:
    db.execute(text("INSERT INTO system_settings (key, value, updated_at, updated_by) VALUES (:k, CAST(:v AS jsonb), now(), 'demo') "
                    "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now(), updated_by = EXCLUDED.updated_by"),
               {"k": guard.MARK_KEY, "v": json.dumps(value)})


def marks(db) -> dict:
    row = db.execute(text("SELECT value FROM system_settings WHERE key = :k"), {"k": guard.MARK_KEY}).first()
    return dict(row.value or {}) if row else {}


def exec_mark(rt, db, m: DemoMark, plan_row, known: list[str]) -> dict:
    d, domain = _target(db, m.deployment)
    if d is None:
        raise ValueError(f"deployment {m.deployment} not found")
    cur = marks(db)
    if m.demo:
        guard.check_names(m.deployment, domain)      # re-checked at execution: the domain may have changed since the plan
        cur[m.deployment] = {"deployment_id": str(d.id), "domain": domain, "marked_at": datetime.now(timezone.utc).isoformat(),
                             "plan_id": str(plan_row.id)}
    else:
        cur.pop(m.deployment, None)
    _store(db, cur)
    audit.append(db, "deployment.demo_marked" if m.demo else "deployment.demo_unmarked", actor_name="worker", resource="deployment",
                 resource_id=str(d.id), details={"deployment": m.deployment, "domain": domain, "plan_id": str(plan_row.id)})
    return {"deployment": m.deployment, "demo": m.demo, "domain": domain}


SPECS = {ACTION: {"model": DemoMark, "risk": "high", "secrets": (), "admin_only": True}}
EXECUTORS = {ACTION: exec_mark}
PRECHECK = {ACTION: precheck}
