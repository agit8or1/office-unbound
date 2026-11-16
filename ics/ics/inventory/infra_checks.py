"""Check kind `infra`: infrastructure alert rules evaluated from what the inventory and metrics collectors ALREADY recorded (no extra Proxmox polling,
no agent, nothing installed in guests). Results feed the existing check state machine: flap damping, incidents, escalation, maintenance windows,
notifications (email / webhook; SMS and Pushover stay opt-in per ADR-0007).

Rules (target = a node name / VMID / storage name, or "*" for every one the read token can see):
  node_offline     node status is not "online"
  guest_stopped    guest is not running (for guests that should run; "unexpectedly stopped" = configure it on the guests you expect to run)
  node_cpu         node CPU % >= warn_pct / crit_pct
  node_memory      node memory % >= warn_pct / crit_pct
  storage_used     storage used % >= warn_pct / crit_pct; an inactive storage is critical
Data older than `stale_after_seconds` is reported as STALE (warning), never as a reading: no value is ever estimated or fabricated.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import text

RULES = ("node_offline", "guest_stopped", "node_cpu", "node_memory", "storage_used")


class InfraCheckConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    endpoint_id: UUID
    rule: Literal["node_offline", "guest_stopped", "node_cpu", "node_memory", "storage_used"]
    target: str = Field(default="*", max_length=64)
    warn_pct: int = Field(default=85, ge=1, le=100)
    crit_pct: int = Field(default=95, ge=1, le=100)
    stale_after_seconds: int = Field(default=900, ge=120, le=86400)

    @model_validator(mode="after")
    def _v(self):
        if self.target != "*" and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}", self.target):
            raise ValueError("target is '*' or a node / VMID / storage name")
        if self.rule == "guest_stopped" and self.target != "*" and not self.target.isdigit():
            raise ValueError("guest_stopped targets a VMID or '*'")
        if self.warn_pct > self.crit_pct:
            raise ValueError("warn_pct must not exceed crit_pct")
        return self


def _pct(used, total):
    return None if not total else round(100.0 * float(used or 0) / float(total), 1)


def evaluate(rt, cfg: dict):
    from ..checks import Outcome
    c = InfraCheckConfig.model_validate(cfg)
    now = datetime.now(timezone.utc)
    q = {"e": str(c.endpoint_id), "t": c.target}
    with rt.session() as db:
        if c.rule in ("node_offline", "node_cpu", "node_memory"):
            rows = db.execute(text("SELECT name AS key, status, cpu_pct, mem_used, mem_total, observed_at FROM infra_nodes WHERE endpoint_id = :e "
                                   "AND (:t = '*' OR name = :t) ORDER BY name"), q).all()
        elif c.rule == "guest_stopped":
            rows = db.execute(text("SELECT vmid::text AS key, name, node, status, observed_at FROM infra_guests WHERE endpoint_id = :e "
                                   "AND (:t = '*' OR vmid::text = :t) ORDER BY vmid"), q).all()
        else:
            rows = db.execute(text("SELECT name AS key, node, active, enabled, used, total, observed_at FROM infra_storage WHERE endpoint_id = :e "
                                   "AND (:t = '*' OR name = :t) ORDER BY name, node"), q).all()
    if not rows:
        return Outcome("warning", f"no {c.rule.split('_')[0]} data recorded for target {c.target!r} (not visible to the read token, or never discovered)",
                       None, {"cause": "no_data", "rule": c.rule})
    crit, warn, stale, ok = [], [], [], 0
    for r in rows:
        age = (now - r.observed_at).total_seconds() if r.observed_at else None
        label = f"{r.key}" + (f"@{r.node}" if getattr(r, "node", None) and c.rule == "storage_used" else "")
        if age is None or age > c.stale_after_seconds:
            stale.append(f"{label} (last data {int(age // 60) if age is not None else '?'} min ago)")
            continue
        if c.rule == "node_offline":
            if r.status != "online":
                crit.append(f"{label} is {r.status}")
            else:
                ok += 1
        elif c.rule == "guest_stopped":
            if r.status != "running":
                crit.append(f"{label} {r.name or ''} is {r.status}".replace("  ", " "))
            else:
                ok += 1
        else:
            if c.rule == "node_cpu":
                v = None if r.cpu_pct is None else round(float(r.cpu_pct), 1)
            elif c.rule == "node_memory":
                v = _pct(r.mem_used, r.mem_total)
            else:
                if r.enabled is False:
                    ok += 1
                    continue
                if r.active is False:
                    crit.append(f"{label} is inactive")
                    continue
                v = _pct(r.used, r.total)
            if v is None:
                stale.append(f"{label} (metric not reported by Proxmox)")
            elif v >= c.crit_pct:
                crit.append(f"{label} {v}% >= {c.crit_pct}%")
            elif v >= c.warn_pct:
                warn.append(f"{label} {v}% >= {c.warn_pct}%")
            else:
                ok += 1
    d = {"rule": c.rule, "critical": crit[:50], "warning": warn[:50], "stale": stale[:50], "ok": ok}
    if crit:
        return Outcome("critical", "; ".join(crit[:5]) + (f" (+{len(crit) - 5} more)" if len(crit) > 5 else ""), None, d)
    if warn or stale:
        msg = "; ".join((warn + [f"STALE {s}" for s in stale])[:5])
        return Outcome("warning", msg, None, {**d, "cause": "stale" if stale and not warn else "threshold"})
    return Outcome("ok", f"{ok} ok", None, d)
