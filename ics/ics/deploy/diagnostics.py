"""Read-only diagnostics of a deployment's VMs: the last lines of an allowlisted service journal or log file, read by the node agent's
`guest.journal` runbook (agent >= 0.8.1, agent/ou_agent/diagspec.py) and redacted on the VM before they leave it.

This is a READ, not a mutation: no plan, no approval. Administrators only, scoped like every deployment endpoint (a customer-scoped administrator
sees only its customers' deployments); the VM must belong to the deployment and its agent must have reported the runbook at enrollment. Every
read is audited (who, which VM, which unit/file, how many lines, the outcome) WITHOUT the log content. The request carries keys of fixed tables
only; the agent validates them again against its own copy (tests keep the two in sync) and maps them to fixed journal matches / paths."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import text

from .. import agentclient, audit
from ..guest import agentcall
from . import appaccess

RUNBOOK = "guest.journal"
# keep in sync with agent/ou_agent/diagspec.py UNITS / FILES / GREPS (test_diagnostics.py checks it)
UNITS = ("nginx", "php8.3-fpm", "gromox-http", "gromox-zcore", "gromox-midb", "gromox-imap", "gromox-pop3", "gromox-delivery", "gromox-delivery-queue",
         "gromox-event", "gromox-timer", "postfix", "saslauthd", "redis-server", "mariadb", "slapd", "postgresql", "ou-portal", "certbot", "certbot-timer",
         "ou-agent", "ou-bootstrap", "keycloak", "opencloud", "opencloud-collaboration", "collabora")
FILES = ("nginx-error", "nginx-access", "php8.3-fpm", "gromox-php-fpm", "grommunio-sync", "grommunio-sync-error", "grommunio-dav", "letsencrypt")
GREPS = ("error", "warning", "php", "http-5xx", "denied", "timeout", "start-stop")
Unit = Literal[UNITS]          # type: ignore[valid-type]
File = Literal[FILES]          # type: ignore[valid-type]
Grep = Literal[GREPS]          # type: ignore[valid-type]

# what the console suggests first for a VM, by the components the plan put on it (any allowlisted unit/file can still be chosen)
SUGGESTED = {
    "groupware": {"units": ["php8.3-fpm", "gromox-zcore", "gromox-http", "nginx", "gromox-midb", "gromox-imap", "gromox-delivery", "postfix", "mariadb"],
                  "files": ["php8.3-fpm", "nginx-error", "gromox-php-fpm", "grommunio-sync-error", "grommunio-dav"]},
    "identity": {"units": ["keycloak", "slapd", "postgresql"], "files": []},
    "files": {"units": ["opencloud", "opencloud-collaboration", "nginx"], "files": ["nginx-error"]},
    "office": {"units": ["collabora"], "files": []},
    "edge": {"units": ["nginx", "certbot", "certbot-timer"], "files": ["nginx-error", "nginx-access", "letsencrypt"]},
    "portal": {"units": ["ou-portal", "nginx"], "files": ["nginx-error"]},
}
ALWAYS = {"units": ["ou-agent", "ou-bootstrap"], "files": []}


class LogsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    vm: str = Field(pattern=r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
    unit: Unit | None = None
    file: File | None = None
    lines: int = Field(100, ge=1, le=300)
    since_minutes: int | None = Field(None, ge=1, le=1440)
    grep: Grep | None = None

    @model_validator(mode="after")
    def _one(self):
        if (self.unit is None) == (self.file is None):
            raise ValueError("give exactly one of unit or file")
        if self.file is not None and self.since_minutes is not None:
            raise ValueError("since_minutes applies to a unit's journal only")
        return self

    def params(self) -> dict:
        p = {"lines": self.lines, **({"unit": self.unit} if self.unit else {"file": self.file})}
        if self.since_minutes is not None:
            p["since_minutes"] = self.since_minutes
        if self.grep is not None:
            p["grep"] = self.grep
        return p


class DiagError(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status = status


def _vms(db, d) -> dict[str, dict]:
    """VM logical name -> {node, capable} for the deployment's live VMs."""
    rows = db.execute(text("SELECT r.logical_name, r.provider_ref->>'agent_node_id' AS node, n.capabilities FROM deployment_resources r "
                           "LEFT JOIN nodes n ON n.id::text = r.provider_ref->>'agent_node_id' "
                           "WHERE r.deployment_id = :d AND r.kind = 'vm' AND r.state <> 'removed' ORDER BY r.logical_name"), {"d": str(d.id)}).all()
    return {r.logical_name: {"node": r.node, "capable": bool(r.node) and RUNBOOK in (r.capabilities or {})} for r in rows}


def sources(db, d) -> dict:
    plan = appaccess._applied_plan(db, d) or {}
    comps = {v.get("name"): list(v.get("components") or []) for v in plan.get("vms", [])}
    out = []
    for name, v in _vms(db, d).items():
        units, files = [], []
        for c in comps.get(name, []):
            units += SUGGESTED.get(c, {}).get("units", [])
            files += SUGGESTED.get(c, {}).get("files", [])
        units += ALWAYS["units"]
        out.append({"name": name, "components": comps.get(name, []), "enrolled": bool(v["node"]), "available": v["capable"],
                    "suggested_units": list(dict.fromkeys(units)), "suggested_files": list(dict.fromkeys(files))})
    return {"deployment": d.slug, "vms": out, "units": list(UNITS), "files": list(FILES), "greps": list(GREPS), "max_lines": 300}


def read_logs(rt, db, d, body: LogsIn, user, ip: str | None) -> dict:
    vms = _vms(db, d)
    vm = vms.get(body.vm)
    what = {"unit": body.unit} if body.unit else {"file": body.file}
    base = {"deployment": d.slug, "vm": body.vm, **what, "lines": body.lines, "since_minutes": body.since_minutes, "grep": body.grep}

    def _audit(outcome: str, **extra):
        audit.append(db, "deployment.diagnostics_logs_read", actor_id=user.id, actor_name=user.username, ip=ip, resource="deployment",
                     resource_id=str(d.id), details={**base, "outcome": outcome, **extra})
        db.commit()

    if vm is None:
        _audit("refused_unknown_vm")
        raise DiagError(404, f"VM {body.vm} is not part of deployment {d.slug}")
    if not vm["node"]:
        _audit("refused_not_enrolled")
        raise DiagError(409, f"VM {body.vm} has no enrolled agent")
    if not vm["capable"]:
        _audit("refused_agent_too_old")
        raise DiagError(409, f"the agent on {body.vm} does not offer {RUNBOOK} (it needs node agent 0.8.1 or later, from a newer golden image)")
    try:
        resp = agentcall.execute(rt, vm["node"], RUNBOOK, body.params(), deadline=120.0)
    except (agentclient.AgentError, ValueError) as e:
        _audit("agent_unreachable")
        raise DiagError(502, f"the agent on {body.vm} could not be reached: {str(e)[:200]}") from None
    res = resp.get("result") if isinstance(resp.get("result"), dict) else {}
    if resp.get("status") != "ok" or "rejected" in res:
        rej = res.get("rejected") or {}
        code = str(rej.get("code") or resp.get("code"))[:60]
        _audit("rejected", agent_code=code)
        raise DiagError(422, f"{RUNBOOK} refused: {code}: {str(rej.get('message') or res.get('message') or '')[:300]}")
    inner = res.get("result") if isinstance(res.get("result"), dict) else {}
    if res.get("error") or not inner:
        _audit("failed")
        raise DiagError(502, f"{RUNBOOK} failed on {body.vm}: {str(res.get('error') or 'no result')[:200]}")
    lines = [str(x) for x in inner.get("lines", []) if isinstance(x, str)][:300]
    _audit("ok", returned_lines=len(lines), truncated=bool(inner.get("truncated")), error=bool(inner.get("error")))
    return {**base, "target": inner.get("target"), "scope": inner.get("scope"), "exists": inner.get("exists"), "error": inner.get("error"),
            "lines_returned": len(lines), "truncated": bool(inner.get("truncated")), "redacted": bool(inner.get("redacted")), "log": lines}
