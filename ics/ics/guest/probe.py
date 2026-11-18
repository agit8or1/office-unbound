"""Check kind `agent_probe`: a deployment service's health, probed by the node agent on its own loopback (`guest.probe`, agent >= 0.5.0).

Deployment services listen on loopback or are open only to the deployment's own VMs, so the ICS cannot reach them; and a TLS service is
verified against the deployment CA for its own name. The engine registers every http / tcp_tls check of a deployed component as an
agent_probe (executor.h_register_checks); the monitor runs it here through the signed agent channel. No network destination of the ICS."""
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from ..agentclient import AgentError


class Probe(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[a-z][a-z0-9-]{0,62}$")
    kind: Literal["tcp", "tls", "http", "https"]
    port: int = Field(ge=1, le=65535)
    path: str | None = Field(default=None, pattern=r"^/[A-Za-z0-9._~/%?=&+-]{0,200}$")
    expect_status: int | None = Field(default=None, ge=100, le=599)
    body_contains: str | None = Field(default=None, pattern=r'^[\x20-\x7e]{1,100}$')
    server_name: str | None = Field(default=None, min_length=4, max_length=200, pattern=r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")


class AgentProbeCheck(BaseModel):
    model_config = ConfigDict(extra="forbid")
    node_id: UUID
    probe: Probe


def from_plan_check(c: dict, node_id: str, server_name: str | None) -> dict:
    """A plan check (catalog health_checks entry) as the agent probe that tests the same thing on the node."""
    if c["kind"] == "tcp_tls":
        p = {"name": c["name"][:63], "kind": "tls", "port": c["port"], "server_name": server_name}
    elif c["kind"] == "http":
        p = {"name": c["name"][:63], "kind": "http", "port": c["port"], "path": c.get("path") or "/", "expect_status": c.get("expect_status", 200)}
        if c.get("body_contains"):
            p["body_contains"] = c["body_contains"]
    else:
        raise ValueError(f"no agent probe for check kind {c['kind']}")
    return AgentProbeCheck.model_validate({"node_id": node_id, "probe": p}).model_dump(mode="json", exclude_none=True)


def evaluate(rt, cfg: dict):
    from .. import checks
    from . import agentcall
    c = AgentProbeCheck.model_validate(cfg)
    try:
        resp = agentcall.execute(rt, str(c.node_id), "guest.probe", {"probes": [c.probe.model_dump(exclude_none=True)]}, deadline=30.0)
    except (AgentError, ValueError) as e:
        return checks.Outcome("critical", f"node agent unreachable for the probe: {str(e)[:160]}", None, {"cause": "agent"})
    res = resp.get("result") if isinstance(resp.get("result"), dict) else {}
    rows = res.get("probes") if isinstance(res.get("probes"), list) else []
    if resp.get("status") != "ok" or len(rows) != 1:
        return checks.Outcome("critical", f"probe refused by the agent: {str(resp.get('code'))[:80]}", None, {"cause": "agent"})
    r = rows[0]
    return checks.Outcome("ok" if r.get("ok") else "critical", str(r.get("message", ""))[:200], None, {"probe": c.probe.name, "status": r.get("status")})
