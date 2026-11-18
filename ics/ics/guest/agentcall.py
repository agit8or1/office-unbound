"""Deployment-engine helper: send one guest runbook to an enrolled node through the signed agent protocol, with the same durable bookkeeping as
`runbook.execute` (the request row is written BEFORE the call, in its own transaction, so evidence survives a failed job) and an audit event.
The engine's executor steps call `execute()`; nothing here builds a command line - only a runbook name and typed params leave the ICS."""
from sqlalchemy import text

from .. import agentclient, audit
from ..deploy.configure import redact
from ..agentclient import AgentError

GUEST_RUNBOOKS = ("podman.pull_verified", "podman.deploy_unit", "podman.remove_unit", "podman.status", "guest.facts", "pkg.install_pinned",
                  "cfg.hosts", "cfg.tls", "cfg.ldap_init", "cfg.ldap_user", "cfg.pg_db", "cfg.podman_secret", "cfg.volume_files", "cfg.nginx_site", "cfg.firewall")


def execute(rt, node_id: str, action: str, params: dict, job_id: str | None = None, deadline: float = 600.0) -> dict:
    """Returns the agent response dict {status: ok|rejected|error, code, result}. Raises AgentError on transport/signature problems."""
    if action not in GUEST_RUNBOOKS:
        raise ValueError("not a guest runbook")
    with rt.session() as db:
        node = db.execute(text("SELECT * FROM nodes WHERE id = :i"), {"i": node_id}).first()
    if node is None:
        raise ValueError("unknown node")
    if action not in node.capabilities:
        raise ValueError("node does not offer this runbook")
    jid = job_id or agentclient.new_job_id()
    priv = agentclient.load_signing_key(rt.settings.signing_key_file)
    body = agentclient.build_request(priv, action=action, params=params, node_id=str(node.id), job_id=jid, ttl=rt.settings.agent_request_ttl_seconds, epoch=rt.agent_epoch())
    req = body["req"]
    with rt.session() as d2:
        d2.execute(text("INSERT INTO agent_requests (node_id, job_id, nonce, action, issued_at, expires_at) "
                        "VALUES (:n, :j, :nc, :a, to_timestamp(:i), to_timestamp(:e))"),
                   {"n": str(node.id), "j": jid, "nc": req["nonce"], "a": action, "i": req["issued_at"], "e": req["expires_at"]})
        d2.commit()
    code, resp = "transport_or_signature_error", {}
    try:
        _, resp = agentclient.call(node, priv, action=action, params=params, job_id=jid, deadline=deadline,
                                   allow_loopback=rt.settings.allow_loopback_endpoints, req_override=body)
        code = str(resp.get("code"))[:60]
    finally:
        with rt.session() as d2:
            d2.execute(text("UPDATE agent_requests SET status = :s, response_code = :c, finished_at = now() WHERE job_id = :j"),
                       {"s": "done" if code == "ok" else "failed", "c": code, "j": jid})
            audit.append(d2, "guest.runbook", actor_name="worker", resource="node", resource_id=str(node.id),
                         details={"runbook": action, "params": redact(action, params), "agent_status": resp.get("status", "error"), "agent_code": code, "job_id": jid})
            d2.commit()
    return resp


__all__ = ["execute", "AgentError", "GUEST_RUNBOOKS"]
