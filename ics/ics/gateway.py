"""Gateway certificates (ADR-0018 G2/G3, section 11): publicly trusted certificates for a deployment's web names, issued and renewed BY THE
GATEWAY VM itself (agent runbook cfg.acme: certbot HTTP-01 + its own renewal timer), so renewals continue while the ICS is down.

Typed action gateway.certificates.issue {deployment, directory}: staging proves the names validate from the internet (no trusted certificate is
served); production obtains the real certificate and switches the gateway's sites to it (the internal deployment CA keeps verifying the hops to
the other VMs). The ICS keeps only the state (which deployment serves public certificates, for which names), never a private key."""
from __future__ import annotations

import json
import time
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text

from . import audit
from .guest import agentcall
from .deploy import appaccess, configure

STATE_KEY = "gateway.certificates"


class CertIssue(BaseModel):
    model_config = ConfigDict(extra="forbid")
    deployment: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,30}$")
    directory: Literal["staging", "production"] = "staging"


def risk(p: CertIssue) -> str:
    return "normal" if p.directory == "production" else "low"


class GatewayError(Exception):
    pass


def state(db) -> dict:
    row = db.execute(text("SELECT value FROM system_settings WHERE key = :k"), {"k": STATE_KEY}).first()
    return dict(row.value) if row else {}


def public_for(rt, slug: str) -> dict | None:
    """The deployment's public-certificate state, or None (sites keep the deployment certificate)."""
    with rt.session() as db:
        return state(db).get(slug)


def _put_state(db, st: dict) -> None:
    db.execute(text("INSERT INTO system_settings (key, value, updated_at, updated_by) VALUES (:k, CAST(:v AS jsonb), now(), 'gateway') "
                    "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now(), updated_by = EXCLUDED.updated_by"),
               {"k": STATE_KEY, "v": json.dumps(st)})


def web_names(plan: dict, tenant: str | None = None) -> list[str]:
    """The names the gateway serves for a scope (portal, sign-in, files, documents, and mail/autodiscover when the groupware has its own VM):
    exactly what the certificate must cover."""
    edge = configure.vm_of(plan, "edge", tenant) or configure.vm_of(plan, "edge", None)
    names = {configure.fq(plan, tenant, label) for label, (comp, _) in configure.LOCAL_PORT.items() if configure.vm_of(plan, comp, tenant)}
    names |= {configure.fq(plan, tenant, label) for label, comp in configure.EDGE_HTTPS.items()
              if configure.vm_of(plan, comp, tenant) and configure.vm_of(plan, comp, tenant) != edge}
    return sorted(names)


def _edge(plan: dict) -> str:
    vm = configure.vm_of(plan, "edge", None)
    if vm is None:
        raise GatewayError("this deployment has no gateway (edge) VM in the deployment scope")
    return vm


def _run(rt, node_id: str, runbook: str, params: dict) -> dict:
    resp = agentcall.execute(rt, node_id, runbook, params, deadline=900.0)
    res = resp.get("result") if isinstance(resp.get("result"), dict) else {}
    if resp.get("status") != "ok" or "rejected" in res:
        rej = res.get("rejected") or {}
        raise GatewayError(f"{runbook} refused: {rej.get('code') or resp.get('code')}: {str(rej.get('message') or res.get('message') or '')[:300]}")
    inner = res.get("result") if isinstance(res.get("result"), dict) else res
    if inner.get("error"):
        raise GatewayError(f"{runbook} failed: {str(inner['error'])[:900]}")
    return inner


def _edge_node(db, d, edge: str) -> str | None:
    return db.execute(text("SELECT provider_ref->>'agent_node_id' FROM deployment_resources WHERE deployment_id = :d AND kind = 'vm' "
                           "AND logical_name = :n"), {"d": str(d.id), "n": edge}).scalar()


class _Ctx:
    """What configure.edge_runbooks needs, outside a deployment job."""
    def __init__(self, rt, d, plan, addresses):
        self.rt, self.deployment_id, self.slug, self.plan = rt, str(d.id), d.slug, plan
        agent = type("A", (), {"address": staticmethod(lambda vm: addresses[vm])})()
        self.env = type("E", (), {"agent": agent})()


def exec_issue(rt, db, m: CertIssue, plan_row, known) -> dict:
    d = db.execute(text("SELECT * FROM deployments WHERE slug = :s AND status NOT IN ('destroyed', 'destroying')"), {"s": m.deployment}).first()
    if d is None:
        raise GatewayError(f"deployment {m.deployment} not found")
    plan = appaccess._applied_plan(db, d)
    if plan is None:
        raise GatewayError("the deployment has no applied plan yet")
    edge = _edge(plan)
    node = _edge_node(db, d, edge)
    if not node:
        raise GatewayError(f"the gateway VM {edge} has no enrolled agent")
    names = web_names(plan)
    cert_name = "public" if m.directory == "production" else "public-staging"
    t0 = time.monotonic()
    res = _run(rt, node, "cfg.acme", {"names": names, "directory": m.directory, "cert_name": cert_name})
    switched = []
    if m.directory == "production":
        st = state(db)
        st[m.deployment] = {"names": names, "cert_name": cert_name, "issued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                            "certificate": res.get("certificate", "")[:300]}
        _put_state(db, st)
        db.commit()   # the edge configuration below reads it
        ctx = _Ctx(rt, d, plan, appaccess._addresses(db, d))
        for rb in configure.edge_runbooks(ctx, edge):
            if rb["runbook"] in ("cfg.nginx_site", "cfg.nginx_default"):
                _run(rt, node, rb["runbook"], rb["params"])
                switched.append(rb["params"].get("name", rb["runbook"]))
        converted = convert_checks(db, d, names)
    else:
        converted = []
    audit.append(db, "gateway.certificate_issued", actor_name="worker", resource="deployment", resource_id=str(d.id),
                 details={"deployment": d.slug, "directory": m.directory, "names": names, "sites_switched": switched, "checks_converted": converted,
                          "certificate": res.get("certificate", "")[:300], "plan_id": str(plan_row.id), "seconds": int(time.monotonic() - t0)})
    return {"deployment": d.slug, "directory": m.directory, "names": names, "certificate": res.get("certificate"), "sites_switched": switched,
            "checks_converted": converted}


LE_ROOTS = ("/etc/ssl/certs/ISRG_Root_X1.pem", "/etc/ssl/certs/ISRG_Root_X2.pem")


def convert_checks(db, d, names: list[str], roots: tuple[str, ...] = LE_ROOTS) -> list[str]:
    """The gateway's TLS checks run on the gateway VM and trust ONLY the deployment CA (agent guest.probe, by design). Once a name serves the
    public certificate they would fail forever (2026-11-20: edge-tls critical right after the switch). Convert them in place into the ICS's own
    TLS check of the public name, pinned to Let's Encrypt's roots, which also warns before expiry (21 days) and goes critical at 7: same check
    id, so an open incident recovers on its own."""
    from . import checks as checkmod
    pem = "".join(open(r).read() for r in roots)
    out = []
    for c in db.execute(text("SELECT id, name, config FROM checks WHERE deployment_id = :d AND kind = 'agent_probe'"), {"d": str(d.id)}).all():
        pr = (c.config or {}).get("probe") or {}
        if pr.get("kind") != "tls" or pr.get("server_name") not in names or int(pr.get("port") or 0) != 443:
            continue
        cfg = checkmod.validate_config("tcp_tls", {"host": pr["server_name"], "port": 443, "ca_pem": pem})
        db.execute(text("UPDATE checks SET kind = 'tcp_tls', config = CAST(:c AS jsonb), enabled = true, next_run_at = now() WHERE id = :i"),
                   {"c": json.dumps(cfg), "i": str(c.id)})
        out.append(c.name)
    return out
