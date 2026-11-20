"""Gateway certificates (ics/gateway.py, agent cfg.acme, ADR-0018 section 11): public certificates issued by the gateway itself, sites switched
to them while the hops to other VMs stay verified by the deployment CA, the sign-in host's front page sent to the portal."""
import json
import os
import sys

import pytest
from sqlalchemy import text

from ics import gateway, worker
from ics.deploy import appaccess, configure
from ics.deploy.plan import NameSettings, generate_plan

from .test_deploy_names import _ctx, _ok
from .test_deploy_plan import cap, inp, pinned

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))
from ou_agent import cfgspec as c  # noqa: E402
from ou_agent.proto import Reject  # noqa: E402


def _plan():
    return _ok(generate_plan(inp(names=NameSettings(hosts={"portal": "app.acme.example"})), cap(), pinned()))


def test_the_certificate_covers_exactly_the_gateways_web_names():
    assert gateway.web_names(_plan()) == ["app.acme.example", "auth.acme.example", "cloud.acme.example", "office.acme.example"]


def test_sites_switch_to_the_public_certificate_and_keep_the_internal_ca_for_hops(monkeypatch):
    p = _plan()
    ctx, _store = _ctx(p, monkeypatch)
    ctx.rt = object()
    monkeypatch.setattr(gateway, "public_for", lambda rt, slug: None)
    before = {r["params"]["name"]: r["params"] for r in configure.edge_runbooks(ctx, "acme-prod-id") if r["runbook"] == "cfg.nginx_site"}
    assert all(x["tls_name"] == "deployment" and "upstream_ca" not in x for x in before.values())
    assert before["auth"]["root_redirect"] == "https://app.acme.example/"            # Keycloak's front page -> the portal
    monkeypatch.setattr(gateway, "public_for", lambda rt, slug: {"cert_name": "public", "names": gateway.web_names(p)})
    after = {r["params"]["name"]: r["params"] for r in configure.edge_runbooks(ctx, "acme-prod-id") if r["runbook"] == "cfg.nginx_site"}
    assert all(x["tls_name"] == "public" and x["upstream_ca"] == "deployment" for x in after.values())
    for x in after.values():
        assert c.check_nginx_site(x, {"enabled": True})["upstream_ca"] == "deployment"   # what the ICS sends, the agent accepts


def test_the_agent_schema_for_acme_is_closed():
    ok = {"names": ["app.acme.example"], "directory": "staging", "cert_name": "public-staging"}
    assert c.check_acme(dict(ok), {"enabled": True}) == ok
    for bad in ({"directory": "custom"}, {"names": []}, {"names": ["a.example", "a.example"]}, {"names": ["not a name"]}, {"server": "https://evil/"}):
        with pytest.raises(Reject):
            c.check_acme({**ok, **bad}, {"enabled": True})
    with pytest.raises(Reject):
        c.check_nginx_site({"name": "auth", "server_names": ["auth.acme.example"], "upstream": "http://127.0.0.1:8080", "tls_name": "deployment",
                            "max_body_mb": 1, "root_redirect": "http://evil.example/"}, {"enabled": True})


def test_issue_runs_on_the_gateway_records_state_and_switches_sites(rt, client, mk_user, login, monkeypatch):
    adm, ah = login(mk_user("boss", "admin"))
    apr, aph = login(mk_user("second", "approver"))
    with rt.session() as db:
        db.execute(text("INSERT INTO deployments (slug, customer_id, profile, profile_version, status, desired_spec) "
                        "VALUES ('prod', 'c-000000000000', 'small', '1', 'active', '{}'::jsonb)"))
        db.commit()
    p = _plan()
    monkeypatch.setattr(appaccess, "_applied_plan", lambda db, d: p)
    monkeypatch.setattr(appaccess, "_addresses", lambda db, d: {v["name"]: f"10.0.0.{i + 10}" for i, v in enumerate(p["vms"])})
    monkeypatch.setattr(gateway, "_edge_node", lambda db, d, edge: "node-1")
    monkeypatch.setattr(configure, "secret", lambda rt_, dep, name, make=None: (make() if make else name + "-" + "x" * 24))
    calls = []

    def execute(rt_, node, rb, params, deadline=0):
        calls.append((node, rb, params))
        if rb == "cfg.acme":
            return {"status": "ok", "result": {"result": {"certificate": "notAfter=Feb 18 2027\nissuer=C=US, O=Let's Encrypt, CN=R11"}}}
        return {"status": "ok", "result": {"result": {"ok": True}}}
    monkeypatch.setattr(gateway.agentcall, "execute", execute)
    r = adm.post("/api/v1/plans", json={"action": "gateway.certificates.issue", "params": {"deployment": "prod", "directory": "staging"}}, headers=ah)
    assert r.json()["status"] == "approved"                                  # staging: low risk
    assert worker.run_once(rt)
    assert [x[1] for x in calls] == ["cfg.acme"] and calls[0][2]["cert_name"] == "public-staging"
    with rt.session() as db:
        assert gateway.state(db) == {}                                        # a staging test switches nothing
    r = adm.post("/api/v1/plans", json={"action": "gateway.certificates.issue", "params": {"deployment": "prod", "directory": "production"}}, headers=ah)
    pid = r.json()["plan_id"]
    jid = r.json().get("job_id")
    if r.json()["status"] != "approved":
        a = apr.post(f"/api/v1/plans/{pid}/approve", headers=aph)
        assert a.status_code == 200, a.text
        jid = a.json()["job_id"]
    assert worker.run_once(rt)
    job = adm.get(f"/api/v1/jobs/{jid}").json()
    assert job["status"] == "succeeded", job
    acme = [x for x in calls if x[1] == "cfg.acme"][-1][2]
    assert acme == {"names": gateway.web_names(p), "directory": "production", "cert_name": "public"}
    sites = [x[2] for x in calls if x[1] == "cfg.nginx_site"]
    assert sites and all(s["tls_name"] == "public" and s["upstream_ca"] == "deployment" for s in sites)
    with rt.session() as db:
        assert gateway.state(db)["prod"]["names"] == gateway.web_names(p)
