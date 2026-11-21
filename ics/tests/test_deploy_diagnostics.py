"""Read-only diagnostics endpoint (deploy/diagnostics.py): admin only, deployment-scoped, VM must belong to the deployment, agent must offer
guest.journal, every read audited without the log content; the ICS allowlists match the agent's (agent/ou_agent/diagspec.py)."""
import json
import uuid

import pytest
from sqlalchemy import text

from ics.deploy import appaccess, diagnostics
from ou_agent import diagspec

from .test_vault_m import mk_customer, mk_endpoint

H = "/api/v1"
SECRET_LINE = "2026-11-21T10:00:00+0000 php-fpm[1]: PHP Fatal error: Uncaught Exception: boom in /usr/share/grommunio-web/index.php:12"


def _node(db, caps):
    nid = str(uuid.uuid4())
    db.execute(text("INSERT INTO nodes (id, name, address, port, tls_fingerprint_sha256, agent_pubkey, agent_key_fp, capabilities) "
                    "VALUES (:i, :n, '10.0.0.9', 8443, :t, 'k', 'f', CAST(:c AS jsonb))"),
               {"i": nid, "n": "n-" + nid[:8], "t": "ab" * 32, "c": json.dumps(caps)})
    return nid


@pytest.fixture()
def world(rt, mk_user, login, monkeypatch):
    ca, cb = mk_customer(rt, "cust-a"), mk_customer(rt, "cust-b")
    ea, eb = mk_endpoint(rt, "ep-a", ca), mk_endpoint(rt, "ep-b", cb)
    nodes = {}
    with rt.session() as db:
        for k, e in (("a", ea), ("b", eb)):
            dep = db.execute(text("INSERT INTO deployments (slug, customer_id, profile, profile_version, endpoint_id, status, desired_spec) "
                                  "VALUES (:s, :c, 'p', '1', :e, 'active', '{}'::jsonb) RETURNING id"), {"s": f"dep-{k}", "c": f"cust-{k}", "e": e}).scalar()
            for vm, caps in ((f"{k}-groupware", {"guest.facts": {"enabled": True}, "guest.journal": {"enabled": True}}),
                             (f"{k}-old", {"guest.facts": {"enabled": True}})):
                nid = _node(db, caps)
                nodes[vm] = nid
                db.execute(text("INSERT INTO deployment_resources (deployment_id, kind, logical_name, provider_ref, desired, state) "
                                "VALUES (:d, 'vm', :n, CAST(:r AS jsonb), '{}'::jsonb, 'present')"), {"d": dep, "n": vm, "r": json.dumps({"agent_node_id": nid})})
        db.commit()
    sa = mk_user("scoped-admin", "admin")
    with rt.session() as db:
        db.execute(text("UPDATE users SET all_customers = false WHERE username = 'scoped-admin'"))
        db.execute(text("INSERT INTO operator_customers (user_id, customer_id) VALUES (:u, :c)"), {"u": sa["id"], "c": ca})
        db.commit()
    monkeypatch.setattr(appaccess, "_applied_plan", lambda db, d: {"vms": [{"name": f"{d.slug[-1]}-groupware", "components": ["groupware"]},
                                                                          {"name": f"{d.slug[-1]}-old", "components": ["identity"]}]})
    calls = []

    def execute(rt_, node, rb, params, deadline=0):
        calls.append((node, rb, params))
        return {"status": "ok", "code": "ok", "result": {"returncode": 0, "result": {
            "source": "unit", "key": params.get("unit"), "target": "php8.3-fpm.service", "scope": "system",
            "lines": [SECRET_LINE], "count": 1, "truncated": False, "redacted": True}}}
    monkeypatch.setattr(diagnostics.agentcall, "execute", execute)
    return {"nodes": nodes, "calls": calls, "scoped": login(sa), "admin": login(mk_user("all-admin", "admin")),
            "operator": login(mk_user("op", "operator"))}


def _audit(rt):
    with rt.session() as db:
        return [(r.action, r.details, r.actor_name) for r in db.execute(text(
            "SELECT action, details, actor_name FROM audit_events WHERE action = 'deployment.diagnostics_logs_read' ORDER BY seq")).all()]


def test_an_admin_reads_redacted_lines_of_an_allowlisted_unit_and_the_read_is_audited_without_content(rt, world):
    c, h = world["admin"]
    r = c.post(f"{H}/deployments/dep-a/diagnostics/logs", json={"vm": "a-groupware", "unit": "php8.3-fpm", "lines": 50, "grep": "php"}, headers=h)
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["log"] == [SECRET_LINE] and j["lines_returned"] == 1 and j["redacted"] is True and r.headers["cache-control"] == "no-store"
    assert world["calls"] == [(world["nodes"]["a-groupware"], "guest.journal", {"lines": 50, "unit": "php8.3-fpm", "grep": "php"})]
    assert diagspec.check(world["calls"][0][2]) == world["calls"][0][2]       # exactly what the agent accepts
    (action, details, actor), = _audit(rt)
    assert actor == "all-admin" and details["vm"] == "a-groupware" and details["unit"] == "php8.3-fpm" and details["outcome"] == "ok"
    assert details["returned_lines"] == 1 and "Uncaught" not in json.dumps(details)   # never the content


def test_files_are_read_by_key_and_the_sources_list_offers_only_allowlisted_names(world):
    c, h = world["admin"]
    assert c.post(f"{H}/deployments/dep-a/diagnostics/logs", json={"vm": "a-groupware", "file": "nginx-error", "lines": 10}, headers=h).status_code == 200
    assert world["calls"][-1][2] == {"lines": 10, "file": "nginx-error"}
    s = c.get(f"{H}/deployments/dep-a/diagnostics").json()
    assert {v["name"]: v["available"] for v in s["vms"]} == {"a-groupware": True, "a-old": False}
    gw = next(v for v in s["vms"] if v["name"] == "a-groupware")
    assert "php8.3-fpm" in gw["suggested_units"] and "gromox-zcore" in gw["suggested_units"] and "nginx-error" in gw["suggested_files"]
    assert set(s["units"]) == set(diagspec.UNITS) and set(s["files"]) == set(diagspec.FILES) and set(s["greps"]) == set(diagspec.GREPS)


def test_the_ics_allowlists_match_the_agent():
    assert set(diagnostics.UNITS) == set(diagspec.UNITS) and set(diagnostics.FILES) == set(diagspec.FILES) and set(diagnostics.GREPS) == set(diagspec.GREPS)
    for comp in diagnostics.SUGGESTED.values():
        assert set(comp["units"]) <= set(diagspec.UNITS) and set(comp["files"]) <= set(diagspec.FILES)


@pytest.mark.parametrize("body", [
    {"vm": "a-groupware", "unit": "sshd", "lines": 10},                         # not allowlisted
    {"vm": "a-groupware", "file": "../../etc/shadow", "lines": 10},              # path traversal
    {"vm": "a-groupware", "file": "/var/log/nginx/error.log", "lines": 10},      # a path instead of a key
    {"vm": "a-groupware", "unit": "nginx", "lines": 301},                        # oversized
    {"vm": "a-groupware", "unit": "nginx", "lines": 0},
    {"vm": "a-groupware", "unit": "nginx", "file": "nginx-error", "lines": 5},   # both
    {"vm": "a-groupware", "lines": 5},                                           # neither
    {"vm": "a-groupware", "unit": "nginx", "lines": 5, "grep": "pass.*word"},    # free regex
    {"vm": "a-groupware", "unit": "nginx", "lines": 5, "since_minutes": 1441},
    {"vm": "a-groupware", "file": "nginx-error", "lines": 5, "since_minutes": 5},
    {"vm": "a-groupware", "unit": "nginx", "lines": 5, "command": "cat /etc/shadow"},   # unknown field
    {"vm": "A;rm", "unit": "nginx", "lines": 5},
])
def test_anything_outside_the_closed_schema_is_refused_before_the_agent_is_called(world, body):
    c, h = world["admin"]
    assert c.post(f"{H}/deployments/dep-a/diagnostics/logs", json=body, headers=h).status_code == 422
    assert world["calls"] == []


def test_vms_of_another_deployment_and_agents_without_the_runbook_are_refused_and_audited(rt, world):
    c, h = world["admin"]
    r = c.post(f"{H}/deployments/dep-a/diagnostics/logs", json={"vm": "b-groupware", "unit": "nginx", "lines": 5}, headers=h)
    assert r.status_code == 404 and "not part of deployment dep-a" in r.text
    r = c.post(f"{H}/deployments/dep-a/diagnostics/logs", json={"vm": "a-old", "unit": "nginx", "lines": 5}, headers=h)
    assert r.status_code == 409 and "0.8.1" in r.text
    assert world["calls"] == []
    assert [d["outcome"] for _, d, _ in _audit(rt)] == ["refused_unknown_vm", "refused_agent_too_old"]


def test_only_admins_and_only_within_their_customers(rt, world):
    o, oh = world["operator"]
    assert o.post(f"{H}/deployments/dep-a/diagnostics/logs", json={"vm": "a-groupware", "unit": "nginx", "lines": 5}, headers=oh).status_code == 403
    assert o.get(f"{H}/deployments/dep-a/diagnostics").status_code == 403
    s, sh = world["scoped"]
    assert s.post(f"{H}/deployments/dep-a/diagnostics/logs", json={"vm": "a-groupware", "unit": "nginx", "lines": 5}, headers=sh).status_code == 200
    assert s.post(f"{H}/deployments/dep-b/diagnostics/logs", json={"vm": "b-groupware", "unit": "nginx", "lines": 5}, headers=sh).status_code == 404
    assert s.get(f"{H}/deployments/dep-b/diagnostics").status_code == 404
    assert [n for n, _, _ in world["calls"]] == [world["nodes"]["a-groupware"]]
    a, ah = world["admin"]
    assert a.post(f"{H}/deployments/dep-a/diagnostics/logs", json={"vm": "a-groupware", "unit": "nginx", "lines": 5}).status_code in (401, 403)   # CSRF


def test_an_agent_refusal_is_reported_and_audited(rt, world, monkeypatch):
    monkeypatch.setattr(diagnostics.agentcall, "execute", lambda *a, **k: {"status": "rejected", "code": "not_allowed", "result": {"message": "unit is not on the diagnostics allowlist"}})
    c, h = world["admin"]
    r = c.post(f"{H}/deployments/dep-a/diagnostics/logs", json={"vm": "a-groupware", "unit": "nginx", "lines": 5}, headers=h)
    assert r.status_code == 422 and "not_allowed" in r.text
    assert _audit(rt)[-1][1]["outcome"] == "rejected"


def test_callback_keeps_optional_runbooks_only_for_images_that_report_them():
    from ics.guest import callback, cloudinit
    conf = {"agent_config": {"listen": {}, "runbooks": {"guest.facts": {"enabled": True}, "guest.journal": {"enabled": True}}}}
    assert "guest.journal" not in callback.gate_features(json.loads(json.dumps(conf)), [])["agent_config"]["runbooks"]
    assert "guest.journal" in callback.gate_features(json.loads(json.dumps(conf)), ["guest.journal"])["agent_config"]["runbooks"]
    assert set(cloudinit.OPTIONAL_RUNBOOKS) <= set(__import__("ou_agent.firstboot", fromlist=["x"]).FEATURES)
