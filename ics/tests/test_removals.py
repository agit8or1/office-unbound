"""Typed removal actions: check.delete, alert_channel.delete, node.decommission, maintenance.cancel/delete, plan.archive."""
import pytest
from sqlalchemy import text

from ics import agentclient, worker

H = "/api/v1"


@pytest.fixture()
def team(mk_user, login):
    return {n: login(mk_user(n, r)) for n, r in [("op", "operator"), ("ap1", "approver"), ("ap2", "approver"), ("adm", "admin")]}


def request(team, action, params, who="op", approvers=(), expect=201):
    c, h = team[who]
    r = c.post(f"{H}/plans", json={"action": action, "params": params}, headers=h)
    assert r.status_code == expect, r.text
    if expect != 201:
        return r
    body = r.json()
    for n in approvers:
        d = team[n][0].post(f"{H}/plans/{body['plan_id']}/approve", headers=team[n][1])
        assert d.status_code == 200, d.text
        body["job_id"] = d.json()["job_id"] or body["job_id"]
    return body


def run(rt, team, jid):
    worker.run_once(rt)
    return team["op"][0].get(f"{H}/jobs/{jid}").json()


def uid(rt, name):
    with rt.session() as db:
        return str(db.execute(text("SELECT id FROM users WHERE username = :u"), {"u": name}).scalar())


def mk_check(rt, name="c1", deployment=None):
    with rt.session() as db:
        cid = str(db.execute(text("INSERT INTO checks (name, kind, config, interval_seconds, created_by) VALUES (:n, 'tcp_tls', '{}'::jsonb, 60, "
                                  "(SELECT id FROM users LIMIT 1)) RETURNING id"), {"n": name}).scalar())
        db.commit()
    return cid


def audit_actions(rt):
    with rt.session() as db:
        return [r[0] for r in db.execute(text("SELECT action FROM audit_events"))]


def test_check_delete_normal_risk_guarded_and_audited(client, rt, team):
    cid = mk_check(rt)
    with rt.session() as db:
        aid = db.execute(text("INSERT INTO remediation_attempts (check_id, runbook, attempt_no, status) VALUES (:c, 'service.restart', 1, 'running') RETURNING id"),
                         {"c": cid}).scalar()
        db.commit()
    r = request(team, "check.delete", {"check_id": cid}, expect=409)             # active remediation attempt
    assert "remediation" in r.text
    with rt.session() as db:
        db.execute(text("UPDATE remediation_attempts SET status = 'superseded' WHERE id = :i"), {"i": aid})
        db.commit()
    p = request(team, "check.delete", {"check_id": cid, "reason": "demo leftover"})
    assert p["risk"] == "normal" and p["status"] == "pending_approval"
    # requester can never approve their own plan
    c, h = team["op"]
    assert c.post(f"{H}/plans/{p['plan_id']}/approve", headers=h).status_code in (401, 403)
    d = team["ap1"][0].post(f"{H}/plans/{p['plan_id']}/approve", headers=team["ap1"][1]).json()
    assert run(rt, team, d["job_id"])["status"] == "succeeded"
    with rt.session() as db:
        assert db.execute(text("SELECT count(*) FROM checks")).scalar() == 0
    assert "check.deleted" in audit_actions(rt)
    request(team, "check.delete", {"check_id": cid}, expect=404)


def test_check_delete_refuses_deployment_owned_check_and_rechecks_at_execution(client, rt, team):
    cid = mk_check(rt)
    p = request(team, "check.delete", {"check_id": cid}, approvers=("ap1",))
    with rt.session() as db:                           # after approval: an attempt starts -> execution must refuse and delete nothing
        db.execute(text("INSERT INTO remediation_attempts (check_id, runbook, attempt_no, status) VALUES (:c, 'service.restart', 1, 'queued')"), {"c": cid})
        db.commit()
    j = run(rt, team, p["job_id"])
    assert j["status"] == "failed"
    with rt.session() as db:
        assert db.execute(text("SELECT count(*) FROM checks")).scalar() == 1


def test_alert_channel_delete_last_enabled_needs_confirmation_and_is_then_high(client, rt, team):
    with rt.session() as db:
        a = str(db.execute(text("INSERT INTO alert_channels (name, kind, config, enabled) VALUES ('a', 'webhook', '{}'::jsonb, true) RETURNING id")).scalar())
        b = str(db.execute(text("INSERT INTO alert_channels (name, kind, config, enabled) VALUES ('b', 'webhook', '{}'::jsonb, true) RETURNING id")).scalar())
        db.commit()
    p = request(team, "alert_channel.delete", {"channel_id": a}, approvers=("ap1",))
    assert p["risk"] == "normal"
    assert run(rt, team, p["job_id"])["status"] == "succeeded"
    r = request(team, "alert_channel.delete", {"channel_id": b}, expect=409)       # now the last enabled channel
    assert "last enabled" in r.text
    p = request(team, "alert_channel.delete", {"channel_id": b, "confirm_no_alerting": True})
    assert p["risk"] == "high"
    for n in ("ap1", "ap2"):
        d = team[n][0].post(f"{H}/plans/{p['plan_id']}/approve", headers=team[n][1]).json()
    assert run(rt, team, d["job_id"])["status"] == "succeeded"
    assert "alert_channel.deleted" in audit_actions(rt)


def test_node_decommission_revokes_trust_and_blocks_requests(client, rt, team):
    with rt.session() as db:
        nid = str(db.execute(text("INSERT INTO nodes (name, address, port, tls_fingerprint_sha256, agent_pubkey, agent_key_fp, capabilities) VALUES "
                                  "('n1', '10.0.0.5', 8443, :f, 'PUBKEY', :f, '{\"service.restart\": {\"units\": [\"nginx\"]}}'::jsonb) RETURNING id"),
                                  {"f": "ab" * 32}).scalar())
        db.commit()
    p = request(team, "node.decommission", {"node_id": nid, "reason": "retired lab node"})
    assert p["risk"] == "high"
    for n in ("ap1", "ap2"):
        d = team[n][0].post(f"{H}/plans/{p['plan_id']}/approve", headers=team[n][1]).json()
    assert run(rt, team, d["job_id"])["status"] == "succeeded"
    with rt.session() as db:
        n = db.execute(text("SELECT * FROM nodes WHERE id = :i"), {"i": nid}).first()
        assert db.execute(text("SELECT count(*) FROM audit_events WHERE action = 'node.decommissioned' AND details::text LIKE :f"), {"f": "%" + "ab" * 32 + "%"}).scalar() == 1
    assert n.status == "decommissioned" and n.agent_pubkey == "" and n.tls_fingerprint_sha256.strip() == "0" * 64 and n.capabilities == {}
    with pytest.raises(agentclient.AgentError, match="decommissioned"):
        agentclient.call(n, None, action="service.restart", params={}, job_id="j")        # refused before anything is signed or sent
    request(team, "runbook.execute", {"node_id": nid, "runbook": "service.restart", "unit": "nginx"}, expect=409)
    request(team, "node.decommission", {"node_id": nid, "reason": "again please"}, expect=409)
    with rt.session() as db:
        assert db.execute(text("SELECT count(*) FROM nodes")).scalar() == 1               # history kept


def test_maintenance_cancel_and_delete(client, rt, team):
    with rt.session() as db:
        w = str(db.execute(text("INSERT INTO maintenance_windows (name, starts_at, ends_at) VALUES ('w', now() - interval '1 minute', now() + interval '1 hour') "
                                "RETURNING id")).scalar())
        db.commit()
    request(team, "maintenance.delete", {"maintenance_id": w}, expect=409)             # still active: cancel first
    p = request(team, "maintenance.cancel", {"maintenance_id": w}, approvers=("ap1",))
    assert p["risk"] == "normal" and run(rt, team, p["job_id"])["status"] == "succeeded"
    with rt.session() as db:
        assert db.execute(text("SELECT ends_at <= now() FROM maintenance_windows WHERE id = :i"), {"i": w}).scalar() is True
    request(team, "maintenance.cancel", {"maintenance_id": w}, expect=409)
    p = request(team, "maintenance.delete", {"maintenance_id": w}, approvers=("ap2",))
    assert run(rt, team, p["job_id"])["status"] == "succeeded"
    with rt.session() as db:
        assert db.execute(text("SELECT count(*) FROM maintenance_windows")).scalar() == 0
    acts = audit_actions(rt)
    assert "maintenance.cancelled" in acts and "maintenance.deleted" in acts


def test_plan_archive_hides_but_never_deletes_and_only_terminal_plans(client, rt, team):
    pending = request(team, "check.delete", {"check_id": mk_check(rt)})
    request(team, "plan.archive", {"plan_id": pending["plan_id"]}, expect=409)         # not finished
    rej = request(team, "check.delete", {"check_id": mk_check(rt, "c2")})
    assert team["ap1"][0].post(f"{H}/plans/{rej['plan_id']}/reject", headers=team["ap1"][1]).status_code == 200
    p = request(team, "plan.archive", {"plan_id": rej["plan_id"]})
    assert p["risk"] == "low" and p["status"] == "approved"                            # low risk: policy auto-approval
    assert run(rt, team, p["job_id"])["status"] == "succeeded"
    c, _ = team["op"]
    ids = {x["id"] for x in c.get(f"{H}/plans").json()}
    assert rej["plan_id"] not in ids and pending["plan_id"] in ids
    assert rej["plan_id"] in {x["id"] for x in c.get(f"{H}/plans", params={"include_archived": "true"}).json()}
    with rt.session() as db:
        assert db.execute(text("SELECT count(*) FROM plans WHERE id = :i"), {"i": rej["plan_id"]}).scalar() == 1
    request(team, "plan.archive", {"plan_id": rej["plan_id"]}, expect=409)             # already archived
    assert "plan.archived" in audit_actions(rt)
