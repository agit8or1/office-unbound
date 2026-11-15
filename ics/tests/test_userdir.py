"""Operator user directory, invitations, access policy and the user-management plan actions (agent G)."""
import re

import pytest
from sqlalchemy import text

from ics import auth, worker
from .conftest import totp_for

H = "/api/v1"


@pytest.fixture()
def team(mk_user, login):
    return {n: login(mk_user(n, r)) for n, r in [("vw", "viewer"), ("op", "operator"), ("ap1", "approver"), ("ap2", "approver"), ("adm", "admin")]}


def plan(team, who, action, params, expect=201):
    c, h = team[who]
    r = c.post(f"{H}/plans", json={"action": action, "params": params}, headers=h)
    assert r.status_code == expect, r.text
    return r.json()


def approve(team, pid, who):
    c, h = team[who]
    r = c.post(f"{H}/plans/{pid}/approve", headers=h)
    assert r.status_code == 200, r.text
    return r.json()


def approve2(team, pid):
    approve(team, pid, "ap1")
    return approve(team, pid, "ap2")


def directory(team, who="adm", **q):
    r = team[who][0].get(f"{H}/users", params=q)
    assert r.status_code == 200, r.text
    return {u["username"]: u for u in r.json()}


def test_directory_fields_and_ip_visibility(team):
    d = directory(team)
    assert set(d) == {"vw", "op", "ap1", "ap2", "adm"}
    a = d["adm"]
    assert a["status"] == "active" and a["role"] == "admin" and a["privileged"] and a["mfa_enrolled"] and a["active_sessions"] == 1
    assert a["last_login_at"] and a["last_login_ip"]
    v = directory(team, "vw")
    v = directory(team, "vw")
    assert v["adm"]["last_login_at"] is None and v["adm"]["mfa_enrolled"] is None and all("last_login_ip" not in u for u in v.values())  # review 3 L8
    assert "sessions" not in team["vw"][0].get(f"{H}/users/{a['id']}").json()
    assert team["adm"][0].get(f"{H}/users/{a['id']}").json()["sessions"]


def test_directory_filters_and_unauthenticated(team, client):
    assert set(directory(team, role="approver")) == {"ap1", "ap2"}
    assert set(directory(team, q="ap")) == {"ap1", "ap2"}
    assert set(directory(team, status="disabled")) == set()
    assert client.get(f"{H}/users").status_code == 401
    assert team["adm"][0].get(f"{H}/users", params={"role": "root"}).status_code == 422
    assert team["adm"][0].get(f"{H}/users/00000000-0000-0000-0000-000000000000").status_code == 404


def test_detail_recent_events_and_role_history(team, rt):
    uid = directory(team)["op"]["id"]
    r = team["adm"][0].get(f"{H}/users/{uid}").json()
    assert any(e["action"] == "auth.login" and "ip" in e for e in r["recent_events"])
    assert r["role_history"][0]["kind"] == "invited"
    pid = plan(team, "adm", "user.set_role", {"username": "op", "role": "approver", "justification": "second on-call approver"})["plan_id"]
    approve2(team, pid)
    worker.run_once(rt)
    r = team["adm"][0].get(f"{H}/users/{uid}").json()
    h = r["role_history"][-1]
    assert (h["kind"], h["role"], h["previous_role"], h["by"]) == ("role_change", "approver", "operator", "adm")
    assert h["justification"] == "second on-call approver" and h["plan_id"] == pid
    assert r["role_set_by"] == "adm" and r["privileged"]
    assert all("ip" not in e for e in team["vw"][0].get(f"{H}/users/{uid}").json()["recent_events"])


def test_invite_flow_invitations_and_revoke(team, rt, client):
    plan(team, "op", "user.invite", {"username": "n1", "role": "viewer"}, 403)
    plan(team, "op", "user.invite", {"username": "n2", "role": "admin", "justification": "x" * 12}, 403)
    p = plan(team, "adm", "user.invite", {"username": "n1", "role": "operator"})
    assert p["risk"] == "low" and p["job_id"]  # viewer/operator invite: policy auto-approval
    worker.run_once(rt)
    inv = team["vw"][0].get(f"{H}/invitations").json()
    assert [(i["username"], i["status"], i["token"], i["invited_by"]) for i in inv] == [("n1", "pending", "not_issued", "adm")]
    assert not any("hash" in k for i in inv for k in i)
    assert directory(team)["n1"]["status"] == "invited"
    with rt.session() as db:
        tok = auth.issue_enrollment_token(db, rt, "n1")
    assert team["adm"][0].get(f"{H}/invitations").json()[0]["token"] == "issued"
    plan(team, "adm", "user.revoke_invite", {"username": "n1", "reason": "wrong person"})
    worker.run_once(rt)
    assert directory(team)["n1"]["status"] == "revoked"
    assert team["adm"][0].get(f"{H}/invitations", params={"status": "revoked"}).json()[0]["token"] == "none"
    r = client.post(f"{H}/auth/enroll", json={"username": "n1", "token": tok, "password": "a long password 123"})
    assert r.status_code == 401  # revoked invite is unusable even with a valid token
    plan(team, "adm", "user.revoke_invite", {"username": "n1"}, 409)
    plan(team, "adm", "user.enable", {"username": "n1"}, 409)
    with rt.session() as db:
        assert db.execute(text("SELECT count(*) FROM audit_events WHERE action='user.invite_revoked'")).scalar() == 1


def test_expired_invitation(team, rt):
    plan(team, "adm", "user.invite", {"username": "n3", "role": "viewer"})
    worker.run_once(rt)
    with rt.session() as db:
        auth.issue_enrollment_token(db, rt, "n3")
        db.execute(text("UPDATE users SET enrollment_expires_at = now() - interval '1 hour' WHERE username='n3'"))
        db.commit()
    assert [i["status"] for i in team["adm"][0].get(f"{H}/invitations", params={"status": "expired"}).json()] == ["expired"]
    assert team["adm"][0].get(f"{H}/invitations", params={"status": "bogus"}).status_code == 422


def test_privileged_invite_justification_two_approvers_and_provenance(team, rt, login):
    plan(team, "adm", "user.invite", {"username": "pa", "role": "approver"}, 422)  # no justification
    p = plan(team, "adm", "user.invite", {"username": "pa", "role": "approver", "justification": "covering holiday rota"})
    assert p["risk"] == "high" and p["approvals_required"] == 2 and p["job_id"] is None
    assert team["adm"][0].post(f"{H}/plans/{p['plan_id']}/approve", headers=team["adm"][1]).status_code == 403  # self
    assert approve(team, p["plan_id"], "ap1")["status"] == "pending_approval"
    approve(team, p["plan_id"], "ap2")
    worker.run_once(rt)
    d = directory(team)["pa"]
    assert d["status"] == "invited" and d["created_by"] == "adm" and d["role"] == "approver"
    with rt.session() as db:
        tok = auth.issue_enrollment_token(db, rt, "pa")
        uri = auth.enroll_begin(db, rt, "pa", tok, "pa password 123456", "127.0.0.1")
        u = {"username": "pa", "password": "pa password 123456", "secret": re.search(r"secret=([A-Z2-7]+)", uri).group(1)}
        auth.enroll_confirm(db, rt, "pa", tok, totp_for(u), "127.0.0.1")
    pc, ph = login(u)
    other = plan(team, "adm", "user.invite", {"username": "zz", "role": "admin", "justification": "second admin for DR"})["plan_id"]
    r = pc.post(f"{H}/plans/{other}/approve", headers=ph)
    assert r.status_code == 403 and "created or elevated" in r.json()["detail"]


def test_disable_enable_and_session_revocation(team, rt, mk_user, login):
    vc, _ = login(mk_user("tmp", "operator"))
    assert vc.get(f"{H}/auth/me").status_code == 200
    p = plan(team, "adm", "user.disable", {"username": "tmp", "reason": "left company"})
    assert p["risk"] == "normal" and p["approvals_required"] == 1
    approve(team, p["plan_id"], "ap1")
    worker.run_once(rt)
    assert directory(team)["tmp"]["status"] == "disabled"
    assert vc.get(f"{H}/auth/me").status_code == 401  # sessions ended
    plan(team, "adm", "user.disable", {"username": "tmp"}, 409)
    e = plan(team, "adm", "user.enable", {"username": "tmp"})
    approve(team, e["plan_id"], "ap1")
    worker.run_once(rt)
    assert directory(team)["tmp"]["status"] == "active"
    assert plan(team, "adm", "user.disable", {"username": "ap2"})["risk"] == "high"
    vc2, _ = login(mk_user("tmp2", "viewer"))
    assert plan(team, "adm", "user.revoke_sessions", {"username": "tmp2"})["risk"] == "low"
    worker.run_once(rt)
    assert vc2.get(f"{H}/auth/me").status_code == 401
    assert directory(team)["tmp2"]["active_sessions"] == 0


def test_guards_and_authorization(team, rt):
    plan(team, "adm", "user.disable", {"username": "adm"}, 422)
    plan(team, "adm", "user.set_role", {"username": "adm", "role": "viewer"}, 422)
    plan(team, "adm", "user.revoke_sessions", {"username": "nobody"}, 404)
    plan(team, "adm", "user.set_role", {"username": "op", "role": "operator"}, 409)
    for who in ("vw", "op", "ap1"):
        for a in ("user.disable", "user.enable", "user.revoke_sessions", "user.revoke_invite"):
            plan(team, who, a, {"username": "vw"}, 403)


def test_last_admin_guard_in_executor(team, rt):
    """Race: the plan was valid when requested, but the other admin vanished before the job ran -> job fails, nothing changes."""
    with rt.session() as db:
        db.execute(text("UPDATE users SET role='admin' WHERE username='ap2'"))
        db.commit()
    team["ap2"] = team["ap2"]  # session survives the role change
    p = plan(team, "ap2", "user.disable", {"username": "adm"})
    approve(team, p["plan_id"], "ap1")
    with rt.session() as db:
        db.execute(text("UPDATE users SET role='viewer' WHERE username='ap2'"))
        db.commit()
    worker.run_once(rt)
    assert directory(team)["adm"]["status"] == "active"


def test_target_cannot_decide_own_account_plan(team):
    p = plan(team, "adm", "user.disable", {"username": "ap1"})
    c, h = team["ap1"]
    assert c.post(f"{H}/plans/{p['plan_id']}/approve", headers=h).status_code == 403
    assert c.post(f"{H}/plans/{p['plan_id']}/reject", headers=h).status_code == 403


def test_locked_status(team, client):
    for _ in range(6):
        client.post(f"{H}/auth/login", json={"username": "vw", "password": "wrong password!!", "totp_code": "000000"})
    assert directory(team)["vw"]["status"] == "locked"


def test_access_policy_and_matrix(team):
    for who in ("vw", "adm"):
        r = team[who][0].get(f"{H}/access-policy")
        assert r.status_code == 200
    p = r.json()
    assert [a["required"] for a in p["approvals"]] == [0, 1, 2]
    assert p["mfa"]["mandatory"] and p["sessions"]["max_per_user"] == 10 and p["lockout"]["max_failures"] == 5
    last = [c for c in p["capabilities"] if "last sign-in" in c["capability"]][0]
    assert last["roles"] == {"viewer": False, "operator": False, "approver": False, "admin": True}
    assert any(x["id"] == "provenance" for x in p["rules"])


def test_actions_catalog_lists_new_actions(team):
    cat = {a["action"] for a in team["vw"][0].get(f"{H}/actions").json()}
    assert {"user.invite", "user.revoke_invite", "user.disable", "user.enable", "user.revoke_sessions", "user.set_role"} <= cat
