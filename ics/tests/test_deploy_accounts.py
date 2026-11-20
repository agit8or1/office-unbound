"""Sign-in accounts on a deployment (deploy/accounts.py, directory.account.set; owner: "change password to 8 char min")."""
import json
import os
import sys

import pytest
from pydantic import ValidationError
from sqlalchemy import text

from ics import gateway, worker
from ics.deploy import accounts, appaccess, configure

from .test_gateway_certs import _plan

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))
from ou_agent import cfgspec as c  # noqa: E402
from ou_agent.proto import Reject  # noqa: E402

PW = "Chin00k1"


@pytest.mark.parametrize("pw, ok", [("Chin00k1", True), ("Chin00k", False), ("has space1", False), ("x" * 129, False), ("Abc-def_9", True)])
def test_person_passwords_need_8_characters_machine_secrets_keep_16(pw, ok):
    good = {"domain": "acme.example", "uid": "admin", "given_name": "Admin", "surname": "Administrator", "mail": "admin@acme.example",
            "password": pw, "groups": ["mail-users"]}
    if ok:
        assert c.check_ldap_user(good, {"enabled": True})["password"] == pw
        accounts.AccountSet(deployment="prod", username="admin", password=pw)
    else:
        with pytest.raises(Reject):
            c.check_ldap_user(good, {"enabled": True})
        with pytest.raises(ValidationError):
            accounts.AccountSet(deployment="prod", username="admin", password=pw)
    with pytest.raises(Reject):   # a database password (machine secret) still needs 16
        c.check_pg_db({"role": "keycloak", "database": "keycloak", "password": "Chin00k1"}, {"enabled": True})


def test_account_is_created_with_a_mailbox_and_the_password_is_never_stored(rt, client, mk_user, login, monkeypatch):
    adm, ah = login(mk_user("boss", "admin"))
    apr, aph = login(mk_user("second", "approver"))
    with rt.session() as db:
        db.execute(text("INSERT INTO deployments (slug, customer_id, profile, profile_version, status, desired_spec) "
                        "VALUES ('prod', 'c-000000000000', 'small', '1', 'active', '{}'::jsonb)"))
        db.commit()
    p = _plan()
    monkeypatch.setattr(appaccess, "_applied_plan", lambda db, d: p)
    monkeypatch.setattr(appaccess, "_addresses", lambda db, d: {v["name"]: f"10.0.0.{i + 10}" for i, v in enumerate(p["vms"])})
    monkeypatch.setattr(gateway, "_edge_node", lambda db, d, vm: "node-" + vm)
    monkeypatch.setattr(configure, "secret", lambda rt_, dep, name, make=None: (make() if make else name + "-" + "x" * 24))
    monkeypatch.setattr(configure, "realm_key", lambda rt_, dep, t=None: KEY)
    calls = []

    def execute(rt_, node, rb, params, deadline=0):
        calls.append((node, rb, params))
        res = {"created": True} if rb == "cfg.ldap_user" else {"mailboxes": {"created": ["admin@acme.example"], "existing": ["ou-admin@acme.example"]}}
        return {"status": "ok", "result": {"result": res}}
    monkeypatch.setattr(gateway.agentcall, "execute", execute)
    r = adm.post("/api/v1/plans", json={"action": "directory.account.set", "params": {"deployment": "prod", "username": "admin", "password": PW}}, headers=ah)
    assert r.status_code in (200, 201), r.text
    a = apr.post(f"/api/v1/plans/{r.json()['plan_id']}/approve", headers=aph)
    assert a.status_code == 200, a.text
    assert worker.run_once(rt)
    assert adm.get(f"/api/v1/jobs/{a.json()['job_id']}").json()["status"] == "succeeded"
    ldap = next(x for x in calls if x[1] == "cfg.ldap_user")
    assert ldap[0] == "node-acme-prod-id" and ldap[2]["uid"] == "admin" and ldap[2]["password"] == PW
    assert c.check_ldap_user(ldap[2], {"enabled": True}) == ldap[2]
    assert set(ldap[2]["groups"]) == {"opencloudAdmin", "mail-users", "org-admin"}
    gro = next(x for x in calls if x[1] == "cfg.gromox")
    assert gro[0] == "node-acme-prod-groupware" and "admin@acme.example" in gro[2]["mailboxes"]
    with rt.session() as db:
        dump = json.dumps([[str(v) for v in row] for row in db.execute(text("SELECT details FROM audit_events")).all()])
        dump += json.dumps([[str(v) for v in row] for row in db.execute(text("SELECT params, result FROM plans p JOIN jobs j ON j.plan_id = p.id")).all()])
        dump += json.dumps([[str(v) for v in row] for row in db.execute(text("SELECT value FROM system_settings")).all()])
        assert accounts.accounts(db) == {"prod": ["admin"]}
    assert PW not in dump


KEY = configure._rsa_key()


def _setup(rt, monkeypatch, calls, results=None):
    with rt.session() as db:
        db.execute(text("INSERT INTO deployments (slug, customer_id, profile, profile_version, status, desired_spec) "
                        "VALUES ('prod', 'c-000000000000', 'small', '1', 'active', '{}'::jsonb)"))
        db.commit()
    p = _plan()
    monkeypatch.setattr(appaccess, "_applied_plan", lambda db, d: p)
    monkeypatch.setattr(appaccess, "_addresses", lambda db, d: {v["name"]: f"10.0.0.{i + 10}" for i, v in enumerate(p["vms"])})
    monkeypatch.setattr(gateway, "_edge_node", lambda db, d, vm: "node-" + vm)
    monkeypatch.setattr(configure, "secret", lambda rt_, dep, name, make=None: (make() if make else name + "-" + "x" * 24))
    monkeypatch.setattr(configure, "realm_key", lambda rt_, dep, t=None: KEY)

    def execute(rt_, node, rb, params, deadline=0):
        calls.append((node, rb, params))
        return {"status": "ok", "result": {"result": (results or {}).get(rb, {"ok": True})}}
    monkeypatch.setattr(gateway.agentcall, "execute", execute)
    return p


def _run_plan(adm, ah, apr, aph, action, params, extra=None):
    r = adm.post("/api/v1/plans", json={"action": action, "params": params}, headers=ah)
    assert r.status_code in (200, 201), r.text
    jid = r.json().get("job_id")
    for c_, h_ in [(apr, aph), *([extra] if extra else [])]:
        if jid:
            break
        a = c_.post(f"/api/v1/plans/{r.json()['plan_id']}/approve", headers=h_)
        assert a.status_code == 200, a.text
        jid = a.json()["job_id"]
    assert worker.run_once(rt_ref[0])
    return adm.get(f"/api/v1/jobs/{jid}").json()


rt_ref = [None]


def test_a_user_role_gets_user_groups_and_loses_admin_groups(rt, client, mk_user, login, monkeypatch):
    rt_ref[0] = rt
    adm, ah = login(mk_user("boss", "admin"))
    apr, aph = login(mk_user("second", "approver"))
    calls = []
    _setup(rt, monkeypatch, calls)
    job = _run_plan(adm, ah, apr, aph, "directory.account.set",
                    {"deployment": "prod", "username": "jane", "password": "Jane-pass-1", "role": "user", "display_name": "Jane Doe"})
    assert job["status"] == "succeeded", job
    ldap = next(x[2] for x in calls if x[1] == "cfg.ldap_user")
    assert ldap["groups"] == ["opencloudUser", "mail-users"] and ldap["given_name"] == "Jane" and ldap["surname"] == "Doe"
    grp = next(x[2] for x in calls if x[1] == "cfg.ldap_groups")
    assert grp == {"domain": "acme.example", "uid": "jane", "add": [], "remove": ["opencloudAdmin", "org-admin"]}
    assert c.check_ldap_groups(grp, {"enabled": True}) == grp and c.check_ldap_user(ldap, {"enabled": True}) == ldap


def test_people_lock_and_delete_go_to_the_deployments_own_directory(rt, client, mk_user, login, monkeypatch):
    rt_ref[0] = rt
    adm, ah = login(mk_user("boss", "admin"))
    apr, aph = login(mk_user("second", "approver"))
    op, oh = login(mk_user("op", "operator"))
    calls = []
    listing = {"people": [{"uid": "ou-admin", "mail": "ou-admin@acme.example", "display_name": "Office Unbound Administrator",
                           "groups": ["mail-users", "opencloudAdmin", "org-admin"], "locked": False},
                          {"uid": "jane", "mail": "jane@acme.example", "given_name": "Jane", "surname": "Doe", "groups": ["mail-users"], "locked": True}],
               "groups": [], "truncated": False}
    _setup(rt, monkeypatch, calls, {"cfg.ldap_list": listing, "cfg.ldap_delete": {"deleted": True}})
    assert op.get("/api/v1/deployments/prod/people").status_code == 403
    r = adm.get("/api/v1/deployments/prod/people").json()
    assert [(x["username"], x["role"], x["locked"], x["system"]) for x in r["people"]] == [("jane", "user", True, False), ("ou-admin", "admin", False, True)]
    assert r["people"][0]["name"] == "Jane Doe" and calls[-1][0] == "node-acme-prod-id"
    assert _run_plan(adm, ah, apr, aph, "directory.account.lock", {"deployment": "prod", "username": "jane", "locked": False})["status"] == "succeeded"
    assert calls[-1][1:] == ("cfg.ldap_lock", {"domain": "acme.example", "uid": "jane", "locked": False})
    apr2 = login(mk_user("third", "approver"))   # high risk: two approvers
    assert _run_plan(adm, ah, apr, aph, "directory.account.delete", {"deployment": "prod", "username": "jane"}, apr2)["status"] == "succeeded"
    assert calls[-1][1:] == ("cfg.ldap_delete", {"domain": "acme.example", "uid": "jane"})


def test_tenancy_mode_is_chosen_once_and_not_switched_under_live_deployments(rt, client, mk_user, login):
    rt_ref[0] = rt
    adm, ah = login(mk_user("boss", "admin"))
    apr, aph = login(mk_user("second", "approver"))
    assert adm.get("/api/v1/settings/tenancy").json() == {"mode": None, "deployments": 0, "can_change": True, "note": None}
    assert _run_plan(adm, ah, apr, aph, "settings.tenancy.set", {"mode": "single"})["status"] == "succeeded"
    with rt.session() as db:
        db.execute(text("INSERT INTO deployments (slug, customer_id, profile, profile_version, status, desired_spec) "
                        "VALUES ('live', 'c-000000000000', 'small', '1', 'active', '{}'::jsonb)"))
        db.commit()
    t = adm.get("/api/v1/settings/tenancy").json()
    assert t["mode"] == "single" and t["can_change"] is False and "not available" in t["note"]
    job = _run_plan(adm, ah, apr, aph, "settings.tenancy.set", {"mode": "multi"})
    assert job["status"] == "failed" and "not available" in json.dumps(job["error"])
    assert adm.get("/api/v1/settings/tenancy").json()["mode"] == "single"


def test_ou_admin_and_bad_names_are_refused_when_the_plan_is_made():
    """Security review 2026-11-21: ou-admin is never changed or locked from People; names follow the agent's rule."""
    import pytest
    from pydantic import ValidationError
    from ics.deploy.accounts import AccountLock, AccountSet
    for bad in (lambda: AccountLock(deployment="prod", username="ou-admin", locked=True),
                lambda: AccountSet(deployment="prod", username="ou-admin", password="abcdefgh1"),
                lambda: AccountSet(deployment="prod", username="jane", password="abcdefgh1", display_name="Jane 2")):
        with pytest.raises(ValidationError):
            bad()
    assert AccountSet(deployment="prod", username="jane", password="abcdefgh1", display_name="Jane O'Neil").display_name == "Jane O'Neil"
