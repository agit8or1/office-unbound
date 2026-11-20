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
