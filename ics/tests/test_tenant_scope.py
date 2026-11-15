"""Tenant isolation (A20): customer-scoped operators must not see another customer's deployments or identity stacks.
Found by blueprints/lab/tests/t20_tenant_isolation.py against two real customer stacks (the lists were global)."""
import uuid

import pytest
from sqlalchemy import text

from .test_identity import add_stack
from .test_vault_m import mk_customer, mk_endpoint

H = "/api/v1"


@pytest.fixture()
def scoped(rt, mk_user, login):
    ca, cb = mk_customer(rt, "cust-a"), mk_customer(rt, "cust-b")
    ea, eb = mk_endpoint(rt, "ep-a", ca), mk_endpoint(rt, "ep-b", cb)
    with rt.session() as db:
        for k, e in (("a", ea), ("b", eb)):
            db.execute(text("INSERT INTO deployments (slug, customer_id, profile, profile_version, endpoint_id, status, desired_spec) "
                            "VALUES (:s, :c, 'p', '1', :e, 'active', '{}'::jsonb)"), {"s": f"dep-{k}", "c": f"cust-{k}", "e": e})
        db.commit()
    sa = mk_user("scoped-a", "operator")
    with rt.session() as db:
        db.execute(text("UPDATE users SET all_customers = false WHERE username = 'scoped-a'"))
        db.execute(text("INSERT INTO operator_customers (user_id, customer_id) VALUES (:u, :c)"), {"u": sa["id"], "c": ca})
        db.commit()
    return ca, cb, login(sa), login(mk_user("all", "operator"))


def test_deployments_are_scoped_to_the_operators_customers(scoped):
    ca, cb, (s, sh), (a, ah) = scoped
    assert [d["slug"] for d in s.get(f"{H}/deployments").json()] == ["dep-a"]
    assert s.get(f"{H}/deployments/dep-a").status_code == 200
    for path in ("", "/resources", "/events", "/drift"):
        assert s.get(f"{H}/deployments/dep-b{path}").status_code == 404, path
    assert s.post(f"{H}/deployments/dep-b/destroy/preview", headers=sh).status_code == 404
    assert [d["slug"] for d in a.get(f"{H}/deployments").json()] == ["dep-a", "dep-b"]   # MSP all-customers scope unchanged


def test_identity_stacks_are_scoped_to_the_operators_customers(scoped, rt):
    ca, cb, (s, sh), (a, ah) = scoped
    add_stack(rt, name="stack-a", customer_id=ca)
    add_stack(rt, name="stack-b", customer_id=cb)
    add_stack(rt, name="stack-legacy")                       # no customer binding: visible to all-customers operators only
    assert [x["name"] for x in s.get(f"{H}/identity/stacks").json()] == ["stack-a"]
    assert sorted(x["name"] for x in a.get(f"{H}/identity/stacks").json()) == ["stack-a", "stack-b", "stack-legacy"]
    assert s.get(f"{H}/identity/users?stack=stack-b").json() == []
    assert s.get(f"{H}/identity/reconcile?stack=stack-b").json() == []
    # identity actions on the other customer's stack are refused like any other cross-customer object (404, not 403)
    assert s.post(f"{H}/plans", json={"action": "idm.reconcile", "params": {"stack": "stack-b"}}, headers=sh).status_code == 404
    assert s.post(f"{H}/plans", json={"action": "idm.reconcile", "params": {"stack": "stack-legacy"}}, headers=sh).status_code == 404
