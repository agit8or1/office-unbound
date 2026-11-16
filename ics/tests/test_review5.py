"""Security review 5 regression tests (M3-M7, L1, L5, L7). Each fails on the pre-fix code."""
import json
import os
import subprocess
import uuid

import pytest
from sqlalchemy import text

from ics.providers.proxmox import scope_change as scm
from ics.provisioning.model import Policy
from ics.provisioning.scope_model import ScopeTarget
from .test_identity import stack_params
from .test_provisioning import POLICY
from .test_vault_m import mk_customer, mk_endpoint

H = "/api/v1"
DEF = "00000000-0000-0000-0000-00000000a001"


# ------------------------------------------------------------------------------------------------------------------------------ M3
def test_m3_templates_are_a_widening_even_when_a_storage_is_dropped():
    old = Policy.model_validate({**POLICY, "scope_mode": "single_node"})
    nodes = {"pve06"}
    new = scm.target_policy(old, ScopeTarget(mode="single_node", nodes=["pve06"], template_vmids=[9612, 131, 555]))
    assert scm.direction(old, new, nodes) == "widen"                                                      # was "same"
    new2 = scm.target_policy(old, ScopeTarget(mode="single_node", nodes=["pve06"], template_vmids=[9612, 131, 555], storages=["PVE06-Storage"]))
    assert scm.direction(old, new2, nodes) in ("widen",)                                                  # was "narrow" with a storage dropped
    fewer = scm.target_policy(old, ScopeTarget(mode="single_node", nodes=["pve06"], template_vmids=[9612]))
    assert scm.direction(old, fewer, nodes) == "narrow"


# ------------------------------------------------------------------------------------------------------------------------------ M4/M5/M6
@pytest.fixture()
def world(rt, mk_user, login):
    ca, cb = mk_customer(rt, "cust-a"), mk_customer(rt, "cust-b")
    ea, eb = mk_endpoint(rt, "ep-a", ca), mk_endpoint(rt, "ep-b", cb)
    users = {"all": mk_user("all-op", "operator"), "all_ap": mk_user("all-ap", "approver"), "sa": mk_user("scoped-a", "approver"), "none": mk_user("scoped-none", "viewer")}
    with rt.session() as db:
        db.execute(text("UPDATE users SET all_customers = false WHERE username IN ('scoped-a', 'scoped-none')"))
        db.execute(text("INSERT INTO operator_customers (user_id, customer_id) VALUES (:u, :c)"), {"u": users["sa"]["id"], "c": ca})
        ids = {}
        for k, cu in (("a", ca), ("b", cb)):
            ids[f"node_{k}"] = str(db.execute(text(
                "INSERT INTO nodes (name, address, port, tls_fingerprint_sha256, agent_pubkey, agent_key_fp, customer_id) VALUES (:n, '10.0.0.5', 8443, :f, 'k', :f, :c) RETURNING id"),
                {"n": f"zz-{k}-node", "f": "ab" * 32, "c": cu}).scalar())
            ids[f"check_{k}"] = str(db.execute(text(
                "INSERT INTO checks (name, kind, config, interval_seconds, customer_id, created_by) VALUES (:n, 'tcp_tls', '{\"host\":\"x\"}'::jsonb, 60, :c, :u) RETURNING id"),
                {"n": f"zz-{k}-check", "c": cu, "u": users["all"]["id"]}).scalar())
            ids[f"inc_{k}"] = str(db.execute(text("INSERT INTO incidents (check_id, severity, status, title) VALUES (:c, 'critical', 'open', :t) RETURNING id"),
                                             {"c": ids[f"check_{k}"], "t": f"zz-{k}-incident"}).scalar())
            ids[f"chan_{k}"] = str(db.execute(text("INSERT INTO alert_channels (name, kind, config, enabled, customer_id) VALUES (:n, 'webhook', '{}'::jsonb, false, :c) RETURNING id"),
                                              {"n": f"zz-{k}-channel", "c": cu}).scalar())
            db.execute(text("INSERT INTO maintenance_windows (name, check_id, starts_at, ends_at, reason, customer_id) VALUES (:n, :ck, now(), now() + interval '1 hour', 'r', :c)"),
                       {"n": f"zz-{k}-maint", "ck": ids[f"check_{k}"], "c": cu})
            ids[f"pol_{k}"] = str(db.execute(text(
                "INSERT INTO backup_policies (name, tier, deployment, runner_node_id, schedule, retention, rpo_seconds, rto_seconds, repo, verify, repo_secret_enc, customer_id) "
                "VALUES (:n, 'files', 'd', :nd, CAST(:sch AS jsonb), CAST(:ret AS jsonb), 3600, 600, CAST(:repo AS jsonb), CAST(:ver AS jsonb), '\\x'::bytea, :c) RETURNING id"),
                {"n": f"zz-{k}-policy", "nd": ids[f"node_{k}"], "c": cu, "sch": json.dumps({"every_hours": 6}), "ret": json.dumps({"last": 3, "daily": 7, "weekly": 4, "monthly": 6}),
                 "repo": "{}", "ver": json.dumps({"check_every_seconds": 86400, "restore_every_seconds": 604800, "check_read_data_percent": 10})}).scalar())
        db.commit()
    return {"ca": ca, "cb": cb, "ea": ea, "eb": eb, "ids": ids, "users": users, "sessions": {k: login(v) for k, v in users.items()}}


def test_m4_a_scoped_approver_cannot_decide_another_customers_plan(rt, world):
    ids, us = world["ids"], world["users"]
    pid = str(uuid.uuid4())
    with rt.session() as db:
        db.execute(text("INSERT INTO plans (id, action, params, risk, status, requested_by, params_hash, customer_id) "
                        "VALUES (:i, 'check.delete', CAST(:p AS jsonb), 'normal', 'pending_approval', :u, 'h', :c)"),
                   {"i": pid, "p": json.dumps({"check_id": ids["check_b"]}), "u": us["all"]["id"], "c": world["cb"]})
        db.commit()
    c, h = world["sessions"]["sa"]
    assert c.post(f"{H}/plans/{pid}/approve", headers=h).status_code == 404
    assert c.post(f"{H}/plans/{pid}/reject", headers=h).status_code == 404
    with rt.session() as db:
        assert db.execute(text("SELECT status FROM plans WHERE id = :i"), {"i": pid}).scalar() == "pending_approval"
        assert db.execute(text("SELECT count(*) FROM plan_approvals WHERE plan_id = :i"), {"i": pid}).scalar() == 0
    ac, ah = world["sessions"]["all_ap"]
    assert ac.post(f"{H}/plans/{pid}/approve", headers=ah).status_code == 200      # an all-customers approver still can


def test_m5_every_listed_get_route_is_scoped_or_explicitly_global(client, world):
    """Enumerates ALL GET routes of the app. For every route not on the global allowlist, a customer-A-scoped user and a user with NO customers must not see
    any marker of customer B (and the zero-scope user nothing of A either); path parameters are filled with customer B's objects."""
    ids = world["ids"]
    GLOBAL = {   # path -> reason it carries no customer data
        "/api/v1/actions": "static action catalogue", "/api/v1/auth/me": "the caller's own identity", "/api/v1/version": "minimal for non-admins (L5)",
        "/api/v1/system": "ICS host health (admin view of the ICS itself)", "/api/v1/catalog/profiles": "static deployment profile catalogue",
        "/api/v1/catalog/components": "static component catalogue", "/api/v1/setup/state": "ICS first-run state", "/api/v1/audit": "403 for scoped operators",
        "/api/v1/audit/verify": "hash-chain verdict only", "/api/v1/users": "ICS operator directory (MSP staff)", "/api/v1/users/{user_id}": "ICS operator directory (MSP staff)",
        "/api/v1/invitations": "ICS operator directory (MSP staff)", "/api/v1/access-policy": "ICS access policy", "/api/v1/operators/scopes": "operator scope admin view",
        "/healthz": "liveness", "/readyz": "liveness", "/approve": "public approval page (token-gated)", "/": "console shell", "/docs": "disabled",
        "/api/v1/credentials/access-review": "scoped in its handler (customer filter)", }
    params = {"endpoint_id": world["eb"], "check_id": ids["check_b"], "incident_id": ids["inc_b"], "customer_id": world["cb"], "provider_id": world["eb"],
              "slug": "dep-b", "job_id": str(uuid.uuid4()), "package_id": str(uuid.uuid4()), "approval_id": str(uuid.uuid4()), "credential_id": str(uuid.uuid4())}
    markers = ["zz-b-", "cust-b", "ep-b", "dep-b", ids["check_b"], ids["inc_b"], ids["node_b"], ids["chan_b"], ids["pol_b"], world["eb"]]
    seen = 0
    for route in client.app.routes:
        methods = getattr(route, "methods", None) or set()
        path = getattr(route, "path", "")
        if "GET" not in methods or path in GLOBAL or path.startswith(("/openapi", "/redoc", "/static", "/assets")):
            continue
        names = [seg[1:-1] for seg in path.split("/") if seg.startswith("{")]
        missing = [n for n in names if n not in params]
        assert not missing, f"{path}: unmapped path parameter(s) {missing}: scope it and map it here, or allowlist it with a reason"
        url = path
        for n in names:
            url = url.replace("{" + n + "}", params[n])
        for who in ("sa", "none"):
            c, _ = world["sessions"][who]
            r = c.get(url)
            body = r.text
            assert r.status_code != 500, (path, who, body[:200])
            for mk in markers:
                assert mk not in body, f"{path} leaks customer B data ({mk!r}) to {who}: {body[:300]}"
            if who == "none":
                assert "zz-a-" not in body and "cust-a" not in body, f"{path} shows customer A data to a user with no customers"
        seen += 1
    assert seen > 25


def test_m5_scoped_operator_sees_its_own_monitoring_objects(client, world):
    c, _ = world["sessions"]["sa"]
    assert [x["name"] for x in c.get(f"{H}/nodes").json()] == ["zz-a-node"]
    assert [x["name"] for x in c.get(f"{H}/checks").json()] == ["zz-a-check"]
    assert [x["title"] for x in c.get(f"{H}/incidents").json()] == ["zz-a-incident"]
    assert [x["name"] for x in c.get(f"{H}/alert-channels").json()] == ["zz-a-channel"]
    assert [x["name"] for x in c.get(f"{H}/maintenance").json()] == ["zz-a-maint"]
    assert [x["name"] for x in c.get(f"{H}/backups/policies").json()] == ["zz-a-policy"]
    ids = world["ids"]
    assert c.get(f"{H}/checks/{ids['check_a']}/results").status_code == 200
    assert c.get(f"{H}/checks/{ids['check_b']}/results").status_code == 404
    assert c.get(f"{H}/checks/{ids['check_b']}/remediation").status_code == 404
    assert c.get(f"{H}/incidents/{ids['inc_b']}").status_code == 404
    a, _ = world["sessions"]["all"]
    assert sorted(x["name"] for x in a.get(f"{H}/nodes").json()) == ["zz-a-node", "zz-b-node"]       # the MSP all-customers scope is unchanged


def test_m5_new_objects_default_to_the_msp_internal_customer(rt):
    with rt.session() as db:
        nid = db.execute(text("INSERT INTO nodes (name, address, port, tls_fingerprint_sha256, agent_pubkey, agent_key_fp) VALUES ('n', 'h', 1, :f, 'k', :f) RETURNING id"),
                         {"f": "ab" * 32}).scalar()
        assert str(db.execute(text("SELECT customer_id FROM nodes WHERE id = :i"), {"i": nid}).scalar()) == DEF


def test_m6_stack_cannot_reference_another_customers_node(client, world, rt):
    ids = world["ids"]
    c, h = world["sessions"]["all"]
    base = dict(gromox_node_id=None, mail_host=None, mail_ca_pem=None, files_url="https://127.0.0.1:8443", ldap_url="ldaps://127.0.0.1:636", kc_url="https://127.0.0.1:8443")
    p = stack_params(name="x-stack", customer_id=world["ca"], files_node_id=ids["node_b"], **base)
    r = c.post(f"{H}/plans", json={"action": "idm.stack.register", "params": p}, headers=h)
    assert r.status_code == 422 and "node not found" in r.text, r.text                      # was 201: B's node accepted for A's stack
    ok = stack_params(name="y-stack", customer_id=world["ca"], files_node_id=ids["node_a"], **base)
    assert c.post(f"{H}/plans", json={"action": "idm.stack.register", "params": ok}, headers=h).status_code == 201
    ghost = stack_params(name="z-stack", customer_id=world["ca"], files_node_id=str(uuid.uuid4()), **base)
    r2 = c.post(f"{H}/plans", json={"action": "idm.stack.register", "params": ghost}, headers=h)
    assert r2.status_code == 422 and r2.json() == r.json() or "node not found" in r2.text   # no existence oracle


def test_m6_agent_user_refuses_a_node_of_another_customer(rt, world):
    from ics import identity
    with pytest.raises(identity.IdentityError, match="does not belong"):
        identity.agent_user(rt, world["ids"]["node_b"], "pbx.kick_user", "alice", [], customer=world["ca"])


# ------------------------------------------------------------------------------------------------------------------------------ L1
def test_l1_sweeper_wipes_expired_bootstrap_secrets_and_unrevealed_sip_credentials(rt, world):
    from ics import actions
    from ics.guest import bootsecrets
    rec = bootsecrets.issue(rt, "00000000-0000-0000-0000-0000000000c1", "vm1", 140, "callback", config={"v": 1})
    live = bootsecrets.issue(rt, "00000000-0000-0000-0000-0000000000c2", "vm2", 141, "callback", config={"v": 1})
    with rt.session() as db:
        db.execute(text("UPDATE guest_bootstrap SET expires_at = now() - interval '2 hours' WHERE id = :i"), {"i": rec.id})
        db.commit()
    actions.reap_expired(rt)
    assert bootsecrets.secrets_wiped(rt, rec.id) and not bootsecrets.secrets_wiped(rt, live.id)
    with rt.session() as db:
        assert db.execute(text("SELECT state FROM guest_bootstrap WHERE id = :i"), {"i": rec.id}).scalar() == "expired"
        assert db.execute(text("SELECT count(*) FROM audit_events WHERE action = 'guest.bootstrap_secret_swept'")).scalar() == 1


def test_l1_sip_sweeper(rt, world):
    from ics import actions
    uid = world["users"]["all"]["id"]
    with rt.session() as db:
        sid = db.execute(text("INSERT INTO idm_stacks (name, config, secret_enc) VALUES ('s', '{}'::jsonb, '\\x'::bytea) RETURNING id")).scalar()
        u = db.execute(text("INSERT INTO idm_users (stack_id, uid, mail, state, entry_uuid, display_name) VALUES (:s, 'alice', 'a@x', 'active', gen_random_uuid(), 'Alice') RETURNING id"), {"s": sid}).scalar()
        a = db.execute(text("INSERT INTO idm_sip_credentials (user_id, requested_by, device, secret_enc, expires_at) VALUES (:u, :r, 'web', '\\x01'::bytea, now() - interval '1 minute') RETURNING id"),
                       {"u": u, "r": uid}).scalar()
        b = db.execute(text("INSERT INTO idm_sip_credentials (user_id, requested_by, device, secret_enc, expires_at) VALUES (:u, :r, 'desk', '\\x01'::bytea, now() + interval '1 hour') RETURNING id"),
                       {"u": u, "r": uid}).scalar()
        db.commit()
    actions.reap_expired(rt)
    with rt.session() as db:
        assert db.execute(text("SELECT secret_enc IS NULL FROM idm_sip_credentials WHERE id = :i"), {"i": a}).scalar() is True
        assert db.execute(text("SELECT secret_enc IS NULL FROM idm_sip_credentials WHERE id = :i"), {"i": b}).scalar() is False


# ------------------------------------------------------------------------------------------------------------------------------ L5
def test_l5_version_detail_only_for_admins(client, mk_user, login, rt):
    from ics import version as ver
    assert client.get(f"{H}/version").json() == {"product": "Office Unbound", "version": ver.__version__.split(".")[0]}
    assert "." not in client.get("/readyz").json()["version"]
    v, _ = login(mk_user("viewer1", "viewer"))
    assert v.get(f"{H}/version").json() == {"product": "Office Unbound", "version": ver.__version__.split(".")[0]}
    ad, _ = login(mk_user("admin1", "admin"))
    d = ad.get(f"{H}/version").json()
    assert d["version"] == ver.__version__ and "components" in d and "schema" in d
    with rt.session() as db:                       # an admin limited to one customer is not an all-customers admin
        db.execute(text("UPDATE users SET all_customers = false WHERE username = 'admin1'"))
        db.commit()
    assert ad.get(f"{H}/version").json() == {"product": "Office Unbound", "version": ver.__version__.split(".")[0]}


# ------------------------------------------------------------------------------------------------------------------------------ L7
RECIPE = os.path.join(os.path.dirname(__file__), "..", "..", "blueprints", "build", "guest-image", "recipe.sh")


def run_recipe(tmp_path, **env):
    e = {"PATH": os.environ["PATH"], "WORK": str(tmp_path / "w"), "UPSTREAM_KEY_FPR": "A" * 40, **env}
    return subprocess.run(["bash", RECIPE, "debian-12", "fetch"], env=e, capture_output=True, text=True)


def test_l7_upstream_must_be_pinned_fresh_and_never_older_than_the_last(tmp_path):
    r = run_recipe(tmp_path)
    assert r.returncode == 3 and "UPSTREAM_SERIAL is not pinned" in r.stderr
    r = run_recipe(tmp_path, UPSTREAM_SERIAL="20240101-1", OU_TODAY="20261115")
    assert r.returncode == 3 and "days old" in r.stderr
    (tmp_path / "w").mkdir(exist_ok=True)
    (tmp_path / "w" / "upstream-serial.last").write_text("20261110-5\n")
    r = run_recipe(tmp_path, UPSTREAM_SERIAL="20261101-1", OU_TODAY="20261115")
    assert r.returncode == 3 and "OLDER than the last accepted" in r.stderr
    r = run_recipe(tmp_path, UPSTREAM_SERIAL="20261112-1", OU_TODAY="20261115", UPSTREAM_KEY_FPR="")      # passes the serial gate, then stops at the key pin
    assert "serial" not in r.stderr.lower() or "not pinned" not in r.stderr.split("UPSTREAM_KEY_FPR")[0]
    assert r.returncode == 3 and "UPSTREAM_KEY_FPR is not pinned" in r.stderr
