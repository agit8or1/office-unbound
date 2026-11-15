"""Integration of provider provisioning (agent L) with the credential vault / customers / approvals (agent M).
Proxmox is the stateful simulator (test double)."""
import json
import zipfile
import io

import pytest
from sqlalchemy import text

from ics import monitor
from ics.credentials import service as cred
from ics.provisioning import actions as pa, service as psvc
from ics.tenancy import plan_provider, policy as tpolicy
from .infra_fixtures import H
from .test_inventory import World
from .test_provisioning import POLICY, owner, preview, mode_a  # noqa: F401  (fixtures)
from .test_vault_m import mk_customer

MON = {"preset": "monitoring", "scope": {"nodes": ["pve06"], "pools": ["officeunbound-pve06"], "storages": ["PVE06-Storage"]}}


@pytest.fixture()
def w(rt, mk_user, login):
    return World(rt, mk_user, login)


def _dump(owner_engine):
    with owner_engine.connect() as c:
        out = []
        for q in ("SELECT params::text, coalesce(secret_enc::text,'') FROM plans", "SELECT coalesce(result::text,''), coalesce(error::text,'') FROM jobs",
                  "SELECT details_canon FROM audit_events", "SELECT data::text FROM provision_artifacts"):
            out += [[str(x) for x in r] for r in c.execute(text(q)).all()]
    return json.dumps(out)


# (1) token secrets and temporary credentials live only in the credential subsystem --------------------------------------------
def test_mode_a_secrets_in_vault_and_temp_credentials_wiped(w, owner, rt, owner_engine):
    pv, p, j = mode_a(w, owner)
    assert j["status"] == "succeeded", j
    eid = j["result"]["endpoint_id"]
    with rt.session() as db:
        ep = db.execute(text("SELECT * FROM endpoints WHERE id = :i"), {"i": eid}).first()
        assert ep.inventory_credential_id and ep.provision_credential_id
        assert not ep.token_secret_enc and not ep.provision_secret_enc                       # no parallel legacy storage
        tmp = db.execute(text("SELECT * FROM credentials WHERE purpose = 'temporary_provisioning'")).all()
        assert len(tmp) == 2                                                                   # preview + apply
        for c in tmp:
            assert c.status == "revoked" and c.purged_at is not None and len(bytes(c.secret_enc)) == 0
            assert (c.expires_at - c.created_at).total_seconds() <= 15 * 60 + 1
        assert db.execute(text("SELECT count(*) FROM plans WHERE secret_enc IS NOT NULL")).scalar() == 0
    assert cred.endpoint_secret(rt, ep, "provision") == owner.sim.tokens["ics-svc@pve!ics-prov"]["secret"]
    assert owner.sim.ROOT_PW not in _dump(owner_engine)


def test_temp_credential_exists_with_ttl_while_plan_is_pending_and_is_wiped_on_reject(w, owner, rt):
    params = {"name": "owner", "base_url": owner.url, "fingerprint_sha256": owner.fingerprint, "admin_username": "root@pam",
              "admin_password": owner.sim.ROOT_PW, "policy": POLICY}
    pl = w.plan("provider.provision.plan_preview", params)
    with rt.session() as db:
        c = db.execute(text("SELECT * FROM credentials WHERE id = :i"), {"i": pl["plan_id"]}).first()
        assert c and c.purpose == "temporary_provisioning" and c.status == "active" and len(bytes(c.secret_enc)) > 0
        assert (c.expires_at - c.created_at).total_seconds() <= 15 * 60 + 1
        assert db.execute(text("SELECT secret_enc FROM plans WHERE id = :i"), {"i": pl["plan_id"]}).scalar() is None
    while __import__("ics.worker", fromlist=["x"]).run_once(rt):
        pass
    with rt.session() as db:   # preview is low risk -> ran at once -> credential destroyed
        assert db.execute(text("SELECT status FROM credentials WHERE id = :i"), {"i": pl["plan_id"]}).scalar() == "revoked"
    # a high-risk plan rejected before running: wiped on reject
    pv = preview(w, owner)
    ap = w.plan("provider.provision.apply", {**{k: v for k, v in params.items() if k != "policy"}, "preview_id": pv["preview_id"], "plan_hash": pv["plan_hash"]})
    with rt.session() as db:
        assert db.execute(text("SELECT status FROM credentials WHERE id = :i"), {"i": ap["plan_id"]}).scalar() == "active"
    assert w.a1.post(f"{H}/plans/{ap['plan_id']}/reject", headers=w.a1h).status_code == 200
    with rt.session() as db:
        r = db.execute(text("SELECT status, length(secret_enc) AS n FROM credentials WHERE id = :i"), {"i": ap["plan_id"]}).first()
        assert r.status == "revoked" and r.n == 0
    assert not owner.sim.changes


def test_expired_temp_credential_is_unusable_and_reaped(w, owner, rt):
    pv = preview(w, owner)
    params = {"name": "owner", "base_url": owner.url, "fingerprint_sha256": owner.fingerprint, "admin_username": "root@pam",
              "admin_password": owner.sim.ROOT_PW, "preview_id": pv["preview_id"], "plan_hash": pv["plan_hash"]}
    ap = w.plan("provider.provision.apply", params)
    with rt.session() as db:
        db.execute(text("UPDATE credentials SET expires_at = now() - interval '1 minute' WHERE id = :i"), {"i": ap["plan_id"]})
        db.commit()
    with pytest.raises(cred.CredentialUnavailable):
        cred.get_secret(rt, ap["plan_id"])
    from ics.actions import reap_expired
    reap_expired(rt)
    with rt.session() as db:
        r = db.execute(text("SELECT status, length(secret_enc) AS n FROM credentials WHERE id = :i"), {"i": ap["plan_id"]}).first()
        assert r.status == "revoked" and r.n == 0
        # not alerted as a (long-lived) credential expiry
        assert db.execute(text("SELECT count(*) FROM credential_alerts WHERE credential_id = :i"), {"i": ap["plan_id"]}).scalar() == 0
    assert not owner.sim.changes


def test_revoke_destroys_endpoint_credentials(w, owner, rt):
    pv, p, j = mode_a(w, owner)
    eid = j["result"]["endpoint_id"]
    pk, jk = w.run("provider.token.revoke", {"endpoint_id": eid, "confirm_name": "owner"})
    assert jk["status"] == "succeeded", jk
    with rt.session() as db:
        rows = db.execute(text("SELECT status, length(secret_enc) AS n FROM credentials WHERE purpose IN ('inventory','provision') AND label LIKE 'owner%'")).all()
        assert rows and all(r.status == "revoked" and r.n == 0 for r in rows)


# (2) permission plan + package on the customer approval link --------------------------------------------------------------------
def test_customer_approval_shows_real_permissions_and_package(client, rt, mk_user, login, owner):
    cust = mk_customer(rt, "Acme", mode="customer_approval")
    op, oh = login(mk_user("op", "operator"))
    a1, a1h = login(mk_user("ap1", "approver"))
    a2, a2h = login(mk_user("ap2", "approver"))
    r = op.post(f"{H}/plans", json={"action": "provider.provision.package", "params": {"customer_id": cust, "pve_major": 9, "policy": POLICY}}, headers=oh)
    assert r.status_code == 201, r.text
    pl = r.json()
    assert pl["customer_approval_id"] if "customer_approval_id" in pl else True
    with rt.session() as db:
        ap = db.execute(text("SELECT * FROM customer_approvals WHERE plan_id = :p"), {"p": pl["plan_id"]}).first()
    assert ap is not None
    prop = ap.proposal
    assert not prop["stub_plan"] and "package_files" in prop and "provision.sh" in prop["package_files"]
    privs = {(x["path"], x["privilege"]) for x in prop["permissions"]}
    assert ("/pool/officeunbound-pve06", "VM.Allocate") in privs and ("/nodes/pve06", "Sys.Audit") in privs
    assert not any(p["privilege"] in ("Permissions.Modify", "User.Modify") for p in prop["permissions"])
    # operator submits -> link; the customer sees the real plan and downloads the real package
    sub = op.post(f"{H}/customer-approvals/{ap.id}/submit", json={}, headers=oh)
    assert sub.status_code in (200, 201), sub.text
    token = sub.json()["link_path"].split("#t=")[1]
    pub = "/api/v1/public/approvals"
    v = client.post(f"{pub}/view", json={"token": token}).json()
    assert v["package_available"] and any(x["privilege"] == "VM.Allocate" for x in v["permissions"])
    z = client.post(f"{pub}/package", json={"token": token})
    assert z.status_code == 200 and z.headers["content-type"] == "application/zip"
    names = zipfile.ZipFile(io.BytesIO(z.content)).namelist()
    assert {"provision.sh", "rollback.sh", "report.md", "package.json"} <= set(names)
    assert client.post(f"{pub}/package", json={"token": "a.bad.token.x"}).status_code == 404
    # plan is held until the customer approves (the ICS approval alone is not enough)
    assert pl["status"] == "pending_approval"
    for c_, h_ in ((a1, a1h), (a2, a2h)):
        c_.post(f"{H}/plans/{pl['plan_id']}/approve", headers=h_)
    with rt.session() as db:
        assert db.execute(text("SELECT count(*) FROM jobs WHERE plan_id = :i"), {"i": pl["plan_id"]}).scalar() == 0   # no job before the customer decides
    d = client.post(f"{pub}/decide", json={"token": token, "decision": "approve", "name": "Pat Customer", "email": "pat@acme.example",
                                           "statement": "I am authorised to approve this", "proposal_hash": v["proposal_hash"]})
    assert d.status_code == 200 and d.json()["job_released"] is True, d.text


# (3) per-customer policy gates provider actions ----------------------------------------------------------------------------------
def test_policy_classification_of_every_provider_action():
    class P:  # minimal stand-ins
        provision_token_id = None
    for a in ("provider.provision.apply", "provider.permissions.reconcile", "provider.token.rotate", "provider.token.revoke"):
        assert tpolicy.classify(a, P())[0] is True
    assert tpolicy.classify("provider.provision.plan_preview", P()) == (False, None)
    assert tpolicy.CATEGORY_OF["provider.token.revoke"] == "revoke_credential" and tpolicy.CATEGORY_OF["provider.provision.apply"] == "expand_permissions"
    P.provision_token_id = "x@pve!y"
    assert tpolicy.classify("provider.credential.import", P()) == (True, "expand_permissions")


def test_monitoring_only_customer_refuses_mode_a_and_privileged_package(w, owner, rt):
    cust = mk_customer(rt, "Mon", mode="monitoring_only")
    base = {"customer_id": cust, "name": "mon", "base_url": owner.url, "fingerprint_sha256": owner.fingerprint}
    # read-only preview is allowed, even with a privileged policy
    w.plan("provider.provision.plan_preview", {**base, "admin_username": "root@pam", "admin_password": owner.sim.ROOT_PW, "policy": POLICY})
    # a monitoring-preset package is allowed, a deploy package is refused
    w.plan("provider.provision.package", {"customer_id": cust, "pve_major": 9, "policy": MON})
    r = w.o.post(f"{H}/plans", json={"action": "provider.provision.package", "params": {"customer_id": cust, "pve_major": 9, "policy": POLICY}}, headers=w.oh)
    assert r.status_code == 403
    # Mode A apply is refused (admin credentials on a monitoring-only customer's cluster)
    while __import__("ics.worker", fromlist=["x"]).run_once(rt):
        pass
    with rt.session() as db:
        art = db.execute(text("SELECT id, plan_hash FROM provision_artifacts WHERE kind = 'plan' ORDER BY created_at DESC LIMIT 1")).first()
    r = w.o.post(f"{H}/plans", json={"action": "provider.provision.apply", "params": {**base, "admin_username": "root@pam", "admin_password": owner.sim.ROOT_PW,
                                                                                          "preview_id": str(art.id), "plan_hash": art.plan_hash}}, headers=w.oh)
    assert r.status_code == 403
    assert not owner.sim.changes


def test_extra_approvals_apply_to_provider_actions(w, owner, rt):
    cust = mk_customer(rt, "Own", msp_owned=True, mode="auto", extra={"expand_permissions": 1, "revoke_credential": 1})
    pv = preview(w, owner, customer_id=cust)
    params = {"customer_id": cust, "name": "owner", "base_url": owner.url, "fingerprint_sha256": owner.fingerprint, "admin_username": "root@pam",
              "admin_password": owner.sim.ROOT_PW, "preview_id": pv["preview_id"], "plan_hash": pv["plan_hash"]}
    ap = w.plan("provider.provision.apply", params)
    assert ap["risk"] == "high" and ap["approvals_required"] == 3          # 2 (high) + 1 extra (expand_permissions)
    assert w.a1.post(f"{H}/plans/{ap['plan_id']}/reject", headers=w.a1h).status_code == 200


def test_customer_approval_mode_gates_apply_until_customer_approves(w, owner, rt):
    cust = mk_customer(rt, "Cust", mode="customer_approval")
    pv = preview(w, owner, customer_id=cust)
    params = {"customer_id": cust, "name": "owner", "base_url": owner.url, "fingerprint_sha256": owner.fingerprint, "admin_username": "root@pam",
              "admin_password": owner.sim.ROOT_PW, "preview_id": pv["preview_id"], "plan_hash": pv["plan_hash"]}
    ap = w.plan("provider.provision.apply", params)
    for c, h in ((w.a1, w.a1h), (w.a2, w.a2h)):
        c.post(f"{H}/plans/{ap['plan_id']}/approve", headers=h)
    while __import__("ics.worker", fromlist=["x"]).run_once(rt):
        pass
    with rt.session() as db:
        assert db.execute(text("SELECT status FROM plans WHERE id = :i"), {"i": ap["plan_id"]}).scalar() == "pending_approval"
        assert db.execute(text("SELECT count(*) FROM jobs WHERE plan_id = :i"), {"i": ap["plan_id"]}).scalar() == 0
    assert not owner.sim.changes


# (4) customer scoping of providers/permissions/packages endpoints -----------------------------------------------------------------
def test_scoping_of_permissions_and_package_endpoints(w, owner, rt, mk_user, login):
    pv, p, j = mode_a(w, owner)                        # default customer
    eid = j["result"]["endpoint_id"]
    other = mk_customer(rt, "Other", mode="customer_approval")
    pk = w.plan("provider.provision.package", {"customer_id": other, "pve_major": 9, "policy": MON}) if False else None
    # a package bound to "other"
    w2 = w.plan("provider.provision.package", {"customer_id": other, "pve_major": 9, "policy": MON})
    assert w.a1.post(f"{H}/plans/{w2['plan_id']}/approve", headers=w.a1h).status_code == 200
    while __import__("ics.worker", fromlist=["x"]).run_once(rt):
        pass
    with rt.session() as db:
        pkg = db.execute(text("SELECT id, customer_id FROM provision_artifacts WHERE kind = 'package'")).first()
        assert str(pkg.customer_id) == other
        uid = db.execute(text("SELECT id FROM users WHERE username = 'op'")).scalar()
    # scope operator 'sc' to 'other' only
    sc = mk_user("sc", "admin")
    with rt.session() as db:
        db.execute(text("UPDATE users SET all_customers = false WHERE username = 'sc'"))
        db.execute(text("INSERT INTO operator_customers (user_id, customer_id) SELECT id, :c FROM users WHERE username = 'sc'"), {"c": other})
        db.commit()
    c, h = login(sc)
    assert c.get(f"{H}/providers/{eid}/permissions", headers=h).status_code == 404            # other customer's endpoint
    assert c.post(f"{H}/providers/{eid}/permissions/check", headers=h).status_code == 404
    assert c.get(f"{H}/providers/unbound/provisioning/packages/{pkg.id}", headers=h).status_code == 200   # own customer's package
    # package of the default customer is invisible to the scoped operator
    with rt.session() as db:
        db.execute(text("UPDATE provision_artifacts SET customer_id = '00000000-0000-0000-0000-00000000a001' WHERE id = :i"), {"i": str(pkg.id)})
        db.commit()
    assert c.get(f"{H}/providers/unbound/provisioning/packages/{pkg.id}", headers=h).status_code == 404
    assert w.ad.get(f"{H}/providers/unbound/provisioning/packages/{pkg.id}").status_code == 200
    assert w.v.get(f"{H}/providers/{eid}/permissions").status_code == 200                       # all-customers viewer still sees it
    # a scoped operator cannot reference another customer's preview
    r = c.post(f"{H}/plans", json={"action": "provider.provision.package", "params": {"customer_id": "00000000-0000-0000-0000-00000000a001", "pve_major": 9, "policy": MON}}, headers=h)
    assert r.status_code == 404


# (5) drift / token failure reach the alert outbox -------------------------------------------------------------------------------
def test_drift_and_token_failure_reach_alert_outbox(w, owner, rt):
    with rt.session() as db:
        db.execute(text("INSERT INTO alert_channels (name, kind, config, enabled) VALUES ('ops', 'webhook', CAST('{\"url\":\"https://example.invalid/h\"}' AS jsonb), true)"))
        db.commit()
    pv, p, j = mode_a(w, owner)
    eid = j["result"]["endpoint_id"]
    owner.sim.roles["OfficeUnboundDeploy"].discard("VM.Snapshot")
    assert w.o.post(f"{H}/providers/{eid}/permissions/check", headers=w.oh).json()["ok"] is False
    with rt.session() as db:
        ev = [r.event for r in db.execute(text("SELECT event FROM notifications")).all()]
    assert ev.count("provider.permissions.drift") == 1
    w.o.post(f"{H}/providers/{eid}/permissions/check", headers=w.oh)                         # unchanged status: no repeat
    owner.sim.tokens.pop("ics-svc@pve!ics-prov")
    assert w.o.post(f"{H}/providers/{eid}/permissions/check", headers=w.oh).json()["error_code"] == "token_failed"
    with rt.session() as db:
        rows = db.execute(text("SELECT event, detail FROM notifications")).all()
    assert [r.event for r in rows].count("provider.permissions.drift") == 1 and [r.event for r in rows].count("provider.token.failed") == 1
    assert all(owner.sim.ROOT_PW not in (r.detail or "") for r in rows)
    psvc._next.clear()
