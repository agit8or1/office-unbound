"""Credential vault, MSP customers/policies, customer scoping, external customer approval, master-key re-wrap."""
import json
import logging
import os
import re
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text

from ics import audit, cli, monitor, worker
from ics.actions import endpoint_binding
from ics.credentials import envelope, expiry, rewrap, service
from ics.tenancy import approvals, public
from ics.vault import Vault, VaultError
from .pve_mock import SEC, TID

H = "/api/v1"
S1, S2 = "Sup3rSecretValue_One1", "Sup3rSecretValue_Two2"
DEFAULT = "00000000-0000-0000-0000-00000000a001"


def mk_customer(rt, name, *, msp_owned=False, mode="customer_approval", extra=None):
    with rt.session() as db:
        cid = db.execute(text("INSERT INTO customers (name, msp_owned, provisioning_mode, extra_approvals) VALUES (:n, :o, :m, CAST(:x AS jsonb)) RETURNING id"),
                         {"n": name, "o": msp_owned, "m": mode, "x": json.dumps(extra or {})}).scalar()
        db.commit()
    return str(cid)


def mk_cred(rt, customer=DEFAULT, secret=S1, provider="fakeprov", purpose="inventory", expires_at=None, label="cred"):
    with rt.session() as db:
        cid = service.create(db, rt, provider=provider, customer_id=customer, label=label, credential_type="api_token", purpose=purpose,
                             secret=secret, identity="svc@pve!ics", expires_at=expires_at, actor="test")
        db.commit()
    return cid


def mk_endpoint(rt, name, customer, pve=None):
    with rt.session() as db:
        eid = db.execute(text("INSERT INTO endpoints (name, type, base_url, token_id, token_secret_enc, fingerprint_sha256, customer_id) "
                              "VALUES (:n, 'proxmox', :u, :t, '\\x'::bytea, :f, :c) RETURNING id"),
                         {"n": name, "u": pve.url if pve else "https://pve.invalid:8006", "t": TID, "f": pve.fingerprint if pve else "ab" * 32, "c": customer}).scalar()
        db.commit()
    return str(eid)


def plan(c, h, action, params):
    r = c.post(f"{H}/plans", json={"action": action, "params": params}, headers=h)
    assert r.status_code == 201, r.text
    return r.json()


def run_plan(users, rt, action, params, need=2):
    """requester = users[0]; approvals by the following users; executes the job. Returns the job."""
    (c, h), approvers = users[0], users[1:]
    p = plan(c, h, action, params)
    job_id = p["job_id"]
    for ac, ah in approvers[: p["approvals_required"]] if p["status"] != "approved" else []:
        r = ac.post(f"{H}/plans/{p['plan_id']}/approve", headers=ah)
        assert r.status_code == 200, r.text
        job_id = r.json().get("job_id") or job_id
    while worker.run_once(rt):
        pass
    return c.get(f"{H}/jobs/{job_id}").json() if job_id else p


@pytest.fixture()
def team(mk_user, login):
    return {"op": login(mk_user("op", "operator")), "ap": login(mk_user("ap", "approver")), "ap2": login(mk_user("ap2", "approver")),
            "ap3": login(mk_user("ap3", "approver")), "adm": login(mk_user("adm", "admin"))}


# ------------------------------------------------------------------ envelope encryption
def test_envelope_roundtrip_and_aad_swap(rt):
    a, b = mk_cred(rt, secret=S1, label="a"), mk_cred(rt, secret=S2, label="b")
    assert service.get_secret(rt, a) == S1 and service.get_secret(rt, b) == S2
    with rt.session() as db:
        ra, rb = service.get_row(db, a), service.get_row(db, b)
        assert S1.encode() not in bytes(ra.secret_enc) and S1.encode() not in bytes(ra.wrapped_key)
        # swap the whole encrypted record: bound to id -> must fail
        db.execute(text("UPDATE credentials SET secret_enc = :s, wrapped_key = :w WHERE id = :i"), {"s": rb.secret_enc, "w": rb.wrapped_key, "i": a})
        db.commit()
    with pytest.raises(VaultError):
        service.get_secret(rt, a)
    # restoring a's own blob but changing the bound provider / customer also fails
    with rt.session() as db:
        db.execute(text("UPDATE credentials SET secret_enc = :s, wrapped_key = :w WHERE id = :i"), {"s": ra.secret_enc, "w": ra.wrapped_key, "i": a})
        db.commit()
    assert service.get_secret(rt, a) == S1
    other = mk_customer(rt, "other-co")
    for col, val in (("provider", "otherprov"), ("customer_id", other)):
        with rt.session() as db:
            db.execute(text(f"UPDATE credentials SET {col} = :v WHERE id = :i"), {"v": val, "i": a})
            db.commit()
        with pytest.raises(VaultError):
            service.get_secret(rt, a)
        with rt.session() as db:
            db.execute(text(f"UPDATE credentials SET {col} = :v WHERE id = :i"), {"v": ra.provider if col == "provider" else DEFAULT, "i": a})
            db.commit()
    assert service.get_secret(rt, a) == S1


# ------------------------------------------------------------------ master key re-wrap (+ admin CLI)
def test_master_key_rewrap_job_and_cli(rt, mk_user, tmp_path, monkeypatch, capsys):
    mk_user("someone", "operator")  # has a vault-encrypted TOTP seed
    ids = [mk_cred(rt, secret=S1, label="a"), mk_cred(rt, secret=S2, label="b")]
    newkey = tmp_path / "new.key"
    newkey.write_bytes(os.urandom(32))
    newkey.chmod(0o600)
    monkeypatch.setattr(cli, "Runtime", lambda: rt)
    assert cli.main(["rewrap-master", "--new-key-file", str(newkey)]) == 0
    assert "re-wrapped" in capsys.readouterr().out
    new = Vault.from_file(str(newkey))
    with rt.session() as db:
        for cid, sec in zip(ids, (S1, S2)):
            r = service.get_row(db, cid)
            assert r.master_key_id == envelope.vault_key_id(new)
            assert envelope.unseal(new, r.wrapped_key, r.secret_enc, r.id, r.provider, r.customer_id).decode() == sec
            with pytest.raises(VaultError):  # the old key no longer opens the data keys
                envelope.unseal(rt.vault, r.wrapped_key, r.secret_enc, r.id, r.provider, r.customer_id)
        t = db.execute(text("SELECT username, totp_secret_enc FROM users WHERE username = 'someone'")).first()
        assert new.decrypt(t.totp_secret_enc, "user-totp:someone")
        assert db.execute(text("SELECT count(*) FROM audit_events WHERE action = 'vault.master_key_rewrapped'")).scalar() == 1
        assert audit.verify_chain(db)["ok"]
    # a failing re-wrap (wrong "old" key) changes nothing
    with rt.session() as db:
        before = db.execute(text("SELECT wrapped_key FROM credentials ORDER BY id")).all()
        with pytest.raises(VaultError):
            rewrap.rewrap_all(db, rt.vault, Vault(os.urandom(32)))
        db.rollback()
        assert db.execute(text("SELECT wrapped_key FROM credentials ORDER BY id")).all() == before


# ------------------------------------------------------------------ rotation history, retire/purge, revocation
def test_rotation_history_retire_purge_and_revoke(rt):
    old = mk_cred(rt, secret=S1)
    with rt.session() as db:
        new = service.supersede(db, rt, old, secret=S2, actor="alice", reason="scheduled rotation", kind="rotated")
        db.commit()
    with rt.session() as db:
        o, n = service.get_row(db, old), service.get_row(db, new)
        assert o.status == "retired" and o.replaced_by == n.id and o.retire_after > datetime.now(timezone.utc)
        assert [e["event"] for e in service.history(db, old)] == ["created", "rotated_to"]
        assert service.history(db, new)[-1]["reason"] == "scheduled rotation" and service.history(db, new)[-1]["actor"] == "alice"
    with pytest.raises(service.CredentialUnavailable):
        service.get_secret(rt, old)  # retired = not usable
    assert service.get_secret(rt, new) == S2
    with rt.session() as db:  # retired credential is kept (not deleted) until the grace period ends
        assert service.get_row(db, old).secret_enc and service.purge_retired(db) == 0
        db.execute(text("UPDATE credentials SET retire_after = now() - interval '1 minute' WHERE id = :i"), {"i": old})
        assert service.purge_retired(db) == 1
        db.commit()
        r = service.get_row(db, old)
        assert r.purged_at and len(bytes(r.secret_enc)) == 0 and r is not None
    with rt.session() as db:
        service.revoke(db, new, actor="bob", reason="customer revoked access")
        db.commit()
    with pytest.raises(service.CredentialUnavailable):
        service.get_secret(rt, new)
    with rt.session() as db:
        r = service.get_row(db, new)
        assert r.status == "revoked" and len(bytes(r.secret_enc)) == 0
        with pytest.raises(service.CredentialUnavailable):  # revoked credentials are never silently re-created / superseded
            service.supersede(db, rt, new, secret=S1, actor="x", reason="try")


# ------------------------------------------------------------------ expiry alerts through the notification pipeline
def test_expiry_alert_pipeline(rt):
    with rt.session() as db:
        db.execute(text("INSERT INTO alert_channels (name, kind, config, enabled) VALUES ('wh', 'webhook', '{}', true)"))
        db.commit()
    soon = mk_cred(rt, expires_at=datetime.now(timezone.utc) + timedelta(days=3), label="soon")
    later = mk_cred(rt, expires_at=datetime.now(timezone.utc) + timedelta(days=90), label="later")
    assert expiry.tick(rt)["expiring"] == 1 and expiry.tick(rt)["expiring"] == 0   # fires once
    with rt.session() as db:
        assert service.get_row(db, soon).status == "expiring" and service.get_row(db, later).status == "active"
        n = db.execute(text("SELECT * FROM notifications WHERE event = 'credential.expiring'")).all()
        assert len(n) == 1 and n[0].incident_id is None and n[0].status == "pending"
        msg = monitor.build_message(db, n[0])
        assert "soon" in msg.text and S1 not in msg.text
        db.execute(text("UPDATE credentials SET expires_at = now() - interval '1 minute' WHERE id = :i"), {"i": soon})
        db.commit()
    assert expiry.tick(rt)["expired"] == 1
    with rt.session() as db:
        assert service.get_row(db, soon).status == "expired"
        assert db.execute(text("SELECT count(*) FROM notifications WHERE event = 'credential.expired'")).scalar() == 1
    with pytest.raises(service.CredentialUnavailable):
        service.get_secret(rt, soon)


# ------------------------------------------------------------------ typed actions end to end + no secret leakage
def test_typed_actions_e2e_and_no_leakage(client, rt, team, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    monkeypatch.setitem(service.TESTERS, "fakeprov", lambda rt_, cred, secret, ep: (secret != "Reject_This_Secret1", "ok"))
    users = [team["op"], team["ap"], team["ap2"]]
    job = run_plan(users, rt, "credential.create", {"provider": "fakeprov", "customer_id": DEFAULT, "label": "dc1 inventory", "credential_type": "api_token",
                                                    "purpose": "inventory", "identity": "svc@pve!ics", "secret": S1, "datacenter": "dc1"})
    assert job["status"] == "succeeded", job
    cid = job["result"]["credential_id"]
    op, oh = team["op"]
    meta = op.get(f"{H}/credentials/{cid}").json()
    assert meta["status"] == "active" and meta["datacenter"] == "dc1" and meta["customer_id"] == DEFAULT and "secret_enc" not in meta
    t = run_plan([team["op"]], rt, "credential.test", {"credential_id": cid})
    assert t["status"] == "succeeded" and t["result"]["ok"] is True
    # replace with a rejected secret: nothing persisted? (tester only runs for endpoint-attached credentials) -> rotate works
    job = run_plan(users, rt, "credential.rotate", {"credential_id": cid, "secret": S2, "reason": "scheduled"}, 1)
    assert job["status"] == "succeeded", job
    new = job["result"]["credential_id"]
    assert op.get(f"{H}/credentials/{cid}").json()["status"] == "retired"
    hist = op.get(f"{H}/credentials/{new}").json()["history"]
    assert hist[-1]["event"] == "rotated_from" and hist[-1]["reason"] == "scheduled"
    assert service.get_secret(rt, new) == S2
    job = run_plan([team["op"], team["ap"], team["ap2"]], rt, "credential.revoke", {"credential_id": new, "reason": "customer asked"})
    assert job["status"] == "succeeded"
    with pytest.raises(service.CredentialUnavailable):
        service.get_secret(rt, new)
    # access review comes from the audit log
    rev = team["ap"][0].get(f"{H}/credentials/access-review").json()
    events = {(e["event"], e["credential_id"]) for e in rev}
    assert ("credential.created", cid) in events and ("credential.revoked", new) in events
    assert any(e["event"] == "credential.use" and e["who"] for e in rev)
    # no secret anywhere
    with rt.session() as db:
        dump = json.dumps([[str(c) for c in r] for r in db.execute(text("SELECT details, resource_id, actor_name FROM audit_events")).all()])
        dump += json.dumps([[str(c) for c in r] for r in db.execute(text("SELECT params, result, error FROM plans p JOIN jobs j ON j.plan_id = p.id")).all()])
        assert db.execute(text("SELECT count(*) FROM plans WHERE secret_enc IS NOT NULL")).scalar() == 0
        assert audit.verify_chain(db)["ok"]
    dump += json.dumps(op.get(f"{H}/plans").json()) + json.dumps(op.get(f"{H}/jobs").json()) + json.dumps(op.get(f"{H}/credentials").json())
    dump += json.dumps(rev) + caplog.text
    for sec in (S1, S2):
        assert sec not in dump


# ------------------------------------------------------------------ cross-customer isolation + customer-scoped operator
def test_cross_customer_isolation(client, rt, team, mk_user, login, pve):
    ca, cb = mk_customer(rt, "cust-a"), mk_customer(rt, "cust-b")
    ea, eb = mk_endpoint(rt, "ep-a", ca, pve), mk_endpoint(rt, "ep-b", cb, pve)
    cred_a, cred_b = mk_cred(rt, ca, label="a"), mk_cred(rt, cb, label="b")
    with rt.session() as db:
        for t in ("infra_nodes",):
            for e in (ea, eb):
                db.execute(text("INSERT INTO infra_nodes (endpoint_id, name, status, observed_at) VALUES (:e, :n, 'online', now())"), {"e": e, "n": f"n-{e[:4]}"})
        db.commit()
    scoped = mk_user("scoped", "operator")
    with rt.session() as db:
        db.execute(text("UPDATE users SET all_customers = false WHERE username = 'scoped'"))
        db.execute(text("INSERT INTO operator_customers (user_id, customer_id) VALUES (:u, :c)"), {"u": scoped["id"], "c": ca})
        db.commit()
    s, sh = login(scoped)
    assert [e["id"] for e in s.get(f"{H}/endpoints").json()] == [ea]
    assert s.get(f"{H}/endpoints/{eb}").status_code == 404 and s.get(f"{H}/endpoints/{ea}").status_code == 200
    assert s.get(f"{H}/endpoints/{eb}/inventory").status_code == 404
    assert [c["id"] for c in s.get(f"{H}/credentials").json()] == [cred_a]
    assert s.get(f"{H}/credentials/{cred_b}").status_code == 404 and s.get(f"{H}/credentials/{cred_a}").status_code == 200
    assert [c["id"] for c in s.get(f"{H}/customers").json()] == [ca] and s.get(f"{H}/customers/{cb}").status_code == 404
    nodes = s.get(f"{H}/infra/nodes").json()
    assert {n["endpoint_id"] for n in nodes} == {ea}
    assert s.get(f"{H}/infra/summary").json()["nodes"]["total"] == 1
    # use: plans against the other customer's objects are refused (404, not 403: existence is not disclosed)
    for action, params in (("inventory.refresh", {"endpoint_id": eb}), ("credential.test", {"credential_id": cred_b}),
                           ("credential.revoke", {"credential_id": cred_b, "reason": "nope nope"})):
        assert s.post(f"{H}/plans", json={"action": action, "params": params}, headers=sh).status_code == 404, action
    assert s.post(f"{H}/plans", json={"action": "inventory.refresh", "params": {"endpoint_id": ea}}, headers=sh).status_code == 201
    # scoped operators cannot create customers/scopes or read the global audit log; their plan list shows only their customers
    assert s.post(f"{H}/plans", json={"action": "customer.create", "params": {"name": "x"}}, headers=sh).status_code in (403, 404)
    assert s.get(f"{H}/audit").status_code in (403,)
    ac, ah = team["ap"]
    pa = ac.get(f"{H}/plans").json()
    assert pa  # the all-customers approver sees every plan
    assert {p["id"] for p in s.get(f"{H}/plans").json()} <= {p["id"] for p in pa}
    # the MSP all-customers operator sees both
    assert {e["id"] for e in team["op"][0].get(f"{H}/endpoints").json()} == {ea, eb}
    # customer-scoped operator cannot touch another customer's approvals
    op, oh = team["op"]
    ap_id = op.post(f"{H}/customer-approvals", json={"customer_id": cb, "title": "t"}, headers=oh).json()["id"]
    assert s.get(f"{H}/customer-approvals/{ap_id}").status_code == 404
    assert s.post(f"{H}/customer-approvals/{ap_id}/submit", json={}, headers=sh).status_code == 404
    assert s.post(f"{H}/customer-approvals", json={"customer_id": cb, "title": "t"}, headers=sh).status_code == 404


def test_scope_and_customer_actions(client, rt, team):
    job = run_plan([team["adm"], team["ap"], team["ap2"]], rt, "customer.create", {"name": "Acme GmbH", "msp_owned": False})
    assert job["status"] == "succeeded", job
    cid = job["result"]["customer_id"]
    c, h = team["adm"]
    assert c.get(f"{H}/customers/{cid}").json()["provisioning_mode"] == "customer_approval"
    # auto provisioning is only for MSP-owned infrastructure
    r = c.post(f"{H}/plans", json={"action": "customer.create", "params": {"name": "Bad", "provisioning_mode": "auto"}}, headers=h)
    assert r.status_code == 422
    job = run_plan([team["adm"], team["ap"], team["ap2"]], rt, "operator.set_scope", {"username": "op", "all_customers": False, "customer_ids": [cid]})
    assert job["status"] == "succeeded", job
    assert {"username": "op", "all_customers": False, "customer_ids": [cid]} in c.get(f"{H}/operators/scopes").json()


# ------------------------------------------------------------------ policies
def test_policies_monitoring_only_and_extra_approvals(client, rt, team):
    mon = mk_customer(rt, "mon-co", mode="monitoring_only")
    op, oh = team["op"]
    r = op.post(f"{H}/plans", json={"action": "credential.create", "params": {
        "provider": "fakeprov", "customer_id": mon, "label": "prov", "credential_type": "api_token", "purpose": "provision", "secret": S1}}, headers=oh)
    assert r.status_code == 403 and "monitoring-only" in r.text
    assert op.post(f"{H}/plans", json={"action": "credential.create", "params": {   # inventory credential is fine
        "provider": "fakeprov", "customer_id": mon, "label": "inv", "credential_type": "api_token", "purpose": "inventory", "secret": S1}}, headers=oh).status_code == 201
    strict = mk_customer(rt, "strict-co", msp_owned=True, mode="auto", extra={"revoke_credential": 1})
    cid = mk_cred(rt, strict)
    p = plan(op, oh, "credential.revoke", {"credential_id": cid, "reason": "cleanup now"})
    assert p["risk"] == "high" and p["approvals_required"] == 3 and p["extra_approvals"] == 1
    for k in ("ap", "ap2"):
        r = team[k][0].post(f"{H}/plans/{p['plan_id']}/approve", headers=team[k][1])
        assert r.json()["status"] == "pending_approval"
    r = team["ap3"][0].post(f"{H}/plans/{p['plan_id']}/approve", headers=team["ap3"][1])
    assert r.json()["status"] == "approved" and r.json()["job_id"]
    # a customer without extra approvals needs just the normal two
    other = mk_cred(rt, DEFAULT)
    assert plan(op, oh, "credential.revoke", {"credential_id": other, "reason": "cleanup now"})["approvals_required"] == 2


# ------------------------------------------------------------------ external customer approval workflow
def test_customer_approval_flow(client, rt, team, caplog):
    caplog.set_level(logging.DEBUG)
    public.reset_rate_limits()
    cust = mk_customer(rt, "owner-co")  # customer-owned, customer_approval
    op, oh = team["op"]
    p = plan(op, oh, "credential.create", {"provider": "fakeprov", "customer_id": cust, "label": "prov token", "credential_type": "api_token",
                                           "purpose": "provision", "secret": S1, "identity": "ics@pve!prov",
                                           "permissions": [{"path": "/pool/ou", "privilege": "VM.Allocate", "reason": "create VMs"}]})
    assert p["customer_approval_required"] and p["approvals_required"] == 2 and p["job_id"] is None
    aid = p["customer_approval_id"]
    for k in ("ap", "ap2"):  # ICS approvals alone do not release the job
        r = team[k][0].post(f"{H}/plans/{p['plan_id']}/approve", headers=team[k][1])
        assert r.status_code == 200
    assert r.json()["status"] == "pending_approval" and r.json()["waiting_for"] == "customer_approval" and r.json()["job_id"] is None
    assert worker.run_once(rt) is False
    with rt.session() as db:  # the job runner re-verifies the gate even if a job were somehow queued
        assert db.execute(text("SELECT status FROM plans WHERE id = :i"), {"i": p["plan_id"]}).scalar() == "pending_approval"
    # draft cannot be used before it is submitted
    pub = f"{H}/public/approvals"
    assert client.post(f"{pub}/view", json={"token": "a.x.y.z"}).status_code == 404
    sub = op.post(f"{H}/customer-approvals/{aid}/submit", json={"ttl_hours": 24}, headers=oh)
    assert sub.status_code == 200
    link = sub.json()["link_path"]
    assert link.startswith("/approve#t=")
    token = link.split("#t=")[1]
    # the link is never stored recoverably, never in the API afterwards, never logged
    got = op.get(f"{H}/customer-approvals/{aid}").json()
    assert token not in json.dumps(got) and got["status"] == "pending"
    # tampered / foreign tokens are indistinguishable from unknown ones
    t_bad = token[:-2] + ("aa" if not token.endswith("aa") else "bb")
    assert client.post(f"{pub}/view", json={"token": t_bad}).status_code == 404
    other = op.post(f"{H}/customer-approvals", json={"customer_id": cust, "title": "x"}, headers=oh).json()["id"]
    assert client.post(f"{pub}/view", json={"token": token.replace(aid, other)}).status_code == 404
    # CSRF/content-type hardening and cookies are irrelevant
    assert client.post(f"{pub}/view", content=json.dumps({"token": token}), headers={"content-type": "text/plain"}).status_code in (415, 422)  # never processed
    v = client.post(f"{pub}/view", json={"token": token})
    assert v.status_code == 200 and v.json()["permissions"][0]["privilege"] == "VM.Allocate" and v.json()["customer"] == "owner-co"
    assert "instructions" in client.post(f"{pub}/instructions", json={"token": token}).json()
    body = {"token": token, "decision": "approve", "name": "Erika Muster", "email": "erika@customer.example",
            "statement": "I am authorised to approve these permissions.", "proposal_hash": v.json()["proposal_hash"]}
    assert client.post(f"{pub}/decide", json={**body, "proposal_hash": "0" * 64}).status_code == 409   # not the proposal she reviewed
    assert client.post(f"{pub}/decide", json={**body, "email": "nope"}).status_code == 422
    assert client.post(f"{pub}/decide", json={**body, "statement": ""}).status_code == 422
    d = client.post(f"{pub}/decide", json=body, headers={"user-agent": "TestBrowser/1"})
    assert d.status_code == 200 and d.json()["status"] == "approved" and d.json()["job_released"] is True
    comp = d.json()["completion_link_path"].split("#c=")[1]
    # single use
    assert client.post(f"{pub}/decide", json=body).status_code == 404
    assert client.post(f"{pub}/view", json={"token": token}).status_code == 404
    # the released job now runs
    assert worker.run_once(rt) is True
    # approver identity is in the hash-chained audit
    with rt.session() as db:
        e = db.execute(text("SELECT details, actor_name, ip FROM audit_events WHERE action = 'customer_approval.approved'")).first()
        assert e.details["approver_name"] == "Erika Muster" and e.details["approver_email"] == "erika@customer.example"
        assert e.details["approver_user_agent"] == "TestBrowser/1" and e.details["statement"] and e.ip
        assert audit.verify_chain(db)["ok"]
        dump = json.dumps([[str(c) for c in r] for r in db.execute(text("SELECT details, actor_name FROM audit_events")).all()])
    assert token not in dump and comp not in dump and token not in caplog.text and comp not in caplog.text and S1 not in dump
    with rt.session() as db:  # the 404s above fed the (per-IP) failure backoff: that is the designed behaviour; reset it for the next steps
        db.execute(text("DELETE FROM login_attempts"))
        db.commit()
    public.reset_rate_limits()
    # completion link: also single use, and a decision link cannot be used as completion link
    assert client.post(f"{pub}/complete", json={"token": token, "name": "Erika Muster", "email": "erika@customer.example"}).status_code == 404
    c = client.post(f"{pub}/complete", json={"token": comp, "name": "Erika Muster", "email": "erika@customer.example", "note": "done"})
    assert c.status_code == 200 and c.json()["status"] == "provisioned"
    assert client.post(f"{pub}/complete", json={"token": comp, "name": "Erika Muster", "email": "erika@customer.example"}).status_code == 404
    assert op.get(f"{H}/customer-approvals/{aid}").json()["status"] == "provisioned"


def test_customer_approval_expiry_reject_and_rate_limit(client, rt, team):
    public.reset_rate_limits()
    cust = mk_customer(rt, "owner-two")
    op, oh = team["op"]
    pub = f"{H}/public/approvals"

    def new_link():
        aid = op.post(f"{H}/customer-approvals", json={"customer_id": cust, "title": "t", "params": {"summary": "s"}}, headers=oh).json()["id"]
        return aid, op.post(f"{H}/customer-approvals/{aid}/submit", json={}, headers=oh).json()["link_path"].split("#t=")[1]

    aid, tok = new_link()
    with rt.session() as db:
        db.execute(text("UPDATE customer_approvals SET token_expires_at = now() - interval '1 second' WHERE id = :i"), {"i": aid})
        db.commit()
    assert client.post(f"{pub}/view", json={"token": tok}).status_code == 404
    assert op.get(f"{H}/customer-approvals/{aid}").json()["status"] == "expired"
    aid, tok = new_link()
    r = client.post(f"{pub}/decide", json={"token": tok, "decision": "reject", "name": "Max Mustermann", "email": "max@customer.example", "note": "no"})
    assert r.status_code == 200 and r.json()["status"] == "rejected" and "completion_link_path" not in r.json()
    assert client.post(f"{pub}/view", json={"token": tok}).status_code == 404
    aid, tok = new_link()
    r = client.post(f"{pub}/decide", json={"token": tok, "decision": "request_changes", "name": "Max Mustermann", "email": "max@customer.example", "note": "narrow it"})
    assert r.json()["status"] == "changes_requested"
    # rate limit (per IP)
    public.reset_rate_limits()
    codes = [client.post(f"{pub}/view", json={"token": "garbage"}).status_code for _ in range(40)]
    assert 429 in codes and codes[0] == 404
    # the page itself: strict CSP, no cookies required
    page = client.get("/approve")
    assert page.status_code == 200 and "script-src 'sha256-" in page.headers["content-security-policy"] and "unsafe" not in page.headers["content-security-policy"]
    public.reset_rate_limits()


# ------------------------------------------------------------------ data migration of existing endpoint secrets
def test_migration_of_legacy_endpoint_secrets(client, rt, team, pve):
    eid = uuid.uuid4()
    b = endpoint_binding(pve.url, TID, pve.fingerprint, None)
    with rt.session() as db:
        db.execute(text("INSERT INTO endpoints (id, name, type, base_url, token_id, token_secret_enc, fingerprint_sha256) "
                        "VALUES (:i, 'legacy', 'proxmox', :u, :t, :s, :f)"),
                   {"i": str(eid), "u": pve.url, "t": TID, "s": rt.vault.encrypt(SEC.encode(), f"endpoint-token:{eid}:{b}"), "f": pve.fingerprint})
        db.commit()
    assert service.adopt_all(rt) == 1 and service.adopt_all(rt) == 0   # idempotent
    with rt.session() as db:
        ep = db.execute(text("SELECT * FROM endpoints WHERE id = :i"), {"i": str(eid)}).first()
        assert ep.token_secret_enc is None and ep.inventory_credential_id and ep.customer_id
        cr = service.get_row(db, ep.inventory_credential_id)
        assert cr.provider == "proxmox" and cr.purpose == "inventory" and cr.identity == TID and str(cr.customer_id) == str(ep.customer_id)
        assert SEC.encode() not in bytes(cr.secret_enc)
        assert db.execute(text("SELECT count(*) FROM audit_events WHERE action = 'credential.migrated'")).scalar() == 1
    assert service.get_secret(rt, ep.inventory_credential_id) == SEC
    # the migrated endpoint still works through the credential reference
    job = run_plan([team["op"]], rt, "inventory.refresh", {"endpoint_id": str(eid)})
    assert job["status"] == "succeeded", job
    # revoking the credential stops inventory use at once
    with rt.session() as db:
        service.revoke(db, ep.inventory_credential_id, actor="t", reason="customer revoked")
        db.commit()
    job = run_plan([team["op"]], rt, "inventory.refresh", {"endpoint_id": str(eid)})
    assert job["status"] == "failed" and "revoked" in json.dumps(job["error"])
    assert SEC not in json.dumps(job)


def test_endpoint_register_creates_credentials_and_references_them(client, rt, team, pve):
    users = [team["op"], team["ap"], team["ap2"]]
    job = run_plan(users, rt, "endpoint.register", {"name": "lab-pve", "type": "proxmox", "base_url": pve.url, "token_id": TID,
                                                    "token_secret": SEC, "fingerprint_sha256": pve.fingerprint})
    assert job["status"] == "succeeded", job
    with rt.session() as db:
        ep = db.execute(text("SELECT * FROM endpoints WHERE name = 'lab-pve'")).first()
        assert ep.token_secret_enc is None and str(ep.customer_id) == DEFAULT and ep.inventory_credential_id
    # rotating via the credential subsystem keeps the endpoint working (tester = real Proxmox read client against the mock)
    job = run_plan(users, rt, "credential.rotate", {"credential_id": str(ep.inventory_credential_id), "secret": SEC, "reason": "test rotation"})
    assert job["status"] == "succeeded", job
    with rt.session() as db:
        ep2 = db.execute(text("SELECT inventory_credential_id FROM endpoints WHERE name = 'lab-pve'")).first()
        assert ep2.inventory_credential_id != ep.inventory_credential_id
    bad = run_plan(users, rt, "credential.rotate", {"credential_id": str(ep2.inventory_credential_id), "secret": "Wrong_Secret_Value_9", "reason": "bad rotation"})
    assert bad["status"] == "failed" and "401" in json.dumps(bad["error"])
    with rt.session() as db:  # nothing persisted for the failed rotation
        assert db.execute(text("SELECT inventory_credential_id FROM endpoints WHERE name = 'lab-pve'")).scalar() == ep2.inventory_credential_id
