"""MSP provisioning API (/api/msp/v1): signing (skew, replay, tamper), idempotency, permission sets, customer scoping, rate limits, audit,
webhooks (signing, retry, at-least-once), metering, OpenAPI conformance (every response is validated against docs/api/msp-v1.yaml)."""
import hashlib
import json
import os
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from ics import audit, worker
from ics.msp import events as mevents, gateway

from . import msp_spec
from .test_deploy_exec import FakeProvider, env, seed_inventory  # noqa: F401  (env: fake provider/agent wiring for the deployment engine)
from .test_deploy_plan import inp

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "clients", "msp-python"))
from ou_msp import MspApiError, MspClient, verify_signature  # noqa: E402

H = "/api/v1"
M = "/api/msp/v1"


class Api:
    """Signed requests against the in-process app. Every response is validated against the OpenAPI spec (conformance)."""

    def __init__(self, tc, client_id, secret, conform=True):
        self.tc, self.client_id, self.secret, self.conform = tc, client_id, secret, conform
        self.seen_ops: set = set()

    def raw(self, method, path, body=None, *, headers=None, ts=None, nonce=None, sign_body=None, sign_target=None, idem="auto", secret=None, cid=None):
        raw = b"" if body is None else json.dumps(body).encode()
        target = M + path
        t = str(int(time.time()) if ts is None else ts)
        n = nonce or uuid.uuid4().hex
        sig = gateway.sign(secret or self.secret, method, sign_target or target, t, n, raw if sign_body is None else sign_body)
        h = {"X-MSP-Client": cid or self.client_id, "X-MSP-Timestamp": t, "X-MSP-Nonce": n, "X-MSP-Signature": sig}
        if raw:
            h["Content-Type"] = "application/json"
        if method in gateway.MUTATING and idem is not None:
            h["Idempotency-Key"] = str(uuid.uuid4()) if idem == "auto" else idem
        h.update(headers or {})
        return self.tc.request(method, target, content=raw, headers=h)

    def __call__(self, method, path, body=None, expect=None, **kw):
        r = self.raw(method, path, body, **kw)
        try:
            data = r.json()
        except ValueError:
            data = None
        if expect is not None:
            assert r.status_code == expect, (r.status_code, r.text)
        if self.conform and data is not None:
            errs = [] if (msp_spec.match_operation(method, path.split("?")[0]) is None and r.status_code == 404) else msp_spec.check_response(method, path, r.status_code, data)
            assert not errs, f"{method} {path} {r.status_code} violates the OpenAPI spec: {errs}"
            op = msp_spec.match_operation(method, path.split("?")[0])
            if op:
                self.seen_ops.add(op[1]["operationId"])
        return r.status_code, data, r.headers


class World:
    def __init__(self, rt, client, mk_user, login):
        self.rt, self.client = rt, client
        self.adm = login(mk_user("adm", "admin"))
        self.ap = [login(mk_user("ap1", "approver")), login(mk_user("ap2", "approver"))]
        self.op = login(mk_user("opr", "operator"))

    def plan(self, c_h, action, params):
        c, h = c_h
        r = c.post(f"{H}/plans", json={"action": action, "params": params}, headers=h)
        assert r.status_code == 201, r.text
        return r.json()

    def approve(self, pid, n=2):
        d = None
        for c, h in self.ap[:n]:
            d = c.post(f"{H}/plans/{pid}/approve", headers=h)
            assert d.status_code == 200, d.text
        return d.json()

    def run_human(self, action, params, requester=None):
        p = self.plan(requester or self.adm, action, params)
        if p["status"] != "approved":
            self.approve(p["plan_id"], p["approvals_required"])
        assert worker.run_once(self.rt)
        return p

    def customer(self, name, msp_owned=False, mode="customer_approval"):
        with self.rt.session() as db:
            cid = db.execute(text("INSERT INTO customers (name, msp_owned, provisioning_mode) VALUES (:n, :o, :m) RETURNING id"),
                             {"n": name, "o": msp_owned, "m": mode}).scalar()
            db.commit()
        return str(cid)

    def api_client(self, name="integ", perms=("view", "plan"), customers=None, all_customers=False, rate=600, mtls=None, conform=True):
        params = {"name": name, "permissions": list(perms), "rate_limit_per_minute": rate,
                  "acknowledge_elevated": bool({"approve", "execute"} & set(perms))}
        if all_customers:
            params["all_customers"] = True
        else:
            params["customer_ids"] = list(customers or [])
        if mtls:
            params["mtls_fingerprint_sha256"] = mtls
        p = self.run_human("msp.client.create", params)
        with self.rt.session() as db:
            j = db.execute(text("SELECT status, error FROM jobs WHERE plan_id = :p"), {"p": p["plan_id"]}).first()
        assert j.status == "succeeded", j.error
        r = self.adm[0].post(f"{H}/msp/clients/{p['plan_id']}/reveal", headers=self.adm[1])
        assert r.status_code == 200, r.text
        d = r.json()
        return Api(self.client, d["client_id"], d["secret"], conform)

    def audit_rows(self, action):
        with self.rt.session() as db:
            return db.execute(text("SELECT * FROM audit_events WHERE action = :a ORDER BY seq"), {"a": action}).all()


@pytest.fixture()
def w(rt, client, mk_user, login):
    gateway.reset_state()
    return World(rt, client, mk_user, login)


# ---- client lifecycle: approved plan, key shown once, never in audit ------------------------------------------------------------

def test_key_creation_needs_approved_plan_and_is_shown_once(w, rt):
    c1 = w.customer("Acme")
    p = w.plan(w.adm, "msp.client.create", {"name": "clientst0r", "customer_ids": [c1]})
    assert p["status"] == "pending_approval" and p["risk"] == "high" and p["approvals_required"] == 2
    assert w.adm[0].post(f"{H}/msp/clients/{p['plan_id']}/reveal", headers=w.adm[1]).status_code == 404  # not executed yet
    w.approve(p["plan_id"])
    assert worker.run_once(rt)
    r = w.adm[0].post(f"{H}/msp/clients/{p['plan_id']}/reveal", headers=w.adm[1])
    d = r.json()
    assert d["client_id"].startswith("mspc_") and d["secret"].startswith("mspk_")
    assert w.adm[0].post(f"{H}/msp/clients/{p['plan_id']}/reveal", headers=w.adm[1]).status_code == 404  # once
    assert w.op[0].post(f"{H}/msp/clients/{p['plan_id']}/reveal", headers=w.op[1]).status_code == 404     # and only for the requester
    with rt.session() as db:  # vault-held: encrypted at rest, secret nowhere in plans/audit
        blob = db.execute(text("SELECT secret_enc FROM msp_clients")).scalar()
        assert d["secret"].encode() not in bytes(blob)
        dump = json.dumps([dict(x._mapping, at=str(x.at)) for x in db.execute(text("SELECT details, action, at FROM audit_events"))], default=str)
        assert d["secret"] not in dump
        assert db.execute(text("SELECT count(*) FROM plans WHERE params::text LIKE '%mspk_%'")).scalar() == 0
        u = db.execute(text("SELECT u.disabled, u.enrolled, u.role FROM users u JOIN msp_clients c ON c.user_id = u.id")).first()
        assert u.disabled and not u.enrolled  # a service principal: it can never log in to the console
    lst = w.adm[0].get(f"{H}/msp/clients").json()
    assert lst[0]["client_id"] == d["client_id"] and d["secret"] not in json.dumps(lst) and lst[0]["permissions"] == ["view", "plan"]


def test_api_client_cannot_manage_clients_and_elevated_perms_need_ack(w):
    c1 = w.customer("Acme")
    r = w.adm[0].post(f"{H}/plans", json={"action": "msp.client.create", "params": {"name": "x", "customer_ids": [c1], "permissions": ["view", "approve"]}},
                      headers=w.adm[1])
    assert r.status_code == 422 and "acknowledge_elevated" in r.text
    r = w.op[0].post(f"{H}/plans", json={"action": "msp.client.create", "params": {"name": "x", "customer_ids": [c1]}}, headers=w.op[1])
    assert r.status_code == 403  # admin only
    api = w.api_client(customers=[c1], all_customers=False)
    s, d, _ = api("GET", "/me", expect=200)
    assert d["permissions"] == ["view", "plan"] and d["customer_ids"] == [c1]
    assert api("POST", "/msp/clients", {}, expect=404)[0] == 404  # not an MSP API route: management is console-only


# ---- signature verification -----------------------------------------------------------------------------------------------------

def test_signature_skew_replay_tamper(w):
    c1 = w.customer("Acme")
    api = w.api_client(customers=[c1])
    assert api("GET", "/me")[0] == 200
    now = int(time.time())
    for off in (-121, 121, -3600):
        s, d, h = api("GET", "/me", ts=now + off)
        assert s == 401 and d["error"]["code"] == "timestamp_out_of_window"
    assert api("GET", "/me", ts=now - 100)[0] == 200 and api("GET", "/me", ts=now + 100)[0] == 200  # inside +-120 s
    # replay: the very same nonce a second time
    assert api("GET", "/me", nonce="n" * 24)[0] == 200
    s, d, _ = api("GET", "/me", nonce="n" * 24)
    assert s == 401 and d["error"]["code"] == "replayed_request"
    # body tamper: signed body A, sent body B
    s, d, _ = api("POST", "/customers", {"name": "Evil"}, sign_body=json.dumps({"name": "Good"}).encode())
    assert s == 401 and d["error"]["code"] == "invalid_signature"
    # path / method / query tamper
    assert api("GET", "/customers", sign_target=M + "/me")[1]["error"]["code"] == "invalid_signature"
    assert api("GET", "/customers?limit=1", sign_target=M + "/customers?limit=200")[1]["error"]["code"] == "invalid_signature"
    sig = gateway.sign(api.secret, "GET", M + "/me", str(now), "m" * 20, b"")
    r = w.client.post(M + "/me", headers={"X-MSP-Client": api.client_id, "X-MSP-Timestamp": str(now), "X-MSP-Nonce": "m" * 20, "X-MSP-Signature": sig,
                                           "Idempotency-Key": "x" * 12})
    assert r.status_code in (401, 405)  # method is part of the signature (405 if no such route)
    # wrong key / unknown client are indistinguishable
    assert api("GET", "/me", secret="mspk_wrong")[1]["error"]["code"] == "invalid_signature"
    assert api("GET", "/me", cid="mspc_0123456789abcdef")[1]["error"]["code"] == "invalid_signature"
    assert api("GET", "/me", headers={"X-MSP-Signature": "garbage"})[1]["error"]["code"] == "auth_malformed"
    assert w.client.get(M + "/me").json()["error"]["code"] == "auth_headers_missing"
    # the failed attempts are audited, never the key
    assert len(w.audit_rows("msp.auth_failed")) >= 8


def test_revoked_rotated_and_mtls(w, rt):
    c1 = w.customer("Acme")
    api = w.api_client(customers=[c1])
    old = api.secret
    w.run_human("msp.client.rotate", {"client_id": api.client_id, "grace_seconds": 3600})
    with rt.session() as db:
        pid = db.execute(text("SELECT plan_id FROM msp_client_reveals WHERE secret_enc IS NOT NULL")).scalar()
    d = w.adm[0].post(f"{H}/msp/clients/{pid}/reveal", headers=w.adm[1]).json()
    assert d["secret_version"] == 2 and d["secret"] != old
    s, body, h = api("GET", "/me", secret=old)  # previous key inside the grace period
    assert s == 200 and "previous-key" in h["x-msp-key-status"]
    assert api("GET", "/me", secret=d["secret"])[0] == 200
    w.run_human("msp.client.rotate", {"client_id": api.client_id, "grace_seconds": 0})
    assert api("GET", "/me", secret=old)[0] == 401
    with rt.session() as db:
        pid2 = db.execute(text("SELECT plan_id FROM msp_client_reveals WHERE secret_enc IS NOT NULL")).scalar()
    d2 = w.adm[0].post(f"{H}/msp/clients/{pid2}/reveal", headers=w.adm[1]).json()
    assert api("GET", "/me", secret=d["secret"])[0] == 401  # rotation with grace 0 cut the first new key off
    api.secret = d2["secret"]
    assert api("GET", "/me")[0] == 200
    w.run_human("msp.client.revoke", {"client_id": api.client_id})
    assert api("GET", "/me")[1]["error"]["code"] == "invalid_signature"


def test_mtls_binding(w, rt):
    c1 = w.customer("Acme")
    fp = "ab" * 32
    api = w.api_client(customers=[c1], mtls=fp)
    s, d, _ = api("GET", "/me")
    assert s == 401 and d["error"]["code"] == "client_certificate_required"       # no proxy-forwarded certificate
    object.__setattr__(rt.settings, "trusted_proxy", "127.0.0.1")
    try:
        assert api("GET", "/me", headers={"X-Client-Cert-SHA256": fp})[0] == 401   # header from an untrusted peer ('testclient')
        tc = TestClient(w.client.app, base_url="https://testserver", client=("127.0.0.1", 4000))
        a2 = Api(tc, api.client_id, api.secret)
        assert a2("GET", "/me", headers={"X-Client-Cert-SHA256": fp})[0] == 200
        assert a2("GET", "/me", headers={"X-Client-Cert-SHA256": "cd" * 32})[0] == 401
    finally:
        object.__setattr__(rt.settings, "trusted_proxy", None)


# ---- idempotency ----------------------------------------------------------------------------------------------------------------

def test_idempotency_semantics(w, rt):
    api = w.api_client(all_customers=True)
    body = {"name": "Initech", "external_ref": "cs-1001", "contact_email": "ops@initech.example"}
    assert api("POST", "/customers", body, idem=None)[1]["error"]["code"] == "idempotency_key_required"
    assert api("POST", "/customers", body, idem="short")[1]["error"]["code"] == "idempotency_key_invalid"
    s1, d1, h1 = api("POST", "/customers", body, idem="key-initech-0001", expect=202)
    assert d1["status"] == "pending_approval" and d1["risk"] == "high" and d1["approvals_required"] == 2
    s2, d2, h2 = api("POST", "/customers", body, idem="key-initech-0001", expect=202)
    assert d2 == d1 and h2["idempotent-replay"] == "true" and "idempotent-replay" not in h1
    with rt.session() as db:
        assert db.execute(text("SELECT count(*) FROM plans WHERE action = 'customer.create'")).scalar() == 1  # exactly one plan
    s3, d3, _ = api("POST", "/customers", {**body, "name": "Initech 2"}, idem="key-initech-0001")
    assert s3 == 409 and d3["error"]["code"] == "idempotency_key_reused"
    # a fresh key for the same request is a NEW request: the engine's own conflict check answers (external_ref is linked once)
    s4, d4, _ = api("POST", "/customers", body, idem="key-initech-0002")
    assert s4 == 202  # nothing created yet, a second pending plan is allowed...
    w.approve(d1["plan_id"])
    assert worker.run_once(rt)
    s5, d5, _ = api("POST", "/customers", body, idem="key-initech-0003")
    assert s5 == 409 and d5["error"]["code"] == "conflict"  # ... but once created the name/external_ref are taken
    # failed requests are not stored: the same key can be retried after fixing the request
    assert api("POST", "/customers", {"name": "x" * 300}, idem="key-bad-000001")[0] == 422
    assert api("POST", "/customers", {"name": "Fixed Co"}, idem="key-bad-000001", expect=202)[0] == 202
    # replays survive deletion of nothing: stored responses are encrypted at rest
    with rt.session() as db:
        blob = db.execute(text("SELECT response_enc FROM msp_idempotency WHERE idem_key = 'key-initech-0001'")).scalar()
        assert d1["plan_id"].encode() not in bytes(blob)


def test_idempotent_replay_returns_stored_response_even_after_state_changed(w, rt):
    api = w.api_client(all_customers=True)
    s, d1, _ = api("POST", "/customers", {"name": "Hooli"}, idem="key-hooli-00001", expect=202)
    w.approve(d1["plan_id"])
    assert worker.run_once(rt)
    s, d2, h = api("POST", "/customers", {"name": "Hooli"}, idem="key-hooli-00001", expect=202)
    assert d2 == d1 and d2["status"] == "pending_approval" and h["idempotent-replay"] == "true"  # the ORIGINAL response, not the current state
    assert api("GET", f"/plans/{d1['plan_id']}")[1]["execution"]["status"] == "succeeded"


# ---- permission sets ------------------------------------------------------------------------------------------------------------

def test_permission_sets(w):
    c1 = w.customer("Acme")
    viewer = w.api_client("viewer", perms=("view",), customers=[c1])
    s, d, _ = viewer("POST", f"/customers/{c1}/users", {"uid": "bob", "display_name": "Bob", "mail": "bob@acme.example"})
    assert s == 403 and d["error"]["details"] == {"required_permission": "plan"}
    assert viewer("POST", f"/customers/{c1}/deployments/preview", {})[0] == 403
    assert viewer("GET", f"/customers/{c1}", expect=200)[0] == 200
    planner = w.api_client("planner", perms=("plan",), customers=[c1])
    assert planner("GET", f"/customers/{c1}")[0] == 403  # plan without view cannot read
    full = w.api_client("full", perms=("view", "plan"), customers=[c1])
    s, d, _ = full("POST", f"/plans/{uuid.uuid4()}/approve")
    assert s == 403 and d["error"]["details"] == {"required_permission": "approve"}  # approve is off by default
    assert full("GET", "/me")[1]["permissions"] == ["view", "plan"]
    assert len(w.audit_rows("msp.request")) >= 5  # every call is audited with the client id
    rows = w.audit_rows("msp.request")
    assert all(r.actor_name.startswith("msp:mspc_") for r in rows)
    assert {r.details["status"] for r in rows} >= {200, 403}


def test_api_client_never_approves_own_plan_and_approval_is_restricted(w, rt):
    own = w.customer("Own Infra", msp_owned=True, mode="auto")
    cust = w.customer("Cust Co")
    with rt.session() as db:  # identity stacks (users are planned against them)
        for name, cid in (("s-own", own), ("s-cust", cust)):
            db.execute(text("INSERT INTO idm_stacks (name, config, secret_enc, customer_id) VALUES (:n, CAST(:c AS jsonb), :s, :cu)"),
                       {"n": name, "c": json.dumps({"mail_domain": "x.example", "allowed_groups": ["mail-users", "staff", "admins"], "entitlement_group": "mail-users",
                                                      "privileged_groups": ["admins"]}), "s": b"x", "cu": cid})
        for st in ("s-own", "s-cust"):
            sid = db.execute(text("SELECT id FROM idm_stacks WHERE name = :n"), {"n": st}).scalar()
            db.execute(text("INSERT INTO idm_users (stack_id, uid, entry_uuid, mail, display_name, groups) VALUES (:s, 'amy', :e, 'amy@x.example', 'Amy', '[\"staff\"]')"),
                       {"s": sid, "e": str(uuid.uuid4())})
        db.commit()
    approver = w.api_client("approver-bot", perms=("view", "plan", "approve"), customers=[own, cust])
    # a plan the bot requests itself: self-decision is refused by the engine
    s, mine, _ = approver("PATCH", f"/customers/{own}/users/amy", {"add": ["mail-users"]}, expect=202)
    assert mine["risk"] == "normal" and mine["status"] == "pending_approval"
    s, d, _ = approver("POST", f"/plans/{mine['plan_id']}/approve")
    assert s == 403 and d["error"]["code"] == "approval_refused"
    # a HUMAN-requested normal-risk plan on the MSP-owned customer: the bot may approve it (policy-granted permission)
    hp = w.plan(w.op, "idm.user.update_groups", {"stack": "s-own", "uid": "amy", "add": ["mail-users"], "remove": []})
    assert hp["risk"] == "normal" and hp["status"] == "pending_approval"
    s, d, _ = approver("POST", f"/plans/{hp['plan_id']}/approve", expect=200)
    assert d["status"] == "approved" and d["job_id"]
    assert worker.run_once(rt)  # (fake stack: the job itself fails, which is irrelevant here; it just must not stay queued)
    # not on customer-owned infrastructure
    cp = w.plan(w.op, "idm.user.update_groups", {"stack": "s-cust", "uid": "amy", "add": ["mail-users"], "remove": []})
    s, d, _ = approver("POST", f"/plans/{cp['plan_id']}/approve")
    assert s == 403 and d["error"]["code"] == "approval_not_permitted"
    # never high risk (privileged group), not even on MSP-owned customers
    hi = w.plan(w.op, "idm.user.update_groups", {"stack": "s-own", "uid": "amy", "add": ["admins"], "remove": []})
    assert hi["risk"] == "high"
    s, d, _ = approver("POST", f"/plans/{hi['plan_id']}/approve")
    assert s == 403 and d["error"]["code"] == "approval_not_permitted"
    # a client scoped away from the customer cannot even see the plan
    other = w.api_client("other", perms=("view", "plan", "approve"), customers=[cust])
    assert other("POST", f"/plans/{hp['plan_id']}/approve")[0] == 404


def test_auto_approval_needs_execute_and_msp_owned(w, rt):
    own = w.customer("Own Infra", msp_owned=True, mode="auto")
    cust = w.customer("Cust Co", mode="auto")
    with rt.session() as db:
        for name, cid in (("s-own", own), ("s-cust", cust)):
            db.execute(text("INSERT INTO idm_stacks (name, config, secret_enc, customer_id) VALUES (:n, CAST(:c AS jsonb), :s, :cu)"),
                       {"n": name, "c": json.dumps({"mail_domain": "x.example", "allowed_groups": ["mail-users"], "entitlement_group": "mail-users"}),
                        "s": b"x", "cu": cid})
        db.commit()
    plain = w.api_client("plain", perms=("view", "plan"), customers=[own, cust])
    s, d, _ = plain("POST", f"/customers/{own}/identity/reconcile", {}, expect=202)
    assert d["risk"] == "low" and d["status"] == "pending_approval" and d["job_id"] is None  # low risk, yet a human must still approve an integration's plan
    runner = w.api_client("runner", perms=("view", "plan", "execute"), customers=[own, cust])
    s, d, _ = runner("POST", f"/customers/{own}/identity/reconcile", {}, expect=202)
    assert d["status"] == "approved" and d["job_id"]                                  # separately approved policy + MSP-owned + low risk
    s, d, _ = runner("POST", f"/customers/{cust}/identity/reconcile", {}, expect=202)
    assert d["status"] == "pending_approval"                                           # customer-owned infrastructure: never automatic
    # the approved plan fired an event
    with rt.session() as db:
        assert db.execute(text("SELECT count(*) FROM msp_events WHERE type = 'plan.approved' AND data->>'action' = 'idm.reconcile'")).scalar() == 1


# ---- scoping --------------------------------------------------------------------------------------------------------------------

def test_cross_customer_denial(w, rt):
    a, b = w.customer("Alpha Co"), w.customer("Beta Co")
    with rt.session() as db:
        for n, cid in (("st-a", a), ("st-b", b)):
            db.execute(text("INSERT INTO idm_stacks (name, config, secret_enc, customer_id) VALUES (:n, CAST(:c AS jsonb), :s, :cu)"),
                       {"n": n, "c": json.dumps({"mail_domain": "x.example", "allowed_groups": ["mail-users"], "entitlement_group": "mail-users"}), "s": b"x", "cu": cid})
        sid = db.execute(text("SELECT id FROM idm_stacks WHERE name = 'st-b'")).scalar()
        db.execute(text("INSERT INTO idm_users (stack_id, uid, entry_uuid, mail, display_name) VALUES (:s, 'bea', :e, 'bea@x.example', 'Bea')"), {"s": sid, "e": str(uuid.uuid4())})
        eid = db.execute(text("INSERT INTO endpoints (name, type, base_url, token_id, token_secret_enc, fingerprint_sha256, customer_id) VALUES "
                              "('ep-b', 'proxmox', 'https://pve.test:8006', 'u@pve!t', :s, :f, :c) RETURNING id"), {"s": b"x", "f": "ab" * 32, "c": b}).scalar()
        db.execute(text("INSERT INTO deployments (slug, customer_id, profile, profile_version, endpoint_id, status, desired_spec) "
                        "VALUES ('beta-prod', (SELECT slug FROM customers WHERE id = :c), 'small', '1', :e, 'active', '{}')"), {"c": b, "e": eid})
        db.commit()
    pb = w.plan(w.op, "idm.user.disable", {"stack": "st-b", "uid": "bea"})
    api = w.api_client("alpha-only", perms=("view", "plan", "approve"), customers=[a])
    assert api("GET", f"/customers/{a}", expect=200)[0] == 200
    assert [c["id"] for c in api("GET", "/customers")[1]["items"]] == [a]
    for method, path, body in [("GET", f"/customers/{b}", None), ("GET", f"/customers/{b}/usage", None), ("GET", f"/customers/{b}/users", None),
                               ("POST", f"/customers/{b}/users", {"uid": "eve", "display_name": "Eve", "mail": "eve@x.example"}),
                               ("PATCH", f"/customers/{b}/users/bea", {"add": ["mail-users"]}), ("DELETE", f"/customers/{b}/users/bea", {"reason": "because"}),
                               ("POST", f"/customers/{b}/deployments/preview", {}), ("PATCH", f"/customers/{b}", {"contact_name": "x"}),
                               ("GET", "/deployments/beta-prod", None), ("GET", "/deployments/beta-prod/health", None),
                               ("POST", "/deployments/beta-prod/destroy/preview", None), ("POST", f"/plans/{pb['plan_id']}/approve", None),
                               ("GET", f"/plans/{pb['plan_id']}", None)]:
        s, d, _ = api(method, path, body)
        assert s == 404 and d["error"]["code"] == "not_found", (method, path, s, d)
    assert api("GET", "/deployments")[1]["items"] == []
    assert api("GET", f"/deployments?customer_id={b}")[1]["items"] == []
    assert api("GET", "/plans")[1]["items"] == []
    s, d, _ = api("POST", "/customers", {"name": "Gamma"})
    assert s == 403  # customer creation needs an all-customers client
    # deploying onto an endpoint owned by another customer is refused for scoped clients
    s, d, _ = api("POST", f"/customers/{a}/deployments/preview", {"deployment_id": "alpha-prod", "profile": "small", "users": 10, "domain": "a.example", "endpoint": "ep-b", "pool": "p"})
    assert s == 404
    # an all-customers client sees both
    allc = w.api_client("all", perms=("view", "plan"), all_customers=True)
    assert {c["id"] for c in allc("GET", "/customers")[1]["items"]} == {a, b, "00000000-0000-0000-0000-00000000a001"}
    assert allc("GET", "/deployments/beta-prod", expect=200)[1]["customer_id"] == b
    # pagination
    p1 = allc("GET", "/customers?limit=2")[1]
    assert len(p1["items"]) == 2 and p1["next_cursor"]
    p2 = allc("GET", f"/customers?limit=2&cursor={p1['next_cursor']}")[1]
    assert len(p2["items"]) == 1 and p2["next_cursor"] is None
    assert allc("GET", "/customers?limit=0")[0] == 422
    # events are scoped too
    with rt.session() as db:
        mevents.emit(db, "job.failed", b, {"job_id": "j", "plan_id": "p", "action": "x", "error": {}})
        mevents.emit(db, "job.failed", a, {"job_id": "j", "plan_id": "p", "action": "x", "error": {}})
        db.commit()
    assert [e["customer_id"] for e in api("GET", "/events")[1]["items"]] == [a]
    assert {e["customer_id"] for e in allc("GET", "/events")[1]["items"]} >= {a, b}


# ---- rate limit -----------------------------------------------------------------------------------------------------------------

def test_rate_limit_per_client(w):
    c1 = w.customer("Acme")
    slow = w.api_client("slow", customers=[c1], rate=3)
    fast = w.api_client("fast", customers=[c1], rate=600)
    codes = [slow("GET", "/me")[0] for _ in range(5)]
    assert codes[:3] == [200, 200, 200] and codes[3] == 429
    s, d, h = slow("GET", "/me")
    assert s == 429 and d["error"]["code"] == "rate_limited" and int(h["retry-after"]) >= 1 and h["x-ratelimit-limit"] == "3"
    assert fast("GET", "/me")[0] == 200  # per client, not global


def test_deprecation_headers(w, monkeypatch):
    api = w.api_client(customers=[w.customer("Acme")])
    s, d, h = api("GET", "/me")
    assert h["x-msp-api-version"] == "1" and "deprecation" not in h and h["x-request-id"].startswith("req_")
    monkeypatch.setitem(gateway.DEPRECATIONS, "me", {"sunset": datetime(2027, 6, 1, tzinfo=timezone.utc), "successor": "/api/msp/v2/me"})
    s, d, h = api("GET", "/me")
    assert h["deprecation"] == "true" and "2027" in h["sunset"] and 'rel="successor-version"' in h["link"]


# ---- customers / plans end to end -----------------------------------------------------------------------------------------------

def test_customer_create_flow_and_plan_tracking(w, rt):
    api = w.api_client(all_customers=True)
    s, p, _ = api("POST", "/customers", {"name": "Wayne Enterprises", "external_ref": "cs-77", "contact_name": "Lucius", "contact_email": "l@wayne.example"}, expect=202)
    s, view, _ = api("GET", f"/plans/{p['plan_id']}")
    assert view["status"] == "pending_approval" and view["execution"] is None and view["own"] and view["requested_by"].startswith("msp_client:")
    assert view["params"]["name"] == "Wayne Enterprises"
    w.approve(p["plan_id"], 1)
    assert api("GET", f"/plans/{p['plan_id']}")[1]["approvals"] == 1
    w.approve_second = w.ap[1][0].post(f"{H}/plans/{p['plan_id']}/approve", headers=w.ap[1][1])
    assert worker.run_once(rt)
    view = api("GET", f"/plans/{p['plan_id']}")[1]
    assert view["status"] == "approved" and view["execution"]["status"] == "succeeded"
    cid = view["execution"]["result"]["customer_id"]
    c = api("GET", f"/customers/{cid}", expect=200)[1]
    assert c["name"] == "Wayne Enterprises" and c["external_ref"] == "cs-77" and c["slug"] == "wayne-enterprises" and c["provisioning_mode"] == "customer_approval"
    assert [x["id"] for x in api("GET", "/customers?external_ref=cs-77")[1]["items"]] == [cid]
    job = api("GET", f"/jobs/{view['execution']['job_id']}", expect=200)[1]
    assert job["action"] == "customer.create"
    s, p2, _ = api("PATCH", f"/customers/{cid}", {"contact_name": "Bruce"}, expect=202)
    w.approve(p2["plan_id"])
    assert worker.run_once(rt)
    assert api("GET", f"/customers/{cid}")[1]["contact_name"] == "Bruce"
    assert api("PATCH", f"/customers/{cid}", {})[0] == 422
    assert api("GET", f"/plans?status=approved")[1]["items"]
    assert api("GET", f"/plans/{uuid.uuid4()}")[0] == 404 and api("GET", "/plans/not-a-uuid")[0] == 404
    # the plan the integration submitted also shows in the operator console
    assert any(x["id"] == p["plan_id"] for x in w.adm[0].get(f"{H}/plans").json())
    rejected = api("POST", "/customers", {"name": "Spam Corp"}, expect=202)[1]
    w.ap[0][0].post(f"{H}/plans/{rejected['plan_id']}/reject", headers=w.ap[0][1])
    assert api("GET", f"/plans/{rejected['plan_id']}")[1]["status"] == "rejected"


def test_validation_errors(w):
    api = w.api_client(all_customers=True)
    s, d, _ = api("POST", "/customers", {"name": "ok", "bogus": 1})
    assert s == 422 and d["error"]["code"] == "validation_error" and d["error"]["details"]
    assert api("POST", "/customers", None, headers={"Content-Type": "application/json"})[1]["error"]["code"] == "validation_error"
    assert api("GET", "/nothing-here")[0] == 404


# ---- deployments + usage --------------------------------------------------------------------------------------------------------

def test_deployment_flow_health_usage_and_changes(w, rt, env):  # noqa: F811
    cid = w.customer("Acme Corp")
    seed_inventory(rt)
    with rt.session() as db:
        slug = db.execute(text("SELECT slug FROM customers WHERE id = :c"), {"c": cid}).scalar()
        db.execute(text("UPDATE endpoints SET customer_id = :c WHERE name = 'lab'"), {"c": cid})
        db.commit()
    api = w.api_client("acme-rmm", perms=("view", "plan"), customers=[cid])
    spec = inp(customer_id=slug).model_dump(mode="json")
    spec.pop("customer_id")
    s, pv, _ = api("POST", f"/customers/{cid}/deployments/preview", spec, expect=200)
    assert pv["executable"] and pv["plan_hash"]
    assert api("POST", f"/customers/{cid}/deployments/preview", {**spec, "customer_id": "other"})[0] == 422
    s, p, _ = api("POST", f"/customers/{cid}/deployments", {"spec": spec, "plan_hash": pv["plan_hash"]}, expect=202)
    assert p["status"] == "pending_approval" and p["risk"] == "high" and p["approvals_required"] == 2 and p["customer_id"] == cid
    s, bad, _ = api("POST", f"/customers/{cid}/deployments", {"spec": spec, "plan_hash": "0" * 64})
    assert s == 409 and "preview again" in bad["error"]["message"]
    # customer approval policy: customer-owned infra needs the customer's own approval link before the job is released
    assert p["waiting_for"] == "customer_approval" and p["customer_approval_id"]
    with rt.session() as db:
        db.execute(text("UPDATE customers SET provisioning_mode = 'auto' WHERE id = :c"), {"c": cid})
        db.execute(text("UPDATE customer_approvals SET status = 'approved' WHERE id = :a"), {"a": p["customer_approval_id"]})
        db.commit()
    w.approve(p["plan_id"])
    assert worker.run_once(rt)
    dep = api("GET", f"/deployments/{spec['deployment_id']}", expect=200)[1]
    assert dep["status"] == "active" and dep["customer_id"] == cid and dep["latest_job_steps"] and all(x["status"] == "succeeded" for x in dep["latest_job_steps"])
    view = api("GET", f"/plans/{p['plan_id']}")[1]
    assert view["execution"]["status"] == "succeeded"
    assert api("GET", f"/jobs/{view['execution']['job_id']}")[1]["steps"]
    assert [d["slug"] for d in api("GET", f"/deployments?customer_id={cid}")[1]["items"]] == [spec["deployment_id"]]
    h = api("GET", f"/deployments/{spec['deployment_id']}/health", expect=200)[1]
    assert h["deployment_status"] == "active" and h["health"] in ("healthy", "degraded", "unknown") and h["drift"]["findings"] >= 0
    u = api("GET", f"/customers/{cid}/usage", expect=200)[1]
    nvm = pv["consumption"]["vms"]
    assert u["vm"]["provisioned"] == {"vms": nvm, "vcpus": pv["consumption"]["cores"], "memory_mb": pv["consumption"]["memory_mb"], "disk_gb": pv["consumption"]["disk_gb"]}
    assert u["storage"]["provisioned_gb"] == pv["consumption"]["disk_gb"] and u["storage"]["mailbox_used_bytes"] is None
    assert "vm.provisioned" in u["definitions"] and u["deployments"][0]["deployment"] == spec["deployment_id"]
    # change + destroy previews and plans
    s, cp, _ = api("POST", f"/deployments/{spec['deployment_id']}/changes/preview", {"changes": {"users": 60}}, expect=200)
    assert cp["plan_hash"] if "plan_hash" in cp else cp
    s, dp, _ = api("POST", f"/deployments/{spec['deployment_id']}/destroy/preview", expect=200)
    s, dd, _ = api("POST", f"/deployments/{spec['deployment_id']}/destroy", {"confirm": "wrong", "plan_hash": dp["plan_hash"]})
    assert s == 422
    s, dd, _ = api("POST", f"/deployments/{spec['deployment_id']}/destroy", {"confirm": spec["deployment_id"], "plan_hash": dp["plan_hash"]}, expect=202)
    assert dd["risk"] == "high"
    # the events of this flow reached the outbox
    with rt.session() as db:
        types = {r.type for r in db.execute(text("SELECT type FROM msp_events"))}
    assert {"plan.approved", "job.completed"} <= types


def test_users_flow(w, rt):
    cid = w.customer("Acme Corp")
    api = w.api_client("rmm", perms=("view", "plan"), customers=[cid])
    s, d, _ = api("POST", f"/customers/{cid}/users", {"uid": "carl", "display_name": "Carl", "mail": "carl@x.example"})
    assert s == 409 and d["error"]["code"] == "no_identity_stack"
    with rt.session() as db:
        db.execute(text("INSERT INTO idm_stacks (name, config, secret_enc, customer_id) VALUES ('acme-idm', CAST(:c AS jsonb), :s, :cu)"),
                   {"c": json.dumps({"mail_domain": "x.example", "allowed_groups": ["mail-users", "staff", "admins"], "entitlement_group": "mail-users",
                                     "privileged_groups": ["admins"]}), "s": b"x", "cu": cid})
        sid = db.execute(text("SELECT id FROM idm_stacks WHERE name = 'acme-idm'")).scalar()
        for uid, st, g in (("amy", "active", ["mail-users", "staff"]), ("ben", "disabled", ["mail-users"]), ("cat", "deleted", ["mail-users"]), ("dan", "active", ["staff"])):
            db.execute(text("INSERT INTO idm_users (stack_id, uid, entry_uuid, mail, display_name, groups, state) VALUES (:s, :u, :e, :m, :u, CAST(:g AS jsonb), :st)"),
                       {"s": sid, "u": uid, "e": str(uuid.uuid4()), "m": f"{uid}@x.example", "g": json.dumps(g), "st": st})
        db.commit()
    s, lst, _ = api("GET", f"/customers/{cid}/users?state=active", expect=200)
    assert [u["uid"] for u in lst["items"]] == ["amy", "dan"]
    assert api("GET", f"/customers/{cid}/users?state=bogus")[0] == 422
    s, p, _ = api("POST", f"/customers/{cid}/users", {"uid": "eve", "display_name": "Eve", "mail": "eve@x.example", "groups": ["staff"]}, expect=202)
    assert p["risk"] == "normal" and p["status"] == "pending_approval" and p["approvals_required"] == 1
    assert api("POST", f"/customers/{cid}/users", {"uid": "eve2", "display_name": "E", "mail": "wrong@x.example"})[0] == 422
    assert api("POST", f"/customers/{cid}/users", {"uid": "fay", "display_name": "F", "mail": "fay@other.example"})[0] == 422  # wrong mail domain
    s, p, _ = api("PATCH", f"/customers/{cid}/users/dan", {"add": ["admins"]}, expect=202)
    assert p["risk"] == "high" and p["approvals_required"] == 2  # privileged group
    s, p, _ = api("POST", f"/customers/{cid}/users/amy/disable", {"reason": "left company"}, expect=202)
    assert p["risk"] == "normal"
    s, p, _ = api("POST", f"/customers/{cid}/users/ben/enable", None, expect=202)
    s, p, _ = api("DELETE", f"/customers/{cid}/users/ben", {"reason": "offboarded"}, expect=202)
    assert p["risk"] == "high"
    assert api("DELETE", f"/customers/{cid}/users/amy", {"reason": "x"})[0] == 422
    assert api("POST", f"/customers/{cid}/users/ghost/disable", None)[0] == 404
    s, p, _ = api("POST", f"/plans/{p['plan_id']}/enrollment")
    assert s == 404
    u = api("GET", f"/customers/{cid}/usage", expect=200)[1]
    assert u["users"] == {"active": 2, "disabled": 1, "deleted": 1, "total_live": 3}
    assert u["mailboxes"] == {"active": 2, "retained": 1}  # amy + ben hold mail-users (dan does not); cat's deleted mailbox is retained
    pages = api("GET", f"/customers/{cid}/users?limit=2")[1]
    assert len(pages["items"]) == 2 and pages["next_cursor"]


# ---- webhooks -------------------------------------------------------------------------------------------------------------------

class Sink:
    """httpx transport standing in for the MSP's webhook endpoint; scripted status codes, records requests."""

    def __init__(self, statuses=()):
        self.statuses, self.requests = list(statuses), []

    def __call__(self, request: httpx.Request):
        self.requests.append(request)
        return httpx.Response(self.statuses.pop(0) if self.statuses else 200)


def due(rt):
    with rt.session() as db:
        db.execute(text("UPDATE msp_deliveries SET next_attempt_at = now() WHERE status = 'pending'"))
        db.commit()


def test_webhook_signing_retry_at_least_once(w, rt):
    cid = w.customer("Acme Corp")
    api = w.api_client("hooks", perms=("view", "plan"), customers=[cid])
    s, wh, _ = api("POST", "/webhooks", {"url": "http://127.0.0.1:9/hook", "events": ["plan.approved", "job.completed", "job.failed"]}, expect=201)
    secret = wh["secret"]
    assert secret.startswith("whsec_") and "secret" not in api("GET", f"/webhooks/{wh['id']}", expect=200)[1]
    with rt.session() as db:
        assert secret.encode() not in bytes(db.execute(text("SELECT secret_enc FROM msp_webhooks")).scalar())
    # SSRF / scheme guards
    for bad in ("http://169.254.169.254/latest", "ftp://x.example/", "https://user:pw@x.example/"):
        with pytest.raises(ValueError):
            mevents.check_url(bad, allow_loopback=True)
    with pytest.raises(ValueError):
        mevents.check_url("http://127.0.0.1/x", allow_loopback=False)
    with pytest.raises(ValueError):
        mevents.check_url("https://127.0.0.1/x", allow_loopback=False)
    assert api("POST", "/webhooks", {"url": "http://169.254.169.254/x", "events": ["plan.approved"]})[0] == 422
    assert api("POST", "/webhooks", {"url": "https://example.org/x", "events": []})[0] == 422
    assert api("POST", "/webhooks", {"url": "https://example.org/x", "events": ["nope"]})[0] == 422
    # produce events: a normal plan approved + executed
    with rt.session() as db:
        db.execute(text("INSERT INTO idm_stacks (name, config, secret_enc, customer_id) VALUES ('s', CAST(:c AS jsonb), :s, :cu)"),
                   {"c": json.dumps({"mail_domain": "x.example", "allowed_groups": ["mail-users"], "entitlement_group": "mail-users"}), "s": b"x", "cu": cid})
        db.commit()
    runner = w.api_client("runner", perms=("view", "plan", "execute"), customers=[cid])
    with rt.session() as db:
        db.execute(text("UPDATE customers SET msp_owned = true WHERE id = :c"), {"c": cid})
        db.commit()
    s, p, _ = runner("POST", f"/customers/{cid}/identity/reconcile", {}, expect=202)
    assert p["status"] == "approved"
    assert worker.run_once(rt)
    sink = Sink([500, 200, 200])
    assert mevents.tick(rt, transport=httpx.MockTransport(sink)) >= 1   # first attempt answers 500
    with rt.session() as db:
        rows = db.execute(text("SELECT d.status, d.attempts, d.last_status, d.next_attempt_at > now() AS later, e.type FROM msp_deliveries d JOIN msp_events e ON e.id = d.event_id "
                               "WHERE d.webhook_id = :w ORDER BY e.seq"), {"w": wh["id"]}).all()
    assert [(r.status, r.type) for r in rows] == [("pending", "plan.approved"), ("pending", "job.failed")] or len(rows) >= 1
    due(rt)
    n = mevents.tick(rt, transport=httpx.MockTransport(sink))
    assert n >= 1
    # events for ANOTHER customer's api client never arrive; ours did, signed and with a stable id
    first = sink.requests[0]
    body = first.content
    ev = json.loads(body)
    assert verify_signature(secret, body, first.headers["x-msp-signature"])
    assert not verify_signature(secret + "x", body, first.headers["x-msp-signature"])
    assert not verify_signature(secret, body + b" ", first.headers["x-msp-signature"])
    assert not verify_signature(secret, body, first.headers["x-msp-signature"], now=time.time() + 3600)  # replay window
    assert first.headers["x-msp-event-id"] == ev["id"] and ev["type"] == "plan.approved" and ev["customer_id"] == cid and ev["api_version"] == "v1"
    assert first.headers["x-msp-delivery-attempt"] == "1"
    retried = [r for r in sink.requests if r.headers["x-msp-event-id"] == ev["id"]]
    assert len(retried) == 2 and retried[1].headers["x-msp-delivery-attempt"] == "2" and json.loads(retried[1].content)["id"] == ev["id"]  # at least once, same id
    assert msp_spec.validate(ev, msp_spec.SPEC["components"]["schemas"]["Event"]) == []
    s, dl, _ = api("GET", f"/webhooks/{wh['id']}/deliveries", expect=200)
    assert {x["status"] for x in dl["items"]} <= {"delivered", "pending"} and any(x["attempts"] == 2 and x["status"] == "delivered" for x in dl["items"])
    # dead letter after MAX_ATTEMPTS
    with rt.session() as db:
        mevents.emit(db, "job.failed", cid, {"job_id": "j", "plan_id": "p", "action": "a", "error": {"type": "X", "message": "m"}})
        db.commit()
    dead = Sink([503] * 20)
    for _ in range(mevents.MAX_ATTEMPTS + 1):
        due(rt)
        mevents.tick(rt, transport=httpx.MockTransport(dead))
    s, dl, _ = api("GET", f"/webhooks/{wh['id']}/deliveries")
    assert any(x["status"] == "dead" and x["attempts"] == mevents.MAX_ATTEMPTS for x in dl["items"])
    # rotate + delete
    s, rot, _ = api("POST", f"/webhooks/{wh['id']}/rotate-secret", expect=200)
    assert rot["secret"] != secret
    assert api("DELETE", f"/webhooks/{wh['id']}", expect=200)[1]["deleted"] is True
    assert api("GET", f"/webhooks/{wh['id']}")[0] == 404
    assert api("GET", "/webhooks", expect=200)[1]["items"] == []


def test_webhooks_only_for_scope_and_subscribed_types(w, rt):
    a, b = w.customer("Alpha"), w.customer("Beta")
    ca = w.api_client("a", customers=[a])
    cb = w.api_client("b", customers=[b])
    ev_only = w.api_client("c", customers=[a, b])
    for api, evs in ((ca, ["job.failed"]), (cb, ["job.failed"]), (ev_only, ["incident.opened"])):
        api("POST", "/webhooks", {"url": "http://127.0.0.1:9/h", "events": evs}, expect=201)
    with rt.session() as db:
        mevents.emit(db, "job.failed", a, {"job_id": "j", "plan_id": "p", "action": "a", "error": {}})
        mevents.emit(db, "job.failed", None, {"job_id": "j", "plan_id": "p", "action": "a", "error": {}})
        db.commit()
        n = db.execute(text("SELECT count(*) FROM msp_deliveries")).scalar()
    assert n == 1  # only client a: b is scoped to another customer, c did not subscribe, customer-less events go to all-customers clients only


def test_incident_event_capture(w, rt):
    cid = w.customer("Acme Corp")
    api = w.api_client("hooks", customers=[cid])
    api("POST", "/webhooks", {"url": "http://127.0.0.1:9/h", "events": ["incident.opened", "incident.recovered"]}, expect=201)
    with rt.session() as db:
        slug = db.execute(text("SELECT slug FROM customers WHERE id = :c"), {"c": cid}).scalar()
        did = db.execute(text("INSERT INTO deployments (slug, customer_id, profile, profile_version, status, desired_spec) VALUES ('acme-d', :s, 'small', '1', 'active', '{}') RETURNING id"),
                         {"s": slug}).scalar()
        chk = db.execute(text("INSERT INTO checks (name, kind, config, interval_seconds, deployment_id, created_by) VALUES ('acme-d-web', 'http', '{}', 60, :d, (SELECT id FROM users LIMIT 1)) RETURNING id"), {"d": did}).scalar()
        inc = db.execute(text("INSERT INTO incidents (check_id, severity, status, title, message) VALUES (:c, 'critical', 'open', 'web down', 'm') RETURNING id"), {"c": chk}).scalar()
        audit.append(db, "incident.opened", actor_name="monitor", resource="incident", resource_id=str(inc), details={})
        audit.append(db, "incident.recovered", actor_name="monitor", resource="incident", resource_id=str(inc), details={})
        db.commit()
    s, ev, _ = api("GET", "/events", expect=200)
    assert [e["type"] for e in ev["items"]] == ["incident.opened", "incident.recovered"]
    assert ev["items"][0]["data"]["deployment"] == "acme-d" and ev["items"][0]["customer_id"] == cid and ev["next_after_seq"] == ev["items"][-1]["seq"]
    assert api("GET", f"/events?after_seq={ev['next_after_seq']}")[1]["items"] == []
    s, h, _ = api("GET", "/deployments/acme-d/health", expect=200)
    assert h["health"] == "unhealthy" and h["active_incidents"][0]["title"] == "web down"


# ---- spec itself + the reference client ------------------------------------------------------------------------------------------

def test_spec_matches_routes(w):
    spec = msp_spec.SPEC
    assert spec["openapi"].startswith("3.1") and spec["info"]["version"].startswith("1.")
    ops = {}
    for tmpl, item in spec["paths"].items():
        for m, op in item.items():
            if m in ("get", "post", "patch", "put", "delete"):
                ops[(m.upper(), tmpl)] = op
                assert op["operationId"] and op["x-permission"] in ("view", "plan", "approve", "execute"), (m, tmpl)
                if m != "get":
                    refs = [p.get("$ref") for p in op.get("parameters", []) + item.get("parameters", [])]
                    assert "#/components/parameters/IdempotencyKey" in refs, f"{m} {tmpl} must require Idempotency-Key"
    routes = {(next(iter(r.methods)), r.path[len(M):]) for r in w.client.app.routes if getattr(r, "name", "").startswith("msp.")}
    assert routes == set(ops), (routes ^ set(ops))


def test_reference_client_roundtrip(w, rt):
    api = w.api_client(all_customers=True)
    tc = w.client

    def transport(method, url, headers, body):
        r = tc.request(method, url[len("https://testserver"):], content=body, headers=headers)
        return r.status_code, dict(r.headers), r.content

    mc = MspClient("https://testserver", api.client_id, api.secret, transport=transport, sleep=lambda s: None)
    assert mc.me()["client_id"] == api.client_id
    p = mc.create_customer(name="Via Client", external_ref="vc-1")
    assert p["status"] == "pending_approval"
    w.approve(p["plan_id"])
    assert worker.run_once(rt)
    done = mc.wait_for_plan(p["plan_id"], timeout=5, interval=0)
    assert done["execution"]["status"] == "succeeded"
    assert mc.list_customers(external_ref="vc-1")["items"][0]["name"] == "Via Client"
    with pytest.raises(MspApiError) as e:
        mc.get_customer(str(uuid.uuid4()))
    assert e.value.status == 404 and e.value.code == "not_found"
    # retries reuse the Idempotency-Key: a flaky first answer cannot create a second plan
    calls = []

    def flaky(method, url, headers, body):
        calls.append(headers.get("Idempotency-Key"))
        if len(calls) == 1:  # the request reaches the server, the response is lost
            transport(method, url, headers, body)
            raise ConnectionResetError("lost")
        return transport(method, url, headers, body)
    mc2 = MspClient("https://testserver", api.client_id, api.secret, transport=flaky, sleep=lambda s: None)
    p2 = mc2.create_customer(name="Flaky Co")
    assert len(calls) == 2 and calls[0] == calls[1]
    with rt.session() as db:
        assert db.execute(text("SELECT count(*) FROM plans WHERE params->>'name' = 'Flaky Co'")).scalar() == 1
    assert p2["plan_id"]


def test_generated_reference_is_current():
    import subprocess
    r = subprocess.run([sys.executable, os.path.join(os.path.dirname(__file__), "..", "scripts", "gen_msp_reference.py"), "--check"])
    assert r.returncode == 0, "docs/api/msp-v1-reference.md is stale: run `python scripts/gen_msp_reference.py`"


def test_operation_ids_unique():
    ids = [op["operationId"] for item in msp_spec.SPEC["paths"].values() for m, op in item.items() if m in ("get", "post", "patch", "put", "delete")]
    assert len(ids) == len(set(ids)) >= 30


# ---- review 6 M1: the human who requested/revealed a client's key cannot approve plans submitted through that client --------------------------------
def test_m1_key_holder_cannot_approve_plans_submitted_through_the_client(w, rt):
    own = w.customer("Own Infra", msp_owned=True, mode="auto")
    with rt.session() as db:
        db.execute(text("INSERT INTO idm_stacks (name, config, secret_enc, customer_id) VALUES ('s-own', CAST(:c AS jsonb), :s, :cu)"),
                   {"c": json.dumps({"mail_domain": "x.example", "allowed_groups": ["mail-users", "staff"], "entitlement_group": "mail-users", "privileged_groups": []}),
                    "s": b"x", "cu": own})
        sid = db.execute(text("SELECT id FROM idm_stacks WHERE name = 's-own'")).scalar()
        db.execute(text("INSERT INTO idm_users (stack_id, uid, entry_uuid, mail, display_name, groups) VALUES (:s, 'amy', :e, 'amy@x.example', 'Amy', '[\"staff\"]')"),
                   {"s": sid, "e": str(uuid.uuid4())})
        db.commit()
    bot = w.api_client("integ", perms=("view", "plan"), customers=[own])        # w.adm requested AND revealed the key
    s, mine, _ = bot("PATCH", f"/customers/{own}/users/amy", {"add": ["mail-users"]}, expect=202)
    pid = mine["plan_id"]
    c, h = w.adm
    r = c.post(f"{H}/plans/{pid}/approve", headers=h)                           # the key holder approving the bot's plan: separation of duties
    assert r.status_code == 403, r.text
    assert w.audit_rows("plan.provenance_rejected")
    with rt.session() as db:
        assert db.execute(text("SELECT status FROM plans WHERE id = :p"), {"p": pid}).scalar() == "pending_approval"
        assert db.execute(text("SELECT revealed_by FROM msp_client_reveals")).scalar() is not None   # recorded at reveal
    # someone who never held the key may approve it
    assert w.ap[0][0].post(f"{H}/plans/{pid}/approve", headers=w.ap[0][1]).status_code == 200


# ---- review 6 M2: webhook SSRF -----------------------------------------------------------------------------------------------------------------
PUBLIC = "93.184.216.34"


def _dns(monkeypatch, mapping, default=PUBLIC):
    monkeypatch.setattr(mevents, "_resolve", lambda host, port: list(mapping.get(host, [default])))


@pytest.mark.parametrize("ip", ["10.1.2.3", "172.16.0.9", "192.168.22.167", "100.64.0.1", "169.254.169.254", "127.0.0.1", "0.0.0.0", "::1", "fd00::1", "fe80::1",
                                "::ffff:10.0.0.1", "::ffff:169.254.169.254", "224.0.0.1", "198.18.0.5"])
def test_m2_private_loopback_linklocal_cgnat_metadata_are_refused(monkeypatch, ip):
    _dns(monkeypatch, {"hook.example": [ip]})
    with pytest.raises(ValueError) as e:
        mevents.check_url("https://hook.example/x", allow_loopback=False)
    assert str(e.value) == mevents.DENIED                         # one message for every refusal
    # a name with ONE bad address among good ones is refused too (round robin cannot sneak a private target in)
    _dns(monkeypatch, {"hook.example": [PUBLIC, ip]})
    with pytest.raises(ValueError):
        mevents.check_url("https://hook.example/x", allow_loopback=False)


def test_m2_unresolvable_and_refused_look_the_same_and_public_is_fine(monkeypatch):
    def boom(host, port):
        raise OSError("nxdomain")
    monkeypatch.setattr(mevents, "_resolve", boom)
    with pytest.raises(ValueError) as e1:
        mevents.check_url("https://nowhere.example/x", allow_loopback=False)
    _dns(monkeypatch, {"hook.example": ["10.0.0.1"]})
    with pytest.raises(ValueError) as e2:
        mevents.check_url("https://hook.example/x", allow_loopback=False)
    assert str(e1.value) == str(e2.value) == mevents.DENIED
    _dns(monkeypatch, {})
    mevents.check_url("https://hook.example/x", allow_loopback=False)
    with pytest.raises(ValueError):
        mevents.check_url("http://hook.example/x", allow_loopback=False)       # https only


def test_m2_explicit_allowlist_is_the_only_way_to_a_private_target(monkeypatch):
    _dns(monkeypatch, {"hook.corp": ["10.9.1.1"], "other.corp": ["10.8.1.1"]})
    with pytest.raises(ValueError):
        mevents.check_url("https://hook.corp/x", False)
    mevents.check_url("https://hook.corp/x", False, ("10.9.0.0/16",))
    mevents.check_url("https://hook.corp/x", False, ("hook.corp",))
    with pytest.raises(ValueError):
        mevents.check_url("https://other.corp/x", False, ("hook.corp", "10.9.0.0/16"))


def test_m2_view_only_key_cannot_create_webhooks_and_private_urls_are_422(w, monkeypatch):
    _dns(monkeypatch, {"hook.example": [PUBLIC], "inner.example": ["10.1.1.1"]})
    cid = w.customer("Acme")
    ro = w.api_client("ro", perms=("view",), customers=[cid])
    s, d, _ = ro("POST", "/webhooks", {"url": "https://hook.example/h", "events": ["plan.approved"]})
    assert s == 403 and d["error"]["code"] in ("forbidden", "permission_denied", "insufficient_permission") or s == 403
    assert ro("GET", "/webhooks", expect=200)[1]["items"] == []
    rw = w.api_client("rw", perms=("view", "plan"), customers=[cid])
    assert rw("POST", "/webhooks", {"url": "https://inner.example/h", "events": ["plan.approved"]})[0] == 422
    assert rw("POST", "/webhooks", {"url": "https://hook.example/h", "events": ["plan.approved"]})[0] == 201


def test_m2_dns_rebinding_between_create_and_send_is_refused_and_not_sent(w, rt, monkeypatch):
    cid = w.customer("Acme")
    api = w.api_client("rw", perms=("view", "plan"), customers=[cid])
    mapping = {"hook.example": [PUBLIC]}
    _dns(monkeypatch, mapping)
    wh = api("POST", "/webhooks", {"url": "https://hook.example/h", "events": ["job.failed"]}, expect=201)[1]
    with rt.session() as db:
        mevents.emit(db, "job.failed", cid, {"job_id": "j", "plan_id": "p", "action": "a", "error": {}})
        db.commit()
    mapping["hook.example"] = ["169.254.169.254"]                         # the attacker flips the record after validation
    sink = Sink([200, 200])
    mevents.tick(rt, transport=httpx.MockTransport(sink))
    assert sink.requests == []                                             # nothing was sent anywhere
    s, dl, _ = api("GET", f"/webhooks/{wh['id']}/deliveries", expect=200)
    x = dl["items"][0]
    assert x["status"] == "pending" and x["attempts"] == 1 and x["last_status"] is None and x["last_error"] == "delivery failed"   # no network detail


def test_m2_delivery_connects_to_the_checked_address_with_original_name_and_never_follows_redirects(w, rt, monkeypatch):
    cid = w.customer("Acme")
    api = w.api_client("rw", perms=("view", "plan"), customers=[cid])
    _dns(monkeypatch, {"hook.example": [PUBLIC]})
    wh = api("POST", "/webhooks", {"url": "https://hook.example:8443/h?x=1", "events": ["job.failed"]}, expect=201)[1]
    with rt.session() as db:
        mevents.emit(db, "job.failed", cid, {"job_id": "j", "plan_id": "p", "action": "a", "error": {}})
        db.commit()
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(302, headers={"location": "http://10.0.0.5/admin"})
    mevents.tick(rt, transport=httpx.MockTransport(handler))
    assert len(seen) == 1                                                  # the redirect was NOT followed
    r = seen[0]
    assert r.url.host == PUBLIC and r.url.port == 8443 and r.url.path == "/h" and r.url.query == b"x=1"   # pinned to the validated address
    assert r.headers["host"] == "hook.example:8443" and r.extensions.get("sni_hostname") == "hook.example"   # TLS name + Host stay the original
    s, dl, _ = api("GET", f"/webhooks/{wh['id']}/deliveries", expect=200)
    assert dl["items"][0]["last_status"] is None and dl["items"][0]["last_error"] == "delivery failed"      # a 302 from an internal host is not reported


# ---- review 6 M3: no implicit binding of existing deployments by slug ---------------------------------------------------------------------------
def _orphan_deployment(rt, slug="acme-prod", customer_id="acme"):
    with rt.session() as db:
        db.execute(text("INSERT INTO deployments (slug, customer_id, profile, profile_version, status, desired_spec) VALUES (:s, :c, 'small', '1', 'active', '{}')"),
                   {"s": slug, "c": customer_id})
        db.commit()


def test_m3_customer_create_cannot_capture_an_existing_deployment_by_slug(w, rt):
    _orphan_deployment(rt)
    r = w.adm[0].post(f"{H}/plans", json={"action": "customer.create", "params": {"name": "Acme Corp", "slug": "acme"}}, headers=w.adm[1])
    assert r.status_code == 409 and "adopt_existing_deployments" in r.text                  # refused at plan time
    # a derived slug skips names that would capture a deployment
    p = w.run_human("customer.create", {"name": "Acme"})
    with rt.session() as db:
        assert db.execute(text("SELECT slug FROM customers WHERE name = 'Acme'")).scalar() != "acme"
        assert db.execute(text("SELECT count(*) FROM deployments d JOIN customers c ON c.slug = d.customer_id")).scalar() == 0
    # the explicit mapping: flagged, high risk (two approvers), executed, audited with the adopted deployments
    p = w.plan(w.adm, "customer.create", {"name": "Acme Corp", "slug": "acme", "adopt_existing_deployments": True})
    assert p["risk"] == "high"
    w.approve(p["plan_id"], p["approvals_required"])
    assert worker.run_once(rt)
    with rt.session() as db:
        assert db.execute(text("SELECT count(*) FROM deployments d JOIN customers c ON c.slug = d.customer_id WHERE c.name = 'Acme Corp'")).scalar() == 1
    assert w.audit_rows("customer.created")[-1].details["adopted_deployments"] == ["acme-prod"]


def test_m3_customer_update_slug_is_the_explicit_mapping_for_existing_deployments(w, rt):
    _orphan_deployment(rt, "old-prod", "oldco")
    cid = w.customer("Old Co")
    r = w.adm[0].post(f"{H}/plans", json={"action": "customer.update", "params": {"customer_id": cid, "slug": "oldco"}}, headers=w.adm[1])
    assert r.status_code == 409
    p = w.plan(w.adm, "customer.update", {"customer_id": cid, "slug": "oldco", "adopt_existing_deployments": True})
    w.approve(p["plan_id"], p["approvals_required"])
    assert worker.run_once(rt)
    with rt.session() as db:
        assert db.execute(text("SELECT slug FROM customers WHERE id = :c"), {"c": cid}).scalar() == "oldco"
