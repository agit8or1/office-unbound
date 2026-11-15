"""Identity lifecycle: action validation + risk policy, the full create/disable/enable/delete flow against in-memory LDAP/Keycloak/agent fakes
(so the real worker, approvals, vault, audit and redaction code paths run), one-time enrollment, VERIFY semantics, reconcile classification,
and the node-agent identity runbooks (real agent, stub systemctl)."""
import datetime
import json
import os
import re
import subprocess
import sys
import time
import types
import uuid

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from pydantic import ValidationError
from sqlalchemy import text

from ics import agentclient, identity, idprobe, worker
from ics.identity import IdentityError
from .conftest import FakeAgent

H = "/api/v1"


def _pem() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "lab ca")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=30)).sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


PEM = _pem()
LDAP_PW, KC_SECRET, MAS_SECRET = "ldap-service-pw-12345", "kc-service-secret-12345", "mas-service-secret-12345"


def stack_params(**over):
    p = {"name": "acme", "ldap_url": "ldaps://ldap.example.test", "ldap_bind_dn": "cn=svc-ics,ou=system,dc=x,dc=test",
         "ldap_bind_password": LDAP_PW, "ldap_people_dn": "ou=people,dc=x,dc=test", "ldap_groups_dn": "ou=groups,dc=x,dc=test",
         "mail_domain": "x.test", "allowed_groups": ["mail-users", "files-users", "files-admin"], "privileged_groups": ["files-admin"],
         "kc_url": "https://auth.example.test", "kc_realm": "acme", "kc_client_id": "ou-ics", "kc_client_secret": KC_SECRET,
         "kc_offline_clients": ["desktop"], "identity_ca_pem": PEM, "files_url": "https://cloud.example.test",
         "files_node_id": str(uuid.uuid4()), "gromox_node_id": str(uuid.uuid4()), "mail_host": "mail.example.test", "mail_ca_pem": PEM,
         "reconcile_interval_seconds": 60}
    p.update(over)
    return p


# ---- in-memory systems ----------------------------------------------------------------------------------------------------------------
_REAL_MAS_ACTIVE = identity.Mas.active_sessions
_REAL_MAS_KINDS = identity.Mas.KINDS
_REAL_PROFILE_CHECK = identity.Keycloak.profile_check            # captured before the fixtures replace identity.Keycloak
_PROFILE_LOCKED = identity.Keycloak.PROFILE_LOCKED


class World:
    def __init__(self):
        self.ldap: dict = {}
        self.kc: dict = {}
        self.gx: dict = {}
        self.stuck_imap = False
        self.profile = [{"name": "username", "permissions": {"view": ["admin", "user"], "edit": ["admin"]}},
                        {"name": "email", "permissions": {"view": ["admin", "user"], "edit": ["admin"]}},
                        {"name": "firstName", "permissions": {"view": ["admin", "user"], "edit": ["admin", "user"]}}]
        self.app_tokens: dict = {}          # uid -> number of live OpenCloud app tokens
        self.devices: dict = {}             # uid -> {device_id: wipe status}
        self.picks_up_after: int | None = None   # wipe is "delivered" after this many gromox.devices polls (None: never)
        self.polls = 0
        self.pw_at_wipe = None
        self.kicked: list = []
        self.revoke_ok = True
        self.passwords: dict = {}
        self.calls: list = []
        self.mas: dict = {}  # uid -> {"id","locked","deactivated","sessions"}

    def entitled(self, uid):
        e = self.ldap.get(uid)
        return bool(e) and not e["locked"] and "mail-users" in e["groups"]


@pytest.fixture()
def world(monkeypatch):
    w = World()

    class FakeDir:
        _ldap3 = types.SimpleNamespace(BASE=0)

        def __init__(self, rt, stack):
            w.calls.append(("ldap.connect", stack.cfg["ldap_bind_dn"]))

        def close(self): pass
        def _search(self, *a, **k): return [object()]

        def get(self, uid):
            e = w.ldap.get(uid)
            return dict(e, groups=sorted(e["groups"])) if e else None

        def list_people(self): return [dict(e, groups=sorted(e["groups"])) for e in w.ldap.values()]

        def add(self, uid, name, mail):
            w.ldap[uid] = {"uid": uid, "dn": f"uid={uid},ou=people", "mail": mail, "display_name": name, "locked": False, "groups": set(),
                           "entry_uuid": str(uuid.uuid4())}

        def member(self, group, uid, add):
            (w.ldap[uid]["groups"].add if add else w.ldap[uid]["groups"].discard)(group)

        def set_password(self, uid, pw):
            w.passwords[uid] = pw
            w.ldap[uid]["locked"] = False if w.ldap[uid].get("pw_resets_lock") else w.ldap[uid]["locked"]

        def lock(self, uid): w.ldap[uid]["locked"] = True
        def unlock(self, uid): w.ldap[uid]["locked"] = False
        def delete(self, uid): w.ldap.pop(uid)

        def can_bind(self, uid, pw):
            return bool(uid in w.ldap and not w.ldap[uid]["locked"] and w.passwords.get(uid) == pw)

    class FakeKC:
        def __init__(self, rt, stack): self.offline_clients = stack.cfg["kc_offline_clients"]
        def close(self): pass
        def req(self, *a, **k): return types.SimpleNamespace(json=lambda: 3)
        def find(self, uid): return w.kc.get(uid)
        def profile_check(self):
            fake = types.SimpleNamespace(req=lambda *a, **k: types.SimpleNamespace(json=lambda: {"attributes": w.profile}), PROFILE_LOCKED=_PROFILE_LOCKED)
            return _REAL_PROFILE_CHECK(fake)

        def set_enabled(self, user, en): w.kc[user["username"]]["enabled"] = en
        def logout(self, kid): [u.update(sessions=0) for u in w.kc.values() if u["id"] == kid]
        def consent_clients(self, kid): return ["desktop"]
        def revoke_consent(self, kid, c): [u.update(offline=0) for u in w.kc.values() if u["id"] == kid]
        def sessions(self, kid): return [u["sessions"] for u in w.kc.values() if u["id"] == kid][0]
        def offline_sessions(self, kid, extra=()): return [u["offline"] for u in w.kc.values() if u["id"] == kid][0]
        def delete(self, kid): [w.kc.pop(k) for k in [k for k, u in w.kc.items() if u["id"] == kid]]

    class FakeMas:
        def __init__(self, rt, stack): assert stack.mas_secret == MAS_SECRET
        def close(self): pass
        def probe(self): pass
        def find(self, uid):
            m = w.mas.get(uid)
            return {"id": m["id"], "locked": m["locked"], "deactivated": m["deactivated"]} if m else None
        def _by(self, mid): return [m for m in w.mas.values() if m["id"] == mid][0]
        def lock(self, mid): w.calls.append(("mas.lock", mid)); self._by(mid)["locked"] = True
        def unlock(self, mid): w.calls.append(("mas.unlock", mid)); self._by(mid)["locked"] = False
        def deactivate(self, mid): w.calls.append(("mas.deactivate", mid)); self._by(mid).update(deactivated=True, locked=True)
        def active_sessions(self, mid): return [("oauth2-sessions", str(i)) for i in range(self._by(mid)["sessions"])]
        def end_sessions(self, mid): n = self._by(mid)["sessions"]; self._by(mid)["sessions"] = 0; return n
        def state(self, uid):
            m = w.mas.get(uid)
            return {"user_present": False} if not m else {"user_present": True, "locked": m["locked"], "deactivated": m["deactivated"], "active_sessions": m["sessions"]}

    w.FakeMas = FakeMas

    def fake_agent(rt, node_id, action, uid, known):
        e = w.ldap.get(uid)
        w.calls.append((action, uid))
        if action == "gromox.sync_user":
            row = w.gx.get(uid)
            if e is None and row:
                row["address_status"] = 1
            elif e is not None:
                row = w.gx.setdefault(uid, {"externid": e["entry_uuid"], "address_status": 0, "mode": "0770"})
                row["address_status"] = 0 if w.entitled(uid) else 1
                if row["address_status"] == 0:
                    row["mode"] = "0770"
            return {"uid": uid, "sync": [{"action": "sync", "detail": ""}], "sync_errors": 0,
                    "state": {"exists": uid in w.gx, **w.gx.get(uid, {})}, "released": False}
        if action == "gromox.kick_user":
            w.gx[uid]["mode"] = "0000"
            return {"uid": uid, "frozen": True, "midb_unloaded": True, "maildir_mode": "0000"}
        if action == "gromox.user_state":
            r = w.gx.get(uid)
            return {"uid": uid, "state": {"exists": bool(r), **(r or {})}, "maildir_mode": (r or {}).get("mode")}
        if action == "opencloud.check_user":
            return {"uid": uid, "resolved": bool(e) and not e["locked"]}
        if action == "opencloud.revoke_app_tokens":
            if not e or e["locked"]:
                return {"uid": uid, "resolved": False, "ok": False}
            n = w.app_tokens.get(uid, 0)
            if w.revoke_ok:
                w.app_tokens[uid] = 0
            return {"uid": uid, "resolved": True, "ok": w.revoke_ok, "listed": n + 1, "revoked": n if w.revoke_ok else 0, "remaining": 0 if w.revoke_ok else n,
                    "temp_token_dead": True}
        if action == "gromox.kill_sessions":
            w.kicked.append(uid)
            return {"uid": uid, "kick_sent": True}
        if action in ("gromox.wipe_devices", "gromox.devices"):
            devs = w.devices.get(uid, {})
            if action == "gromox.wipe_devices":
                w.pw_at_wipe = w.passwords.get(uid)
                w.polls = 0
                for d in devs:
                    devs[d] = max(devs[d], 2)
            else:
                w.polls += 1
                if w.picks_up_after is not None and w.polls >= w.picks_up_after:
                    for d in devs:
                        devs[d] = 4
            names = {0: "none", 2: "wipe_pending", 4: "wipe_delivered", 8: "wiped_acknowledged"}
            return {"uid": uid, "devices": [{"device": d, "status": s, "status_name": names[s], "last_sync": 1, "history": []} for d, s in sorted(devs.items())]}
        raise AssertionError(action)

    monkeypatch.setattr(identity, "Directory", FakeDir)
    monkeypatch.setattr(identity, "Keycloak", FakeKC)
    monkeypatch.setattr(identity, "Mas", FakeMas)
    monkeypatch.setattr(identity, "agent_user", fake_agent)
    monkeypatch.setattr(identity.time, "sleep", lambda s: None)
    return w


def add_stack(rt, **over):
    p = stack_params(**over)
    m = identity.StackRegister.model_validate(p)
    cfg = m.model_dump(mode="json", exclude={"ldap_bind_password", "kc_client_secret", "mas_client_secret"})
    sid = str(uuid.uuid4())
    sec = {"ldap_bind_password": LDAP_PW, "kc_client_secret": KC_SECRET, **({"mas_client_secret": MAS_SECRET} if m.mas_client_secret else {})}
    enc = rt.vault.encrypt(json.dumps(sec).encode(), identity.stack_aad(sid, cfg))
    with rt.session() as d:
        d.execute(text("INSERT INTO idm_stacks (id, name, config, secret_enc) VALUES (:i, :n, CAST(:c AS jsonb), :s)"),
                  {"i": sid, "n": cfg["name"], "c": json.dumps(cfg), "s": enc})
        d.commit()
    return sid


class Env:
    def __init__(self, client, mk_user, login, rt):
        self.rt = rt
        self.op, self.oh = login(mk_user("op", "operator"))
        self.ap1, self.h1 = login(mk_user("ap1", "approver"))
        self.ap2, self.h2 = login(mk_user("ap2", "approver"))

    def plan(self, action, params, approvers=None, expect=201):
        r = self.op.post(f"{H}/plans", json={"action": action, "params": params}, headers=self.oh)
        assert r.status_code == expect, r.text
        if expect != 201:
            return r
        j = r.json()
        for c, h in (approvers if approvers is not None else [(self.ap1, self.h1), (self.ap2, self.h2)][:j["approvals_required"]]):
            if j["status"] == "pending_approval":
                a = c.post(f"{H}/plans/{j['plan_id']}/approve", headers=h)
                assert a.status_code == 200, a.text
                j["job_id"] = a.json()["job_id"]
        return j

    def run(self, j):
        while worker.run_once(self.rt):
            pass
        return self.op.get(f"{H}/jobs/{j['job_id']}").json()


@pytest.fixture()
def env(client, mk_user, login, rt):
    return Env(client, mk_user, login, rt)


def create_user(env, uid="alice", groups=("files-users",), **kw):
    j = env.plan("idm.user.create", {"stack": "acme", "uid": uid, "display_name": f"Alice {uid}", "mail": f"{uid}@x.test", "groups": list(groups), **kw})
    return j, env.run(j)


# ---- validation -------------------------------------------------------------------------------------------------------------------------
def test_parameter_validation():
    for bad in ({"uid": "Alice"}, {"uid": "a"}, {"uid": "al;ice"}, {"uid": "al ice"}, {"mail": "bob@x.test"}, {"mail": "alice@@x.test"},
                {"display_name": " lead"}, {"display_name": "x\ny"}, {"groups": ["a b"]}, {"groups": ["x"] * 21}, {"extra": 1}, {"stack": "bad name"}):
        p = {"stack": "acme", "uid": "alice", "display_name": "Alice A", "mail": "alice@x.test", "groups": [], **bad}
        with pytest.raises(ValidationError):
            identity.UserCreate.model_validate(p)
    identity.UserCreate.model_validate({"stack": "acme", "uid": "alice", "display_name": "Alice A", "mail": "alice@x.test"})
    for p in ({"add": [], "remove": []}, {"add": ["g"], "remove": ["g"]}):
        with pytest.raises(ValidationError):
            identity.UserUpdateGroups.model_validate({"stack": "acme", "uid": "alice", **p})
    with pytest.raises(ValidationError):
        identity.UserDisable.model_validate({"stack": "acme", "uid": "alice", "verify_timeout_seconds": 500})
    with pytest.raises(ValidationError):
        identity.UserDelete.model_validate({"stack": "acme", "uid": "alice"})  # reason is mandatory
    for bad in ({"ldap_url": "ldap://h"}, {"ldap_url": "ldaps://h/../x"}, {"kc_url": "http://h"}, {"kc_url": "https://u:p@h"}, {"privileged_groups": ["zz"]},
                {"ldap_bind_password": "short"}, {"identity_ca_pem": "nope"}, {"entitlement_group": "zz"}, {"gromox_node_id": str(uuid.uuid4()), "mail_host": None}):
        with pytest.raises(ValidationError):
            identity.StackRegister.model_validate(stack_params(**bad))
    assert "ldap-service-pw-12345" not in repr(identity.StackRegister.model_validate(stack_params()))


def test_catalog_lists_identity_actions_with_risk(env):
    cat = {a["action"]: a["risk"] for a in env.op.get(f"{H}/actions").json()}
    assert cat["idm.user.create"] == "normal" and cat["idm.user.disable"] == "normal" and cat["idm.user.delete"] == "high"
    assert cat["idm.stack.register"] == "high" and cat["idm.reconcile"] == "low"


# ---- risk tiers / approvals -------------------------------------------------------------------------------------------------------------
def test_normal_risk_needs_exactly_one_other_approver(env, rt, world):
    add_stack(rt)
    r = env.plan("idm.user.create", {"stack": "acme", "uid": "alice", "display_name": "Alice A", "mail": "alice@x.test", "groups": ["files-users"]},
                 approvers=[])
    assert r["risk"] == "normal" and r["status"] == "pending_approval" and r["approvals_required"] == 1 and r["job_id"] is None
    assert env.op.post(f"{H}/plans/{r['plan_id']}/approve", headers=env.oh).status_code == 403          # requester role/self
    ok = env.ap1.post(f"{H}/plans/{r['plan_id']}/approve", headers=env.h1)
    assert ok.status_code == 200 and ok.json()["status"] == "approved" and ok.json()["job_id"]            # ONE approver is enough
    assert env.ap2.post(f"{H}/plans/{r['plan_id']}/approve", headers=env.h2).status_code == 409


def test_requester_who_is_an_approver_cannot_approve_own_identity_plan(client, mk_user, login, rt):
    add_stack(rt)
    ad, adh = login(mk_user("adm", "admin"))
    r = ad.post(f"{H}/plans", json={"action": "idm.user.create", "params": {"stack": "acme", "uid": "bob", "display_name": "Bob B", "mail": "bob@x.test"}}, headers=adh)
    assert r.status_code == 201
    assert ad.post(f"{H}/plans/{r.json()['plan_id']}/approve", headers=adh).status_code == 403


def test_high_risk_tiers(env, rt, world):
    add_stack(rt)
    create_user(env)
    p = env.plan("idm.user.create", {"stack": "acme", "uid": "carl", "display_name": "Carl C", "mail": "carl@x.test", "groups": ["files-admin"]}, approvers=[])
    assert p["risk"] == "high" and p["approvals_required"] == 2 and p["privileged"] == ["files-admin"]
    q = env.plan("idm.user.update_groups", {"stack": "acme", "uid": "alice", "add": ["files-admin"]}, approvers=[])
    assert q["risk"] == "high" and q["approvals_required"] == 2
    q2 = env.plan("idm.user.update_groups", {"stack": "acme", "uid": "alice", "add": ["files-users"]}, approvers=[])
    assert q2["risk"] == "normal"
    rec = env.plan("idm.reconcile", {"stack": "acme"}, approvers=[])
    assert rec["risk"] == "low" and rec["status"] == "approved" and rec["job_id"]                        # read-only report: auto-approved
    # one approval of a high plan does not run it
    a = env.ap1.post(f"{H}/plans/{p['plan_id']}/approve", headers=env.h1).json()
    assert a["status"] == "pending_approval" and a["job_id"] is None


def test_plan_time_checks(env, rt, world):
    add_stack(rt)
    base = {"stack": "acme", "uid": "alice", "display_name": "Alice A", "mail": "alice@x.test"}
    assert env.plan("idm.user.create", {**base, "stack": "nope"}, expect=404)
    assert env.plan("idm.user.create", {**base, "mail": "alice@evil.test"}, expect=422)
    assert env.plan("idm.user.create", {**base, "groups": ["not-allowed"]}, expect=422)
    assert env.plan("idm.user.create", {**base, "uid": "bad uid", "mail": "bad uid@x.test"}, expect=422)
    create_user(env)
    assert env.plan("idm.user.create", base, expect=409)                                               # duplicate
    for action, params in (("idm.user.disable", {"stack": "acme", "uid": "ghost"}), ("idm.user.enable", {"stack": "acme", "uid": "ghost"})):
        assert env.plan(action, params, expect=404)
    assert env.plan("idm.user.enable", {"stack": "acme", "uid": "alice"}, expect=422)                    # not disabled
    assert env.plan("idm.user.delete", {"stack": "acme", "uid": "alice", "reason": "test"}, expect=422)  # delete only after disable
    assert env.plan("idm.user.update_groups", {"stack": "acme", "uid": "alice", "add": ["other"]}, expect=422)


# ---- provisioning flow ------------------------------------------------------------------------------------------------------------------
def test_create_records_stable_id_provisions_every_system_and_issues_a_one_time_token(env, rt, world):
    add_stack(rt)
    j, job = create_user(env)
    assert job["status"] == "succeeded", job["error"]
    res = job["result"]
    entry_uuid = world.ldap["alice"]["entry_uuid"]
    assert res["entry_uuid"] == entry_uuid and res["opencloud_visible"] is True
    with rt.session() as d:
        row = d.execute(text("SELECT * FROM idm_users WHERE uid = 'alice'")).first()
    assert row.entry_uuid == entry_uuid and row.state == "active" and sorted(row.groups) == ["files-users", "mail-users"]
    assert world.gx["alice"]["externid"] == entry_uuid and world.gx["alice"]["address_status"] == 0
    assert [c[0] for c in world.calls if c[0].startswith(("gromox", "opencloud"))] == ["gromox.sync_user", "opencloud.check_user"]
    assert "alice" not in world.passwords                                                                 # no password exists until the user enrols
    # the token is shown ONLY to the requester, once
    assert env.ap1.post(f"{H}/identity/enrollments/{j['plan_id']}/reveal", headers=env.h1).status_code == 404
    r = env.op.post(f"{H}/identity/enrollments/{j['plan_id']}/reveal", headers=env.oh)
    assert r.status_code == 200 and r.json()["uid"] == "alice"
    token = r.json()["token"]
    assert env.op.post(f"{H}/identity/enrollments/{j['plan_id']}/reveal", headers=env.oh).status_code == 404
    with rt.session() as d:
        assert d.execute(text("SELECT token_enc IS NULL AND revealed_at IS NOT NULL FROM idm_enrollments")).scalar() is True
        stored = d.execute(text("SELECT token_sha256 FROM idm_enrollments")).scalar()
    assert token.split(".")[1] not in stored
    # redemption: user sets their own password
    pw = "a-long-initial-passphrase-77"
    anon = lambda body: env.op.post(f"{H}/identity/enroll", json=body, headers={})  # noqa: E731  (no CSRF/session needed: unauthenticated by design)
    base = {"stack": "acme", "uid": "alice", "token": token}
    assert anon({**base, "password": "short"}).status_code == 422
    assert anon({**base, "password": "alice-alice-alice-1"}).status_code == 422                            # contains the uid
    assert anon({**base, "uid": "bob", "password": pw}).status_code == 403
    assert anon({**base, "token": token[:-3] + "xyz", "password": pw}).status_code == 403
    assert anon({**base, "token": "-" * 36 + ".x" * 15, "password": pw}).status_code == 403                    # malformed id: generic refusal, no 500
    assert anon({**base, "password": pw}).status_code == 200 and world.passwords["alice"] == pw
    assert anon({**base, "password": pw + "x"}).status_code == 403                                         # single use
    # nothing sensitive in audit / jobs / plans
    with rt.session() as d:
        blob = json.dumps([str(r[0]) for r in d.execute(text("SELECT details FROM audit_events")).all()])
        blob += json.dumps([str(r[0]) for r in d.execute(text("SELECT result FROM jobs")).all()]) + json.dumps(env.op.get(f"{H}/plans").json())
    for secret in (token, token.split(".")[1], pw, LDAP_PW, KC_SECRET):
        assert secret not in blob
    assert env.ap1.get(f"{H}/audit/verify").json()["ok"] is True


def test_enrollment_token_burns_after_five_failures_and_expires(env, rt, world):
    add_stack(rt)
    j, _ = create_user(env)
    token = env.op.post(f"{H}/identity/enrollments/{j['plan_id']}/reveal", headers=env.oh).json()["token"]
    eid, secret = token.split(".")
    for _ in range(5):
        assert env.op.post(f"{H}/identity/enroll", json={"stack": "acme", "uid": "alice", "token": f"{eid}.{'z' * 43}", "password": "long-enough-pw-12"}).status_code == 403
    assert env.op.post(f"{H}/identity/enroll", json={"stack": "acme", "uid": "alice", "token": token, "password": "long-enough-pw-12"}).status_code == 403
    assert "alice" not in world.passwords
    j2, _ = create_user(env, "dora")
    tok2 = env.op.post(f"{H}/identity/enrollments/{j2['plan_id']}/reveal", headers=env.oh).json()["token"]
    with rt.session() as d:
        d.execute(text("UPDATE idm_enrollments SET expires_at = now() - interval '1 second' WHERE user_id = (SELECT id FROM idm_users WHERE uid='dora')"))
        d.commit()
    assert env.op.post(f"{H}/identity/enroll", json={"stack": "acme", "uid": "dora", "token": tok2, "password": "long-enough-pw-12"}).status_code == 403


def test_create_refuses_to_adopt_an_unmanaged_directory_entry(env, rt, world):
    add_stack(rt)
    world.ldap["alice"] = {"uid": "alice", "dn": "x", "mail": "alice@x.test", "display_name": "x", "locked": False, "groups": set(), "entry_uuid": "u1"}
    _, job = create_user(env)
    assert job["status"] == "failed" and "unmanaged" in job["error"]["message"]
    with rt.session() as d:
        assert d.execute(text("SELECT count(*) FROM idm_users")).scalar() == 0


def test_update_groups_syncs_entitlement_and_ends_sso_on_removal(env, rt, world):
    add_stack(rt)
    create_user(env)
    world.kc["alice"] = {"id": "k1", "username": "alice", "enabled": True, "sessions": 2, "offline": 1}
    j = env.plan("idm.user.update_groups", {"stack": "acme", "uid": "alice", "remove": ["mail-users"], "add": []})
    job = env.run(j)
    assert job["status"] == "succeeded" and job["result"]["groups"] == ["files-users"]
    assert world.kc["alice"]["sessions"] == 0 and world.gx["alice"]["address_status"] == 1              # entitlement removed -> mailbox suspended
    with rt.session() as d:
        assert d.execute(text("SELECT groups FROM idm_users WHERE uid='alice'")).scalar() == ["files-users"]


# ---- deprovisioning + VERIFY ------------------------------------------------------------------------------------------------------------
def patch_probes(monkeypatch, world, refuse_after=0.0):
    """Probes that behave like real systems: credentials are valid until the directory entry is locked."""
    def up(uid): return uid in world.ldap and not world.ldap[uid]["locked"]
    monkeypatch.setattr(idprobe, "kc_password_grant", lambda cfg, uid, pw, offline=False: (up(uid), {"access_token": "a", "refresh_token": "r"} if up(uid) else {}))
    monkeypatch.setattr(idprobe, "kc_refresh", lambda cfg, rt_: not world.kc.get("alice", {}).get("enabled", True) is False and up("alice") or False)
    monkeypatch.setattr(idprobe, "files_bearer", lambda cfg, tok, uid: up(uid))
    monkeypatch.setattr(idprobe, "files_webdav_bearer", lambda cfg, tok, uid: up(uid))
    for n in ("imap_login", "ews_getfolder", "activesync_options"):
        monkeypatch.setattr(idprobe, n, lambda cfg, mail, pw: up(mail.split("@")[0]))
    monkeypatch.setattr(idprobe, "imap_open", lambda cfg, mail, pw: object())
    monkeypatch.setattr(idprobe, "imap_session_alive", lambda m: True if world.stuck_imap else up("alice"))


def test_disable_with_canary_probes_records_each_path_and_enable_reenrols(env, rt, world, monkeypatch):
    add_stack(rt, probe_client_id="probe")
    patch_probes(monkeypatch, world)
    create_user(env)
    world.kc["alice"] = {"id": "k1", "username": "alice", "enabled": True, "sessions": 2, "offline": 1}
    d = env.plan("idm.user.disable", {"stack": "acme", "uid": "alice", "verify_timeout_seconds": 5, "reason": "leaver"})
    job = env.run(d)
    assert job["status"] == "succeeded", job["error"]
    v = job["result"]["verification"]
    assert v["mode"] == "canary_probe" and v["overall"] == "PASS" and v["not_revoked"] == []
    assert set(v["paths"]) >= {"kc_login", "kc_sso_refresh", "kc_offline_refresh", "oc_bearer_graph", "oc_bearer_webdav", "imap_login",
                               "imap_open_session", "ews_getfolder", "activesync_options", "ldap_bind", "oc_user_resolution"}
    assert all(o["status"] == "refused" and float(o["seconds"]) <= identity.TARGET_SECONDS for o in v["paths"].values())
    assert v["state"]["gromox"] == {"address_status": 1, "maildir_mode": "0000"} and v["state"]["keycloak"]["offline_sessions"] == 0
    assert world.ldap["alice"]["locked"] and world.kc["alice"]["enabled"] is False and world.passwords["alice"] != "x"
    with rt.session() as db:
        assert db.execute(text("SELECT state FROM idm_users WHERE uid='alice'")).scalar() == "disabled"
        aud = [r[0] for r in db.execute(text("SELECT details::text FROM audit_events WHERE action='identity.verify'")).all()]
    assert aud and "kc_login" in aud[0] and "[redacted]" not in aud[0]                                      # per-path timings survive audit scrubbing
    assert world.passwords["alice"] not in json.dumps(job)                                                  # canary never in the job
    # enable: old credential gone, a NEW one-time enrollment is issued, mailbox released
    e = env.plan("idm.user.enable", {"stack": "acme", "uid": "alice"})
    ej = env.run(e)
    assert ej["status"] == "succeeded" and not world.ldap["alice"]["locked"] and world.kc["alice"]["enabled"] and world.gx["alice"]["address_status"] == 0
    assert env.op.post(f"{H}/identity/enrollments/{e['plan_id']}/reveal", headers=env.oh).status_code == 200


def test_verify_failure_is_loud_when_a_path_stays_valid(env, rt, world, monkeypatch):
    add_stack(rt, probe_client_id="probe")
    patch_probes(monkeypatch, world)
    world.stuck_imap = True                                                                                 # an IMAP session nobody can kill
    create_user(env)
    d = env.plan("idm.user.disable", {"stack": "acme", "uid": "alice", "verify_timeout_seconds": 5})
    job = env.run(d)
    assert job["status"] == "failed" and "VERIFY FAILED" in job["error"]["message"] and "imap_open_session" in job["error"]["message"]
    with rt.session() as db:
        row = db.execute(text("SELECT state, last_verification FROM idm_users WHERE uid='alice'")).first()
    assert row.state == "disabled" and row.last_verification["overall"] == "FAIL" and row.last_verification["not_revoked"] == ["imap_open_session"]
    assert row.last_verification["paths"]["kc_login"]["status"] == "refused"


def test_disable_without_probe_client_uses_state_checks_and_keeps_credentials(env, rt, world):
    add_stack(rt)   # no probe_client_id -> state_only
    create_user(env)
    world.passwords["alice"] = "users-own-password"
    job = env.run(env.plan("idm.user.disable", {"stack": "acme", "uid": "alice", "verify_timeout_seconds": 5}))
    assert job["status"] == "succeeded"
    v = job["result"]["verification"]
    assert v["mode"] == "state_only" and v["overall"] == "PASS" and world.passwords["alice"] == "users-own-password"
    assert set(v["paths"]) == {"oc_user_resolution"}


def test_state_check_fails_when_gromox_stays_active(env, rt, world, monkeypatch):
    add_stack(rt)
    create_user(env)
    orig = identity.agent_user

    def lying(rt_, node, action, uid, known):
        r = orig(rt_, node, action, uid, known)
        if action == "gromox.sync_user" and world.ldap[uid]["locked"]:
            world.gx[uid]["address_status"] = 0
            r["state"]["address_status"] = 0
        return r
    monkeypatch.setattr(identity, "agent_user", lying)
    job = env.run(env.plan("idm.user.disable", {"stack": "acme", "uid": "alice", "verify_timeout_seconds": 5}))
    assert job["status"] == "failed" and "VERIFY FAILED" in job["error"]["message"]


def test_delete_keeps_mailbox_and_stable_id_and_requires_two_approvers(env, rt, world):
    add_stack(rt)
    create_user(env)
    env.run(env.plan("idm.user.disable", {"stack": "acme", "uid": "alice", "verify_timeout_seconds": 5}))
    world.kc["alice"] = {"id": "k1", "username": "alice", "enabled": False, "sessions": 0, "offline": 0}
    d = env.plan("idm.user.delete", {"stack": "acme", "uid": "alice", "reason": "end of contract"}, approvers=[])
    assert d["risk"] == "high" and d["approvals_required"] == 2
    env.ap1.post(f"{H}/plans/{d['plan_id']}/approve", headers=env.h1)
    d["job_id"] = env.ap2.post(f"{H}/plans/{d['plan_id']}/approve", headers=env.h2).json()["job_id"]
    job = env.run(d)
    assert job["status"] == "succeeded" and job["result"]["mailbox_retained"] is True
    assert "alice" not in world.ldap and "alice" not in world.kc and world.gx["alice"]["address_status"] == 1 and world.gx["alice"]["mode"] == "0000"
    with rt.session() as db:
        assert db.execute(text("SELECT state FROM idm_users WHERE uid='alice'")).scalar() == "deleted"
    assert env.plan("idm.user.disable", {"stack": "acme", "uid": "alice"}, expect=404)
    # the retained mailbox keeps the address reserved (no purge action exists): re-creating the uid is refused at plan time
    assert env.plan("idm.user.create", {"stack": "acme", "uid": "alice", "display_name": "Alice Again", "mail": "alice@x.test"}, expect=409)


def test_tampered_plan_is_refused_at_execution(env, rt, world):
    add_stack(rt)
    create_user(env)
    d = env.plan("idm.user.disable", {"stack": "acme", "uid": "alice"}, approvers=[])
    env.ap1.post(f"{H}/plans/{d['plan_id']}/approve", headers=env.h1)
    with rt.session() as db:
        db.execute(text("UPDATE plans SET params = jsonb_set(params, '{uid}', '\"mallory\"') WHERE id = :i"), {"i": d["plan_id"]})
        db.commit()
    with rt.session() as db:
        jid = db.execute(text("SELECT id FROM jobs WHERE plan_id = :p"), {"p": d["plan_id"]}).scalar()
    d["job_id"] = str(jid)
    job = env.run(d)
    assert job["status"] == "failed" and "changed after approval" in job["error"]["message"] and not world.ldap["alice"]["locked"]


# ---- vault binding, register, reconcile -------------------------------------------------------------------------------------------------
def test_stack_credentials_are_vault_bound_to_the_config(rt):
    add_stack(rt)
    assert identity.load_stack(rt, "acme").ldap_pw == LDAP_PW
    with rt.session() as d:
        assert LDAP_PW.encode() not in bytes(d.execute(text("SELECT secret_enc FROM idm_stacks")).scalar())
        d.execute(text("UPDATE idm_stacks SET config = jsonb_set(config, '{ldap_bind_dn}', '\"cn=admin,dc=x,dc=test\"')"))
        d.commit()
    with pytest.raises(IdentityError, match="cannot be decrypted"):
        identity.load_stack(rt, "acme")                                                                     # pointing the stack at another bind DN voids the secret


def test_register_stack_requires_two_approvers_and_hides_secrets(env, rt, world):
    p = stack_params(files_node_id=None, gromox_node_id=None, mail_host=None, mail_ca_pem=None, files_url=None,
                     ldap_url="ldaps://127.0.0.1:636", kc_url="https://127.0.0.1:8443")
    assert env.plan("idm.stack.register", {**p, "name": "meta", "ldap_url": "ldaps://169.254.169.254"}, expect=422)   # SSRF guard at plan time
    r = env.plan("idm.stack.register", {**p, "name": "reg"}, approvers=[])
    assert r["risk"] == "high" and r["approvals_required"] == 2
    j = env.plan("idm.stack.register", {**p, "name": "reg2"})
    job = env.run(j)
    assert job["status"] == "succeeded", job["error"]
    stacks = env.op.get(f"{H}/identity/stacks").json()
    assert {s["name"] for s in stacks} == {"reg2"}
    dump = json.dumps(stacks) + json.dumps(env.op.get(f"{H}/plans").json())
    with rt.session() as d:
        dump += json.dumps([str(r[0]) for r in d.execute(text("SELECT details FROM audit_events")).all()])
    assert LDAP_PW not in dump and KC_SECRET not in dump and "BEGIN CERTIFICATE" not in json.dumps(stacks)


def test_reconcile_reports_destructive_drift_and_never_repairs(env, rt, world):
    add_stack(rt)
    create_user(env)
    env.run(env.plan("idm.user.disable", {"stack": "acme", "uid": "alice", "verify_timeout_seconds": 5}))
    clean = env.run(env.plan("idm.reconcile", {"stack": "acme"}))
    assert clean["status"] == "succeeded" and clean["result"]["critical"] == 0 and clean["result"]["findings"] == []
    world.ldap["alice"]["locked"] = False                                                                    # out-of-band unlock
    world.kc["alice"] = {"id": "k", "username": "alice", "enabled": True, "sessions": 1, "offline": 0}
    world.ldap["stranger"] = {"uid": "stranger", "dn": "x", "mail": "s@x.test", "display_name": "S", "locked": False, "groups": set(), "entry_uuid": "zz"}
    job = env.run(env.plan("idm.reconcile", {"stack": "acme"}))
    kinds = {(f["uid"], f["kind"]): f["severity"] for f in job["result"]["findings"]}
    assert kinds[("alice", "ldap_not_locked")] == "critical" and kinds[("alice", "kc_enabled")] == "critical" and kinds[("alice", "opencloud_resolves")] == "critical"
    assert kinds[("stranger", "unmanaged_directory_user")] == "info" and job["result"]["critical"] >= 3
    assert world.ldap["alice"]["locked"] is False and world.kc["alice"]["enabled"] is True                  # report only: nothing was changed
    assert env.op.get(f"{H}/identity/reconcile").json()[0]["ok"] is False


def test_periodic_reconcile_runs_when_due(rt, world):
    add_stack(rt)
    assert identity.reconcile_due(rt) == 1 and identity.reconcile_due(rt) == 0                              # claimed: not again within the interval
    with rt.session() as d:
        assert d.execute(text("SELECT count(*) FROM idm_reconcile_runs WHERE trigger = 'periodic'")).scalar() == 1


def test_classify_table():
    cfg = {"entitlement_group": "mail-users"}
    L = {"entry_uuid": "u", "locked": True, "groups": ["mail-users"]}
    u = {"uid": "a", "state": "disabled", "entry_uuid": "u", "groups": ["mail-users"]}
    kinds = lambda *a: {f["kind"] for f in identity.classify(*a)}  # noqa: E731
    assert kinds(u, L, None, {"address_status": 1, "maildir_mode": "0000"}, {"resolved": False}, cfg) == set()
    assert kinds(u, {**L, "locked": False}, {"enabled": True, "online_sessions": 0, "offline_sessions": 0}, {"address_status": 0}, {"resolved": True}, cfg) == \
        {"ldap_not_locked", "kc_enabled", "gromox_active", "opencloud_resolves"}
    assert "gromox_mailbox_open" in kinds(u, L, None, {"address_status": 1, "maildir_mode": "0770"}, None, cfg)
    assert "ldap_entryuuid_mismatch" in kinds(u, {**L, "entry_uuid": "other"}, None, None, None, cfg)
    assert kinds(u, None, None, None, None, cfg) == {"ldap_missing"}
    act = {**u, "state": "active"}
    assert kinds(act, {**L, "locked": False}, {"enabled": True}, {"address_status": 0, "maildir_mode": "0770"}, {"resolved": True}, cfg) == set()
    assert kinds(act, {**L, "locked": False, "groups": []}, None, {"address_status": 1}, {"resolved": False}, cfg) == \
        {"gromox_suspended", "opencloud_invisible", "group_drift"}
    dele = {**u, "state": "deleted"}
    assert kinds(dele, L, {"enabled": False}, {"address_status": 0}, None, cfg) == {"ldap_exists_deleted", "kc_orphan", "gromox_active"}
    assert all(f["severity"] == "critical" for f in identity.classify(dele, L, {"enabled": False}, {"address_status": 0}, None, cfg))


# ---- probes: measurement semantics ------------------------------------------------------------------------------------------------------
def test_measure_records_first_refusal_and_never_counts_errors_as_refused(monkeypatch):
    monkeypatch.setattr(idprobe, "PROBE_TIMEOUT", 1.0)
    n = {"slow": 0}

    def slow():
        n["slow"] += 1
        return n["slow"] < 3          # accepted twice, refused on the third poll

    t0 = time.monotonic()
    out = idprobe.measure({"refused_now": lambda: False, "slow": slow, "never": lambda: True, "flaky": lambda: None}, t0, 4.5, interval=0.4)
    assert out["refused_now"]["status"] == "refused" and float(out["refused_now"]["seconds"]) < 0.5
    assert out["slow"]["status"] == "refused" and out["slow"]["polls"] == 3 and 0.7 <= float(out["slow"]["seconds"]) < 2.0
    assert out["never"]["status"] == "still_accepted" and out["never"]["seconds"] is None
    assert out["flaky"]["status"] == "inconclusive"


# ---- node agent: identity runbooks --------------------------------------------------------------------------------------------------------
@pytest.fixture()
def uagent(tmp_path, monkeypatch):
    results = tmp_path / "ou-rb"
    results.mkdir()
    fa = FakeAgent(tmp_path, extra={"gromox.user_state": {"enabled": True}, "opencloud.check_user": {"enabled": True}})
    monkeypatch.setattr(fa.runbooks, "RESULT_DIR", str(results))
    yield fa, results
    fa.stop()


def enrolled_node(fa, nid=None, priv=None):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = priv or Ed25519PrivateKey.generate()
    nid = nid or str(uuid.uuid4())
    ident = agentclient.identity("127.0.0.1", fa.port, fa.tls_fp, allow_loopback=True)
    agentclient.enroll("127.0.0.1", fa.port, fa.tls_fp, token=fa.token, ics_pubkey_b64=agentclient.pub_b64(priv.public_key()), node_id=nid,
                       expect_agent_pubkey_b64=ident["agent_pubkey"], allow_loopback=True)
    return priv, types.SimpleNamespace(id=nid, address="127.0.0.1", port=fa.port, tls_fingerprint_sha256=fa.tls_fp, agent_pubkey=ident["agent_pubkey"])


def acall(fa, priv, node, action, params):
    return agentclient.call(node, priv, action=action, params=params, job_id=str(uuid.uuid4()), allow_loopback=True)[1]


def test_agent_user_runbooks_fixed_argv_validated_uid_and_fresh_result(uagent):
    fa, results = uagent
    priv, node = enrolled_node(fa)
    (results / "gromox-state-alice.json").write_text(json.dumps({"uid": "alice", "ts": int(time.time()) + 5, "state": {"address_status": 1}}))
    r = acall(fa, priv, node, "gromox.user_state", {"user": "alice"})
    assert r["status"] == "ok" and r["result"]["returncode"] == 0 and r["result"]["result"]["state"]["address_status"] == 1
    assert fa.calls()[-1] == "--no-ask-password start --wait ou-rb-gromox-state@alice.service"             # exact argv, template unit, no shell
    for bad in ({"user": "Alice"}, {"user": "al;ice"}, {"user": "a"}, {"user": "../x"}, {"user": "alice", "x": 1}, {"unit": "alice"}, {}, {"user": 5}):
        n = len(fa.calls())
        r = acall(fa, priv, node, "gromox.user_state", bad)
        assert r["status"] == "rejected" and r["code"] == "bad_params" and len(fa.calls()) == n
    n = len(fa.calls())
    for action in ("gromox.sync_user", "gromox.kick_user"):                                               # not enabled in this agent's root-owned config
        r = acall(fa, priv, node, action, {"user": "alice"})
        assert r["status"] == "rejected" and r["code"] == "not_allowed"
    assert len(fa.calls()) == n
    # a stale or foreign result file is never trusted
    (results / "gromox-state-bob.json").write_text(json.dumps({"uid": "bob", "ts": int(time.time()) - 600}))
    assert acall(fa, priv, node, "gromox.user_state", {"user": "bob"})["result"]["result"] is None
    (results / "gromox-state-carol.json").write_text(json.dumps({"uid": "someone-else", "ts": int(time.time()) + 5}))
    assert acall(fa, priv, node, "gromox.user_state", {"user": "carol"})["result"]["result"] is None


def test_ics_agent_user_helper_end_to_end(uagent, rt):
    fa, results = uagent
    priv = agentclient.load_signing_key(rt.settings.signing_key_file)          # the key the ICS really signs with
    _, node = enrolled_node(fa, priv=priv)
    with rt.session() as d:
        d.execute(text("INSERT INTO nodes (id, name, address, port, tls_fingerprint_sha256, agent_pubkey, agent_key_fp, capabilities) "
                       "VALUES (:i, 'n', '127.0.0.1', :p, :t, :k, :f, '{}'::jsonb)"),
                  {"i": node.id, "p": fa.port, "t": fa.tls_fp, "k": node.agent_pubkey, "f": fa.key_fp})
        d.commit()
    (results / "opencloud-check-alice.json").write_text(json.dumps({"uid": "alice", "ts": int(time.time()) + 5, "resolved": True}))
    r = identity.agent_user(rt, node.id, "opencloud.check_user", "alice", [])
    assert r["resolved"] is True
    # unusable result (helper wrote nothing) -> an error, never a silent success
    with pytest.raises(IdentityError, match="helper failed"):
        identity.agent_user(rt, node.id, "opencloud.check_user", "nobody", [])
    # disallowed runbook on this agent -> rejected by the AGENT's own allowlist
    with pytest.raises(IdentityError, match="rejected"):
        identity.agent_user(rt, node.id, "gromox.sync_user", "alice", [])
    with rt.session() as d:
        rows = d.execute(text("SELECT action, response_code FROM agent_requests ORDER BY id")).all()
        assert [tuple(r) for r in rows] == [("opencloud.check_user", "ok"), ("opencloud.check_user", "ok"), ("gromox.sync_user", "not_allowed")]
        assert d.execute(text("SELECT count(*) FROM audit_events WHERE action = 'runbook.executed'")).scalar() == 3


def test_polkit_rule_only_starts_the_fixed_templates(tmp_path):
    cfg = tmp_path / "agent.json"
    cfg.write_text(json.dumps({"listen": {"address": "0.0.0.0", "port": 1}, "runbooks": {"service.restart": {"units": ["gromox-imap"]},
                                                                                           "gromox.user_state": {"enabled": True}}}))
    out = subprocess.run([sys.executable, os.path.join(os.path.dirname(__file__), "..", "agent", "deploy", "render_polkit.py"), str(cfg)],
                         capture_output=True, text=True, check=True).stdout
    assert 'var tmpl = ["ou-rb-gromox-state"]' in out and 'var allowed = ["gromox-imap.service"]' in out
    assert "action.lookup(\"verb\") == \"start\"" in out and "polkit.Result.NO" in out
    assert re.search(r"\[a-z\]\[a-z0-9\._-\]\{1,31\}", out)                                                   # instance name is the validated uid pattern
    assert "ou-rb-gromox-sync" not in out                                                                     # templates of runbooks that are not enabled are not allowed
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"listen": {"address": "0.0.0.0", "port": 1}, "runbooks": {"gromox.user_state": {"enabled": True, "x": "y"}}}))
    from ou_agent import runbooks
    with pytest.raises(ValueError):
        runbooks.validate_config(json.loads(bad.read_text()))


# ---- Matrix (MAS) downstream -------------------------------------------------------------------------------------------------------------
MAS = {"mas_url": "https://mas.example.test", "mas_client_id": "ou-ics", "mas_client_secret": MAS_SECRET}


def test_mas_parameters_come_together_and_secret_is_a_secret():
    with pytest.raises(ValidationError):
        identity.StackRegister.model_validate(stack_params(mas_url="https://mas.example.test"))
    with pytest.raises(ValidationError):
        identity.StackRegister.model_validate(stack_params(mas_url="http://mas.example.test", mas_client_id="x1", mas_client_secret=MAS_SECRET))
    m = identity.StackRegister.model_validate(stack_params(**MAS))
    assert MAS_SECRET not in repr(m)


def test_disable_locks_matrix_ends_sessions_enable_unlocks_delete_deactivates(env, rt, world, monkeypatch):
    add_stack(rt, probe_client_id="probe", **MAS)
    patch_probes(monkeypatch, world)
    create_user(env)
    world.kc["alice"] = {"id": "k1", "username": "alice", "enabled": True, "sessions": 1, "offline": 0}
    world.mas["alice"] = {"id": "m1", "locked": False, "deactivated": False, "sessions": 2}
    job = env.run(env.plan("idm.user.disable", {"stack": "acme", "uid": "alice", "verify_timeout_seconds": 5, "reason": "leaver"}))
    assert job["status"] == "succeeded", job["error"]
    v = job["result"]["verification"]
    assert v["overall"] == "PASS" and v["paths"]["matrix_access"]["status"] == "refused"
    assert v["state"]["matrix"] == {"user_present": True, "locked": True, "deactivated": False, "active_sessions": 0}
    step = [x for x in job["result"]["steps"] if x["step"] == "matrix.lock"][0]
    assert step["sessions_ended"] == 2 and step["locked"]
    assert MAS_SECRET not in json.dumps(job)
    e = env.run(env.plan("idm.user.enable", {"stack": "acme", "uid": "alice"}))
    assert e["status"] == "succeeded" and world.mas["alice"]["locked"] is False
    env.run(env.plan("idm.user.disable", {"stack": "acme", "uid": "alice", "verify_timeout_seconds": 5, "reason": "leaver"}))
    d = env.run(env.plan("idm.user.delete", {"stack": "acme", "uid": "alice", "reason": "gone"}))
    assert d["status"] == "succeeded", d["error"]
    assert world.mas["alice"]["deactivated"] and ("mas.deactivate", "m1") in world.calls


def test_disable_ok_for_user_without_matrix_and_fails_loud_when_a_session_survives(env, rt, world, monkeypatch):
    add_stack(rt, **MAS)
    create_user(env)
    j = env.run(env.plan("idm.user.disable", {"stack": "acme", "uid": "alice", "verify_timeout_seconds": 5, "reason": "leaver"}))
    assert j["status"] == "succeeded" and j["result"]["verification"]["state"]["matrix"] == {"user_present": False}
    env.run(env.plan("idm.user.enable", {"stack": "acme", "uid": "alice"}))
    world.mas["alice"] = {"id": "m1", "locked": False, "deactivated": False, "sessions": 1}

    class Sticky(world.FakeMas):
        def end_sessions(self, mid): return 0  # sessions cannot be ended
    monkeypatch.setattr(identity, "Mas", Sticky)
    j = env.run(env.plan("idm.user.disable", {"stack": "acme", "uid": "alice", "verify_timeout_seconds": 5, "reason": "leaver"}))
    assert j["status"] == "failed" and "VERIFY FAILED" in j["error"]["message"]


def test_classify_matrix():
    row = {"uid": "a", "state": "disabled", "entry_uuid": "u", "groups": []}
    ldap = {"entry_uuid": "u", "locked": True, "groups": []}
    cfg = {"entitlement_group": "mail-users"}

    def kinds(mx, st="disabled"):
        return {f["kind"] for f in identity.classify({**row, "state": st}, ldap if st != "deleted" else None, None, None, None, cfg, mx)}
    assert kinds({"user_present": True, "locked": False, "deactivated": False, "active_sessions": 1}) == {"matrix_not_locked", "matrix_sessions_remain"}
    assert kinds({"user_present": True, "locked": True, "deactivated": False, "active_sessions": 0}) == set()
    assert kinds({"user_present": False}) == set()
    assert "matrix_active" in kinds({"user_present": True, "locked": True, "deactivated": False, "active_sessions": 0}, "deleted")
    assert "matrix_locked" in kinds({"user_present": True, "locked": True, "deactivated": False, "active_sessions": 0}, "active")
    assert {"matrix_not_locked", "matrix_sessions_remain", "matrix_active"} <= identity.DESTRUCTIVE


def test_reconcile_reports_matrix_drift(env, rt, world):
    add_stack(rt, **MAS)
    create_user(env)
    env.run(env.plan("idm.user.disable", {"stack": "acme", "uid": "alice", "verify_timeout_seconds": 5, "reason": "leaver"}))
    world.mas["alice"] = {"id": "m1", "locked": False, "deactivated": False, "sessions": 1}   # injected drift
    r = identity.reconcile(rt, "acme")
    assert {"matrix_not_locked", "matrix_sessions_remain"} <= {f["kind"] for f in r["findings"]} and r["critical"] >= 2


def test_mas_client_calls_exact_endpoints(rt):
    """The real Mas class against a fake transport: client-credentials token, only the whitelisted admin endpoints."""
    import httpx
    seen = []

    def handler(req: httpx.Request):
        seen.append((req.method, req.url.path))
        if req.url.path == "/oauth2/token":
            assert req.headers["authorization"].startswith("Basic ") and b"urn%3Amas%3Aadmin" in req.content
            return httpx.Response(200, json={"access_token": "t", "expires_in": 300})
        assert req.headers["authorization"] == "Bearer t"
        if req.url.path.endswith("/by-username/alice"):
            return httpx.Response(200, json={"data": {"id": "M1", "attributes": {"locked_at": "2026-01-01T00:00:00Z", "deactivated_at": None}}})
        if req.url.path.endswith("/by-username/ghost"):
            return httpx.Response(404, json={})
        if req.url.path in ("/api/admin/v1/oauth2-sessions", "/api/admin/v1/compat-sessions"):
            return httpx.Response(200, json={"data": [{"id": "S1"}]})
        return httpx.Response(200, json={})

    cfg = {**stack_params(**{**MAS, "mas_url": "https://127.0.0.1"})}
    cfg.pop("mas_client_secret")
    stack = identity.Stack(type("R", (), {"id": uuid.uuid4(), "name": "acme", "config": cfg}),
                           {"ldap_bind_password": LDAP_PW, "kc_client_secret": KC_SECRET, "mas_client_secret": MAS_SECRET})
    mas = identity.Mas(rt, stack)
    mas.http = httpx.Client(transport=httpx.MockTransport(handler))
    assert mas.find("alice") == {"id": "M1", "locked": True, "deactivated": False} and mas.find("ghost") is None
    assert mas.end_sessions("M1") == 2
    mas.lock("M1")
    assert ("POST", "/api/admin/v1/oauth2-sessions/S1/finish") in seen and ("POST", "/api/admin/v1/compat-sessions/S1/finish") in seen
    assert ("POST", "/api/admin/v1/users/M1/lock") in seen
    assert all(p.startswith("/api/admin/v1/") or p == "/oauth2/token" for _, p in seen)


def test_reconcile_alerts_when_email_or_username_become_user_editable(env, rt, world):
    """Security review 4, M4: the realm profile must keep email/username admin-edit-only; drift is a CRITICAL finding (report only)."""
    add_stack(rt)
    create_user(env)
    ok = env.run(env.plan("idm.reconcile", {"stack": "acme"}))["result"]
    assert not [f for f in ok["findings"] if f["kind"].startswith("kc_profile")]
    world.profile[1]["permissions"]["edit"] = ["admin", "user"]                      # email becomes user-editable (e.g. re-import of the old realm export)
    r = env.run(env.plan("idm.reconcile", {"stack": "acme"}))["result"]
    f = [f for f in r["findings"] if f["kind"] == "kc_profile_user_editable"]
    assert len(f) == 1 and f[0]["severity"] == "critical" and "'email'" in f[0]["detail"] and r["ok"] is False and r["critical"] >= 1
    world.profile[1]["permissions"]["edit"] = ["admin"]
    del world.profile[0]                                                              # username attribute missing: cannot verify -> warning
    r = env.run(env.plan("idm.reconcile", {"stack": "acme"}))["result"]
    assert [f["kind"] for f in r["findings"] if f["kind"].startswith("kc_profile")] == ["kc_profile_attribute_missing"]


def test_mas_active_sessions_follows_cursor_pages():
    """Review 4, L5: more than 100 sessions must all be listed (and ended), not just the first page."""
    ids = {"oauth2-sessions": [f"o{i:03d}" for i in range(230)], "compat-sessions": ["c1"]}

    def req(method, path, **kw):
        p = kw["params"]
        allids = ids[path.lstrip("/")]
        start = allids.index(p["page[after]"]) + 1 if p.get("page[after]") else 0
        return types.SimpleNamespace(json=lambda: {"data": [{"id": i} for i in allids[start:start + 100]]})
    fake = types.SimpleNamespace(req=req, KINDS=_REAL_MAS_KINDS)
    got = _REAL_MAS_ACTIVE(fake, "user1")
    assert len([g for g in got if g[0] == "oauth2-sessions"]) == 230 and ("compat-sessions", "c1") in got
