"""Telephony as a downstream of the identity lifecycle: extension assignment (LDAP telephoneNumber), PBX provisioning/kick/state runbooks,
one-time SIP credential reveal, and the PBX provisioner itself (blueprints/telephony/pbx/ou_pbx.py) against fakes.
Reuses the in-memory LDAP/Keycloak/agent world of test_identity; the PBX is a small fake that mirrors the real provisioner's rules."""
import importlib.util
import json
import os
import time
import uuid

import pytest
from sqlalchemy import text

from ics import agentclient, identity
from .test_identity import (MAS, add_stack, create_user, env, enrolled_node, acall, patch_probes, world, uagent,  # noqa: F401
                            stack_params)

PBX_NODE = str(uuid.uuid4())
PBXP = {"pbx_node_id": PBX_NODE, "pbx_domain": "pbx.example.test"}
SIP_PW = "0123456789abcdef0123456789abcdef"


class Pbx:
    """What the PBX node would answer: derives everything from the directory (like ou_pbx.sync)."""

    def __init__(self, w):
        self.w, self.devices, self.contacts, self.channels = w, {}, {}, {}
        self.sticky = False   # a kick that does not take effect (negative test)

    def known(self, uid):
        e = self.w.ldap.get(uid)
        return bool(e) and bool(e.get("extension")) and not e["locked"]

    def sync(self):
        for uid in list(self.devices):
            if not self.known(uid):
                self.devices.pop(uid)
                if not self.sticky:
                    self.contacts.pop(uid, None)
                    self.channels.pop(uid, None)

    def report(self, uid):
        e = self.w.ldap.get(uid) or {}
        return {"uid": uid, "extension": e.get("extension"), "known_to_pbx": self.known(uid), "devices": sorted(self.devices.get(uid, {})),
                "endpoint_present": bool(self.devices.get(uid)), "contacts": self.contacts.get(uid, 0), "channels": self.channels.get(uid, 0)}


@pytest.fixture()
def pbx(world, monkeypatch):
    p = Pbx(world)
    base_agent = identity.agent_user
    base_dir = identity.Directory

    class Dir(base_dir):
        def add(self, uid, name, mail, extension=None):
            super().add(uid, name, mail)
            world.ldap[uid]["extension"] = extension
            world.calls.append(("ldap.add.ext", uid, extension))

        def extension_owner(self, ext):
            return next((u for u, e in world.ldap.items() if e.get("extension") == ext), None)

        def set_extension(self, uid, ext):
            world.ldap[uid]["extension"] = ext

        def get(self, uid):
            return super().get(uid)

    def agent(rt, node_id, action, uid, known, device=None, raw=False):
        if not action.startswith("pbx."):
            return base_agent(rt, node_id, action, uid, known)
        assert str(node_id) == PBX_NODE
        world.calls.append((action, uid) + ((device,) if device else ()))
        if action == "pbx.sync_extensions":
            p.sync()
            return p.report(uid)
        if action == "pbx.kick_user":
            c, ch = (p.contacts.get(uid, 0), p.channels.get(uid, 0)) if not p.sticky else (0, 0)
            p.sync()
            p.contacts.pop(uid, None) if not p.sticky else None
            p.channels.pop(uid, None) if not p.sticky else None
            return {**p.report(uid), "contacts_removed": c, "channels_hung_up": ch, "endpoint_removed": True}
        if action == "pbx.user_state":
            return p.report(uid)
        if action == "pbx.issue_credential":
            assert raw and device in ("web", "native", "desk")
            p.devices.setdefault(uid, {})[device] = "md5-only"
            return {"username": f"{uid}.{device}", "password": SIP_PW, "extension": (world.ldap[uid] or {}).get("extension"), "realm": "ou-pbx",
                    "domain": "pbx.internal", "display_name": "Alice", "wss": "wss://pbx.example.test:8089/ws", "tls_port": 5061}
        raise AssertionError(action)

    monkeypatch.setattr(identity, "Directory", Dir)
    monkeypatch.setattr(identity, "agent_user", agent)
    return p


def run_plan(env, action, params, **kw):
    j = env.plan(action, params, **kw)
    return j, env.run(j)


# ---- validation -----------------------------------------------------------------------------------------------------------------------
def test_parameter_validation():
    with pytest.raises(Exception):
        identity.StackRegister.model_validate(stack_params(pbx_node_id=PBX_NODE))          # node without domain
    with pytest.raises(Exception):
        identity.StackRegister.model_validate(stack_params(pbx_domain="pbx.example.test"))
    assert identity.StackRegister.model_validate(stack_params(**PBXP)).pbx_node_id
    for bad in ("0123", "123", "12345", "12a4", "+1234", "1234\n"):
        with pytest.raises(Exception):
            identity.UserCreate.model_validate({"stack": "acme", "uid": "alice", "display_name": "Alice A", "mail": "alice@x.test", "extension": bad})
    with pytest.raises(Exception):
        identity.IssueSipCredential.model_validate({"stack": "acme", "uid": "alice", "device": "../x"})
    with pytest.raises(Exception):
        identity.UserSetExtension.model_validate({"stack": "acme", "uid": "alice"})          # extension is required (null removes it)
    assert identity.UserSetExtension.model_validate({"stack": "acme", "uid": "alice", "extension": None}).extension is None


# ---- create / update --------------------------------------------------------------------------------------------------------------------
def test_create_with_extension_writes_telephoneNumber_and_syncs_the_pbx(env, rt, world, pbx):
    add_stack(rt, **PBXP)
    j, job = create_user(env, extension="1010")
    assert job["status"] == "succeeded", job["error"]
    assert world.ldap["alice"]["extension"] == "1010"
    assert ("pbx.sync_extensions", "alice") in world.calls
    step = [s for s in job["result"]["steps"] if s["step"] == "pbx.sync"][0]
    assert step["known_to_pbx"] is True and job["result"]["extension"] == "1010"
    with rt.session() as d:
        assert d.execute(text("SELECT extension FROM idm_users WHERE uid = 'alice'")).scalar() == "1010"
    # extensions are unique per stack (plan time) and need a PBX node
    env.plan("idm.user.create", {"stack": "acme", "uid": "bob", "display_name": "Bob B", "mail": "bob@x.test", "extension": "1010"}, expect=409)


def test_extension_needs_a_pbx_node(env, rt, world, pbx):
    add_stack(rt)  # no PBX
    r = env.plan("idm.user.create", {"stack": "acme", "uid": "alice", "display_name": "Alice A", "mail": "alice@x.test", "extension": "1010"}, expect=422)
    assert "PBX" in r.text


def test_set_extension_change_and_remove_end_registrations(env, rt, world, pbx):
    add_stack(rt, **PBXP)
    create_user(env, extension="1010")
    j, job = run_plan(env, "idm.user.issue_sip_credential", {"stack": "acme", "uid": "alice", "device": "web"})
    assert job["status"] == "succeeded", job["error"]
    pbx.contacts["alice"], pbx.channels["alice"] = 1, 1
    j, job = run_plan(env, "idm.user.set_extension", {"stack": "acme", "uid": "alice", "extension": "1011"})
    assert job["status"] == "succeeded", job["error"]
    assert world.ldap["alice"]["extension"] == "1011" and ("pbx.kick_user", "alice") in world.calls     # changed number: old registrations are ended
    assert pbx.contacts.get("alice", 0) == 0 or pbx.report("alice")["known_to_pbx"]
    j, job = run_plan(env, "idm.user.set_extension", {"stack": "acme", "uid": "alice", "extension": None})
    assert job["status"] == "succeeded" and world.ldap["alice"]["extension"] is None
    assert pbx.devices.get("alice") is None and pbx.channels.get("alice", 0) == 0                          # credentials purged by the sync
    with rt.session() as d:
        assert d.execute(text("SELECT extension FROM idm_users WHERE uid = 'alice'")).scalar() is None
        assert d.execute(text("SELECT count(*) FROM audit_events WHERE action = 'identity.extension_changed'")).scalar() == 2
    # a second user cannot take a number that is in use
    create_user(env, uid="carol", extension="1020")
    env.plan("idm.user.set_extension", {"stack": "acme", "uid": "alice", "extension": "1020"}, expect=409)


# ---- one-time SIP credential -------------------------------------------------------------------------------------------------------------
def test_sip_credential_is_revealed_once_to_the_requester_and_never_stored_in_clear(env, rt, world, pbx, mk_user, login):
    add_stack(rt, **PBXP)
    create_user(env, extension="1010")
    j, job = run_plan(env, "idm.user.issue_sip_credential", {"stack": "acme", "uid": "alice", "device": "native"})
    assert job["status"] == "succeeded", job["error"]
    assert ("pbx.issue_credential", "alice", "native") in world.calls
    assert SIP_PW not in json.dumps(job)                                      # not in the job result
    with rt.session() as d:
        assert SIP_PW not in json.dumps([dict(r._mapping, **{"details": r.details}) for r in d.execute(text("SELECT * FROM audit_events")).all()], default=str)
        row = d.execute(text("SELECT secret_enc FROM idm_sip_credentials")).first()
        assert row.secret_enc is not None and SIP_PW.encode() not in bytes(row.secret_enc)    # encrypted at rest until revealed
    other, oh = login(mk_user("other", "operator"))
    assert other.post(f"/api/v1/identity/sip-credentials/{j['plan_id']}/reveal", headers=oh).status_code == 404   # not the requester
    r = env.op.post(f"/api/v1/identity/sip-credentials/{j['plan_id']}/reveal", headers=env.oh)
    assert r.status_code == 200, r.text
    b = r.json()
    assert b["password"] == SIP_PW and b["username"] == "alice.native" and b["extension"] == "1010" and b["domain"] == "pbx.example.test"
    assert r.headers["cache-control"] == "no-store"
    assert env.op.post(f"/api/v1/identity/sip-credentials/{j['plan_id']}/reveal", headers=env.oh).status_code == 404   # once
    with rt.session() as d:
        assert d.execute(text("SELECT secret_enc IS NULL AND revealed_at IS NOT NULL FROM idm_sip_credentials")).scalar() is True
        assert d.execute(text("SELECT count(*) FROM audit_events WHERE action = 'identity.sip_credential_revealed'")).scalar() == 1
        assert SIP_PW not in json.dumps([r.details for r in d.execute(text("SELECT details FROM audit_events")).all()])


def test_sip_credential_expires_and_needs_an_extension(env, rt, world, pbx):
    add_stack(rt, **PBXP)
    create_user(env)                                                            # no extension
    r = env.plan("idm.user.issue_sip_credential", {"stack": "acme", "uid": "alice", "device": "web"}, expect=422)
    assert "extension" in r.text
    run_plan(env, "idm.user.set_extension", {"stack": "acme", "uid": "alice", "extension": "1010"})
    j, job = run_plan(env, "idm.user.issue_sip_credential", {"stack": "acme", "uid": "alice", "device": "web"})
    with rt.session() as d:
        d.execute(text("UPDATE idm_sip_credentials SET expires_at = now() - interval '1 second'"))
        d.commit()
    assert env.op.post(f"/api/v1/identity/sip-credentials/{j['plan_id']}/reveal", headers=env.oh).status_code == 404


# ---- disable / enable / delete ------------------------------------------------------------------------------------------------------------
def test_disable_kicks_the_pbx_and_verifies_no_registration_and_no_call(env, rt, world, pbx, monkeypatch):
    add_stack(rt, probe_client_id="probe", **PBXP)
    patch_probes(monkeypatch, world)
    create_user(env, extension="1010")
    run_plan(env, "idm.user.issue_sip_credential", {"stack": "acme", "uid": "alice", "device": "web"})
    world.kc["alice"] = {"id": "k1", "username": "alice", "enabled": True, "sessions": 1, "offline": 0}
    pbx.contacts["alice"], pbx.channels["alice"] = 1, 1                          # registered and in a call
    j, job = run_plan(env, "idm.user.disable", {"stack": "acme", "uid": "alice", "verify_timeout_seconds": 5, "reason": "leaver"})
    assert job["status"] == "succeeded", job["error"]
    v = job["result"]["verification"]
    assert v["overall"] == "PASS" and v["paths"]["pbx_access"]["status"] == "refused"
    assert v["state"]["pbx"] == {"endpoint_present": False, "contacts": 0, "channels": 0}
    step = [s for s in job["result"]["steps"] if s["step"] == "pbx.kick"][0]
    assert step["registrations_removed"] == 1 and step["channels_hung_up"] == 1 and step["endpoint_removed"] is True
    # enable: the extension is back, the OLD credential is not (a new one-time credential is needed)
    e = env.run(env.plan("idm.user.enable", {"stack": "acme", "uid": "alice"}))
    assert e["status"] == "succeeded" and pbx.report("alice")["known_to_pbx"] and pbx.devices.get("alice") is None
    env.run(env.plan("idm.user.disable", {"stack": "acme", "uid": "alice", "verify_timeout_seconds": 5, "reason": "again"}))
    d = env.run(env.plan("idm.user.delete", {"stack": "acme", "uid": "alice", "reason": "gone"}))
    assert d["status"] == "succeeded", d["error"] and ("pbx.kick_user", "alice") in world.calls


def test_disable_fails_loud_when_the_pbx_keeps_a_registration(env, rt, world, pbx, monkeypatch):
    add_stack(rt, probe_client_id="probe", **PBXP)
    patch_probes(monkeypatch, world)
    create_user(env, extension="1010")
    world.kc["alice"] = {"id": "k1", "username": "alice", "enabled": True, "sessions": 0, "offline": 0}
    pbx.devices["alice"] = {"web": "x"}
    pbx.contacts["alice"], pbx.sticky = 1, True
    j, job = run_plan(env, "idm.user.disable", {"stack": "acme", "uid": "alice", "verify_timeout_seconds": 5, "reason": "leaver"})
    assert job["status"] == "failed" and "VERIFY FAILED" in job["error"]["message"] and "pbx_access" in job["error"]["message"]


def test_stack_without_pbx_is_unchanged(env, rt, world, pbx):
    add_stack(rt)
    create_user(env)
    j, job = run_plan(env, "idm.user.disable", {"stack": "acme", "uid": "alice", "verify_timeout_seconds": 5, "reason": "x"})
    assert job["status"] == "succeeded" and not any(c[0].startswith("pbx.") for c in world.calls)
    assert "pbx" not in job["result"]["verification"]["state"]


# ---- node agent runbooks (real agent, stub systemctl) ----------------------------------------------------------------------------------
@pytest.fixture()
def pagent(tmp_path, monkeypatch):
    from .conftest import FakeAgent
    out, sec = tmp_path / "ou-rb", tmp_path / "ou-rb-secret"
    out.mkdir()
    sec.mkdir()
    fa = FakeAgent(tmp_path, extra={k: {"enabled": True} for k in ("pbx.sync_extensions", "pbx.kick_user", "pbx.user_state", "pbx.issue_credential")})
    monkeypatch.setattr(fa.runbooks, "RESULT_DIR", str(out))
    monkeypatch.setattr(fa.runbooks, "SECRET_DIR", str(sec))
    yield fa, out, sec
    fa.stop()


def test_agent_pbx_runbooks_fixed_argv_and_validated_params(pagent):
    fa, out, sec = pagent
    priv, node = enrolled_node(fa)
    (out / "pbx-kick-alice.json").write_text(json.dumps({"uid": "alice", "ts": int(time.time()) + 5, "contacts_removed": 2, "channels_hung_up": 1}))
    r = acall(fa, priv, node, "pbx.kick_user", {"user": "alice"})
    assert r["status"] == "ok" and r["result"]["result"]["channels_hung_up"] == 1
    assert fa.calls()[-1] == "--no-ask-password start --wait ou-rb-pbx-kick@alice.service"
    for bad in ({"user": "Alice"}, {"user": "alice", "device": "web"}, {}, {"user": "a;b"}):
        n = len(fa.calls())
        r = acall(fa, priv, node, "pbx.user_state", bad)
        assert r["status"] == "rejected" and r["code"] == "bad_params" and len(fa.calls()) == n
    for bad in ({"user": "alice"}, {"user": "alice", "device": "phone"}, {"user": "alice", "device": "web", "x": 1}, {"user": "alice", "device": "../web"}):
        n = len(fa.calls())
        r = acall(fa, priv, node, "pbx.issue_credential", bad)
        assert r["status"] == "rejected" and r["code"] == "bad_params" and len(fa.calls()) == n


def test_agent_issue_result_comes_from_the_secret_dir_and_is_unlinked(pagent):
    fa, out, sec = pagent
    priv, node = enrolled_node(fa)
    f = sec / "pbx-issue-alice.web.json"
    f.write_text(json.dumps({"uid": "alice", "device": "web", "ts": int(time.time()) + 5, "password": SIP_PW, "username": "alice.web"}))
    r = acall(fa, priv, node, "pbx.issue_credential", {"user": "alice", "device": "web"})
    assert r["status"] == "ok" and r["result"]["result"]["password"] == SIP_PW
    assert fa.calls()[-1] == "--no-ask-password start --wait ou-rb-pbx-issue@alice.web.service"
    assert not f.exists()                                                       # the secret never stays on the node
    f.write_text(json.dumps({"uid": "alice", "device": "native", "ts": int(time.time()) + 5, "password": SIP_PW}))   # wrong device = foreign result
    r = acall(fa, priv, node, "pbx.issue_credential", {"user": "alice", "device": "web"})
    assert r["result"]["result"] is None and not f.exists()
    assert not list(out.glob("*issue*"))                                       # nothing credential-like in the world-readable dir


def test_polkit_rule_covers_pbx_templates(tmp_path):
    import subprocess
    import sys
    cfg = tmp_path / "a.json"
    cfg.write_text(json.dumps({"runbooks": {k: {"enabled": True} for k in ("pbx.sync_extensions", "pbx.kick_user", "pbx.user_state", "pbx.issue_credential")}}))
    rule = subprocess.run([sys.executable, os.path.join(os.path.dirname(__file__), "..", "agent", "deploy", "render_polkit.py"), str(cfg)],
                          capture_output=True, text=True, check=True).stdout
    for t in ("ou-rb-pbx-sync", "ou-rb-pbx-kick", "ou-rb-pbx-state", "ou-rb-pbx-issue"):
        assert t in rule
    assert "{1,40}" in rule      # uid.device instance names
    # the generated JavaScript regex must actually match the unit names the agent starts (a doubled backslash once made it match nothing: polkit "Access denied")
    import re as _re
    rx = _re.search(r"var m = /(.*)/\.exec", rule).group(1)
    assert _re.fullmatch(rx, "ou-rb-pbx-sync@lt1dora.service") and _re.fullmatch(rx, "ou-rb-pbx-issue@lt1dora.native.service")
    assert not _re.fullmatch(rx, "ou-rb-pbx-sync@lt1dora\\xservice") and not _re.fullmatch(rx, "ou-rb-pbx-sync@Lt1dora.service")


# ---- the PBX provisioner (blueprints/telephony/pbx/ou_pbx.py) ------------------------------------------------------------------------------------
@pytest.fixture()
def ou_pbx(tmp_path, monkeypatch):
    path = os.path.join(os.path.dirname(__file__), "..", "..", "blueprints", "telephony", "pbx", "ou_pbx.py")
    spec = importlib.util.spec_from_file_location("ou_pbx_under_test", path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    cfgf = tmp_path / "ou-pbx.json"
    cfgf.write_text(json.dumps({"realm": "ou-pbx", "domain": "pbx.test", "wss_url": "wss://pbx.test:8089/ws", "state_dir": str(tmp_path / "state"),
                                "ast_dir": str(tmp_path / "ast"), "voicemail_conf": str(tmp_path / "ast" / "voicemail_ou.conf"), "server_email": "vm@pbx.test"}))
    monkeypatch.setattr(m, "CONF", str(cfgf))
    m._cfg = None
    state = {"users": {"alice": {"uid": "alice", "ext": "1010", "mail": "a@x", "name": "Alice", "locked": False}},
             "contacts": ["alice.web;@abc"], "channels": ["PJSIP/alice.web-00000001"], "log": []}

    def fake_ast(*cmd):
        c = " ".join(cmd)
        state["log"].append(c)
        if c.startswith("database show registrar/contact"):
            return "".join(f"/registrar/contact/{k}      : {{}}\n" for k in state["contacts"])
        if c.startswith("database del registrar/contact"):
            k = c.split()[-1]
            state["contacts"] = [x for x in state["contacts"] if x != k]
            return ""
        if c.startswith("core show channels concise"):
            return "".join(f"{ch}!ou-internal!1003!2!Up!Dial!\n" for ch in state["channels"])
        if c.startswith("channel request hangup"):
            state["channels"] = [x for x in state["channels"] if x != c.split()[-1]]
        return ""

    monkeypatch.setattr(m, "ast", fake_ast)
    monkeypatch.setattr(m, "ldap_users", lambda: {k: dict(v) for k, v in state["users"].items()})
    return m, state


def test_provisioner_stores_only_a_digest_and_a_disabled_user_loses_everything(ou_pbx, tmp_path):
    m, st = ou_pbx
    cred = m.issue("alice", "web")
    assert len(cred["password"]) == 32 and cred["username"] == "alice.web"
    for dp, _, fns in os.walk(tmp_path):
        for f in fns:
            assert cred["password"] not in open(os.path.join(dp, f), errors="ignore").read(), f      # clear password is in no file
    pj = open(tmp_path / "ast" / "pjsip_ou.conf").read()
    assert "md5_cred=" + m.md5_cred("alice.web", "ou-pbx", cred["password"]) in pj
    assert m.user_report("alice", m.ldap_users())["endpoint_present"] is True
    # directory lock -> kick_user: endpoint + credentials purged, contact deleted, call hung up
    st["users"]["alice"]["locked"] = True
    rep = m.kick_user("alice")
    assert rep["known_to_pbx"] is False and rep["endpoint_present"] is False and rep["devices"] == []
    assert rep["contacts_removed"] == 1 and rep["channels_hung_up"] == 1 and rep["endpoint_removed"] is True
    assert st["contacts"] == [] and st["channels"] == []
    assert "alice.web" not in open(tmp_path / "ast" / "pjsip_ou.conf").read()
    # unlock: the old credential does NOT come back
    st["users"]["alice"]["locked"] = False
    m.sync()
    assert "alice.web" not in open(tmp_path / "ast" / "pjsip_ou.conf").read()
    assert m.user_report("alice", m.ldap_users())["known_to_pbx"] is True


def test_provisioner_user_without_extension_or_unknown_user_cannot_get_a_credential(ou_pbx):
    m, st = ou_pbx
    with pytest.raises(PermissionError):
        m.issue("nobody", "web")
    st["users"]["alice"]["locked"] = True
    with pytest.raises(PermissionError):
        m.issue("alice", "web")
