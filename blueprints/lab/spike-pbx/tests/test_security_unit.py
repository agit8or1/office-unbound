"""Security review 4 (M10, M11, L7) unit tests for the telephony spike: no Asterisk, LDAP or Keycloak needed.

Run (ICS host):  PYTHONPATH=<dir containing a jwt package> ICS_VENV/bin/python -m pytest -q blueprints/lab/spike-pbx/tests/test_security_unit.py
(needs fastapi + httpx + PyJWT + cryptography; ldap3 is stubbed. PyJWT alone may come from /usr/lib/python3/dist-packages/jwt via PYTHONPATH.)
"""
import importlib
import json
import os
import socket
import sys
import threading
import time
import types

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
PBX = os.path.join(HERE, "..", "pbx")
PHONE = os.path.join(HERE, "..", "phone")


@pytest.fixture()
def ou_pbx(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "ldap3", types.ModuleType("ldap3"))
    conf = tmp_path / "ou-pbx.json"
    conf.write_text(json.dumps({"ldap": {}, "realm": "ou-pbx", "domain": "pbx.test", "wss_url": "wss://pbx.test/ws", "state_dir": str(tmp_path / "st"),
                                "ast_dir": str(tmp_path / "ast"), "voicemail_conf": str(tmp_path / "ast" / "vm.conf"), "server_email": "vm@pbx.test"}))
    monkeypatch.setenv("OU_PBX_CONF", str(conf))
    monkeypatch.syspath_prepend(PBX)
    sys.modules.pop("ou_pbx", None)
    m = importlib.import_module("ou_pbx")
    m._cfg = None
    m.USERS = {"alice": {"uid": "alice", "ext": "1001", "mail": "a@x.test", "name": "Alice", "locked": False},
               "bob": {"uid": "bob", "ext": "1002", "mail": "b@x.test", "name": "Bob", "locked": False}}
    m.ldap_users = lambda: m.USERS
    m.CALLS = []
    m.ast = lambda *a: m.CALLS.append(("ast",) + a) or ""
    m.kick = lambda ep: m.CALLS.append(("kick", ep))
    yield m
    sys.modules.pop("ou_pbx", None)


def test_web_credential_expires_and_is_dropped_by_sync(ou_pbx):
    cred = ou_pbx.issue("alice", "web", 120)
    assert cred["expires_in"] == 120
    st = ou_pbx.load_state()
    assert st["devices"]["alice"]["web"]["expires"] > time.time()
    pj = open(os.path.join(ou_pbx.cfg()["ast_dir"], "pjsip_ou.conf")).read()
    assert "[alice.web]" in pj
    ou_pbx.CALLS.clear()
    st["devices"]["alice"]["web"]["expires"] = int(time.time()) - 1          # the session ended
    ou_pbx.save_state(st)
    res = ou_pbx.sync()
    assert "alice.web" not in res["endpoints"] and "alice.web" in res["removed"]
    assert "[alice.web]" not in open(os.path.join(ou_pbx.cfg()["ast_dir"], "pjsip_ou.conf")).read()
    assert ("kick", "alice.web") in ou_pbx.CALLS                              # live registration is removed, not left to time out
    assert "alice" not in ou_pbx.load_state()["devices"]


def test_rotation_kicks_the_previous_registration_but_first_issue_does_not(ou_pbx):
    ou_pbx.issue("alice", "web", 300)
    assert ("kick", "alice.web") not in ou_pbx.CALLS
    ou_pbx.issue("alice", "web", 300)
    assert ("kick", "alice.web") in ou_pbx.CALLS


def test_revoke_removes_credential_and_kicks(ou_pbx):
    ou_pbx.issue("alice", "web", 300)
    ou_pbx.CALLS.clear()
    ou_pbx.revoke("alice", "web")
    assert ("kick", "alice.web") in ou_pbx.CALLS and "alice" not in ou_pbx.load_state()["devices"]


def test_display_name_cannot_inject_voicemail_or_callerid_fields(ou_pbx):
    n = ou_pbx.safe_name('Eve, 1234;evil|x="y"\r\n[general]', "eve")
    assert not set(',;|="\r\n\\[]') & set(n) and n
    assert ou_pbx.safe_name(",;|", "eve") == "eve"


# ------------------------------------------------------------------ helper (M11)
@pytest.fixture()
def helper(ou_pbx, tmp_path, monkeypatch):
    import pwd
    me = pwd.getpwuid(os.getuid()).pw_name
    sock = str(tmp_path / "helper.sock")
    monkeypatch.setenv("OU_HELPER_SOCKET", sock)
    monkeypatch.setenv("OU_HELPER_PEER_USER", me)
    monkeypatch.setenv("OU_HELPER_MIN_ISSUE_INTERVAL", "0.3")
    sys.modules.pop("ou_pbx_helper", None)
    h = importlib.import_module("ou_pbx_helper")
    srv = h.make_server()
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    def call(req, raw=None):
        c = socket.socket(socket.AF_UNIX)
        c.settimeout(5)
        c.connect(sock)
        c.sendall(raw if raw is not None else json.dumps(req).encode() + b"\n")
        data = b""
        while not data.endswith(b"\n"):
            chunk = c.recv(4096)
            if not chunk:
                break
            data += chunk
        return json.loads(data)

    yield h, call, ou_pbx
    srv.shutdown()
    srv.server_close()
    sys.modules.pop("ou_pbx_helper", None)


def test_helper_only_offers_web_credentials_for_one_validated_uid(helper):
    h, call, ou_pbx = helper
    assert call({"op": "me", "uid": "alice"}) == {"extension": "1001"}
    r = call({"op": "issue", "uid": "alice", "ttl": 100000, "dev": "native", "device": "desk"})
    assert r["username"] == "alice.web" and r["expires_in"] == 3600                 # device kind cannot be chosen, ttl is clamped
    st = ou_pbx.load_state()["devices"]["alice"]
    assert list(st) == ["web"]
    time.sleep(0.4)
    assert call({"op": "issue", "uid": "alice", "ttl": 1})["expires_in"] == 60      # lower clamp
    for bad in ({"op": "issue", "uid": "../etc"}, {"op": "issue", "uid": "Alice"}, {"op": "issue", "uid": ["alice"]}, {"op": "originate", "uid": "alice"},
                {"op": "sync", "uid": "alice"}, {"op": "revoke"}, {"uid": "alice"}):
        assert "error" in call(bad), bad
    assert "error" in call(None, raw=b"not json\n") and "error" in call(None, raw=b"[1]\n")


def test_helper_rate_limits_issue_per_uid(helper):
    h, call, ou_pbx = helper
    assert "username" in call({"op": "issue", "uid": "bob", "ttl": 300})
    assert call({"op": "issue", "uid": "bob", "ttl": 300}) == {"error": "rate limited"}
    assert "username" in call({"op": "issue", "uid": "alice", "ttl": 300})        # other users unaffected


def test_helper_refuses_any_other_peer_uid(ou_pbx, tmp_path, monkeypatch):
    sock = str(tmp_path / "h2.sock")
    monkeypatch.setenv("OU_HELPER_SOCKET", sock)
    monkeypatch.setenv("OU_HELPER_PEER_USER", "nobody" if os.getuid() != 65534 else "root")
    sys.modules.pop("ou_pbx_helper", None)
    h = importlib.import_module("ou_pbx_helper")
    srv = h.make_server()
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    c = socket.socket(socket.AF_UNIX)
    c.settimeout(5)
    c.connect(sock)
    c.sendall(b'{"op": "issue", "uid": "alice"}\n')
    assert json.loads(c.makefile().readline()) == {"error": "forbidden"}
    assert "alice" not in ou_pbx.load_state()["devices"]
    srv.shutdown()


def test_web_app_has_no_privileged_imports_or_asterisk_access():
    src = open(os.path.join(PHONE, "phone_app.py")).read()
    assert "import ou_pbx" not in src and "/etc/asterisk" not in src and "asterisk" not in src.lower().replace("# ", "").split('"""')[2]
    inst = open(os.path.join(HERE, "..", "20-install-pbx.sh")).read()
    web = inst[inst.index("cat > /etc/systemd/system/ou-phone.service"):]
    web = web[:web.index("\nEOF")]
    assert "User=ou-phone" in web and "SupplementaryGroups" not in web and "ReadWritePaths" not in web and "InaccessiblePaths=/etc/asterisk" in web
    hlp = inst[inst.index("cat > /etc/systemd/system/ou-pbx-helper.service"):]
    assert "SupplementaryGroups=asterisk" in hlp[:hlp.index("\nEOF")]


# ------------------------------------------------------------------ web app (M10)
@pytest.fixture()
def app(tmp_path, monkeypatch):
    from cryptography.hazmat.primitives.asymmetric import rsa
    import jwt
    from fastapi.testclient import TestClient
    sec = tmp_path / "secret"
    sec.write_text("s3cret")
    monkeypatch.setenv("CLIENT_SECRET_FILE", str(sec))
    monkeypatch.setenv("STATIC_DIR", PHONE + "/static")
    monkeypatch.syspath_prepend(PHONE)
    sys.modules.pop("phone_app", None)
    pa = importlib.import_module("phone_app")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update(kid="k1", use="sig", alg="RS256")
    pa._disc.update(jwks_uri="https://kc/jwks", userinfo_endpoint="https://kc/userinfo", authorization_endpoint="https://kc/auth", token_endpoint="https://kc/tok")
    monkeypatch.setattr(pa.httpx, "get", lambda url, **k: types.SimpleNamespace(json=lambda: {"keys": [jwk]}, status_code=200))
    calls = []

    def fake_helper(op, uid, **kw):
        calls.append((op, uid, kw))
        return {"ok": True} if op == "revoke" else ({"extension": "1001"} if op == "me" else {"username": uid + ".web", "password": "x"})
    monkeypatch.setattr(pa, "helper", fake_helper)
    monkeypatch.setattr(pa, "validate", lambda s: True)
    pa.SESSIONS.clear()

    def logout_token(signer=key, **over):
        c = {"iss": pa.ISSUER, "aud": pa.CLIENT_ID, "iat": int(time.time()), "exp": int(time.time()) + 120, "jti": "j", "sub": "sub-alice",
             "events": {"http://schemas.openid.net/event/backchannel-logout": {}}}
        c.update(over)
        c = {k: v for k, v in c.items() if v is not None}
        return jwt.encode(c, signer, algorithm="RS256", headers={"kid": "k1"})

    def login(uid="alice", sub="sub-alice", ttl=1800):
        sid = "sid-" + uid
        pa.SESSIONS[sid] = {"access_token": "t", "sub": sub, "uid": uid, "csrf": "c", "exp": time.time() + ttl}
        cl = TestClient(pa.app, base_url="https://phone.ou-lab.internal")
        cl.cookies.set("ouphone", sid)
        return cl

    return types.SimpleNamespace(pa=pa, calls=calls, token=logout_token, login=login, other=other, client=TestClient(pa.app))


def test_credential_ttl_is_the_remaining_session_time_and_rate_limit_maps_to_429(app):
    cl = app.login(ttl=1800)
    r = cl.post("/api/credential", headers={"X-OU-CSRF": "c", "Origin": app.pa.PUBLIC_BASE})
    assert r.status_code == 200
    (op, uid, kw), = [c for c in app.calls if c[0] == "issue"]
    assert uid == "alice" and 1700 < kw["ttl"] <= 1800
    app.pa.helper = lambda *a, **k: {"error": "rate limited"}
    assert cl.post("/api/credential", headers={"X-OU-CSRF": "c", "Origin": app.pa.PUBLIC_BASE}).status_code == 429


def test_logout_revokes_the_sip_credential(app):
    cl = app.login()
    cl.get("/logout", follow_redirects=False)
    assert ("revoke", "alice", {}) in app.calls and not app.pa.SESSIONS


def test_backchannel_logout_ends_sessions_of_that_subject_and_revokes_sip(app):
    app.login("alice", "sub-alice")
    app.login("bob", "sub-bob")
    r = app.client.post("/backchannel-logout", data={"logout_token": app.token()})
    assert r.status_code == 200
    assert ("revoke", "alice", {}) in app.calls and not any(c[1] == "bob" for c in app.calls if c[0] == "revoke")
    assert list(app.pa.SESSIONS) == ["sid-bob"]


@pytest.mark.parametrize("case", ["wrong_key", "wrong_aud", "wrong_iss", "expired", "no_events", "nonce", "no_sub", "garbage", "alg_none"])
def test_backchannel_logout_rejects_forged_or_malformed_tokens(app, case):
    import jwt
    app.login("alice", "sub-alice")
    tok = {"wrong_key": lambda: app.token(signer=app.other), "wrong_aud": lambda: app.token(aud="someone-else"), "wrong_iss": lambda: app.token(iss="https://evil"),
           "expired": lambda: app.token(exp=int(time.time()) - 10), "no_events": lambda: app.token(events={}), "nonce": lambda: app.token(nonce="n"),
           "no_sub": lambda: app.token(sub=None), "garbage": lambda: "a.b.c",
           "alg_none": lambda: jwt.encode({"iss": app.pa.ISSUER, "aud": app.pa.CLIENT_ID, "sub": "sub-alice", "iat": 1, "exp": 4102444800,
                                           "events": {"http://schemas.openid.net/event/backchannel-logout": {}}}, None, algorithm="none")}[case]()
    r = app.client.post("/backchannel-logout", data={"logout_token": tok})
    assert r.status_code == 400
    assert list(app.pa.SESSIONS) == ["sid-alice"] and not [c for c in app.calls if c[0] == "revoke"]


def test_pending_and_sessions_are_bounded(app):
    pa = app.pa
    for i in range(pa.MAX_PENDING * 3):
        pa.PENDING["s%d" % i] = {"verifier": "v", "exp": time.time() + 600 + i}
        pa.prune()
    assert len(pa.PENDING) <= pa.MAX_PENDING
    for i in range(pa.MAX_SESSIONS + 50):
        pa.SESSIONS["x%d" % i] = {"exp": time.time() + 100 + i, "sub": "s", "uid": "u"}
        pa.prune()
    assert len(pa.SESSIONS) <= pa.MAX_SESSIONS
