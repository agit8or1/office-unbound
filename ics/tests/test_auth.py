import pytest
from sqlalchemy import text

from .conftest import totp_for


def test_login_totp_session_cookie(client, mk_user, rt):
    u = mk_user("alice", "admin")
    r = client.post("/api/v1/auth/login", json={"username": "alice", "password": u["password"], "totp_code": totp_for(u)})
    assert r.status_code == 200
    sc = r.headers["set-cookie"].lower()
    assert "httponly" in sc and "secure" in sc and "samesite=strict" in sc
    assert client.get("/api/v1/auth/me").json()["username"] == "alice"
    with rt.session() as db:
        assert db.execute(text("SELECT count(*) FROM audit_events WHERE action='auth.login'")).scalar() == 1
        stored = db.execute(text("SELECT password_hash, totp_secret_enc FROM users")).first()
    assert stored.password_hash.startswith("$argon2id$") and u["secret"].encode() not in bytes(stored.totp_secret_enc)


def test_login_failures(client, mk_user, rt):
    u = mk_user("bob", "operator")
    for body in ({"password": "wrong password!!", "totp_code": totp_for(u)}, {"password": u["password"], "totp_code": "000000"},
                 {"password": u["password"], "totp_code": ""}):
        r = client.post("/api/v1/auth/login", json={"username": "bob", **body})
        assert r.status_code == 401 and r.json()["detail"] == "invalid credentials"
    assert client.post("/api/v1/auth/login", json={"username": "nobody", "password": "x" * 14, "totp_code": "123456"}).status_code == 401
    with rt.session() as db:
        assert db.execute(text("SELECT count(*) FROM audit_events WHERE action='auth.login_failed'")).scalar() == 4


def test_totp_replay_rejected(client, mk_user):
    u = mk_user("carol", "viewer")
    code = totp_for(u)
    body = {"username": "carol", "password": u["password"], "totp_code": code}
    assert client.post("/api/v1/auth/login", json=body).status_code == 200
    assert client.post("/api/v1/auth/login", json=body).status_code == 401


def test_rate_limit(client, mk_user):
    u = mk_user("dave", "viewer")
    codes = [client.post("/api/v1/auth/login", json={"username": "dave", "password": "bad bad bad bad", "totp_code": "111111"}).status_code
             for _ in range(7)]
    assert codes[:5] == [401] * 5 and codes[5:] == [429, 429]
    # even the correct credentials are backed off now (from this same IP)
    assert client.post("/api/v1/auth/login", json={"username": "dave", "password": u["password"], "totp_code": totp_for(u)}).status_code == 429


def test_unauthenticated_and_csrf(client, mk_user, login, rt):
    assert client.get("/api/v1/endpoints").status_code == 401
    u = mk_user("erin", "operator")
    c, h = login(u)
    body = {"action": "inventory.refresh", "params": {"endpoint_id": "00000000-0000-0000-0000-000000000000"}}
    assert c.post("/api/v1/plans", json=body).status_code == 403               # no CSRF header
    assert c.post("/api/v1/plans", json=body, headers={"X-CSRF-Token": "wrong"}).status_code == 403
    assert c.post("/api/v1/plans", json=body, headers=h).status_code == 404    # passes CSRF, endpoint absent
    assert c.get("/api/v1/endpoints").status_code == 200                       # GET needs no CSRF
    with rt.session() as db:
        assert db.execute(text("SELECT count(*) FROM audit_events WHERE action='auth.csrf_rejected'")).scalar() == 2


def test_logout_invalidates_session(client, mk_user, login):
    c, h = login(mk_user("fay", "viewer"))
    assert c.post("/api/v1/auth/logout", headers=h).status_code == 200
    c.cookies.clear()


def test_roles(client, mk_user, login):
    v, vh = login(mk_user("v", "viewer"))
    o, oh = login(mk_user("o", "operator"))
    a, ah = login(mk_user("a", "approver"))
    ad, adh = login(mk_user("ad", "admin"))
    assert v.get("/api/v1/endpoints").status_code == 200
    assert v.post("/api/v1/plans/preview", json={"blueprint_yaml": "x: 1"}, headers=vh).status_code == 403
    assert o.post("/api/v1/plans/preview", json={"blueprint_yaml": "x: 1"}, headers=oh).status_code == 200
    assert o.get("/api/v1/audit").status_code == 403 and a.get("/api/v1/audit").status_code == 200
    new = {"username": "newbie", "role": "viewer"}
    assert a.post("/api/v1/users", json=new, headers=ah).status_code == 403
    r = ad.post("/api/v1/users", json=new, headers=adh)
    assert r.status_code == 201 and r.json() == {"username": "newbie", "role": "viewer", "invite": True}
    assert ad.post("/api/v1/users", json=new, headers=adh).status_code == 409
