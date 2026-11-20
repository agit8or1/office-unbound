"""Console-issued enrollment token (owner 2026-11-20: "yes, show tokens in the console"): admin only, a fresh authenticator code,
only for an invited (never enrolled, not revoked) account, never for yourself, shown once, audited; the token enrolls the person."""
import json
import re
import time as _t

import pyotp
from sqlalchemy import text

from ics import auth
from .conftest import totp_for


def test_console_token_rules_and_enrollment(rt, client, mk_user, login, monkeypatch):
    admin = mk_user("boss", "admin")
    op = mk_user("op", "operator")
    with rt.session() as db:
        auth.create_invite(db, rt, "newadmin", "admin", actor="test")
    c, h = login(admin)
    oc, oh = login(op)
    url = "/api/v1/invitations/newadmin/token"
    assert oc.post(url, json={"totp_code": totp_for(op)}, headers=oh).status_code == 403           # admins only
    assert c.post(url, json={"totp_code": "000000"}, headers=h).status_code == 401                 # a fresh code is required
    now = [_t.time() + 600]
    monkeypatch.setattr(auth.time, "time", lambda: now[0])
    from ics import actions
    monkeypatch.setattr(actions, "single_admin", lambda rt_: True)   # the owner's install (ADR-0017); two-person mode: next test
    code = lambda: pyotp.TOTP(admin["secret"]).at(now[0])  # noqa: E731
    r = c.post(url, json={"totp_code": code()}, headers=h)
    assert r.status_code == 200, r.text
    tok = r.json()["token"]
    assert r.headers["cache-control"] == "no-store" and len(tok) >= 32
    for who, why in (("op", "enrolled before"), ("boss", "enrolled before"), ("nobody", "no such user")):
        now[0] += 30
        rr = c.post(f"/api/v1/invitations/{who}/token", json={"totp_code": code()}, headers=h)
        assert rr.status_code in (404, 409) and why in rr.text.lower(), rr.text
    # the listing still never returns a token; the token itself enrolls the person
    lst = c.get("/api/v1/invitations", headers=h).json()
    assert tok not in json.dumps(lst) and [i["token"] for i in lst if i["username"] == "newadmin"] == ["issued"]
    monkeypatch.setattr(auth.time, "time", _t.time)
    with rt.session() as db:
        uri = auth.enroll_begin(db, rt, "newadmin", tok, "correct horse battery", "127.0.0.1")
        assert re.search(r"secret=([A-Z2-7]+)", uri)
        ev = db.execute(text("SELECT actor_name, details FROM audit_events WHERE action = 'user.enrollment_issued' ORDER BY seq")).all()
    assert ev[-1].actor_name == "boss" and ev[-1].details["via"] == "console" and tok not in json.dumps([dict(e._mapping) for e in ev], default=str)


def test_console_token_refuses_takeover_paths(rt, client, mk_user, login, monkeypatch):
    """Security review 2026-11-21: host-recovered accounts, scoped admins, two-person mode for privileged roles, code consumed on refusal."""
    from ics import actions
    admin = mk_user("boss2", "admin")
    other = mk_user("admin2", "admin")
    with rt.session() as db:
        auth.issue_enrollment_token(db, rt, "admin2", actor="cli")          # host recovery: enrolled=false again
        auth.create_invite(db, rt, "newop", "operator", actor="test")
        auth.create_invite(db, rt, "newappr", "approver", actor="test")
    c, h = login(admin)
    now = [_t.time() + 900]
    monkeypatch.setattr(auth.time, "time", lambda: now[0])
    code = lambda: pyotp.TOTP(admin["secret"]).at(now[0])  # noqa: E731
    monkeypatch.setattr(actions, "single_admin", lambda rt_: True)
    r = c.post("/api/v1/invitations/admin2/token", json={"totp_code": code()}, headers=h)
    assert r.status_code == 409 and "enrolled before" in r.text
    # the refused request still used up the code
    assert c.post("/api/v1/invitations/newop/token", json={"totp_code": code()}, headers=h).status_code == 401
    now[0] += 30
    monkeypatch.setattr(actions, "single_admin", lambda rt_: False)          # two-person mode
    r = c.post("/api/v1/invitations/newappr/token", json={"totp_code": code()}, headers=h)
    assert r.status_code == 409 and "two-person" in r.text
    now[0] += 30
    assert c.post("/api/v1/invitations/newop/token", json={"totp_code": code()}, headers=h).status_code == 200   # operators still fine
    # a customer-scoped admin is refused
    from ics.auth import User
    u = User.__new__(User); u.id = admin["id"]; u.username = "boss2"; u.customer_ids = ["c-1"]
    with rt.session() as db:
        try:
            auth.issue_invitation_token(db, rt, "newop", actor=u)
            raise AssertionError("scoped admin accepted")
        except Exception as e:
            assert getattr(e, "status_code", None) == 403
