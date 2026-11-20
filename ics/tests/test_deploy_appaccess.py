"""Open your apps (deploy/appaccess.py, GET /deployments/{slug}/access, POST /deployments/{slug}/admin-password)."""
import json

from sqlalchemy import text

from .conftest import totp_for
from ics.deploy import appaccess, configure

PLAN = {"input": {"domain": "e2e-gw1.example"},
        "dns": [{"name": "auth.e2e-gw1.example", "type": "A", "value": "vm:c-x-id", "component": "edge"},
                {"name": "autodiscover.e2e-gw1.example", "type": "CNAME", "value": "mail.e2e-gw1.example", "component": "groupware"},
                {"name": "cloud.e2e-gw1.example", "type": "A", "value": "vm:c-x-id", "component": "files"},
                {"name": "e2e-gw1.example", "type": "MX", "value": "10 mail.e2e-gw1.example", "component": "groupware"},
                {"name": "e2e-gw1.example", "type": "TXT", "value": "v=spf1 mx -all", "component": "groupware"},
                {"name": "mail.e2e-gw1.example", "type": "A", "value": "vm:c-x-mail", "component": "groupware"},
                {"name": "office.e2e-gw1.example", "type": "A", "value": "vm:c-x-id", "component": "office"}]}
PORTAL = {"name": "portal.e2e-gw1.example", "type": "A", "value": "vm:c-x-id", "component": "portal"}


def test_the_portal_is_listed_first():
    out = appaccess.build({**PLAN, "dns": [*PLAN["dns"], PORTAL]}, ADDR)
    assert out["apps"][0]["url"] == "https://portal.e2e-gw1.example/" and "portal.e2e-gw1.example" in out["hosts"][0]["names"]
ADDR = {"c-x-id": "192.168.22.214", "c-x-mail": "192.168.22.215"}


def test_apps_hosts_and_mail_settings_come_from_the_plan():
    out = appaccess.build(PLAN, ADDR)
    assert [(a["title"], a["url"]) for a in out["apps"]] == [
        ("Files", "https://cloud.e2e-gw1.example/"), ("Webmail", "https://mail.e2e-gw1.example/web/"),
        ("Account", "https://auth.e2e-gw1.example/realms/ou/account/")]
    assert out["hosts"] == [{"address": "192.168.22.214", "names": ["auth.e2e-gw1.example", "cloud.e2e-gw1.example", "office.e2e-gw1.example"]},
                            {"address": "192.168.22.215", "names": ["autodiscover.e2e-gw1.example", "mail.e2e-gw1.example"]}]
    assert out["clients"]["imap"] == {"host": "mail.e2e-gw1.example", "port": 993, "security": "SSL/TLS"}
    assert out["clients"]["smtp"]["port"] == 587 and out["admin"] == {"username": "ou-admin", "email": "ou-admin@e2e-gw1.example"}


def test_a_vm_without_an_address_yet_is_left_out():
    out = appaccess.build(PLAN, {"c-x-id": "10.0.0.1"})
    assert all("mail" not in n for h in out["hosts"] for n in h["names"]) and out["clients"] is None
    assert [a["id"] for a in out["apps"]] == ["files", "edge"]


def _deployment(rt, slug="e2e-gw1"):
    with rt.session() as db:
        did = db.execute(text("INSERT INTO deployments (slug, customer_id, profile, profile_version, status, desired_spec) "
                              "VALUES (:s, 'c-000000000000', 'custom', '1', 'active', '{}'::jsonb) RETURNING id"), {"s": slug}).scalar()
        db.commit()
    return str(did)


def test_reveal_needs_admin_a_fresh_code_and_is_audited(rt, client, mk_user, login, monkeypatch):
    admin = mk_user("boss", "admin")
    op = mk_user("op", "operator")
    did = _deployment(rt)
    pw = configure.secret(rt, did, "admin-password")
    c, h = login(admin)
    oc, oh = login(op)
    assert oc.post("/api/v1/deployments/e2e-gw1/admin-password", json={"totp_code": totp_for(op)}, headers=oh).status_code == 403
    assert oc.get("/api/v1/deployments/e2e-gw1/access").status_code == 403
    r = c.post("/api/v1/deployments/e2e-gw1/admin-password", json={"totp_code": "000000"}, headers=h)
    assert r.status_code == 401 and pw not in r.text
    import pyotp
    import time as _t
    from ics import auth
    now = [_t.time() + 600]                      # a server clock past every code the fixtures used
    monkeypatch.setattr(auth.time, "time", lambda: now[0])
    code = pyotp.TOTP(admin["secret"]).at(now[0])
    r = c.post("/api/v1/deployments/e2e-gw1/admin-password", json={"totp_code": code}, headers=h)
    assert r.status_code == 200, r.text
    assert r.json() == {"username": "ou-admin", "password": pw} and r.headers["cache-control"] == "no-store"
    # the same code again is a replay
    assert c.post("/api/v1/deployments/e2e-gw1/admin-password", json={"totp_code": code}, headers=h).status_code == 401
    now[0] += 30
    assert c.post("/api/v1/deployments/e2e-gw1/admin-password", json={"totp_code": pyotp.TOTP(admin["secret"]).at(now[0])}).status_code == 403  # CSRF
    with rt.session() as db:
        ev = db.execute(text("SELECT action, details FROM audit_events WHERE action LIKE 'deployment.admin_password%' OR action = 'auth.step_up_failed' "
                             "ORDER BY seq")).all()
        log = json.dumps([dict(e._mapping) for e in ev], default=str)
    assert [e.action for e in ev] == ["auth.step_up_failed", "deployment.admin_password_revealed", "auth.step_up_failed"]
    assert pw not in log


def test_access_lists_nothing_before_the_deployment_is_created(rt, client, mk_user, login):
    admin = mk_user("boss", "admin")
    _deployment(rt, "e2e-new")
    c, _ = login(admin)
    r = c.get("/api/v1/deployments/e2e-new/access")
    assert r.status_code == 200 and r.json()["ready"] is False and r.json()["apps"] == []


def test_dashboard_shows_the_portal_url_and_each_apps_status_from_its_own_checks(rt, client, mk_user, login, monkeypatch):
    """Owner 2026-11-20: "dashboard should show url for access, all apps status"."""
    v = mk_user("viewer1", "viewer")
    did = _deployment(rt, "e2e-gw1")
    plan = {**PLAN, "dns": [*PLAN["dns"], PORTAL],
            "checks": [{"name": "c-old", "component": "edge"}, {"name": "c-portal", "component": "portal"}, {"name": "c-kc", "component": "identity"},
                       {"name": "c-oc", "component": "files"}, {"name": "c-smtp", "component": "groupware"}]}
    monkeypatch.setattr(appaccess, "_applied_plan", lambda db, d: plan)
    monkeypatch.setattr(appaccess, "_addresses", lambda db, d: ADDR)
    with rt.session() as db:
        uid = db.execute(text("SELECT id FROM users WHERE username = 'viewer1'")).scalar()
        db.execute(text("INSERT INTO checks (name, kind, config, interval_seconds, state, created_by, deployment_id, enabled) "
                        "VALUES ('c-old', 'http', '{}'::jsonb, 60, 'critical', :u, :d, false)"), {"u": uid, "d": did})
        for n, st in (("c-portal", "ok"), ("c-kc", "ok"), ("c-oc", "critical"), ("c-smtp", "ok")):
            db.execute(text("INSERT INTO checks (name, kind, config, interval_seconds, state, created_by, deployment_id) "
                            "VALUES (:n, 'http', '{}'::jsonb, 60, :s, :u, :d)"), {"n": n, "s": st, "u": uid, "d": did})
        db.commit()
    c, _ = login(v)
    r = c.get("/api/v1/dashboard/apps")
    assert r.status_code == 200, r.text
    d = r.json()[0]
    assert d["portal"] == "https://portal.e2e-gw1.example/" and d["health"] == "critical"
    st = {a["id"]: a["status"] for a in d["apps"]}
    assert st["portal"] == "ok" and st["files"] == "critical" and st["groupware"] == "ok"
    svc = {s["id"]: s for s in d["services"]}
    assert svc["files"]["failing"] == ["c-oc"] and svc["identity"]["status"] == "ok"
