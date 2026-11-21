"""Admin area tests: role gating, token/credential forwarding to the ICS tenant API, CSRF, error mapping, one-time link handling, welcome flow, branding.
The ICS is a mock transport; shapes follow ics/ics/tenant_admin/api.py (which has its own authz tests in ics/tests/test_tenant_admin.py)."""
import dataclasses
import json
import re
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_portal import BASE, CFG, Mock, finish  # noqa: E402
from app.main import create_app  # noqa: E402

ICS = "https://ics.test"
KEY = "tsk_abcdefghijkl." + "A" * 43
ACFG = dataclasses.replace(CFG, ics_url=ICS, ics_key=KEY)

USERS = [
    {"uid": "anna", "display_name": "Anna Meyer", "mail": "anna@example.test", "state": "active", "groups": ["mail-users"], "apps": {"mail": True, "files": False},
     "created_at": "2026-11-10T10:00:00+00:00", "disabled_at": None, "is_you": False},
    {"uid": "old", "display_name": "Olga Old", "mail": "old@example.test", "state": "disabled", "groups": [], "apps": {"mail": False, "files": False},
     "created_at": "2026-10-01T10:00:00+00:00", "disabled_at": "2026-11-01T10:00:00+00:00", "is_you": False},
]
APPS = {"apps": {"mail": {"label": "Mail, calendar and contacts", "enabled": True, "group": "mail-users"},
                 "files": {"label": "Files and documents", "enabled": True, "group": "files-users"}}}


def req(state="working", kind="user.create", **kw):
    return {"id": "11111111-1111-1111-1111-111111111111", "kind": kind, "target_uid": "newbie", "summary": "Add Newbie (newbie)", "state": state,
            "state_label": {"working": "In progress", "done": "Done", "waiting_admin": "Waiting for a second administrator"}.get(state, state),
            "approval_mode": "auto", "requested_by": "boss", "requested_by_sub": "s1", "decided_by": None, "created_at": "2026-11-15T10:00:00+00:00",
            "risk": "normal", "can_decide": False, "error": None, **kw}


class IcsMock(Mock):
    def __init__(self):
        super().__init__()
        self.roles = ["org-admin", "opencloudUser"]
        self.ics_calls = []
        self.answers = {}      # (method, path) -> (status, json) overrides
        self.branding = {"display_name": "Acme Brothers", "accent": "#1a5fb4", "has_logo": True, "apps": {"mail": True, "files": False}, "app_labels": {}}
        self.enroll = (200, {"ok": True})

    def id_token(self, **over):
        return super().id_token(roles=self.roles, **over)

    def handler(self, r: httpx.Request) -> httpx.Response:
        if not str(r.url).startswith(ICS):
            return super().handler(r)
        p = r.url.path
        body = json.loads(r.content) if r.content and r.headers.get("content-type", "").startswith("application/json") else r.content
        self.ics_calls.append((r.method, p, dict(r.headers), body))
        if p == "/api/v1/identity/enroll":
            return httpx.Response(self.enroll[0], json=self.enroll[1])
        key = (r.method, p.removeprefix("/api/v1/tenant"))
        if key in self.answers:
            st, js = self.answers[key]
            return httpx.Response(st, json=js)
        k = key[1]
        if k == "/branding":
            return httpx.Response(200, json=self.branding)
        if k == "/branding/logo":
            return httpx.Response(200, content=b"<svg xmlns='http://www.w3.org/2000/svg'/>", headers={"content-type": "image/svg+xml"})
        if r.method == "GET" and k == "/me":
            return httpx.Response(200, json={"customer": "Acme Brothers Ltd", "user": {"username": "bob"}, "domain": "example.test", "users": {"active": 5, "disabled": 1},
                                             "policy": {"self_service_auto": True, "destructive_approval": "second_admin"}, "pending": 0, "planned": ["Creating groups"],
                                             "features": {"aliases": True, "shared": True, "mail_quota": True, "files_quota": True}})
        if k == "/users" and r.method == "GET":
            return httpx.Response(200, json=USERS)
        if k.startswith("/users/") and r.method == "GET":
            u = next((x for x in USERS if x["uid"] == k.split("/")[2]), None)
            return httpx.Response(200, json={**u, "history": []}) if u else httpx.Response(404, json={"detail": "user not found"})
        if k == "/apps":
            return httpx.Response(200, json=APPS)
        if k == "/requests":
            return httpx.Response(200, json=[req("waiting_admin", can_decide=True, summary="Delete Olga (old)")])
        if k.startswith("/requests/") and r.method == "GET":
            return httpx.Response(200, json=req("done"))
        if r.method == "POST" and k == "/users":
            return httpx.Response(202, json={"id": "11111111-1111-1111-1111-111111111111", "state": "working"})
        if r.method == "POST" and k.endswith("/enrollment"):
            return httpx.Response(200, json={"token": "ONE-TIME-TOKEN", "uid": "newbie", "stack": "acme", "expires_at": "2026-11-16T10:00:00+00:00"})
        if r.method == "POST":
            return httpx.Response(202 if "/users/" in k else 200, json={"id": "11111111-1111-1111-1111-111111111111"})
        if k == "/domains":
            d = {"domains": [{"name": "example.test", "primary": True}], "managed_by": "Your service provider adds or removes domains."}
            if "check" in r.url.params:
                d["dns"] = {"example.test": [{"key": "spf", "title": "Sender policy (SPF)", "name": "example.test", "type": "TXT", "expected": "v=spf1 mx -all", "found": [], "status": "missing", "how": "Add one TXT record."}]}
            return httpx.Response(200, json=d)
        if k == "/aliases":
            return httpx.Response(200, json={"domains": ["example.test", "alt.test"], "max_aliases": 20, "users": [
                {"uid": "anna", "display_name": "Anna Meyer", "mail": "anna@example.test", "aliases": ["sales@example.test"]}]})
        if k == "/shared" and r.method == "GET":
            return httpx.Response(200, json={"domain": "example.test", "kinds": [{"key": "full_access", "label": "full access"}, {"key": "send_as", "label": "send as"}, {"key": "send_on_behalf", "label": "send on behalf"}],
                                             "people": [{"uid": "anna", "display_name": "Anna Meyer"}, {"uid": "bob", "display_name": "Bob B"}],
                                             "mailboxes": [{"name": "support", "mail": "support@example.test", "display_name": "Support", "created_at": "2026-11-10T10:00:00+00:00",
                                                            "grants": {"full_access": ["anna"], "send_as": [], "send_on_behalf": []}}]})
        if k == "/quotas":
            return httpx.Response(200, json={"available": {"mail": True, "files": True}, "files_quota_supported": True, "users": [
                {"uid": "anna", "display_name": "Anna Meyer", "has_mailbox": True, "mail": {"used_bytes": 95 * 1048576, "limit_kb": 102400, "send_kb": 102400, "receive_kb": 102400},
                 "files": {"used_bytes": 5 * 1048576, "limit_bytes": 1073741824}}]})
        if k == "/groups":
            return httpx.Response(200, json=[{"name": "mail-users", "label": "Mail, calendar and contacts", "members": 4}])
        return httpx.Response(404, json={"detail": "nothing"})


@pytest.fixture()
def env():
    m = IcsMock()
    app = create_app(ACFG, transport=httpx.MockTransport(m.handler))
    with TestClient(app, base_url=BASE) as c:
        c.follow_redirects = False
        yield c, m, app


def signin(c, m):
    r = c.get("/login?next=/")
    q = parse_qs(urlparse(r.headers["location"]).query)
    m.nonce = q["nonce"][0]
    assert finish(c, q).status_code == 303


def csrf(c):
    return re.search(r'name="csrf" value="([^"]+)"', c.get("/admin/users/new").text).group(1)


def ics_writes(m):
    return [x for x in m.ics_calls if x[0] != "GET" and "identity/enroll" not in x[1]]


def test_not_offered_without_ics_config_and_to_non_admins():
    m = IcsMock()
    with TestClient(create_app(CFG, transport=httpx.MockTransport(m.handler)), base_url=BASE) as c:   # no ics_url
        c.follow_redirects = False
        signin(c, m)
        assert c.get("/admin").status_code == 404 and ">Admin<" not in c.get("/").text
    m = IcsMock()
    m.roles = ["opencloudUser"]
    with TestClient(create_app(ACFG, transport=httpx.MockTransport(m.handler)), base_url=BASE) as c:
        c.follow_redirects = False
        signin(c, m)
        home = c.get("/").text
        assert ">Admin<" not in home and "/admin" not in home
        for path in ("/admin", "/admin/users", "/admin/users/new", "/admin/branding", "/admin/domains", "/admin/requests", "/admin/groups", "/admin/users/anna"):
            assert c.get(path).status_code == 404, path
        for path in ("/admin/users/new", "/admin/apps", "/admin/branding", "/admin/users/anna/do/delete", "/admin/requests/x/decide", "/admin/requests/x/link"):
            assert c.post(path, data={"csrf": "x"}).status_code == 404, path
        assert [x for x in m.ics_calls if "tenant/users" in x[1] or "tenant/me" in x[1]] == []     # nothing about people was ever asked
    # unauthenticated: sent to sign in
    with TestClient(create_app(ACFG, transport=httpx.MockTransport(IcsMock().handler)), base_url=BASE) as c:
        c.follow_redirects = False
        assert c.get("/admin").headers["location"].startswith("/login")


def test_admin_pages_render_and_forward_both_proofs(env):
    c, m, _ = env
    signin(c, m)
    assert ">Admin<" in c.get("/").text
    for path, needle in (("/admin", "Acme Brothers Ltd"), ("/admin/users", "Anna Meyer"), ("/admin/users/anna", "Anna Meyer"), ("/admin/users/new", "Invite someone"),
                         ("/admin/groups", "Groups"), ("/admin/domains", "Check my DNS now"), ("/admin/domains?check=1", "Missing"), ("/admin/branding", "Look and feel"),
                         ("/admin/requests", "Delete Olga"), ("/admin/requests/11111111-1111-1111-1111-111111111111", "Done")):
        r = c.get(path)
        assert r.status_code == 200 and needle in r.text, (path, r.status_code)
        low = r.text.lower()
        assert "<script" not in low and " style=" not in low and not re.search(r"\son[a-z]+=", low), path        # strict CSP: no script, no inline style/handlers
    sent = [x for x in m.ics_calls if x[1].endswith("/tenant/users") and x[0] == "GET"][0]
    assert sent[2]["x-ou-tenant-key"] == KEY and sent[2]["x-ou-user-token"] == "AT1"          # service credential + the admin's own token
    assert "Planned" not in c.get("/admin/users/anna").text and "Planned" in c.get("/admin").text   # only what is really unavailable stays labelled
    q = c.get("/admin/users?q=olga").text
    assert "Olga Old" in q and "Anna Meyer" not in q
    assert "Anna Meyer" not in c.get("/admin/users?show=disabled").text


def test_state_changes_need_csrf_and_forward_choices(env):
    c, m, _ = env
    signin(c, m)
    tok = csrf(c)
    assert c.post("/admin/users/new", data={"name": "New Person", "uid": "newbie", "app_mail": "on"}).status_code == 403
    assert c.post("/admin/users/new", data={"csrf": "wrong", "name": "New Person"}).status_code == 403
    assert ics_writes(m) == []
    r = c.post("/admin/users/new", data={"csrf": tok, "name": "New Person", "uid": "newbie", "app_mail": "on"})
    assert r.status_code == 303 and r.headers["location"].endswith("11111111-1111-1111-1111-111111111111")
    assert ics_writes(m)[-1][3] == {"uid": "newbie", "display_name": "New Person", "apps": {"mail": True, "files": False}}
    r = c.post("/admin/users/new", data={"csrf": tok, "name": "Bad Name", "uid": "Bad Uid!"})
    assert r.status_code == 422 and "user name" in r.text
    assert c.post("/admin/users/new", data={"csrf": tok, "name": "Anna Meyer"}).status_code == 303          # uid suggested: anna.meyer
    assert ics_writes(m)[-1][3]["uid"] == "anna.meyer"
    for what, path, body in (("disable", "disable", {"reason": ""}), ("delete", "delete", {"reason": "removed by an administrator"}), ("enable", "enable", {"reason": ""}),
                             ("reset-password", "reset", {"what": "password"}), ("reset-mfa", "reset", {"what": "mfa"})):
        assert "form" in c.get(f"/admin/users/anna/do/{what}").text
        r = c.post(f"/admin/users/anna/do/{what}", data={"csrf": tok})
        assert r.status_code == 303
        w = ics_writes(m)[-1]
        assert w[1].endswith(f"/users/anna/{path}") and w[3] == body, w
    assert c.get("/admin/users/anna/do/launch").status_code == 404
    r = c.post("/admin/users/anna/apps", data={"csrf": tok, "app_mail": "on", "app_files": "on"})            # files switched on
    assert r.status_code == 303 and ics_writes(m)[-1][3] == {"add": ["files-users"], "remove": []}
    assert c.post("/admin/users/anna/apps", data={"csrf": tok, "app_mail": "on"}).headers["location"].endswith("nochange")
    assert c.post("/admin/requests/x/decide", data={"csrf": tok, "decision": "approve"}).status_code == 303
    assert ics_writes(m)[-1][1].endswith("/requests/x/approve")


def test_progress_page_and_one_time_link(env):
    c, m, _ = env
    signin(c, m)
    tok = csrf(c)
    rid = "11111111-1111-1111-1111-111111111111"
    m.answers[("GET", f"/requests/{rid}")] = (200, req("working"))
    p = c.get(f"/admin/requests/{rid}").text
    assert 'http-equiv="refresh"' in p and "being carried out" in p
    m.answers[("GET", f"/requests/{rid}")] = (200, req("done"))
    p = c.get(f"/admin/requests/{rid}").text
    assert "Create the sign-up link" in p and "ONE-TIME-TOKEN" not in p and "refresh" not in p
    r = c.post(f"/admin/requests/{rid}/link", data={"csrf": tok})
    assert r.status_code == 200 and "no-store" in r.headers["cache-control"]
    link = re.search(r'value="(https://portal\.test/welcome\?[^"]+)"', r.text).group(1).replace("&amp;", "&")
    q = parse_qs(urlparse(link).query)
    assert q == {"s": ["acme"], "u": ["newbie"], "t": ["ONE-TIME-TOKEN"]}
    assert "does not e-mail" in r.text or "do not e-mail" in r.text
    assert c.post(f"/admin/requests/{rid}/link").status_code == 403                                     # CSRF applies
    m.answers[("GET", f"/requests/{rid}")] = (200, req("done", kind="user.disable"))
    assert "sign-up link" not in c.get(f"/admin/requests/{rid}").text
    m.answers[("GET", f"/requests/{rid}")] = (200, req("waiting_admin", can_decide=True))
    t = c.get(f"/admin/requests/{rid}").text
    assert "Confirm this change" in t and "Decline" in t
    m.answers[("GET", f"/requests/{rid}")] = (200, req("waiting_admin", can_decide=False))
    assert "Confirm this change" not in c.get(f"/admin/requests/{rid}").text


def test_ics_errors_become_plain_language(env):
    c, m, _ = env
    signin(c, m)
    m.answers[("GET", "/users")] = (403, {"detail": "not authorised"})
    r = c.get("/admin/users")
    assert r.status_code == 400 and "could not be confirmed" in r.text and "not authorised" not in r.text
    m.answers[("GET", "/users")] = (502, {"detail": "boom"})
    r = c.get("/admin/users")
    assert r.status_code == 503 and "not available" in r.text and "boom" not in r.text
    tok = csrf(c)
    m.answers[("POST", "/users")] = (409, {"detail": "uid already exists in this stack"})
    r = c.post("/admin/users/new", data={"csrf": tok, "name": "Dup", "uid": "anna"})
    assert r.status_code == 422 and "already exists" in r.text
    m.answers[("POST", "/users/anna/disable")] = (409, {"detail": "You cannot disable your own account. Ask another administrator."})
    assert "cannot disable your own account" in c.post("/admin/users/anna/do/disable", data={"csrf": tok}).text
    assert "not found" in c.get("/admin/users/nobody").text.lower()


def test_welcome_flow_relays_password_once_and_never_echoes_it(env):
    c, m, _ = env
    r = c.get("/welcome", params={"s": "acme", "u": "newbie", "t": "TOK"})                 # public page: no sign-in needed
    assert r.status_code == 200 and r.headers["referrer-policy"] == "no-referrer" and "no-store" in r.headers["cache-control"] and 'name="t" value="TOK"' in r.text
    assert c.get("/welcome").status_code == 400
    pw = "correct horse battery staple"
    assert "not the same" in c.post("/welcome", data={"s": "acme", "u": "newbie", "t": "TOK", "password": pw, "again": pw + "x"}).text
    assert [x for x in m.ics_calls if "enroll" in x[1]] == []
    r = c.post("/welcome", data={"s": "acme", "u": "newbie", "t": "TOK", "password": pw, "again": pw})
    assert r.status_code == 200 and "all set" in r.text and pw not in r.text
    assert [x for x in m.ics_calls if "enroll" in x[1]][-1][3] == {"stack": "acme", "uid": "newbie", "token": "TOK", "password": pw}
    m.enroll = (403, {"detail": "invalid or expired enrollment token"})
    r = c.post("/welcome", data={"s": "acme", "u": "newbie", "t": "TOK", "password": pw, "again": pw})
    assert r.status_code == 403 and "no longer works" in r.text and pw not in r.text
    m.enroll = (422, {"detail": "password is too guessable"})
    r = c.post("/welcome", data={"s": "acme", "u": "newbie", "t": "TOK", "password": pw, "again": pw})
    assert r.status_code == 422 and "too guessable" in r.text and pw not in r.text
    assert c.post("/welcome", data={"s": "a", "u": "b", "t": "c", "password": pw, "again": pw}, headers={"Origin": "https://evil.test"}).status_code == 403


def test_branding_is_applied_safely(env):
    c, m, _ = env
    css = c.get("/branding.css")
    assert css.status_code == 200 and "--accent:#1a5fb4" in css.text and css.headers["content-type"].startswith("text/css")
    m.branding = {**m.branding, "accent": "red;}body{display:none", "display_name": "<b>Evil</b>"}
    c.app.state.state["ics"].forget_branding()
    assert c.get("/branding.css").text == ""                                       # anything that is not #rrggbb is dropped
    assert "<b>Evil</b>" not in c.get("/about").text and "&lt;b&gt;Evil" in c.get("/about").text    # escaped
    m.branding = {**m.branding, "accent": "#1a5fb4", "display_name": "Acme Brothers"}
    c.app.state.state["ics"].forget_branding()
    land = c.get("/about").text                                                     # signed-out pages carry the branding
    assert "/branding.css" in land and "Acme Brothers" in land and 'src="/branding/logo"' in land
    lg = c.get("/branding/logo")
    assert lg.headers["content-type"] == "image/svg+xml" and "sandbox" in lg.headers["content-security-policy"]
    signin(c, m)
    home = c.get("/").text                                                          # org turned Files off: the tile is gone, Mail stays
    assert 'data-app="mail"' in home and 'data-app="files"' not in home
    tok = csrf(c)
    m.answers[("PUT", "/branding")] = (422, {"detail": "That colour is too light: white text on buttons would be hard to read. Pick a darker shade."})
    r = c.post("/admin/branding", data={"csrf": tok, "display_name": "X", "accent": "#ffee00"})
    assert r.status_code == 422 and "too light" in r.text
    m.answers.pop(("PUT", "/branding"))
    r = c.post("/admin/branding", data={"csrf": tok, "display_name": "X", "accent": "#112233"}, files={"logo": ("l.png", b"\x89PNG\r\n\x1a\nxx", "image/png")})
    assert r.status_code == 303
    puts = [x for x in ics_writes(m) if x[0] == "PUT"][-2:]
    assert puts[0][3] == {"display_name": "X", "accent": "#112233"} and puts[1][1].endswith("/branding/logo") and puts[1][3].startswith(b"\x89PNG")
    assert c.post("/admin/apps", data={"csrf": tok, "app_mail": "on"}).status_code == 303
    assert [x for x in ics_writes(m) if x[1].endswith("/tenant/apps")][-1][3] == {"apps": {"mail": True, "files": False}}


def test_mailbox_admin_pages_and_forms(env):
    c, m, _ = env
    signin(c, m)
    for path, needle in (("/admin/addresses", "sales@example.test"), ("/admin/shared", "Support"), ("/admin/shared/support", "Anna Meyer"), ("/admin/storage", "95.0 MB of 100.0 MB")):
        r = c.get(path)
        assert r.status_code == 200 and needle in r.text, (path, r.status_code)
        low = r.text.lower()
        assert "<script" not in low and " style=" not in low and not re.search(r"\son[a-z]+=", low), path
        assert "Planned" not in r.text
    assert 'aria-label="Mailbox of Anna Meyer: 95 percent used"' in c.get("/admin/storage").text and 'class="usage full"' in c.get("/admin/storage").text
    assert c.get("/admin/shared/nothere").status_code == 404
    tok = csrf(c)
    # CSRF on every change
    for path in ("/admin/addresses/anna", "/admin/shared", "/admin/shared/support/grant", "/admin/shared/support/delete", "/admin/storage/anna"):
        assert c.post(path, data={"local": "x"}).status_code == 403, path
    assert ics_writes(m) == []
    r = c.post("/admin/addresses/anna", data={"csrf": tok, "local": "Info", "domain": "alt.test", "remove": "sales@example.test"})
    assert r.status_code == 303 and ics_writes(m)[-1][1].endswith("/users/anna/aliases") and ics_writes(m)[-1][3] == {"add": ["info@alt.test"], "remove": ["sales@example.test"]}
    assert c.post("/admin/addresses/anna", data={"csrf": tok, "local": "no good", "domain": "alt.test"}).headers["location"].endswith("badaddress")
    assert c.post("/admin/addresses/anna", data={"csrf": tok}).headers["location"].endswith("nochange")
    r = c.post("/admin/shared", data={"csrf": tok, "name": "Billing", "display_name": "Billing team"})
    assert r.status_code == 303 and ics_writes(m)[-1][3] == {"name": "billing", "display_name": "Billing team"}
    assert c.post("/admin/shared", data={"csrf": tok, "name": "x y", "display_name": "n"}).status_code == 422
    assert c.post("/admin/shared/support/grant", data={"csrf": tok, "uid": "bob", "kind": "send_as"}).status_code == 303
    assert ics_writes(m)[-1][1].endswith("/shared/support/grant") and ics_writes(m)[-1][3] == {"uid": "bob", "kind": "send_as"}
    assert c.post("/admin/shared/support/revoke", data={"csrf": tok, "uid": "anna", "kind": "full_access"}).status_code == 303
    assert ics_writes(m)[-1][1].endswith("/shared/support/revoke")
    assert c.post("/admin/shared/support/delete", data={"csrf": tok, "reason": "gone"}).status_code == 303 and ics_writes(m)[-1][3] == {"reason": "gone"}
    assert c.post("/admin/shared/support/explode", data={"csrf": tok}).status_code == 404
    m.answers[("POST", "/shared/support/grant")] = (422, {"detail": "this person is not active or has no mailbox"})
    r = c.post("/admin/shared/support/grant", data={"csrf": tok, "uid": "bob", "kind": "send_as"})
    assert r.status_code == 422 and "no mailbox" in r.text
    n = len(ics_writes(m))
    assert c.post("/admin/storage/anna", data={"csrf": tok, "mail_mb": "200", "files_mb": "0"}).status_code == 303
    w = ics_writes(m)[n:]
    assert [x[1].rsplit("/tenant", 1)[1] for x in w] == ["/users/anna/quota/mail", "/users/anna/quota/files"] and [x[3] for x in w] == [{"limit_mb": 200}, {"quota_mb": None}]
    assert c.post("/admin/storage/anna", data={"csrf": tok, "mail_mb": "12x"}).headers["location"].endswith("badnumber")
    assert c.post("/admin/storage/anna", data={"csrf": tok}).headers["location"].endswith("nochange")
    assert len(ics_writes(m)) == n + 2


def test_mailbox_admin_pages_are_admin_only(env):
    c, m, _ = env
    m.roles = ["opencloudUser"]
    signin(c, m)
    for path in ("/admin/addresses", "/admin/shared", "/admin/shared/support", "/admin/storage"):
        assert c.get(path).status_code == 404, path
    for path in ("/admin/addresses/anna", "/admin/shared", "/admin/shared/support/grant", "/admin/storage/anna"):
        assert c.post(path, data={"csrf": "x"}).status_code == 404, path


def test_org_branding_for_the_other_apps_is_public_cross_origin_and_strict(env):
    """/brand/org.css + /brand/logo: what the sign-in pages, Files/Docs and webmail skins @import (ics/ics/deploy/brand.py)."""
    c, m, _ = env
    r = c.get("/brand/org.css")                                                     # signed out: the apps' pages load it for anyone
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/css") and r.headers["cache-control"] == "no-cache"
    assert r.headers["cross-origin-resource-policy"] == "cross-origin"              # cloud./mail./auth. are other origins
    assert r.text.startswith(":root{--ou-org-accent:#1a5fb4;--ou-org-accent-dark:color-mix(in srgb,#1a5fb4 55%,#fff)")
    assert f'--ou-org-logo:url("{BASE}/brand/logo")' in r.text
    assert '--ou-org-name:"Acme Brothers"' in r.text                               # the sign-in page header names the organisation
    lg = c.get("/brand/logo")
    assert lg.status_code == 200 and lg.headers["cross-origin-resource-policy"] == "cross-origin" and "sandbox" in lg.headers["content-security-policy"]
    assert c.get("/branding.css").headers["cross-origin-resource-policy"] == "same-origin"   # everything else stays same-origin
    m.branding = {**m.branding, "display_name": 'Evil"}body{display:none} </style>', "accent": None, "has_logo": False}
    c.app.state.state["ics"].forget_branding()
    css = c.get("/brand/org.css").text                                              # a name cannot end the string, declaration or rule
    assert css.startswith(':root{--ou-org-name:"Evil\\22 \\7d body\\7b display\\3a none\\7d  \\3c \\2f style\\3e "}')
    assert css.count('"') == 2 and css.count("{") == 1 and css.count("}") == 1
    m.branding = {**m.branding, "display_name": CFG.mail_domain, "accent": "red;}body{display:none", "has_logo": False}
    c.app.state.state["ics"].forget_branding()
    assert c.get("/brand/org.css").text == ""                                      # nothing set (or nothing valid): the deployment look applies


def test_org_branding_without_ics_is_empty():
    with TestClient(create_app(CFG), base_url=BASE) as c:
        r = c.get("/brand/org.css")
        assert r.status_code == 200 and r.text == "" and c.get("/brand/logo").status_code == 404
