"""Unit/integration tests against a mock identity provider and mock OpenCloud (no network). Run: portal/.venv or system python, `pytest portal/tests`."""
import json
import plistlib
import re
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import devices, services  # noqa: E402
from app.config import Settings  # noqa: E402
from app.main import create_app, safe_next  # noqa: E402

ISS = "https://auth.test/realms/r"
BASE = "https://portal.test"
FILES = "https://cloud.test"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
JWK = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key()))
JWK.update(kid="k1", use="sig", alg="RS256")
SECRET = "s3cr3t-value-for-test"

CFG = Settings(base_url=BASE, issuer=ISS, client_id="ou-portal", client_secret=SECRET, files_url=FILES,
               mail_web_url="https://mail.test/web/", mail_domain="example.test", org_name="Acme", imap_host="mail.test", imap_port=993,
               smtp_host="mail.test", smtp_port=587, dav_host="mail.test", dav_base="/dav", autodiscover_host="autodiscover.example.test")

REPORT = b"""<?xml version="1.0"?><d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">
<d:response><d:href>/x/dir</d:href><d:propstat><d:prop><oc:fileid>s$a!1</oc:fileid><oc:name>dir</oc:name><d:getlastmodified>Sun, 15 Nov 2026 16:35:52 GMT</d:getlastmodified><d:resourcetype><d:collection/></d:resourcetype></d:prop></d:propstat></d:response>
<d:response><d:href>/x/old.docx</d:href><d:propstat><d:prop><oc:fileid>s$a!2</oc:fileid><oc:name>old.docx</oc:name><d:getlastmodified>Sun, 15 Nov 2026 10:00:00 GMT</d:getlastmodified><d:getcontentlength>1500</d:getcontentlength><d:resourcetype/><oc:privatelink>https://evil.test/f/zzz</oc:privatelink></d:prop></d:propstat></d:response>
<d:response><d:href>/x/new.xlsx</d:href><d:propstat><d:prop><oc:fileid>s$a!3</oc:fileid><oc:name>new.xlsx</oc:name><d:getlastmodified>Sun, 15 Nov 2026 17:00:00 GMT</d:getlastmodified><d:resourcetype/></d:prop></d:propstat></d:response>
</d:multistatus>"""


class Mock:
    """Mock Keycloak + OpenCloud. Records what the portal sent."""
    def __init__(self):
        self.nonce = None
        self.calls = []
        self.token_form = None
        self.refresh_fail = False
        self.app_list = None                       # OpenCloud /app/list body; None = 404 (the portal falls back to cfg.editor_app)

    def id_token(self, **over):
        c = dict(iss=ISS, aud="ou-portal", azp="ou-portal", sub="u1", exp=int(time.time()) + 300, iat=int(time.time()), nonce=self.nonce,
                 preferred_username="bob", email="bob@example.test", name="Lab Bob", given_name="Bob", sid="sess-1", roles=["opencloudUser", "default-roles-r"])
        c.update(over)
        return jwt.encode(c, KEY, algorithm="RS256", headers={"kid": "k1"})

    def handler(self, req: httpx.Request) -> httpx.Response:
        u = str(req.url)
        self.calls.append((req.method, u, dict(req.headers)))
        if u.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json={"issuer": ISS, "authorization_endpoint": ISS + "/protocol/openid-connect/auth",
                                             "token_endpoint": ISS + "/protocol/openid-connect/token", "jwks_uri": ISS + "/certs",
                                             "end_session_endpoint": ISS + "/protocol/openid-connect/logout"})
        if u == ISS + "/certs":
            return httpx.Response(200, json={"keys": [JWK]})
        if u == ISS + "/protocol/openid-connect/token":
            form = parse_qs(req.content.decode())
            if form["grant_type"] == ["authorization_code"]:
                self.token_form = form
                return httpx.Response(200, json={"access_token": "AT1", "refresh_token": "RT1", "expires_in": 300, "id_token": self.id_token()})
            if self.refresh_fail:
                return httpx.Response(400, json={"error": "invalid_grant"})
            return httpx.Response(200, json={"access_token": "AT2", "refresh_token": "RT2", "expires_in": 300})
        if u.startswith(ISS + "/account/sessions") and req.method == "GET":
            return httpx.Response(200, json=[{"id": "sess-1", "ipAddress": "10.0.0.1", "started": 1, "lastAccess": 2, "browser": "Firefox", "clients": [{"clientId": "ou-portal", "clientName": "ou-portal"}]}])
        if u.startswith(ISS + "/account/sessions") and req.method == "DELETE":
            return httpx.Response(204)
        if u == ISS + "/account/credentials":
            return httpx.Response(200, json=[{"category": "two-factor", "type": "otp", "userCredentialMetadatas": []}])
        if u == FILES + "/graph/v1.0/me/drive":
            return httpx.Response(200, json={"id": "s$a", "driveAlias": "personal/bob", "root": {"id": "s$a!root"}})
        if req.method == "REPORT":
            self.report_bodies = getattr(self, "report_bodies", []) + [req.content.decode()]
            return httpx.Response(207, content=REPORT)
        if u == FILES + "/graph/v1beta1/me/drive/sharedWithMe":
            return httpx.Response(200, json={"value": [
                {"name": "Budget 2027.xlsx", "lastModifiedDateTime": "2026-11-20T09:00:00Z",
                 "remoteItem": {"id": "s$b!7", "shared": {"sharedBy": {"user": {"displayName": "Anna Meyer"}}}}},
                {"name": "Team folder", "lastModifiedDateTime": "2026-11-21T09:00:00Z", "remoteItem": {"id": "s$b!8", "folder": {}}},
                {"name": "hidden.txt", "@UI.Hidden": True, "lastModifiedDateTime": "2026-11-22T09:00:00Z", "remoteItem": {"id": "s$b!9"}}]})
        if u == FILES + "/ocs/v2.php/apps/notifications/api/v1/notifications":
            if getattr(self, "notes", None) is None:
                return httpx.Response(503)
            return httpx.Response(200, json={"ocs": {"meta": {"status": "ok", "statuscode": 200, "message": ""}, "data": self.notes}})
        if u.startswith(FILES + "/app/new"):
            return httpx.Response(200, json={"file_id": "s$a!newfile"})
        if u == FILES + "/app/list" and self.app_list is not None:
            return httpx.Response(200, json=self.app_list)
        return httpx.Response(404)


@pytest.fixture()
def env():
    m = Mock()
    app = create_app(CFG, transport=httpx.MockTransport(m.handler))
    with TestClient(app, base_url=BASE) as c:
        c.follow_redirects = False
        yield c, m, app


def login(c, m):
    r = c.get("/login?next=/account")
    assert r.status_code == 303
    q = parse_qs(urlparse(r.headers["location"]).query)
    m.nonce = q["nonce"][0]
    return r, q


def finish(c, q, **over):
    return c.get("/auth/callback", params={"code": "abc", "state": q["state"][0], **over})


def test_safe_next():
    assert safe_next("/devices") == "/devices"
    for bad in ("//evil.test", "https://evil.test", "/\\evil", "evil", None, "/a\r\nSet-Cookie: x"):
        assert safe_next(bad) == "/"


def test_safe_next_rejects_control_characters_review3_l7():
    for bad in ("/\t/evil.example", "/a\tb", "/a\x00b", "/a b", "/a\x7fb", "/\x0b/x", "/\u0085x"):
        assert safe_next(bad) == "/", repr(bad)
    assert safe_next("/files/%E2%9C%93?x=1#y") == "/files/%E2%9C%93?x=1#y"


def test_login_flood_cannot_evict_other_users_flows_review3_l6():
    from app.sessions import Store
    st = Store(3600)
    victim = st.new_flow("v", "n", "/", "198.51.100.7")
    for _ in range(Store.FLOWS_MAX + 500):              # the reviewer's probe: > 2000 unauthenticated /login requests from one address
        st.new_flow("v", "n", "/", "203.0.113.9")
    assert len(st.flows) <= Store.FLOWS_PER_IP + 1
    assert st.pop_flow(victim) is not None               # the victim's in-flight sign-in survived
    # global cap reached by many distinct addresses: the heaviest address pays, not a random/oldest victim
    st2 = Store(3600)
    keep = st2.new_flow("v", "n", "/", "198.51.100.7")
    for i in range(Store.FLOWS_MAX):
        st2.new_flow("v", "n", "/", f"10.{i // 250}.{i % 250}.1")
    assert len(st2.flows) <= Store.FLOWS_MAX
    assert st2.pop_flow(keep) is not None


def test_login_uses_pkce_and_bound_state(env):
    c, m, _ = env
    r, q = login(c, m)
    assert q["code_challenge_method"] == ["S256"] and q["response_type"] == ["code"] and q["client_id"] == ["ou-portal"]
    assert q["redirect_uri"] == [BASE + "/auth/callback"] and "openid" in q["scope"][0]
    ck = r.headers["set-cookie"]
    assert ck.startswith("__Host-ou_portal_flow=") and "Secure" in ck and "HttpOnly" in ck and "Path=/" in ck and "Domain" not in ck


def test_full_login_session_and_token_exchange(env):
    c, m, app = env
    _, q = login(c, m)
    r = finish(c, q)
    assert r.status_code == 303 and r.headers["location"] == "/account"
    ck = [h for h in r.headers.get_list("set-cookie") if h.startswith("__Host-ou_portal=")][0]
    assert "HttpOnly" in ck and "Secure" in ck and "SameSite=lax" in ck
    assert "AT1" not in ck and "RT1" not in ck and "bob" not in ck          # the cookie is an opaque id only
    f = m.token_form
    assert f["code_verifier"][0] and f["code"] == ["abc"]
    basic = [h for (mth, u, h) in m.calls if u.endswith("/token")][0]["authorization"]
    assert basic.startswith("Basic ")                                          # confidential client authentication
    page = c.get("/")
    assert page.status_code == 200 and "Hello, Bob" in page.text
    assert "AT1" not in page.text and "RT1" not in page.text and SECRET not in page.text


def test_callback_rejects_wrong_state_and_other_browser(env):
    c, m, _ = env
    _, q = login(c, m)
    assert finish(c, {"state": ["forged"]}).status_code == 400
    # flow cookie missing (state started in another browser)
    c2 = TestClient(c.app, base_url=BASE)
    c2.follow_redirects = False
    assert finish(c2, q).status_code == 400
    assert c.get("/account").status_code == 303                                # still not signed in


def test_callback_rejects_bad_nonce_audience_and_signature(env):
    c, m, _ = env
    for over in ({"nonce": "other"}, {"aud": "someone-else"}, {"iss": "https://evil.test"}, {"exp": int(time.time()) - 600}):
        _, q = login(c, m)
        orig = m.id_token
        m.id_token = lambda **kw: orig(**{**over, **kw})
        assert finish(c, q).status_code == 400, over
        m.id_token = orig
    # signed with another key
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _, q = login(c, m)
    m.id_token = lambda **kw: jwt.encode({"iss": ISS, "aud": "ou-portal", "sub": "x", "exp": int(time.time()) + 99, "iat": int(time.time()), "nonce": m.nonce}, other, algorithm="RS256", headers={"kid": "k1"})
    assert finish(c, q).status_code == 400


def test_unauthenticated_redirects(env):
    c, _, _ = env
    for p in ("/account", "/devices", "/devices/apple.mobileconfig", "/devices/thunderbird.xml"):
        r = c.get(p)
        assert r.status_code == 303 and r.headers["location"].startswith("/login?next=")
    assert c.post("/new/document", data={"csrf": "x"}).status_code == 303
    r = c.get("/")                          # the start page goes straight to the sign-in service
    assert r.status_code == 303 and r.headers["location"] == "/login"


def test_home_recent_and_new_doc_flow(env):
    c, m, _ = env
    _, q = login(c, m)
    finish(c, q)
    page = c.get("/")
    names = re.findall(r'data-file="([^"]+)"', page.text.split('id="h-recent"', 1)[1].split("</section>", 1)[0])
    assert names == ["new.xlsx", "old.docx"]                                   # newest first, folders excluded
    assert "evil.test" not in page.text                                        # link rebuilt on OUR files host
    assert FILES + "/f/s%24a%212" in page.text
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    assert c.post("/new/document", data={"csrf": "wrong"}).status_code == 403
    assert c.post("/new/nope", data={"csrf": csrf}).status_code == 404
    r = c.post("/new/spreadsheet", data={"csrf": csrf})
    assert r.status_code == 303
    loc = r.headers["location"]
    assert loc.startswith(FILES + "/external-documents/personal/bob/New%20spreadsheet") and ".xlsx?fileId=s%24a%21newfile" in loc
    new_call = [u for (mth, u, h) in m.calls if "/app/new" in u][0]
    assert "filename=New%20spreadsheet" in new_call and "parent_container_id=s%24a%21root" in new_call


def test_cross_origin_post_refused(env):
    c, m, _ = env
    _, q = login(c, m)
    finish(c, q)
    csrf = re.search(r'name="csrf" value="([^"]+)"', c.get("/").text).group(1)
    assert c.post("/new/document", data={"csrf": csrf}, headers={"origin": "https://evil.test"}).status_code == 403
    assert c.post("/logout", data={"csrf": "bad"}).status_code == 403


def test_token_refresh_and_expired_session(env):
    c, m, app = env
    _, q = login(c, m)
    finish(c, q)
    s = next(iter(app.state.store.sessions.values()))
    s.access_exp = time.time() + 5
    assert c.get("/").status_code == 200 and s.access_token == "AT2"
    s.access_exp = time.time() + 5
    m.refresh_fail = True
    r = c.get("/account")
    assert r.status_code == 303 and r.headers["location"].startswith("/login")


def test_account_page(env):
    c, m, _ = env
    _, q = login(c, m)
    finish(c, q)
    t = c.get("/account").text
    assert "This device" in t and "Firefox" in t and "Off" in t and "opencloudUser" in t and "default-roles" not in t
    assert 'href="/account/two-step"' in t and 'href="/account/password"' in t        # MFA off: set it up in the sign-in flow
    csrf = re.search(r'name="csrf" value="([^"]+)"', t).group(1)
    r = c.post("/account/sessions/end-others", data={"csrf": csrf})
    assert r.status_code == 303 and "flash=ended" in r.headers["location"]


def test_logout(env):
    c, m, app = env
    _, q = login(c, m)
    finish(c, q)
    csrf = re.search(r'name="csrf" value="([^"]+)"', c.get("/").text).group(1)
    r = c.post("/logout", data={"csrf": csrf})
    loc = urlparse(r.headers["location"])
    assert r.status_code == 303 and loc.path.endswith("/logout") and "id_token_hint" in loc.query
    assert not app.state.store.sessions
    assert c.get("/account").status_code == 303


def test_security_headers(env):
    c, _, _ = env
    r = c.get("/about")
    csp = r.headers["content-security-policy"]
    assert "default-src 'none'" in csp and "script-src" not in csp and "unsafe" not in csp and "frame-ancestors 'none'" in csp
    assert "https:" not in csp.replace("https://auth.test", "").replace("https://cloud.test", "")
    assert r.headers["x-content-type-options"] == "nosniff" and "no-store" in r.headers["cache-control"]
    assert "<script" not in r.text and "style=" not in r.text


def test_autoconfig_public_and_valid(env):
    c, _, _ = env
    for p in ("/.well-known/autoconfig/mail/config-v1.1.xml", "/mail/config-v1.1.xml"):
        r = c.get(p)
        assert r.status_code == 200
        root = ET.fromstring(r.content)
        assert root.tag == "clientConfig"
        assert root.find("emailProvider/domain").text == "example.test"
        assert root.find("emailProvider/incomingServer/hostname").text == "mail.test"
        assert root.find("emailProvider/incomingServer/socketType").text == "SSL"
        assert root.find("emailProvider/incomingServer/username").text == "%EMAILADDRESS%"
        assert root.find("emailProvider/outgoingServer/socketType").text == "STARTTLS"


def test_autoconfig_matches_node_submission_services():
    """The groupware node (blueprints/lab/spike-groupware/gw-mta.sh) provides submission on 587 (STARTTLS) and 465 (implicit TLS): the document must advertise exactly those."""
    import dataclasses
    from app import devices
    for port, sock in ((587, "STARTTLS"), (465, "SSL")):
        root = ET.fromstring(devices.autoconfig_xml(dataclasses.replace(CFG, smtp_port=port)))
        assert root.find("emailProvider/outgoingServer/port").text == str(port)
        assert root.find("emailProvider/outgoingServer/socketType").text == sock
        assert root.find("emailProvider/outgoingServer/authentication").text == "password-cleartext"  # only ever offered after TLS


def test_mobileconfig_content_and_no_secrets(env):
    c, m, _ = env
    _, q = login(c, m)
    finish(c, q)
    r = c.get("/devices/apple.mobileconfig")
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/x-apple-aspen-config")
    p = plistlib.loads(r.content)
    kinds = [x["PayloadType"] for x in p["PayloadContent"]]
    assert kinds == ["com.apple.mail.managed", "com.apple.caldav.account", "com.apple.carddav.account"]
    mail = p["PayloadContent"][0]
    assert mail["EmailAddress"] == "bob@example.test" and mail["IncomingMailServerUsername"] == "bob@example.test"
    assert mail["IncomingMailServerHostName"] == "mail.test" and mail["IncomingMailServerUseSSL"] is True
    blob = r.content.decode().lower()
    for bad in ("password</key>", "passwordenc", "at1", "rt1", SECRET.lower()):
        assert bad not in blob.replace("emailauthpassword", "").replace("outgoingpasswordsameasincomingpassword", "")
    assert not any(k.lower() in ("incomingpassword", "outgoingpassword", "password", "calDAVPassword".lower(), "carddavpassword") for x in p["PayloadContent"] for k in x)
    # stable ids: reinstall replaces, not duplicates
    assert plistlib.loads(c.get("/devices/apple.mobileconfig").content)["PayloadUUID"] == p["PayloadUUID"]


def test_devices_page_checksums_and_platform_order(env):
    c, m, _ = env
    _, q = login(c, m)
    finish(c, q)
    t = c.get("/devices", headers={"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}).text
    assert t.index('id="windows"') < t.index('id="ios"')
    for d in devices.DESKTOP_DOWNLOADS:
        assert d["sha256"] in t and d["url"] in t and re.fullmatch(r"[0-9a-f]{64}", d["sha256"])
    assert "autodiscover.example.test/autodiscover/autodiscover.xml" in t


def test_parse_recent_limit_and_ago():
    items = services.parse_recent(REPORT, CFG, limit=1)
    assert [i["name"] for i in items] == ["new.xlsx"]
    assert services.ago(items[0]["mtime"], now=items[0]["mtime"].timestamp() + 7200) == "2 hours ago"
    assert services.human_size(1536) == "1.5 KB"


def test_about_page_and_footer_show_version(env):
    from app.version import PORTAL_VERSION
    c, m, _ = env
    r = c.get("/about")
    assert r.status_code == 200 and "Office Unbound" in r.text and PORTAL_VERSION in r.text
    assert f"Office Unbound portal v{PORTAL_VERSION}" in r.text                          # footer
    _, q = login(c, m)
    finish(c, q)
    assert PORTAL_VERSION in c.get("/about").text


def test_mail_calendar_contacts_tiles_use_sso_deep_links_and_no_separate_password_note(env):
    c, m, _ = env
    _, q = login(c, m)
    finish(c, q)
    html = c.get("/").text
    found = re.findall(r'<a class="apptile" href="([^"]+)" data-app="(mail|calendar|contacts)"', html)
    assert {app: href for href, app in found} == {"mail": "https://mail.test/web/",
                                                  "calendar": "https://mail.test/web/?action=context&amp;view=calendar",
                                                  "contacts": "https://mail.test/web/?action=context&amp;view=contacts"}
    assert not re.search(r"separate password|own password|same password|sign[- ]in of its own", html, re.I)
    assert CFG.mail_view_url("calendar") == "https://mail.test/web/?action=context&view=calendar"
    with pytest.raises(ValueError):
        CFG.mail_view_url("calendar&view=x")


def test_devices_page_links_mailcraft(env):
    """Owner 2026-11-21: "add link for mailcraft"."""
    c, m, _ = env
    _, q = login(c, m)
    finish(c, q)
    page = c.get("/devices").text
    assert 'href="https://github.com/ZIDAN44/mailcraft"' in page and 'rel="noopener noreferrer"' in page


def test_mailcraft_is_in_the_apps_comparison_as_its_own_project(env):
    """Owner 2026-11-25: "devices#office-apps - missing mailcraft". Its own row and card (not under ArtCraft), facts from its README only."""
    from app import office_apps
    c, m, _ = env
    _, q = login(c, m)
    finish(c, q)
    page = c.get("/devices").text
    assert 'id="app-mailcraft"' in page and 'href="#app-mailcraft"' in page
    mc = next(a for a in office_apps.APPS if a["id"] == "mailcraft")
    assert mc["download"] == "https://mailcraft.dev/#download" and mc["matrix"]["status"] == "Not verified"
    assert [a["id"] for a in office_apps.filtered("linux", "foss")].count("mailcraft") == 1


def _app_list(name, ext="docx"):
    mime = {"docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"}.get(ext, "application/x-" + ext)
    return {"mime-types": [{"mime_type": "text/plain", "ext": "txt", "app_providers": [{"name": "TextEditor"}]},
                           {"mime_type": mime, "ext": ext, "name": "Document", "default_application": name,
                            "app_providers": [{"name": name, "icon": "x"}, {"name": "Other"}]}]}


@pytest.mark.parametrize("listed,route", [("Documents", "external-documents"),           # this release (ICS brand.EDITOR_APP)
                                          ("CollaboraOnline", "external-collaboraonline"),  # a deployment configured before the rename
                                          ("bad name/..", "external-documents"),            # not a valid app name: the configured route
                                          (None, "external-documents")])                    # no registry answer: the configured route
def test_new_document_opens_the_editor_route_opencloud_lists(env, listed, route):
    from app import services
    services._editor_cache.clear()
    c, m, _ = env
    m.app_list = _app_list(listed) if listed else None
    _, q = login(c, m)
    finish(c, q)
    csrf = re.search(r'name="csrf" value="([^"]+)"', c.get("/").text).group(1)
    loc = c.post("/new/document", data={"csrf": csrf}).headers["location"]
    assert loc.startswith(f"{FILES}/{route}/personal/bob/New%20document"), loc
    services._editor_cache.clear()


def test_the_portal_default_editor_route_is_the_deployments():
    """Settings.editor_app = external-<COLLABORATION_APP_NAME lower case> of the ICS's opencloud.env (one name, two places)."""
    env = (Path(__file__).resolve().parents[2] / "blueprints/catalog/templates/files/opencloud.env").read_text()
    name = re.search(r"^COLLABORATION_APP_NAME=(\w+)$", env, re.M).group(1)
    assert CFG.editor_app == f"external-{name.lower()}" == "external-documents"


def _chat_env(chat_up: bool):
    import dataclasses
    m = Mock()
    base = m.handler

    def handler(req):
        if str(req.url) == "https://chat.example.test/healthz":
            return httpx.Response(200, text="ok\n") if chat_up else httpx.Response(502)
        return base(req)
    services._CHAT.update(at=0.0, ok=False)
    cfg = dataclasses.replace(CFG, chat_url="https://chat.example.test")
    return m, create_app(cfg, transport=httpx.MockTransport(handler))


@pytest.mark.parametrize("up", [True, False])
def test_chat_bubble_only_when_chat_answers_and_only_signed_in(up):
    m, app = _chat_env(up)
    with TestClient(app, base_url=BASE) as c:
        c.follow_redirects = False
        assert "chatdock" not in c.get("/about").text                    # signed out: never
        _, q = login(c, m)
        finish(c, q)
        r = c.get("/")
        assert r.status_code == 200
        assert ("chatdock" in r.text) is up
        if up:
            assert '<iframe src="https://chat.example.test/"' in r.text and 'target="ou-chat"' in r.text
            assert "<script" not in r.text                                  # still no script on the portal
        csp = r.headers["content-security-policy"]
        assert "frame-src https://chat.example.test" in csp and "frame-ancestors 'none'" in csp and "script-src" not in csp


def test_chat_url_convention_override_and_off():
    from app.config import _chat_url
    assert _chat_url(None, "acme.example") == "https://chat.acme.example"
    assert _chat_url("https://talk.acme.example/", "acme.example") == "https://talk.acme.example"
    assert _chat_url("off", "acme.example") == ""
    for bad in ("http://chat.acme.example", "https://chat.acme.example/x", "javascript:alert(1)"):
        assert _chat_url(bad, "acme.example") == ""


def _profile_mock(read_only=False, reject=None):
    m = Mock()
    base = m.handler
    m.posted = []
    meta = [{"name": n, "readOnly": read_only or n in ("username", "email"), "required": n in ("username", "firstName", "lastName")}
            for n in ("username", "email", "firstName", "lastName", "displayName", "phone", "mobile")]
    rep = {"id": "u1", "username": "bob", "email": "bob@example.test", "firstName": "Bob", "lastName": "Lab", "attributes": {"phone": ["+1 555 0100"]},
           "userProfileMetadata": {"attributes": meta}}

    def handler(req):
        u = str(req.url)
        if u.startswith(ISS + "/account/?") and req.method == "GET":
            return httpx.Response(200, json=rep)
        if u == ISS + "/account/" and req.method == "POST":
            m.posted.append(json.loads(req.content))
            return httpx.Response(400, json={"errors": [{"field": reject, "errorMessage": "error-invalid"}]}) if reject else httpx.Response(204)
        return base(req)
    return m, handler


def _signed_in(handler, m):
    app = create_app(CFG, transport=httpx.MockTransport(handler))
    c = TestClient(app, base_url=BASE)
    c.follow_redirects = False
    c.__enter__()
    _, q = login(c, m)
    finish(c, q)
    return c


def _csrf(html):
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


def test_account_shows_an_editable_profile_and_saves_only_allowed_fields():
    m, h = _profile_mock()
    c = _signed_in(h, m)
    page = c.get("/account").text
    assert 'name="firstName" value="Bob"' in page and 'name="phone" value="+1 555 0100"' in page and "Save profile" in page
    assert 'name="email"' not in page and 'name="username"' not in page and "bob@example.test" in page     # shown, not editable
    r = c.post("/account/profile", data={"csrf": _csrf(page), "firstName": "Robert", "lastName": "Lab", "mobile": "+1 555 0199",
                                         "email": "evil@example.test", "username": "root"})
    assert r.status_code == 303 and r.headers["location"].startswith("/account?flash=saved")
    sent = m.posted[-1]
    assert sent["firstName"] == "Robert" and sent["email"] == "bob@example.test" and sent["username"] == "bob"
    assert sent["attributes"]["mobile"] == ["+1 555 0199"] and sent["attributes"]["phone"] == ["+1 555 0100"]
    assert "userProfileMetadata" not in sent


def test_profile_save_needs_csrf_and_reports_rejected_fields():
    m, h = _profile_mock(reject="phone")
    c = _signed_in(h, m)
    assert c.post("/account/profile", data={"csrf": "wrong", "phone": "x"}).status_code == 403 and not m.posted
    r = c.post("/account/profile", data={"csrf": _csrf(c.get("/account").text), "phone": "abc"})
    assert r.headers["location"].startswith("/account?flash=invalid&err=phone")
    assert 'aria-invalid="true"' in c.get(r.headers["location"].split("#")[0]).text


def test_read_only_directory_shows_profile_without_a_form():
    m, h = _profile_mock(read_only=True)
    c = _signed_in(h, m)
    page = c.get("/account").text
    assert "Save profile" not in page and "managed by your organisation" in page and "Bob" in page
    assert 'href="/account/password"' not in page and "one-time link" in page


def test_change_password_and_two_step_go_through_the_sign_in_service():
    m, h = _profile_mock()
    c = _signed_in(h, m)
    for what, action, flash in (("password", "UPDATE_PASSWORD", "password"), ("two-step", "CONFIGURE_TOTP", "two-step")):
        r = c.get(f"/account/{what}")
        assert r.status_code == 303
        q = parse_qs(urlparse(r.headers["location"]).query)
        assert q["kc_action"] == [action] and q["code_challenge_method"] == ["S256"]
        m.nonce = q["nonce"][0]
        done = finish(c, q, kc_action_status="success")
        assert done.headers["location"] == f"/account?flash={flash}"
    r = c.get("/account/password")
    q = parse_qs(urlparse(r.headers["location"]).query)
    m.nonce = q["nonce"][0]
    assert finish(c, q, kc_action_status="cancelled").headers["location"] == "/account?flash=cancelled"
    assert c.get("/account/anything").status_code == 404


def test_office_applications_section_filters_and_stays_honest(env):
    from app import office_apps
    c, m, _ = env
    _, q = login(c, m)
    finish(c, q)
    page = c.get("/devices").text
    assert 'id="office-apps"' in page and "Choose how you work" in page
    for a in office_apps.APPS:
        assert a["name"].replace("&", "&amp;") in page
        for k in ("website", "download"):
            assert a[k] is None or a[k].startswith("https://")
        assert set(a["matrix"].values()) <= {"Yes", "No", "Partial", "Requires server", "Depends on edition", "Not verified", "Included", "Browser",
                                              "Alpha", "Stable", "Experimental"}
    assert "✓" not in page and "✔" not in page                                    # no ticks for unconfirmed capabilities
    assert page.count('rel="noopener noreferrer"') >= 2 * (len(office_apps.APPS) - 1) and "not provided by Office Unbound" in page
    assert page.index("Office Unbound Documents") < page.index("LibreOffice")           # the built-in editor first
    mac = c.get("/devices?os=macos&kind=experimental").text
    assert "WordCraft" in mac and "LibreOffice</a>" not in mac and "Office Unbound Documents" in mac
    assert "LibreOffice" in c.get("/devices?os=bogus&kind=<x>").text                    # unknown filter values are ignored
    assert "Choose how you work" in c.get("/").text                                      # reachable from Start something new
    art = next(a for a in office_apps.APPS if a["id"] == "artcraft")
    assert art["group"] == "experimental" and "getartcraft.com" in art["download"]



# ---- the redesigned dashboard (owner brief 2026-11-23) -------------------------------------------------------------------------------

def _dash(env):
    c, m, _ = env
    _, q = login(c, m)
    finish(c, q)
    return c, m


def _csrf(html):
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


def test_dashboard_shows_live_files_and_shares_and_no_invented_mail_or_events(env):
    c, m = _dash(env)
    html = c.get("/").text
    assert 'data-file="new.xlsx"' in html and 'data-file="Budget 2027.xlsx"' in html and "Anna Meyer" in html
    assert "hidden.txt" not in html                                                            # a share the user hid stays hidden
    assert f'href="{FILES}/f/s%24b%217"' in html                                               # opened through OUR files host
    # mail and calendar: honest cards with working actions, never a made-up count or event
    assert "Message previews on the dashboard are not available yet" in html and "An agenda on the dashboard is not available yet" in html
    assert 'href="https://mail.test/web/?action=mailto&amp;to="' in html
    assert len(re.findall(r'<li(?: class="today" aria-current="date")?><span class="wd">', html)) == 7 and html.count('aria-current="date"') == 1
    assert 'data-theme=' not in html.split(">", 2)[1]                                          # system theme by default


def test_theme_and_widgets_are_saved_per_browser_and_need_csrf(env):
    c, m = _dash(env)
    tok = _csrf(c.get("/").text)
    assert c.post("/prefs", data={"csrf": "wrong", "theme": "dark"}).status_code == 403
    r = c.post("/prefs", data={"csrf": tok, "theme": "dark", "next": "/account"})
    assert r.status_code == 303 and r.headers["location"] == "/account" and "ou_prefs=" in r.headers["set-cookie"]
    assert "HttpOnly" in r.headers["set-cookie"] and "Secure" in r.headers["set-cookie"]
    assert '<html lang="en" data-theme="dark">' in c.get("/").text
    assert c.post("/prefs", data={"csrf": tok, "theme": "neon", "next": "//evil.test"}).headers["location"] == "/"   # bad values ignored
    assert '<html lang="en" data-theme="dark">' in c.get("/").text
    m.report_bodies = []
    c.post("/prefs", data={"csrf": tok, "widgets_form": "1", "show": ["inbox", "calendar", "create", "shared"]})
    html = c.get("/").text
    assert 'id="h-recent"' not in html and m.report_bodies == []                               # hidden: not even asked for
    assert 'id="h-shared"' in html


def test_favourites_widget_asks_files_the_way_its_own_favourites_view_does(env):
    c, m = _dash(env)
    m.report_bodies = []
    html = c.get("/").text
    assert any("<oc:pattern>is:favorite</oc:pattern>" in b for b in m.report_bodies)        # the KQL Files' Favourites view sends
    fav = html.split('id="h-fav"', 1)[1].split("</section>", 1)[0]
    assert 'data-file="dir"' in fav and 'data-file="new.xlsx"' in fav                          # folders can be favourites too
    assert f'href="{FILES}/files/favorites"' in fav
    tok = _csrf(html)
    c.post("/prefs", data={"csrf": tok, "widgets_form": "1", "show": ["recent", "shared"]})
    m.report_bodies = []
    assert 'id="h-fav"' not in c.get("/").text and not any("is:favorite" in b for b in m.report_bodies)


def test_bell_shows_files_notifications_escaped_and_asks_files_at_most_once_a_minute(env, monkeypatch):
    c, m = _dash(env)
    from app import main as portal_main
    m.notes = [{"notification_id": "1", "app": "userlog", "user": "bob", "datetime": "2026-11-23T09:00:00Z", "object_id": "x", "object_type": "share",
                "subject": "Anna Meyer shared <b>Budget</b> with you", "message": "Anna Meyer shared Budget with you", "subjectRich": "", "messageRich": ""},
               {"notification_id": "2", "datetime": "2026-11-23T10:00:00Z", "subject": "You were added to space Sales", "message": ""},
               {"notification_id": "3", "datetime": "not a date", "subject": "broken"}]
    monkeypatch.setattr(portal_main, "NOTES_TTL", 0)
    html = c.get("/account").text                                  # every page: the bell is part of the shell
    bell = html.split('class="menu notes"', 1)[1].split("</details>", 1)[0]
    assert 'aria-label="Notifications (2)"' in bell and ">2</span>" in bell
    assert "&lt;b&gt;Budget&lt;/b&gt;" in bell and "<b>Budget</b>" not in bell                 # OpenCloud's text is shown, never as markup
    assert bell.index("You were added to space Sales") < bell.index("Anna Meyer shared")     # newest first
    assert "broken" not in bell
    monkeypatch.setattr(portal_main, "NOTES_TTL", 60)
    n = sum(1 for _, u, _ in m.calls if u.endswith("/notifications"))
    c.get("/"); c.get("/devices")
    assert sum(1 for _, u, _ in m.calls if u.endswith("/notifications")) == n               # cached for the session
    m.notes = None
    monkeypatch.setattr(portal_main, "NOTES_TTL", 0)
    assert "Notifications are not available right now." in c.get("/").text                   # Files down: said plainly, page still works


def test_prefs_cookie_parser_accepts_only_known_values():
    from app.main import WIDGETS, dump_prefs, parse_prefs
    assert parse_prefs(None) == {"theme": "system", "hidden": []}
    assert parse_prefs("light:recent.bogus.inbox") == {"theme": "light", "hidden": ["recent", "inbox"]}
    assert parse_prefs("<script>:") == {"theme": "system", "hidden": []}
    assert dump_prefs({"theme": "dark", "hidden": ["shared", "inbox"]}) == "dark:shared.inbox"
    assert re.fullmatch(r"[a-z:.]+", dump_prefs({"theme": "light", "hidden": list(WIDGETS)}))      # RFC 6265 cookie-octets only


def test_search_sends_one_quoted_phrase_and_lists_files_and_folders(env):
    c, m = _dash(env)
    m.report_bodies = []
    assert "Find a file or folder" in c.get("/search").text and m.report_bodies == []           # no words: no query
    html = c.get("/search", params={"q": 'budget" OR name:*) <x>'}).text
    body = m.report_bodies[-1]
    assert '<oc:pattern>"budget OR name x"</oc:pattern>' in body                     # operators/markup stripped, one phrase
    assert 'data-file="dir"' in html and 'data-file="new.xlsx"' in html                        # folders are results too
    assert "<x>" not in html
