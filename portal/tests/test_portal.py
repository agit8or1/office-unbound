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
            return httpx.Response(207, content=REPORT)
        if u.startswith(FILES + "/app/new"):
            return httpx.Response(200, json={"file_id": "s$a!newfile"})
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
    assert "Sign in" in c.get("/").text


def test_home_recent_and_new_doc_flow(env):
    c, m, _ = env
    _, q = login(c, m)
    finish(c, q)
    page = c.get("/")
    names = re.findall(r'data-file="([^"]+)"', page.text)
    assert names == ["new.xlsx", "old.docx"]                                   # newest first, folders excluded
    assert "evil.test" not in page.text                                        # link rebuilt on OUR files host
    assert FILES + "/f/s%24a%212" in page.text
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    assert c.post("/new/document", data={"csrf": "wrong"}).status_code == 403
    assert c.post("/new/nope", data={"csrf": csrf}).status_code == 404
    r = c.post("/new/spreadsheet", data={"csrf": csrf})
    assert r.status_code == 303
    loc = r.headers["location"]
    assert loc.startswith(FILES + "/external-collaboraonline/personal/bob/New%20spreadsheet") and ".xlsx?fileId=s%24a%21newfile" in loc
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
    assert f"{ISS}/account/account-security/signing-in" in t
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
    r = c.get("/")
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
