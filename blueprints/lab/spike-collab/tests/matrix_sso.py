"""Matrix login through MAS -> Keycloak SSO with a real browser, then plain Client-Server API calls.

login(user) registers a native OAuth2 client at MAS (dynamic registration), runs the authorization-code+PKCE flow in headless
Chromium (MAS -> Keycloak form -> MAS -> loopback redirect), exchanges the code and returns a Client with access/refresh tokens.
"""
import base64
import hashlib
import secrets
import time
import urllib.parse

from playwright.sync_api import sync_playwright

import collab_lib as L

REDIRECT = "http://localhost:8765/cb"


class Client:
    def __init__(self, user, tokens, client_id, device):
        self.user, self.client_id, self.device = user, client_id, device
        self.access, self.refresh = tokens["access_token"], tokens.get("refresh_token")
        self.expires_in = tokens.get("expires_in")
        self.scope = tokens.get("scope")
        self.mxid = None

    def h(self):
        return {"Authorization": "Bearer " + self.access}

    def api(self, method, path, **kw):
        return L.S.request(method, L.HS + path, headers={**self.h(), **kw.pop("headers", {})}, timeout=30, **kw)

    def do_refresh(self):
        r = L.S.post(L.MAS + "/oauth2/token", data={"grant_type": "refresh_token", "refresh_token": self.refresh, "client_id": self.client_id}, timeout=30)
        if r.status_code == 200:
            j = r.json()
            self.access, self.refresh = j["access_token"], j.get("refresh_token", self.refresh)
        return r


def register_client():
    r = L.S.post(L.MAS + "/oauth2/registration", json={
        "client_name": "ou-collab-test", "client_uri": "https://chat.ou-lab.internal/", "redirect_uris": [REDIRECT],
        "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
        "token_endpoint_auth_method": "none", "application_type": "native"}, timeout=30)
    if r.status_code >= 300:
        raise RuntimeError("registration: %s %s" % (r.status_code, r.text[:300]))
    return r.json()["client_id"]


def login(user, pw, headless_page_hook=None, log=print):
    client_id = register_client()
    device = "OUTEST" + secrets.token_hex(4).upper()
    verifier = secrets.token_urlsafe(48)
    chal = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    state = secrets.token_urlsafe(12)
    scope = "openid urn:matrix:org.matrix.msc2967.client:api:* urn:matrix:org.matrix.msc2967.client:device:" + device
    url = L.MAS + "/authorize?" + urllib.parse.urlencode({
        "client_id": client_id, "response_type": "code", "redirect_uri": REDIRECT, "scope": scope, "state": state,
        "code_challenge": chal, "code_challenge_method": "S256", "response_mode": "query", "prompt": "consent"})
    code = None
    t0 = time.time()
    with sync_playwright() as p:
        b = L.browser(p)
        ctx = b.new_context()
        page = ctx.new_page()
        got = {}

        def on_req(req):
            if req.url.startswith(REDIRECT):
                got["url"] = req.url
        page.on("request", on_req)
        page.goto(url)
        for step in range(40):
            if "url" in got:
                break
            page.wait_for_timeout(700)
            u = page.url
            if u.startswith(L.KC):
                if page.query_selector("input[name=username]"):
                    L.kc_login(page, user, pw)
                continue
            if u.startswith(L.MAS):
                # a) provider chooser / "Continue with" button  b) consent  c) "continue" interstitial
                btn = (page.query_selector("a:has-text('Office Unbound SSO')") or page.query_selector("button:has-text('Office Unbound SSO')")
                       or page.query_selector("button:has-text('Create Account')") or page.query_selector("button:has-text('Continue')") or page.query_selector("a:has-text('Continue')"))
                if btn:
                    log("  MAS page %s -> click %r" % (u.split("?")[0], (btn.inner_text() or "").strip()[:40]))
                    btn.click()
        if "url" not in got:
            print("DEBUG page", page.url.split("?")[0], "|", page.inner_text("body")[:400].replace("\n", " / "))
            print("DEBUG controls", [(e.get_attribute("name"), e.get_attribute("type"), (e.inner_text() or e.get_attribute("value") or "")[:30]) for e in page.query_selector_all("button,input,a")][:12])
        b.close()
    if "url" not in got:
        raise RuntimeError("no redirect with code; last page %s" % page.url)
    q = urllib.parse.parse_qs(urllib.parse.urlparse(got["url"]).query)
    if q.get("state", [""])[0] != state or "code" not in q:
        raise RuntimeError("bad callback %s" % got["url"].split("?")[0])
    r = L.S.post(L.MAS + "/oauth2/token", data={"grant_type": "authorization_code", "code": q["code"][0], "redirect_uri": REDIRECT,
                                                "client_id": client_id, "code_verifier": verifier}, timeout=30)
    r.raise_for_status()
    c = Client(user, r.json(), client_id, device)
    c.login_seconds = round(time.time() - t0, 1)
    w = c.api("GET", "/_matrix/client/v3/account/whoami")
    w.raise_for_status()
    c.mxid = w.json()["user_id"]
    return c
