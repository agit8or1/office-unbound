#!/usr/bin/env python3
"""P05 softphone provisioning endpoint: OIDC gate, CSRF, per-user scope, no extension => no credential, secrets not logged, anonymous SIP refused."""
import os
import re
import sys

import requests
from playwright.sync_api import sync_playwright

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pbx_lib as L
from sip_probe import register

rep = L.Report("P05 softphone credential endpoint (Keycloak OIDC gate)")
S = requests.Session()
S.verify = L.CA
r = S.get(L.PHONE + "/api/me")
rep.check("anonymous /api/me -> 401", r.status_code == 401, r.status_code)
r = S.post(L.PHONE + "/api/credential")
rep.check("anonymous POST /api/credential -> 401 (no credential issued)", r.status_code == 401, r.status_code)
r = S.get(L.PHONE + "/", allow_redirects=False)
rep.check("anonymous / redirects to /login (then Keycloak)", r.status_code == 302 and r.headers["location"].endswith("/login"), r.headers.get("location"))
r = S.get(L.PHONE + "/login", allow_redirects=False)
loc = r.headers.get("location", "")
rep.check("login redirect is Keycloak code flow with PKCE S256", "auth.ou-lab.internal" in loc and "code_challenge_method=S256" in loc and "client_id=ou-phone" in loc)
r = S.get(L.PHONE + "/static/index.html")
csp = r.headers.get("content-security-policy", "")
rep.check("strict CSP: no inline/eval, scripts only 'self', connect only self + PBX WSS, frame-ancestors none",
          "script-src 'self'" in csp and "unsafe" not in csp and ("wss://" + L.PBX + ":8089") in csp and "frame-ancestors 'none'" in csp
          and "Strict-Transport-Security" in r.headers, csp)
rep.check("the page has no inline script/style/handlers", not re.search(r"<script(?![^>]*src=)|\son\w+=|style=", r.text), "")
rep.check("anonymous SIP REGISTER for a made-up user is refused", register("mallory.web", "x" * 32, L.CA) in (401, 403, 404))

JS = """async ([m, u, h]) => { const r = await fetch(u, {method: m, headers: h, credentials: 'same-origin'});
  let j = null; try { j = await r.json(); } catch (e) {} return {status: r.status, json: j, cc: r.headers.get('cache-control')}; }"""


def F(pg, m, u, h=None):
    return pg.evaluate(JS, [m, L.PHONE + u, h or {}])


with sync_playwright() as p:
    b = L.browser(p)
    try:
        ctx = b.new_context(permissions=["microphone"])
        pg = ctx.new_page()
        pg.goto(L.PHONE + "/")
        L.kc_login(pg, "alice", L.password("alice")) if "auth.ou-lab" in pg.url else None
        pg.wait_for_selector("#status", timeout=30000)
        L.wait_state(pg, "#status", "no-extension", 15)
        st = pg.inner_text("#status")
        rep.check("alice (no telephoneNumber in LDAP) gets NO credential and no extension", "no extension" in st and pg.inner_text("#ext") == "-", st)
        me = F(pg, "GET", "/api/me")["json"]
        r = F(pg, "POST", "/api/credential", {"X-OU-CSRF": me["csrf"]})
        rep.check("POST /api/credential for a user without extension -> 403", r["status"] == 403, r["status"])
        ctx.close()
        ctx = b.new_context(permissions=["microphone"])
        pg = ctx.new_page()
        pg.goto(L.PHONE + "/")
        L.kc_login(pg, "bob", L.password("bob")) if "auth.ou-lab" in pg.url else None
        pg.wait_for_selector("#status", timeout=30000)
        L.wait_state(pg, "#status", "registered", 20)
        r = F(pg, "POST", "/api/credential")
        rep.check("bob without CSRF header -> 403", r["status"] == 403, r["status"])
        me = F(pg, "GET", "/api/me")["json"]
        r = F(pg, "POST", "/api/credential?user=carol", {"X-OU-CSRF": me["csrf"]})
        j = r["json"]
        rep.check("a user can only obtain HIS OWN credential (?user=carol ignored -> bob.web)", r["status"] == 200 and j["username"] == "bob.web" and j["extension"] == "1002", j["username"])
        rep.check("credential response is no-store", "no-store" in (r["cc"] or ""))
        cookie = [c for c in ctx.cookies() if c["name"] == "ouphone"][0]
        rep.check("session cookie is HttpOnly, Secure, SameSite=Strict", cookie["httpOnly"] and cookie["secure"] and cookie["sameSite"] == "Strict", cookie["sameSite"])
        pw = j["password"]
    finally:
        b.close()
leak = L.pbx("umask 077; cat > /run/pw.tmp; grep -rlF -f /run/pw.tmp /var/log /var/lib/ou-pbx /etc/asterisk /var/spool 2>/dev/null; journalctl --no-pager 2>/dev/null | grep -cF -f /run/pw.tmp; rm -f /run/pw.tmp; true", stdin=pw)
rep.check("issued web password appears in no PBX log/state file or journal", leak.strip().replace("\n", " ") in ("0", ""), leak.strip().replace("\n", " "))
rep.finish()
