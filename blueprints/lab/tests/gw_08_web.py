#!/usr/bin/env python3
"""GW08: grommunio-web (built from grommunio-web-5.2 source): login page served, wrong password rejected, correct login
(303 + session cookie) and the post-login page embeds the user's identity/fullname.
PROVES: nginx->php-fpm->php-mapi->zcore login path for the web client; static build output is served.
DOES NOT PROVE: any in-browser JS functionality (no headless browser used): compose/send, calendar UI, etc."""
import os, re, sys, requests
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gw_lab as L
rep = L.Rep("GW08 grommunio-web")
B = "https://" + L.HOST + "/web/"
S = requests.Session(); S.verify = L.CA
r = S.get(B); rep.check("GET /web/", r.status_code == 200 and "grommunio" in r.text.lower(), "HTTP 200 %d bytes" % len(r.text), "HTTP %s" % r.status_code)
m = re.search(r'src="([^"]+\.js[^"]*)"', r.text)
if m:
    j = S.get(B + m.group(1).lstrip("/").replace("web/", "", 1)); rep.check("static JS served", j.status_code == 200, "%s HTTP 200 %s" % (m.group(1)[:50], j.headers.get("Content-Type")), "HTTP %s" % j.status_code)
S2 = requests.Session(); S2.verify = L.CA
r = S2.post(B, data={"username": L.addr("alice"), "password": "wrong-password", "logon": "Login"}, allow_redirects=False)
rep.check("wrong password rejected", r.status_code != 303, "HTTP %s (no session redirect)" % r.status_code, "login succeeded with wrong password")
r = S.post(B, data={"username": L.addr("alice"), "password": L.PW["alice"], "logon": "Login"}, allow_redirects=False)
rep.check("login redirect", r.status_code == 303, "HTTP 303 -> %s" % r.headers.get("Location"), "HTTP %s" % r.status_code)
r = S.get(B)
rep.check("post-login page has user", L.addr("alice") in r.text and "Alice (lab)" in r.text, "fullname 'Alice (lab)' embedded", "identity not found, %d bytes" % len(r.text))
rep.done()
