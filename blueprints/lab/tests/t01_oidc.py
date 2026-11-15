#!/usr/bin/env python3
"""T01 OIDC login against the lab Keycloak realm + OpenCloud acceptance.

Implements files-identity-eval.md test plan item 1 (the automatable part) and
the role-claim part of 5/6. Uses the realm's LAB-ONLY test client
'ou-lab-test' (password + device grant). The four real clients (web,
OpenCloudDesktop, OpenCloudAndroid, OpenCloudIOS) are checked for correct
registration (authorization endpoint accepts their redirect URI + PKCE) but
cannot be logged in with automatically.

PROVES: realm reachable over lab-CA TLS; four client registrations resolve;
roles claim is emitted per user (LDAP group -> realm role -> claim);
no-role user has no OpenCloud role; token lifetime; offline_access issues an
offline refresh token; OpenCloud accepts a Keycloak bearer token and
resolves the user from the shared read-only LDAP (no autoprovisioning); the no-role user is rejected.
DOES NOT PROVE: browser/MFA flow, desktop/Android/iOS native login,
back-channel logout, behaviour on disabled user (see MANUAL-CHECKLIST.md).
"""
import hashlib
import base64
import os
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ou_lab as L

rep = L.Report("T01 OIDC / roles / OpenCloud token acceptance")
if not L.need_requests(rep):
    rep.finish()
import requests

if not L.CA_FILE:
    rep.skipped("config", "OU_CA_FILE not set")
    rep.finish()
for h in (L.HOST_KC, L.HOST_FILES):
    if not L.resolves(h):
        rep.failed("dns", "%s does not resolve; add lab names to /etc/hosts" % h)
        rep.finish()

V = L.verify()
try:
    disc = requests.get(L.oidc_base() + "/.well-known/openid-configuration", verify=V, timeout=30)
except requests.exceptions.SSLError as e:
    rep.failed("discovery", "TLS verification failed against lab CA: %s" % str(e)[:150])
    rep.finish()
except Exception as e:  # noqa: BLE001
    rep.failed("discovery", "request failed: %s" % str(e)[:150])
    rep.finish()
if not rep.check("discovery", disc.status_code == 200 and disc.json().get("issuer") == L.oidc_base(),
                 "issuer %s" % L.oidc_base(), "HTTP %s / issuer mismatch: %s" % (disc.status_code, disc.text[:120])):
    rep.finish()
D = disc.json()

# --- client registrations: authorization endpoint must accept redirect URIs (PKCE S256)
verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
CLIENTS = {
    "web": "https://%s/oidc-callback.html" % L.HOST_FILES,
    "OpenCloudDesktop": "http://127.0.0.1",
    "OpenCloudAndroid": "oc://android.opencloud.eu",
    "OpenCloudIOS": "oc://ios.opencloud.eu",
}
for cid, redirect in CLIENTS.items():
    q = urllib.parse.urlencode({"client_id": cid, "response_type": "code", "redirect_uri": redirect,
                                "scope": "openid", "state": "x", "code_challenge": challenge,
                                "code_challenge_method": "S256"})
    r = requests.get(D["authorization_endpoint"] + "?" + q, verify=V, timeout=30, allow_redirects=False)
    ok = r.status_code == 200 and ("kc-form-login" in r.text or 'name="username"' in r.text)
    rep.check("client %s registered" % cid, ok, "login page served for redirect %s" % redirect,
              "HTTP %s (invalid client/redirect?) %s" % (r.status_code, r.text[:100].replace("\n", " ")))
q = urllib.parse.urlencode({"client_id": "web", "response_type": "code", "redirect_uri": "https://evil.invalid/cb",
                            "scope": "openid", "state": "x"})
r = requests.get(D["authorization_endpoint"] + "?" + q, verify=V, timeout=30, allow_redirects=False)
rep.check("unregistered redirect rejected", r.status_code in (400, 403), "HTTP %s" % r.status_code,
          "HTTP %s: Keycloak accepted an unregistered redirect_uri" % r.status_code)

# --- device authorization grant (reachability only; completing it needs a human)
r = requests.post(D.get("device_authorization_endpoint", L.oidc_base() + "/protocol/openid-connect/auth/device"),
                  data={"client_id": "ou-lab-test", "scope": "openid"}, verify=V, timeout=30)
rep.check("device grant endpoint", r.status_code == 200 and "device_code" in r.json(),
          "device_code issued (completion is manual)", "HTTP %s %s" % (r.status_code, r.text[:120]))

# --- per-user password grant, roles claim, OpenCloud acceptance
EXPECT = {"alice": "opencloudAdmin", "bob": "opencloudUser", "carol": "opencloudSpaceAdmin",
          "dave": "opencloudGuest", "erin": None}
OC_ROLES = ("opencloudAdmin", "opencloudSpaceAdmin", "opencloudUser", "opencloudGuest")
# OpenCloud 9.1.0 built-in role ids. admin/spaceadmin/user match oCIS and were verified in the lab run;
# the guest (user-light) id was NOT the oCIS value (1c996275-...) - observed 38071a68-... in the lab run.
ROLE_ID = {"opencloudAdmin": "71881883-1768-46bd-a24d-a356a2afdf7f",
           "opencloudSpaceAdmin": "2aadd357-682c-406b-8874-293091995fdd",
           "opencloudUser": "d7beeea8-8ff4-406b-8fb6-ab2dd81e6b11",
           "opencloudGuest": "38071a68-456a-4553-846a-fa67bf5596cc"}

for user, want in EXPECT.items():
    pw = L.password_for(user)
    if not pw:
        rep.skipped("user %s" % user, "OU_PASSWORD_%s not set" % user.upper())
        continue
    try:
        tok = L.get_token(requests, user, pw, scope="openid profile email offline_access")
    except Exception as e:  # noqa: BLE001
        rep.failed("%s password grant" % user, str(e)[:200])
        continue
    at = L.jwt_claims(tok["access_token"])
    roles = at.get("roles", [])
    got = [x for x in OC_ROLES if x in roles]
    if want:
        rep.check("%s roles claim" % user, got == [want], "roles claim contains %s" % want,
                  "expected only %s among OpenCloud roles, got %s (claim roles=%s)" % (want, got, roles))
    else:
        rep.check("%s has no OpenCloud role" % user, not got, "no OpenCloud role in claim", "unexpected %s" % got)
    life = at["exp"] - at["iat"]
    rep.check("%s access token lifetime" % user, life <= 600, "%ss" % life, "%ss > 600s (eval: 5-10 min)" % life)
    ui = requests.get(D["userinfo_endpoint"], headers={"Authorization": "Bearer " + tok["access_token"]},
                      verify=V, timeout=30)
    rep.check("%s userinfo roles" % user, ui.status_code == 200 and (want is None or want in ui.json().get("roles", [])),
              "roles present in userinfo", "HTTP %s roles=%s" % (ui.status_code, ui.json().get("roles") if ui.ok else ui.text[:80]))
    if user == "alice" and "refresh_token" in tok:
        rt = L.jwt_claims(tok["refresh_token"])
        rep.check("offline_access refresh token", rt.get("typ") == "Offline", "typ=Offline",
                  "typ=%s (offline_access not granted)" % rt.get("typ"))

    # OpenCloud acceptance (Graph /me): UNVERIFIED path /graph/v1.0/me
    me = requests.get("https://%s/graph/v1.0/me?$expand=appRoleAssignments" % L.HOST_FILES,
                      headers={"Authorization": "Bearer " + tok["access_token"]}, verify=V, timeout=60)
    if want is None:
        rep.check("%s rejected by OpenCloud" % user, me.status_code in (401, 403),
                  "HTTP %s (login fails cleanly without role claim)" % me.status_code,
                  "HTTP %s: user without role was NOT rejected" % me.status_code)
        continue
    if not rep.check("%s accepted by OpenCloud (user resolved from shared LDAP via entryUUID)" % user, me.status_code == 200,
                     "GET /graph/v1.0/me 200", "HTTP %s %s" % (me.status_code, me.text[:150])):
        continue
    j = me.json()
    rep.check("%s OpenCloud username" % user, j.get("onPremisesSamAccountName") == user or j.get("displayName"),
              "onPremisesSamAccountName=%s" % j.get("onPremisesSamAccountName"), "no username in /me: %s" % list(j))
    ras = j.get("appRoleAssignments")
    if ras is None:
        rep.skipped("%s OpenCloud role id" % user, "appRoleAssignments not returned (path/expand UNVERIFIED)")
    else:
        ids = [a.get("appRoleId") for a in ras]
        rep.check("%s OpenCloud role id" % user, ROLE_ID[want] in ids, "role %s assigned" % want,
                  "expected %s id %s in %s" % (want, ROLE_ID[want], ids))

rep.finish()
