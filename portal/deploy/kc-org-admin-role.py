#!/usr/bin/env python3
"""Lab path to make someone an Organization Admin: ensure the realm role `org-admin` exists and (optionally) grant it to users (idempotent).

The role opens the portal Admin area AND is the claim the ICS tenant API requires in the user's signed token (it is re-checked live in Keycloak
for every change). It carries no Keycloak admin rights and no ICS rights: it is only meaningful to the tenant admin API.
Run INSIDE ou-id1 as root (bootstrap admin password is read there, never printed):
    ORG_ADMIN_USERS=anna,bob python3 kc-org-admin-role.py          # grant        ORG_ADMIN_REVOKE=anna  to take it away again
Environment: KC_URL, KC_CA, KC_REALM (default ou-lab), KC_ADMIN_USER, KC_ADMIN_PASSWORD_FILE.
"""
import json, os, ssl, urllib.error, urllib.parse, urllib.request

URL, REALM = os.environ.get("KC_URL", "https://auth.ou-lab.internal").rstrip("/"), os.environ.get("KC_REALM", "ou-lab")
ctx = ssl.create_default_context(cafile=os.environ.get("KC_CA", "/root/ou-lab-ca/ca.crt"))
ROLE = os.environ.get("ORG_ADMIN_ROLE", "org-admin")


def call(method, path, token=None, data=None, form=None, ok=(200, 201, 204)):
    body = urllib.parse.urlencode(form).encode() if form else (json.dumps(data).encode() if data is not None else None)
    req = urllib.request.Request(URL + path, data=body, method=method)
    if form:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    elif data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=20) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        if e.code in ok:
            return e.code, None
        raise


pw = open(os.environ.get("KC_ADMIN_PASSWORD_FILE", "/root/ou-lab-secrets/keycloak-admin-password")).read().strip()
_, tok = call("POST", "/realms/master/protocol/openid-connect/token", form={
    "grant_type": "password", "client_id": "admin-cli", "username": os.environ.get("KC_ADMIN_USER", "kcadmin"), "password": pw})
T, A = tok["access_token"], f"/admin/realms/{REALM}"
st, role = call("GET", f"{A}/roles/{ROLE}", T, ok=(404,))
if st == 404:
    call("POST", f"{A}/roles", T, {"name": ROLE, "description": "Administrator of this organisation (portal Admin area / ICS tenant API). No infrastructure rights."})
    _, role = call("GET", f"{A}/roles/{ROLE}", T)
    print("role created")
else:
    print("role exists")
for who, grant in [(u, True) for u in os.environ.get("ORG_ADMIN_USERS", "").split(",") if u] + [(u, False) for u in os.environ.get("ORG_ADMIN_REVOKE", "").split(",") if u]:
    _, users = call("GET", f"{A}/users?username={urllib.parse.quote(who)}&exact=true", T)
    if not users:
        print(f"user {who}: not in Keycloak yet (the user must sign in once)")
        continue
    call("POST" if grant else "DELETE", f"{A}/users/{users[0]['id']}/role-mappings/realm", T, [{"id": role["id"], "name": ROLE}])
    print(f"user {who}: role {'granted' if grant else 'revoked'}")
