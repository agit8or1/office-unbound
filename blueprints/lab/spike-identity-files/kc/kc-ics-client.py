#!/usr/bin/env python3
"""Create the ICS service-account client in the customer realm with ONLY the realm-management roles the user lifecycle needs.

  client `ou-ics`: confidential, client-credentials only (no browser flow, no password grant), service account roles:
    realm-management: manage-users  (disable/enable, logout, consents, delete)
                      view-users    (read user, sessions, offline sessions, consents)
                      query-clients (resolve clientId -> uuid for offline-session lookups; read-only)
  NOT granted: realm-admin, manage-realm, manage-clients, view-realm, impersonation, manage-events...
Environment: KC_URL (https://auth.ou-lab.internal), KC_CA (ca file), KC_REALM, KC_ADMIN_USER, KC_ADMIN_PASSWORD (bootstrap admin, used only here),
  OUT_SECRET_FILE (where the client secret is written, mode 0600). Idempotent.
"""
import json, os, sys, urllib.request, urllib.parse, ssl

URL, REALM = os.environ["KC_URL"].rstrip("/"), os.environ.get("KC_REALM", "ou-lab")
ctx = ssl.create_default_context(cafile=os.environ["KC_CA"])
ROLES = ("manage-users", "view-users", "query-clients")


def call(method, path, token=None, data=None, form=None):
    body = urllib.parse.urlencode(form).encode() if form else (json.dumps(data).encode() if data is not None else None)
    req = urllib.request.Request(URL + path, data=body, method=method)
    if form:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    elif data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(req, context=ctx, timeout=20) as r:
        raw = r.read()
        return r.status, (json.loads(raw) if raw else None), r.headers


_, tok, _ = call("POST", "/realms/master/protocol/openid-connect/token", form={
    "grant_type": "password", "client_id": "admin-cli", "username": os.environ["KC_ADMIN_USER"], "password": os.environ["KC_ADMIN_PASSWORD"]})
T = tok["access_token"]
A = f"/admin/realms/{REALM}"
_, cl, _ = call("GET", f"{A}/clients?clientId=ou-ics", T)
if not cl:
    call("POST", f"{A}/clients", T, {"clientId": "ou-ics", "name": "Office Unbound ICS (service account)", "enabled": True, "publicClient": False,
         "protocol": "openid-connect", "serviceAccountsEnabled": True, "standardFlowEnabled": False, "directAccessGrantsEnabled": False,
         "implicitFlowEnabled": False, "clientAuthenticatorType": "client-secret", "fullScopeAllowed": False})
    _, cl, _ = call("GET", f"{A}/clients?clientId=ou-ics", T)
cid = cl[0]["id"]
_, sa, _ = call("GET", f"{A}/clients/{cid}/service-account-user", T)
_, rm, _ = call("GET", f"{A}/clients?clientId=realm-management", T)
rmid = rm[0]["id"]
roles = []
for r in ROLES:
    _, rep, _ = call("GET", f"{A}/clients/{rmid}/roles/{r}", T)
    roles.append({"id": rep["id"], "name": rep["name"]})
call("POST", f"{A}/users/{sa['id']}/role-mappings/clients/{rmid}", T, roles)
# fullScopeAllowed=false: the token only carries roles explicitly scope-mapped to the client
call("POST", f"{A}/clients/{cid}/scope-mappings/clients/{rmid}", T, roles)
# Keycloak 26.8 admin API requires the built-in client scope `kc-admin-api` (adds the admin audience + scope) on the token
_, scopes, _ = call("GET", f"{A}/client-scopes", T)
sid = next(x["id"] for x in scopes if x["name"] == "kc-admin-api")
call("PUT", f"{A}/clients/{cid}/default-client-scopes/{sid}", T)
_, sec, _ = call("GET", f"{A}/clients/{cid}/client-secret", T)
fd = os.open(os.environ["OUT_SECRET_FILE"], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
os.write(fd, sec["value"].encode()); os.close(fd)
_, mapped, _ = call("GET", f"{A}/users/{sa['id']}/role-mappings", T)
print("client ou-ics ready; service-account role mappings:",
      json.dumps({k: [r["name"] for r in v.get("mappings", [])] for k, v in (mapped.get("clientMappings") or {}).items()}),
      "realmMappings:", [r["name"] for r in mapped.get("realmMappings", [])])
