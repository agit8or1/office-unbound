#!/usr/bin/env python3
"""Register the user-portal OIDC client `ou-portal` in the customer realm (idempotent).

Why CONFIDENTIAL (not public): the portal is a backend-for-frontend (BFF). The browser never sees a token; the code
exchange happens server-side, so a client secret CAN be kept secret. A confidential client adds client authentication on
the token endpoint on top of PKCE (S256, enforced by the client attribute). Public+PKCE would be right for SPAs/desktop apps.

Environment: KC_URL, KC_CA, KC_REALM (default ou-lab), KC_ADMIN_USER, KC_ADMIN_PASSWORD (bootstrap admin, used only here),
  PORTAL_URL (https://portal.ou-lab.internal), OUT_SECRET_FILE (client secret, mode 0600). Passwords are never printed.
"""
import json, os, ssl, urllib.parse, urllib.request

URL, REALM = os.environ["KC_URL"].rstrip("/"), os.environ.get("KC_REALM", "ou-lab")
PORTAL = os.environ["PORTAL_URL"].rstrip("/")
CLIENT = os.environ.get("PORTAL_CLIENT_ID", "ou-portal")   # a second client (e.g. a throwaway test portal) can be registered with the same mappers
ctx = ssl.create_default_context(cafile=os.environ["KC_CA"])


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


def claim_mapper(name, typ, config):
    return {"name": name, "protocol": "openid-connect", "protocolMapper": typ, "consentRequired": False, "config": config}


client = {
    "clientId": CLIENT, "name": "Office Unbound user portal (BFF)", "enabled": True, "protocol": "openid-connect",
    "publicClient": False, "clientAuthenticatorType": "client-secret",
    "standardFlowEnabled": True, "implicitFlowEnabled": False, "directAccessGrantsEnabled": False, "serviceAccountsEnabled": False,
    "fullScopeAllowed": True,
    "rootUrl": PORTAL, "baseUrl": PORTAL + "/",
    "redirectUris": [PORTAL + "/auth/callback"], "webOrigins": [],
    "attributes": {"pkce.code.challenge.method": "S256", "post.logout.redirect.uris": PORTAL + "/",
                   "display.on.consent.screen": "false", "backchannel.logout.session.required": "true"},
    "defaultClientScopes": ["web-origins", "profile", "roles", "basic", "email"],
    "optionalClientScopes": ["address", "phone", "offline_access", "microprofile-jwt"],
    "protocolMappers": [
        claim_mapper("roles-flat", "oidc-usermodel-realm-role-mapper", {
            "claim.name": "roles", "multivalued": "true", "jsonType.label": "String", "id.token.claim": "true",
            "access.token.claim": "true", "userinfo.token.claim": "true", "introspection.token.claim": "true"}),
        # OpenCloud resolves the user by this claim (PROXY_USER_OIDC_CLAIM=uuid): without it Keycloak tokens are not accepted.
        claim_mapper("uuid", "oidc-usermodel-attribute-mapper", {
            "user.attribute": "uuid", "claim.name": "uuid", "jsonType.label": "String", "id.token.claim": "true",
            "access.token.claim": "true", "userinfo.token.claim": "true", "introspection.token.claim": "true"}),
    ],
}
_, cl, _ = call("GET", f"{A}/clients?clientId={CLIENT}", T)
if cl:
    cid = cl[0]["id"]
    call("PUT", f"{A}/clients/{cid}", T, {**client, "id": cid})
    print(f"client {CLIENT} updated")
else:
    call("POST", f"{A}/clients", T, client)
    _, cl, _ = call("GET", f"{A}/clients?clientId={CLIENT}", T)
    cid = cl[0]["id"]
    print(f"client {CLIENT} created")
_, sec, _ = call("GET", f"{A}/clients/{cid}/client-secret", T)
fd = os.open(os.environ["OUT_SECRET_FILE"], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
os.write(fd, sec["value"].encode()); os.close(fd)
print("secret written to", os.environ["OUT_SECRET_FILE"])
