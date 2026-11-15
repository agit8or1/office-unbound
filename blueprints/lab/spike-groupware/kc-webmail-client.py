#!/usr/bin/env python3
"""Register the grommunio-web OIDC client `ou-webmail` in the customer realm (idempotent). Runs INSIDE ou-id1.

Confidential client (grommunio-web's PHP backend exchanges the code server-side with the client secret; the browser never
sees a token). Authorization-code flow only: no implicit, no direct-access (password) grants, no service account.
The redirect URI is the deployment directory https://<host>/web (what grommunio-web's keycloak.json `redirect-url` pins).
Environment: KC_URL, KC_CA, KC_REALM (ou-lab), KC_ADMIN_USER, KC_ADMIN_PASSWORD, WEBMAIL_URL, OUT_SECRET_FILE (0600).
Passwords/secrets are never printed.
"""
import json, os, ssl, urllib.parse, urllib.request

URL, REALM = os.environ["KC_URL"].rstrip("/"), os.environ.get("KC_REALM", "ou-lab")
WEB = os.environ["WEBMAIL_URL"].rstrip("/")
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
        return r.status, (json.loads(raw) if raw else None)


_, tok = call("POST", "/realms/master/protocol/openid-connect/token", form={
    "grant_type": "password", "client_id": "admin-cli", "username": os.environ["KC_ADMIN_USER"], "password": os.environ["KC_ADMIN_PASSWORD"]})
T = tok["access_token"]
A = f"/admin/realms/{REALM}"
client = {
    "clientId": "ou-webmail", "name": "Office Unbound webmail (grommunio-web)", "enabled": True, "protocol": "openid-connect",
    "publicClient": False, "clientAuthenticatorType": "client-secret",
    "standardFlowEnabled": True, "implicitFlowEnabled": False, "directAccessGrantsEnabled": False, "serviceAccountsEnabled": False,
    "fullScopeAllowed": False,
    "rootUrl": WEB, "baseUrl": WEB + "/web/",
    "redirectUris": [WEB + "/web"], "webOrigins": [],
    "attributes": {"post.logout.redirect.uris": WEB + "/web/", "display.on.consent.screen": "false", "pkce.code.challenge.method": ""},  # no PKCE: grommunio-web's login_url() sends no code_challenge (a required S256 would make Keycloak reject every login); the confidential secret protects the code exchange
    "defaultClientScopes": ["web-origins", "profile", "basic", "email"],
    "optionalClientScopes": [],
    # the token introspection grommunio-web does after login/refresh needs the client in the token audience
    "protocolMappers": [{"name": "aud-ou-webmail", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper", "consentRequired": False,
                         "config": {"included.client.audience": "ou-webmail", "id.token.claim": "false", "access.token.claim": "true",
                                    "introspection.token.claim": "true"}}],
}
_, cl = call("GET", f"{A}/clients?clientId=ou-webmail", T)
if cl:
    cid = cl[0]["id"]
    # several groupware nodes share the client: keep the redirect URIs / post-logout URIs already registered for other hosts
    old = cl[0]
    client["redirectUris"] = sorted(set(old.get("redirectUris", [])) | set(client["redirectUris"]))
    pl = set(filter(None, (old.get("attributes", {}).get("post.logout.redirect.uris") or "").split("##"))) | {WEB + "/web/"}
    client["attributes"]["post.logout.redirect.uris"] = "##".join(sorted(pl))
    call("PUT", f"{A}/clients/{cid}", T, {**client, "id": cid})
    print("client ou-webmail updated")
else:
    call("POST", f"{A}/clients", T, client)
    _, cl = call("GET", f"{A}/clients?clientId=ou-webmail", T)
    cid = cl[0]["id"]
    print("client ou-webmail created")
_, sec = call("GET", f"{A}/clients/{cid}/client-secret", T)
fd = os.open(os.environ["OUT_SECRET_FILE"], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
os.write(fd, sec["value"].encode()); os.close(fd)
print("secret written to", os.environ["OUT_SECRET_FILE"])
