# copy of lab/spike-pbx/kc-phone-client.py with CLIENT_ID/PHONE_HOST env (second softphone client for ou-pbx2)
#!/usr/bin/env python3
"""Register the telephony-spike OIDC client `ou-phone` in realm ou-lab (idempotent): confidential, code+PKCE(S256),
redirect https://phone.ou-lab.internal/callback. Env: KC_URL, KC_CA, KC_REALM, KC_ADMIN_USER, KC_ADMIN_PASSWORD_FILE, SECRET_DIR
(secret written 0600 as kc-ou-phone-client-secret). The admin password is read from the file and never printed."""
import json, os, ssl, urllib.parse, urllib.request

URL, REALM = os.environ["KC_URL"].rstrip("/"), os.environ.get("KC_REALM", "ou-lab")
ctx = ssl.create_default_context(cafile=os.environ["KC_CA"])
CID, PH = os.environ.get("CLIENT_ID", "ou-phone"), os.environ.get("PHONE_HOST", "phone.ou-lab.internal")   # lab variant: ou-phone2 / phone2.ou-lab.internal
CLIENTS = {
    CID: dict(name="Office Unbound web softphone", redirectUris=[f"https://{PH}/callback"], rootUrl=f"https://{PH}"),
}


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
        return json.loads(raw) if raw else None


pw = open(os.environ["KC_ADMIN_PASSWORD_FILE"]).read().strip()
T = call("POST", "/realms/master/protocol/openid-connect/token", form={
    "grant_type": "password", "client_id": "admin-cli", "username": os.environ.get("KC_ADMIN_USER", "kcadmin"), "password": pw})["access_token"]
A = f"/admin/realms/{REALM}"
for name, c in CLIENTS.items():
    rep = {"clientId": name, "name": c["name"], "enabled": True, "publicClient": False, "protocol": "openid-connect",
           "standardFlowEnabled": True, "directAccessGrantsEnabled": False, "implicitFlowEnabled": False, "serviceAccountsEnabled": False,
           "clientAuthenticatorType": "client-secret", "redirectUris": c["redirectUris"], "webOrigins": [], "rootUrl": c["rootUrl"],
           "attributes": {"pkce.code.challenge.method": "S256", "post.logout.redirect.uris": "+", **c.get("attributes", {})}}
    cl = call("GET", f"{A}/clients?clientId={name}", T)
    if cl:
        call("PUT", f"{A}/clients/{cl[0]['id']}", T, {**cl[0], **rep})
        uid = cl[0]["id"]
    else:
        call("POST", f"{A}/clients", T, rep)
        uid = call("GET", f"{A}/clients?clientId={name}", T)[0]["id"]
    sec = call("GET", f"{A}/clients/{uid}/client-secret", T)["value"]
    path = os.path.join(os.environ["SECRET_DIR"], f"kc-{name}-client-secret")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.write(fd, sec.encode()); os.close(fd)
    print("client", name, "ready, secret ->", path)
