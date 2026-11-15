"""Tiny Keycloak admin helper used by the SSO hardening scripts. Runs INSIDE ou-id1 (admin password read from the local secrets file, never printed)."""
import json, os, ssl, urllib.error, urllib.parse, urllib.request

URL = os.environ.get("KC_URL", "https://auth.ou-lab.internal").rstrip("/")
REALM = os.environ.get("KC_REALM", "ou-lab")
ctx = ssl.create_default_context(cafile=os.environ.get("KC_CA", "/root/ou-lab-ca/ca.crt"))


def call(method, path, token=None, data=None, form=None, ok_codes=()):
    body = urllib.parse.urlencode(form).encode() if form else (json.dumps(data).encode() if data is not None else None)
    req = urllib.request.Request(URL + path, data=body, method=method)
    if form:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    elif data is not None:
        req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=20) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        if e.code in ok_codes:
            return e.code, (json.loads(raw) if raw[:1] in (b"{", b"[") else raw[:200].decode("latin1"))
        raise


def admin_token():
    pw = open(os.environ.get("KC_ADMIN_PASSWORD_FILE", "/root/ou-lab-secrets/keycloak-admin-password")).read().strip()
    return call("POST", "/realms/master/protocol/openid-connect/token",
                form={"grant_type": "password", "client_id": "admin-cli", "username": os.environ.get("KC_ADMIN_USER", "kcadmin"), "password": pw})[1]["access_token"]
