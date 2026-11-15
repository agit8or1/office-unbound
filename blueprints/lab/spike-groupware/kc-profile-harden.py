#!/usr/bin/env python3
"""Realm user-profile hardening: `email` and `username` become admin-edit-only (users keep view). Runs INSIDE ou-id1 next to kc_lib.py.

  kc-profile-harden.py apply   set permissions.edit=[admin] for username+email (idempotent)
  kc-profile-harden.py test    prove what a user can do: creates a throw-away LOCAL user (random password, never printed), signs in with it
                               and tries to change email and username through the Account REST API (what the account console uses); deletes the user.
Why: grommunio/gromox take the mailbox identity from the token's `email` claim (docs/status/webmail-sso-results.md section 4); a user who can edit it
could become another mailbox.
"""
import json
import secrets
import sys
import urllib.error

sys.path.insert(0, "/root")
from kc_lib import REALM, call, admin_token  # noqa: E402

A = f"/admin/realms/{REALM}"


def apply(T):
    _, prof = call("GET", f"{A}/users/profile", T)
    for a in prof["attributes"]:
        if a["name"] in ("username", "email"):
            a["permissions"] = {"view": ["admin", "user"], "edit": ["admin"]}
    call("PUT", f"{A}/users/profile", T, prof)
    _, prof = call("GET", f"{A}/users/profile", T)
    print({a["name"]: a["permissions"]["edit"] for a in prof["attributes"] if a["name"] in ("username", "email")})


def test(T):
    name, pw = "ou-hardtest", secrets.token_urlsafe(18)
    _, ex = call("GET", f"{A}/users?username={name}&exact=true", T)
    for u in ex:
        call("DELETE", f"{A}/users/{u['id']}", T)
    call("POST", f"{A}/users", T, {"username": name, "email": "ou-hardtest@ou-lab.internal", "firstName": "Hard", "lastName": "Test", "enabled": True,
                                   "emailVerified": True, "credentials": [{"type": "password", "value": pw, "temporary": False}]})
    _, us = call("GET", f"{A}/users?username={name}&exact=true", T)
    uid = us[0]["id"]
    try:
        _, tok = call("POST", f"/realms/{REALM}/protocol/openid-connect/token", form={"grant_type": "password", "client_id": "admin-cli", "username": name, "password": pw})
        U = tok["access_token"]
        _, acct = call("GET", f"/realms/{REALM}/account", U)
        out = {}
        for field, new in (("email", "hijack-test@ou-lab.internal"), ("username", "ou-hardtest-renamed")):
            body = {k: acct.get(k) for k in ("username", "email", "firstName", "lastName")}
            body[field] = new
            try:
                code, _ = call("POST", f"/realms/{REALM}/account", U, body)
            except urllib.error.HTTPError as e:
                code = e.code
            _, now = call("GET", f"{A}/users/{uid}", T)
            out[field] = {"http": code, "changed": now[field] == new}
        print(json.dumps(out))
        # firstName must still be editable by the user (profile is not locked entirely)
        body = {k: acct.get(k) for k in ("username", "email", "firstName", "lastName")}
        body["firstName"] = "Edited"
        code, _ = call("POST", f"/realms/{REALM}/account", U, body)
        _, now = call("GET", f"{A}/users/{uid}", T)
        print(json.dumps({"firstName_http": code, "firstName_changed": now.get("firstName") == "Edited"}))
    finally:
        call("DELETE", f"{A}/users/{uid}", admin_token())


if __name__ == "__main__":
    T = admin_token()
    {"apply": apply, "test": test}[sys.argv[1]](T)
