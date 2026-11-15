#!/usr/bin/env python3
"""Matrix probe for the ICS lifecycle lab run (ics/scripts/lab_user_lifecycle.py matrix). Needs the collab test venv (requests, playwright, PyJWT).

  matrix_probe.py login <uid>   password on stdin (never printed); real SSO login MAS -> Keycloak; tokens -> file given by --out (0600)
  matrix_probe.py poll --tokens F --out R [--horizon 90]
        polls once a second: whoami with the access token (refused = not HTTP 200) and every 3 s a refresh with the refresh token (refused = not 200),
        until both are refused or the horizon passed. Writes {"access_refused_epoch","refresh_refused_epoch","polls","start_epoch"} to R.
  matrix_probe.py relogin <uid>  password on stdin: is a NEW SSO login possible? prints {"login": true|false}
"""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import collab_lib as L  # noqa: E402
import matrix_sso as M  # noqa: E402


def write(path, obj):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(obj, f)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=("login", "poll", "relogin"))
    ap.add_argument("uid", nargs="?")
    ap.add_argument("--out")
    ap.add_argument("--tokens")
    ap.add_argument("--horizon", type=float, default=90.0)
    a = ap.parse_args()
    if a.cmd in ("login", "relogin"):
        pw = sys.stdin.readline().strip()
        try:
            c = M.login(a.uid, pw, log=lambda *x: None)
        except Exception as e:  # noqa: BLE001
            if a.cmd == "relogin":
                print(json.dumps({"login": False, "why": type(e).__name__}))
                return 0
            raise
        if a.cmd == "relogin":
            print(json.dumps({"login": True, "mxid": c.mxid}))
            return 0
        ok = c.api("GET", "/_matrix/client/v3/account/whoami").status_code == 200
        write(a.out, {"access": c.access, "refresh": c.refresh, "client_id": c.client_id, "mxid": c.mxid})
        print(json.dumps({"logged_in": ok, "mxid": c.mxid}))
        return 0 if ok else 1
    t = json.load(open(a.tokens))
    access, refresh, cid = t["access"], t["refresh"], t["client_id"]
    start = time.time()
    res = {"start_epoch": round(start, 3), "access_refused_epoch": None, "refresh_refused_epoch": None, "polls": 0}
    n = 0
    while time.time() - start < a.horizon and (res["access_refused_epoch"] is None or res["refresh_refused_epoch"] is None):
        tick = time.time()
        n += 1
        res["polls"] = n
        if res["access_refused_epoch"] is None:
            r = L.S.get(L.HS + "/_matrix/client/v3/account/whoami", headers={"Authorization": "Bearer " + access}, timeout=15)
            if r.status_code != 200:
                res["access_refused_epoch"] = round(time.time(), 3)
                res["access_status"] = r.status_code
        if res["refresh_refused_epoch"] is None and n % 3 == 1:
            r = L.S.post(L.MAS + "/oauth2/token", data={"grant_type": "refresh_token", "refresh_token": refresh, "client_id": cid}, timeout=15)
            if r.status_code == 200:
                j = r.json()
                access, refresh = j["access_token"], j.get("refresh_token", refresh)   # the new token pair is what a live client would use
            else:
                res["refresh_refused_epoch"] = round(time.time(), 3)
                res["refresh_status"] = r.status_code
        time.sleep(max(0.0, 1.0 - (time.time() - tick)))
    write(a.out, res)
    return 0


if __name__ == "__main__":
    sys.exit(main())
