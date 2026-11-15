#!/usr/bin/env python3
"""T06 Disable/deprovision a user: how long do existing sessions and tokens keep working? (ADR-0004 target <= 5 min)

Two scenarios, each with a throw-away directory user:
  A  directory only: lock the account in LDAP (ppolicy pwdAccountLockedTime) and do nothing else
  B  full deprovision as ICS must do it: LDAP lock + Keycloak admin API (logout sessions, revoke offline consents,
     disable the Keycloak user)
Per scenario we log in with (1) an SSO session refresh token and (2) an OFFLINE refresh token (desktop/mobile style),
keep the original access token, lock/disable, then poll every POLL seconds and record the first time each of these
stops working: new password login, SSO refresh, offline refresh, original access token against OpenCloud
(Graph /me and WebDAV). Access tokens live 300 s in this realm (upper bound for stateless JWT validation).

Needs env: OU_CA_FILE, and the directory/KC admin hooks:
  OU_DIR_CMD   template run on the test host, e.g.
               'sudo systemd-run -M ou-id1 --quiet --pipe --wait /root/lab/spike-identity-files/kc/ldap-user.sh {action} {user} {extra}'
  OU_DIR_PW_CMD template printing the user's password line, e.g.
               'sudo systemd-run -M ou-id1 --quiet --pipe --wait /bin/grep ^OU_PASSWORD_{USER}= /root/ou-lab-secrets/test-users.env'
  OU_KC_ADMIN_PASSWORD  Keycloak bootstrap admin password (scenario B; kcadmin)
  OU_T06_MAX   poll horizon seconds (default 420), OU_T06_POLL (default 5)
"""
import os
import shlex
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ou_lab as L

rep = L.Report("T06 Disable user: session/token lifetime after deprovisioning")
if not L.need_requests(rep):
    rep.finish()
import requests

DIR = os.environ.get("OU_DIR_CMD")
DIRPW = os.environ.get("OU_DIR_PW_CMD")
KCPW = os.environ.get("OU_KC_ADMIN_PASSWORD")
if not (L.CA_FILE and DIR and DIRPW):
    rep.skipped("config", "need OU_CA_FILE, OU_DIR_CMD, OU_DIR_PW_CMD"); rep.finish()
V = L.verify()
MAX = int(os.environ.get("OU_T06_MAX", "420")); POLL = int(os.environ.get("OU_T06_POLL", "5"))
TOKEN_URL = L.oidc_base() + "/protocol/openid-connect/token"


def run(tmpl, **kw):
    kw.setdefault("extra", "")
    cmd = shlex.split(tmpl.format(**{k: v for k, v in kw.items()}))
    p = subprocess.run([c for c in cmd if c != ""], capture_output=True, text=True, timeout=120)
    if p.returncode != 0:
        raise RuntimeError("%s failed: %s" % (cmd[-3:], p.stderr[:200]))
    return p.stdout


def grant(user, pw, scope):
    r = requests.post(TOKEN_URL, data={"grant_type": "password", "client_id": "ou-lab-test", "username": user,
                                       "password": pw, "scope": scope}, verify=V, timeout=30)
    return r


def refresh(rt):
    return requests.post(TOKEN_URL, data={"grant_type": "refresh_token", "client_id": "ou-lab-test", "refresh_token": rt},
                         verify=V, timeout=30).status_code


def oc_me(at):
    return requests.get("https://%s/graph/v1.0/me" % L.HOST_FILES, headers={"Authorization": "Bearer " + at}, verify=V, timeout=30).status_code


def oc_dav(at, user):
    return requests.request("PROPFIND", "https://%s/remote.php/dav/files/%s" % (L.HOST_FILES, user),
                            headers={"Authorization": "Bearer " + at, "Depth": "0"}, verify=V, timeout=30).status_code


def kc_admin():
    r = requests.post("https://%s/realms/master/protocol/openid-connect/token" % L.HOST_KC, verify=V, timeout=30,
                      data={"grant_type": "password", "client_id": "admin-cli", "username": "kcadmin", "password": KCPW})
    r.raise_for_status()
    return {"Authorization": "Bearer " + r.json()["access_token"]}


def kc_revoke(user):
    H = kc_admin()
    base = "https://%s/admin/realms/%s" % (L.HOST_KC, L.REALM)
    uid = requests.get(base + "/users", params={"username": user, "exact": "true"}, headers=H, verify=V, timeout=30).json()[0]["id"]
    out = {}
    out["consents"] = [requests.delete("%s/users/%s/consents/%s" % (base, uid, c), headers=H, verify=V, timeout=30).status_code
                       for c in ("ou-lab-test",)]
    out["logout"] = requests.post("%s/users/%s/logout" % (base, uid), headers=H, verify=V, timeout=30).status_code
    out["disable"] = requests.put("%s/users/%s" % (base, uid), json={"enabled": False}, headers=H, verify=V, timeout=30).status_code
    return uid, out


def kc_delete(user):
    H = kc_admin()
    base = "https://%s/admin/realms/%s" % (L.HOST_KC, L.REALM)
    us = requests.get(base + "/users", params={"username": user, "exact": "true"}, headers=H, verify=V, timeout=30).json()
    for u in us:
        requests.delete("%s/users/%s" % (base, u["id"]), headers=H, verify=V, timeout=30)


def scenario(label, user, full):
    run(DIR, action="add", user=user, extra="opencloudUser")
    pw = run(DIRPW, USER=user.upper()).strip().split("=", 1)[1]
    sso = grant(user, pw, "openid profile email")
    off = grant(user, pw, "openid profile email offline_access")
    if not rep.check("%s: baseline login" % label, sso.status_code == 200 and off.status_code == 200,
                     "SSO + offline tokens issued", "HTTP %s/%s %s" % (sso.status_code, off.status_code, sso.text[:100])):
        return
    at, sso_rt, off_rt = sso.json()["access_token"], sso.json()["refresh_token"], off.json()["refresh_token"]
    base = (oc_me(at), oc_dav(at, user), refresh(sso_rt), refresh(off_rt))
    rep.check("%s: baseline OpenCloud+refresh" % label, base == (200, 207, 200, 200), "me/dav/refresh/offline = %s" % (base,),
              "baseline %s (expected 200,207,200,200)" % (base,))
    t0 = time.time()
    run(DIR, action="lock", user=user)
    t_lock = time.time() - t0
    kcinfo = ""
    if full:
        uid, out = kc_revoke(user)
        kcinfo = " kc-revoke=%s done at +%ds" % (out, time.time() - t0)
    print("INFO %s: directory lock applied at t0 (+%.1fs)%s" % (label, t_lock, kcinfo))
    first = {}
    while time.time() - t0 < MAX and len(first) < 5:
        t = time.time() - t0
        probes = {
            "new password login": lambda: grant(user, pw, "openid").status_code != 200,
            "SSO refresh token": lambda: refresh(sso_rt) != 200,
            "offline refresh token": lambda: refresh(off_rt) != 200,
            "old access token -> OpenCloud /me": lambda: oc_me(at) not in (200,),
            "old access token -> OpenCloud WebDAV": lambda: oc_dav(at, user) not in (207,),
        }
        for k, f in probes.items():
            if k not in first:
                try:
                    if f():
                        first[k] = t
                except Exception as e:  # noqa: BLE001
                    print("INFO probe %s error %s" % (k, str(e)[:80]))
        time.sleep(POLL)
    for k in ("new password login", "SSO refresh token", "offline refresh token",
              "old access token -> OpenCloud /me", "old access token -> OpenCloud WebDAV"):
        v = first.get(k)
        txt = "denied after %.0fs" % v if v is not None else "STILL WORKING after %ds (horizon)" % MAX
        # ADR-0004 target: <= 300 s. new logins must be immediate (<= 15 s).
        limit = 15 if k == "new password login" else 300
        rep.check("%s: %s" % (label, k), v is not None and v <= limit, txt, txt + " (target <= %ds)" % limit)
    # cleanup
    try:
        run(DIR, action="delete", user=user)
        if KCPW:
            kc_delete(user)
    except Exception as e:  # noqa: BLE001
        print("INFO cleanup error: %s" % str(e)[:100])


scenario("A directory-lock only", "mallory" + L.RUN_ID[:4], False)
if KCPW:
    scenario("B lock + Keycloak revoke", "trent" + L.RUN_ID[:4], True)
else:
    rep.skipped("scenario B", "OU_KC_ADMIN_PASSWORD not set")
rep.finish()
