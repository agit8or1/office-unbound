#!/usr/bin/env python3
"""C02 Deprovisioning: how long does alice's Matrix access survive?
 A  LDAP lock + Keycloak logout/disable only (what the identity spike's ICS flow does)  -> does Matrix notice? (MAS owns its sessions)
 B  + MAS admin API `lock` (service client, urn:mas:admin)                              -> seconds until access token / refresh / live /sync end
 C  restore (LDAP unlock, Keycloak enable, MAS unlock) and prove alice can log in again.
Env: OU_C02_A_SECONDS (default 330 = past the 300 s access token lifetime), OU_C02_POLL (default 10)."""
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import collab_lib as L
import matrix_sso as M

A_SECONDS = int(os.environ.get("OU_C02_A_SECONDS", "330"))
POLL = int(os.environ.get("OU_C02_POLL", "10"))
LDAP = "/root/lab/spike-identity-files/kc/ldap-user.sh"
ADMIN_ID = "01JZ3QTC0C0PGGYC4MPXMFE0BN"
SECRET_FILE = os.environ.get("OU_MAS_ADMIN_SECRET_FILE", "/tmp/claude-1000/-home-administrator/a1d917f8-7438-424e-a57a-793b46deb95e/scratchpad/chat-r/masadmin.sec")
rep = L.Report("C02 Deprovisioning alice: Matrix session lifetime after LDAP lock + Keycloak revoke (+ MAS lock)")


def mas_admin():
    r = L.S.post(L.MAS + "/oauth2/token", auth=(ADMIN_ID, open(SECRET_FILE).read().strip()), data={"grant_type": "client_credentials", "scope": "urn:mas:admin"}, timeout=30)
    r.raise_for_status()
    return {"Authorization": "Bearer " + r.json()["access_token"]}


def mas_call(method, path):
    return L.S.request(method, L.MAS + "/api/admin/v1" + path, headers=mas_admin(), timeout=30)


pw = L.password("alice")
alice = M.login("alice", pw, log=lambda *a: None)
rep.check("alice logged in before deprovisioning", alice.mxid == "@alice:matrix.ou-lab.internal", alice.mxid)

# live long-poll sync in the background: records when the server first refuses it
state = {"end": None, "since": None, "stop": False}


def sync_loop():
    while not state["stop"]:
        try:
            r = alice.api("GET", "/_matrix/client/v3/sync?timeout=5000" + ("&since=" + state["since"] if state["since"] else ""))
        except Exception as e:  # noqa
            time.sleep(1)
            continue
        if r.status_code != 200:
            state["end"] = (time.time(), r.status_code)
            return
        state["since"] = r.json().get("next_batch")


th = threading.Thread(target=sync_loop, daemon=True)
th.start()
time.sleep(3)
rep.check("live /sync running", state["end"] is None and state["since"] is not None)

H = L.kc_admin_headers()
uid = L.kc_user_id(H, "alice")
kc = "%s/admin/realms/%s/users/%s" % (L.KC, L.REALM, uid)
cleanup = []
try:
    # ---------- A: directory + Keycloak only
    t0 = time.time()
    L.idm(LDAP, "lock", "alice")
    L.S.post(kc + "/logout", headers=H, timeout=30)
    L.S.put(kc, json={"enabled": False}, headers=H, timeout=30)
    cleanup.append("ldap"); cleanup.append("kc")
    t_a = time.time() - t0
    print("A: LDAP lock + Keycloak logout + disable done in %.1fs" % t_a)
    try:
        M.login("alice", pw, log=lambda *a: None)
        new_ok = True
    except Exception as e:  # noqa
        new_ok = False
    rep.check("A: NEW SSO login for alice is refused immediately", not new_ok)
    first_fail = None
    t_end = time.time() + A_SECONDS
    n = 0
    while time.time() < t_end:
        r = alice.api("GET", "/_matrix/client/v3/account/whoami")
        n += 1
        if r.status_code != 200 and first_fail is None:
            first_fail = (time.time() - t0, r.status_code)
        time.sleep(POLL)
    rr = alice.do_refresh()
    refresh_ok = rr.status_code == 200
    who = alice.api("GET", "/_matrix/client/v3/account/whoami")
    rep.check("A: access token (300 s ttl) failed at some point within %ds" % A_SECONDS, first_fail is not None, first_fail if first_fail else "never failed in %d polls (%d s)" % (n, A_SECONDS))
    rep.check("A (FINDING, expected FAIL of 'revocation'): refresh token still works after LDAP lock + KC disable + KC logout", not refresh_ok,
              "refresh -> HTTP %s; whoami with refreshed token -> %s" % (rr.status_code, who.status_code))
    rep.check("A (FINDING): live /sync still running after %ds" % A_SECONDS, state["end"] is None, state["end"])

    # restart the live sync with the refreshed token
    state.update(end=None, since=None)
    th = threading.Thread(target=sync_loop, daemon=True)
    th.start()
    time.sleep(3)

    # ---------- B: MAS admin API lock
    u = mas_call("GET", "/users/by-username/alice").json()["data"]
    mid = u["id"]
    tok_orig = alice.access
    t1 = time.time()
    lk = mas_call("POST", "/users/%s/lock" % mid)
    rep.check("B: MAS admin API lock accepted", lk.status_code == 200, "HTTP %s in %.2fs" % (lk.status_code, time.time() - t1))
    cleanup.append("mas:" + mid)
    time.sleep(2)
    rf = alice.do_refresh()
    tok_new = alice.access if rf.status_code == 200 else None
    rep.check("B: refresh token refused after MAS lock", rf.status_code != 200, "HTTP %s %s" % (rf.status_code, rf.text[:80]))
    end = {}
    horizon = time.time() + 240
    while time.time() < horizon and len(end) < (2 if tok_new else 1):
        for label, t in (("original access token", tok_orig), ("token obtained by refresh after lock", tok_new)):
            if t and label not in end and L.S.get(L.HS + "/_matrix/client/v3/account/whoami", headers={"Authorization": "Bearer " + t}, timeout=30).status_code != 200:
                end[label] = time.time() - t1
        time.sleep(1)
    for label in ("original access token", "token obtained by refresh after lock"):
        if label == "token obtained by refresh after lock" and not tok_new:
            continue
        rep.check("B: %s rejected by Synapse after MAS lock" % label, label in end, ("after %.0fs" % end[label]) if label in end else "still valid after 240s")
    th.join(timeout=10)
    se = state["end"]
    rep.check("B: live /sync terminated by server", se is not None, "%.0fs after lock (HTTP %s)" % (se[0] - t1, se[1]) if se else "still running")
    try:
        M.login("alice", pw, log=lambda *a: None)
        relog = True
    except Exception:  # noqa
        relog = False
    rep.check("B: re-login still impossible (LDAP+KC+MAS all locked)", not relog)
finally:
    state["stop"] = True
    # ---------- C: restore
    for c in cleanup:
        if c == "ldap":
            L.idm(LDAP, "unlock", "alice")
        elif c == "kc":
            er = L.S.put(kc, json={"enabled": True}, headers=H, timeout=30)
            print("restore: Keycloak enable -> HTTP", er.status_code)
        elif c.startswith("mas:"):
            mas_call("POST", "/users/%s/unlock" % c[4:])
    time.sleep(2)
    try:
        c2 = M.login("alice", pw, log=lambda *a: None)
        rep.check("C: after restore alice can log in again", c2.mxid == "@alice:matrix.ou-lab.internal", c2.mxid)
        # D: ending her MAS sessions (instead of lock) - how fast does Synapse stop honouring the token?
        mid = mas_call("GET", "/users/by-username/alice").json()["data"]["id"]
        ok0 = c2.api("GET", "/_matrix/client/v3/account/whoami").status_code == 200   # populates Synapse's introspection cache
        sess = mas_call("GET", "/oauth2-sessions?filter[user]=%s&filter[status]=active" % mid).json()
        n_fin = 0
        t2 = time.time()
        for sd in sess.get("data", []):
            n_fin += mas_call("POST", "/oauth2-sessions/%s/finish" % sd["id"]).status_code == 200
        rep.check("D: MAS admin API finishes alice's oauth2 sessions", ok0 and n_fin >= 1, "%d session(s)" % n_fin)
        dend = None
        while time.time() < t2 + 240:
            if c2.api("GET", "/_matrix/client/v3/account/whoami").status_code != 200:
                dend = time.time() - t2
                break
            time.sleep(1)
        rep.check("D: token rejected by Synapse after session finish", dend is not None, ("after %.0fs" % dend) if dend is not None else "still valid after 240s")
    except Exception as e:  # noqa
        rep.check("C: after restore alice can log in again", False, str(e)[:150])
rep.finish()
