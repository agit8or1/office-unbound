#!/usr/bin/env python3
"""GW-LDAP-02: deprovisioning delay. For throw-away LDAP users, lock the account in OpenLDAP (ldap-user.sh lock = ppolicy
pwdAccountLockedTime) and measure, with warm credential caches and an already-open IMAP session, how long until each path
refuses the (correct) password:  Keycloak password login, IMAPS login, EWS (fresh connection and keep-alive session),
ActiveSync OPTIONS, MAPI/HTTP endpoint (HTTP auth layer).  Scenarios:
  A  lock in LDAP only (no explicit action)              -> bounded by gromox credential caches
  B  lock + explicit reconcile (gw-ldap-sync.py => address_status=1) [+ Keycloak revoke if OU_KC_ADMIN_PASSWORD set]
  C  lock + SIGHUP of gromox-http/zcore/imap (drops authmgr cred cache; http basic cache is per process)
  D  unlock + reconcile restores access
Measured times are seconds after the lock command returned; POLL granularity OU_GWL_POLL (default 1 s), horizon OU_GWL_MAX (default 180 s).
PROVES the measured numbers for this build/config only (auth_cred_caching=1min, http_basic_auth_cred_caching=1min defaults).
DOES NOT PROVE: real client behaviour (Outlook/phones keep tokens/sessions), IMAP/EAS push sessions opened before the lock
beyond what is printed, ActiveSync remote wipe (needs admin-api, see results doc)."""
import os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gw_ldap_lib as G
rep = G.Rep("GW-LDAP-02 deprovision timing")
if not G.lab_access():
    rep.skip("lab access", "need passwordless sudo systemd-run -M %s/%s" % (G.ID_M, G.GW_M)); rep.done()
if not os.path.exists(G.GW_CA):
    rep.skip("config", "gw1 CA missing"); rep.done()
import requests
POLL = float(os.environ.get("OU_GWL_POLL", "1")); MAX = int(os.environ.get("OU_GWL_MAX", "180"))
KCPW = os.environ.get("OU_KC_ADMIN_PASSWORD")
if not G.wait_imap_active(rep, 120): rep.fail("precondition", "gromox-imap inactive"); rep.done()


def provision():
    u = G.new_user("gwd"); mail = G.addr(u)
    rc, out = G.dir_cmd("add", u, "opencloudUser"); assert rc == 0, out
    pw = G.dir_pw(u)
    rc, out = G.gw_sync("--user %s" % mail); assert rc == 0 and "created" in out, out
    return u, mail, pw


def probes(u, mail, pw, sess):
    """name -> callable returning True if ACCEPTED"""
    p = {}
    if G.KC_CA: p["keycloak login"] = lambda: G.kc_login(u, pw).status_code == 200
    p["IMAPS login"] = lambda: G.imap_login(mail, pw)
    p["EWS (new conn)"] = lambda: G.ews(mail, pw)[1]
    p["EWS (keep-alive session)"] = lambda: G.ews(mail, pw, sess)[1]
    p["ActiveSync OPTIONS"] = lambda: G.eas_options(mail, pw)[1]
    p["MAPI/HTTP auth"] = lambda: G.mapi_status(mail, pw)[1]
    return p


def baseline(label, u, mail, pw):
    sess = requests.Session(); sess.verify = G.GW_CA
    pr = probes(u, mail, pw, sess)
    res = {k: f() for k, f in pr.items()}
    rep.check("%s baseline: all paths accept" % label, all(res.values()), "%d paths accepted (caches now warm)" % len(res), "baseline %s" % res)
    return sess, pr, G.imap_open(mail, pw)


def measure(label, u, mail, pw, sess, pr, im, action, expect_max=None):
    t0 = time.time(); action(); tact = time.time() - t0
    t0 = time.time()
    first = {}; last_ok = {}
    stable = 0
    while time.time() - t0 < MAX:
        now = time.time() - t0
        for k, f in pr.items():
            try: acc = f()
            except Exception as e: acc = None
            if acc is False and k not in first: first[k] = now
            if acc: last_ok[k] = now; first.pop(k, None)
        if len(first) == len(pr):
            stable += 1
            if stable >= 3: break
        else: stable = 0
        time.sleep(POLL)
    alive = G.imap_alive(im)
    rep.info("%s: action took %.1fs; first refusal (s after action): %s" % (label, tact, {k: round(v, 1) for k, v in first.items()}))
    for k in pr:
        if k in first and k not in last_ok: pass
    rep.info("%s: pre-existing IMAP session still usable after refusal: %s" % (label, alive))
    return first, alive


# ---------------- A: LDAP lock only
u, mail, pw = provision(); sess, pr, im = baseline("A", u, mail, pw)
first, alive = measure("A lock-only", u, mail, pw, sess, pr, im, lambda: G.dir_cmd("lock", u))
rep.check("A: every path refuses within the cache horizon", len(first) == len(pr) and max(first.values()) <= 125,
          "all %d paths refused; max %.0fs (caches: authmgr 60s + http basic 60s)" % (len(pr), max(first.values())), "refused=%s of %d (horizon %ss)" % (sorted(first), len(pr), MAX))
rep.info("A summary (seconds): %s" % {k: round(v) for k, v in sorted(first.items())})
rep.check("A: Keycloak new login blocked immediately" if G.KC_CA else "A: keycloak", (not G.KC_CA) or first.get("keycloak login", 999) <= 3, "refused at %.1fs" % first.get("keycloak login", 0), "refused at %s" % first.get("keycloak login"))
rep.info("A: open IMAP session survives lock (no reconcile): %s" % alive)
try: im.logout()
except Exception: pass
G.dir_cmd("delete", u)

# ---------------- B: lock + explicit reconcile
u, mail, pw = provision(); sess, pr, im = baseline("B", u, mail, pw)
kc_rt = None
if G.KC_CA:
    r = G.kc_login(u, pw); kc_rt = r.json().get("refresh_token") if r.status_code == 200 else None
def act_b():
    G.dir_cmd("lock", u); rc, out = G.gw_sync("--user %s" % mail); rep.info("B reconcile: %s" % out.strip().splitlines()[0])
first, alive = measure("B lock+reconcile", u, mail, pw, sess, pr, im, act_b)
rep.check("B: every path refused", len(first) == len(pr), "max %.0fs, summary %s" % (max(first.values()), {k: round(v, 1) for k, v in sorted(first.items())}), "not refused: %s" % sorted(set(pr) - set(first)))
rep.info("B: open IMAP session survives lock+reconcile: %s" % alive)
# D: unlock + reconcile
t0 = time.time(); G.dir_cmd("unlock", u); rc, out = G.gw_sync("--user %s" % mail)
ok = False
while time.time() - t0 < 90 and not ok:
    ok = G.imap_login(mail, pw) and G.ews(mail, pw)[1]; time.sleep(1)
rep.check("D: unlock + reconcile restores IMAP+EWS", ok, "restored after %.0fs" % (time.time() - t0), "not restored within 90s")
# KC revoke (t06 finding): LDAP lock alone leaves refresh tokens valid
if kc_rt and KCPW:
    G.dir_cmd("lock", u); G.gw_sync("--user %s" % mail)
    tok = "https://%s/realms/ou-lab/protocol/openid-connect/token" % G.KC_HOST
    def refresh(): return requests.post(tok, data={"grant_type": "refresh_token", "client_id": "ou-lab-test", "refresh_token": kc_rt}, verify=G.KC_CA, timeout=30).status_code
    before = refresh()
    adm = requests.post("https://%s/realms/master/protocol/openid-connect/token" % G.KC_HOST, verify=G.KC_CA, timeout=30, data={"grant_type": "password", "client_id": "admin-cli", "username": "kcadmin", "password": KCPW})
    H = {"Authorization": "Bearer " + adm.json()["access_token"]}; base = "https://%s/admin/realms/ou-lab" % G.KC_HOST
    kid = requests.get(base + "/users", params={"username": u, "exact": "true"}, headers=H, verify=G.KC_CA, timeout=30).json()[0]["id"]
    requests.post("%s/users/%s/logout" % (base, kid), headers=H, verify=G.KC_CA, timeout=30)
    after = refresh()
    rep.info("Keycloak refresh token after LDAP lock: HTTP %s; after admin logout: HTTP %s" % (before, after))
    rep.check("Keycloak: LDAP lock alone does not kill refresh token; revoke does", before == 200 and after != 200, "confirms t06: revoke (logout/consent/disable) required", "before=%s after=%s" % (before, after))
    requests.delete("%s/users/%s" % (base, kid), headers=H, verify=G.KC_CA, timeout=30)
else:
    rep.skip("Keycloak refresh/revoke", "needs OU_CA_FILE and OU_KC_ADMIN_PASSWORD")
try: im.logout()
except Exception: pass
G.dir_cmd("delete", u); G.gw_sync()

# ---------------- C: lock + SIGHUP
if os.environ.get("OU_GWL_SKIP_HUP") == "1":
    rep.skip("C lock+SIGHUP", "OU_GWL_SKIP_HUP=1")
elif not G.wait_imap_active(rep, 300): rep.fail("C precondition", "gromox-imap inactive")
else:
    u, mail, pw = provision(); sess, pr, im = baseline("C", u, mail, pw)
    def act_c():
        G.dir_cmd("lock", u)
        rc, out = G.sh(G.GW_M, "systemctl kill -s HUP gromox-http gromox-zcore gromox-imap; sleep 1; systemctl is-active gromox-http gromox-zcore gromox-imap | tr '\\n' ' '")
        rep.info("C SIGHUP: %s" % out.strip())
    first, alive = measure("C lock+SIGHUP", u, mail, pw, sess, pr, im, act_c)
    rep.check("C: paths refused", len(first) == len(pr), "max %.0fs, summary %s" % (max(first.values()), {k: round(v, 1) for k, v in sorted(first.items())}), "not refused: %s" % sorted(set(pr) - set(first)))
    rep.info("C: open IMAP session survives lock+HUP: %s" % alive)
    G.dir_cmd("delete", u); G.gw_sync()
rep.done()
