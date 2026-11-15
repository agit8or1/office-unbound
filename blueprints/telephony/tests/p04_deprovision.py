#!/usr/bin/env python3
"""P04 deprovisioning: carol is locked in the authoritative LDAP with the documented path (ldap-user.sh lock, ppolicy pwdAccountLockedTime) while
she is registered (web + native) and in a live call with bob.
  A) explicit re-run of provisioning (`ou-pbx sync`): measure lock -> sync done -> REGISTER refused; live call hung up; contacts gone.
  B) timer only (ou-pbx-sync.timer, every 15 s): measure lock -> REGISTER refused (worst case should be ~15 s + sync time).
Finally carol is unlocked and must be re-provisioned (old credentials are NOT resurrected)."""
import json
import os
import re
import sys
import time

from playwright.sync_api import sync_playwright

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pbx_lib as L
from sip_probe import register

rep = L.Report("P04 deprovisioning: lock carol in LDAP -> PBX refuses her")
KC = "/root/lab/spike-identity-files/kc/ldap-user.sh"


def issue(user, dev):
    return json.loads(L.pbx("cd /tmp; sudo -u ou-pbx ou-pbx issue --user %s --device %s" % (user, dev)))


def lock(u):
    rc, out, err = L.sh("ou-id1", "%s lock %s" % (KC, u))
    return rc == 0


def unlock(u):
    return L.sh("ou-id1", "%s unlock %s" % (KC, u))[0] == 0


def poll_refused(user, pw, limit):
    t0 = time.time()
    last = None
    while time.time() - t0 < limit:
        last = register(user, pw, L.CA)
        if last != 200:
            return time.time() - t0, last
        time.sleep(0.5)
    return None, last


# ---- scenario A: explicit sync, with a live web call
nc = issue("carol", "native")
bob_native = issue("bob", "native")
rep.check("baseline: carol.native REGISTER over TLS accepted", register(nc["username"], nc["password"], L.CA) == 200)
rep.check("baseline: bob.native REGISTER accepted (control user)", register(bob_native["username"], bob_native["password"], L.CA) == 200)
with sync_playwright() as p:
    b = L.browser(p)
    try:
        cb, pb = L.open_phone(b, "bob")
        cc, pc = L.open_phone(b, "carol")
        rep.check("both web softphones registered", L.wait_state(pb, "#status", "registered", 30) is not None and L.wait_state(pc, "#status", "registered", 30) is not None)
        pb.fill("#number", "1003")
        pb.click("#call")
        pc.wait_for_selector("#answer", state="visible", timeout=15000)
        pc.click("#answer")
        rep.check("live call bob <-> carol connected", L.wait_state(pb, "#callstate", "connected", 20) is not None)
        time.sleep(2)
        pre = L.ast("core show channels concise")
        rep.check("PBX has the 2 live channels", len(re.findall(r"^PJSIP/", pre, re.M)) == 2)
        # make the timer unable to pre-empt the explicit run
        L.pbx("systemctl stop ou-pbx-sync.timer")
        t_lock = time.time()
        ok = lock("carol")
        t_locked = time.time()
        rep.check("carol locked in LDAP (ldap-user.sh lock, pwdAccountLockedTime set)", ok, "%.1fs" % (t_locked - t_lock))
        rc, out, err = L.sh(L.MACHINE, "cd /tmp; sudo -u ou-pbx ou-pbx sync")
        t_sync = time.time()
        print("   | sync output: " + out.strip())
        rep.check("provisioning re-run removed carol's endpoints", "carol.web" in out and "carol.native" in out and '"removed"' in out)
        dt, code = poll_refused(nc["username"], nc["password"], 10)
        t_ref = time.time()
        rep.check("carol.native REGISTER with her (previously valid) credential is now refused", dt is not None and code in (401, 403, 404), "status %s" % code)
        print("   | MEASURED A (explicit run): lock %.1fs | LDAP lock -> sync finished %.1fs | LDAP lock -> first refused REGISTER %.1fs"
              % (t_locked - t_lock, t_sync - t_locked, t_ref - t_locked))
        rep.check("refused within 5 s of the LDAP change when provisioning is re-run immediately", t_ref - t_locked < 5, "%.1fs" % (t_ref - t_locked))
        time.sleep(1)
        post = L.ast("core show channels concise")
        rep.check("live call of carol hung up by the PBX", "carol" not in post and "PJSIP" not in post, post.strip()[:120] or "no channels")
        contacts = L.ast("pjsip show contacts")
        rep.check("carol's registered contacts (web + native) deleted on the PBX", "carol." not in contacts, re.sub(r"\s+", " ", contacts)[-160:])
        rep.check("bob (control user) still registers", register(bob_native["username"], bob_native["password"], L.CA) == 200)
        old_web = L.wait_state(pc, "#callstate", "ended", 5)
        rep.check("carol's browser call state is 'ended' (media/signalling torn down)", old_web is not None, pc.get_attribute("#callstate", "data-state"))
    finally:
        b.close()

# ---- restore, re-provision, scenario B: timer only
rep.check("unlock carol", unlock("carol"))
L.pbx("systemctl start ou-pbx-sync.timer; sudo -u ou-pbx ou-pbx sync >/dev/null")
nc2 = issue("carol", "native")
rep.check("after unlock the OLD credential still does not work (purged, not resurrected)", register(nc["username"], nc["password"], L.CA) in (401, 403))
rep.check("re-issued credential works", register(nc2["username"], nc2["password"], L.CA) == 200)
time.sleep(1)
L.pbx("systemctl restart ou-pbx-sync.timer")
time.sleep(2)
t_lock = time.time()
lock("carol")
t_locked = time.time()
dt, code = poll_refused(nc2["username"], nc2["password"], 45)
t_ref = time.time()
print("   | MEASURED B (timer only, 15 s period): LDAP lock -> first refused REGISTER %.1fs (status %s)" % (t_ref - t_locked, code))
rep.check("timer-driven deprovisioning refuses carol within 20 s (15 s period + sync)", dt is not None and (t_ref - t_locked) < 20, "%.1fs" % (t_ref - t_locked))
# ---- leave the lab in a clean state: carol unlocked, no stale devices
unlock("carol")
L.pbx("sudo -u ou-pbx ou-pbx sync >/dev/null; sudo -u ou-pbx ou-pbx revoke --user bob --device native >/dev/null; sudo -u ou-pbx ou-pbx revoke --user carol --device native >/dev/null")
rep.finish()
