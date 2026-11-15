#!/usr/bin/env python3
"""C05 Keycloak back-channel logout -> MAS (`on_backchannel_logout: logout_all`) -> Synapse.
Does a plain Keycloak user logout (admin API, what ICS does first on deprovision) end the Matrix session without any MAS admin call?
Measures seconds until Synapse refuses alice's token, and whether the refresh token still works."""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import collab_lib as L
import matrix_sso as M

rep = L.Report("C05 Keycloak user logout -> MAS back-channel logout -> Matrix session end")
pw = L.password("alice")
alice = M.login("alice", pw, log=lambda *a: None)
rep.check("alice logged in", bool(alice.mxid), alice.mxid)
rep.check("token works (primes Synapse's introspection cache)", alice.api("GET", "/_matrix/client/v3/account/whoami").status_code == 200)
H = L.kc_admin_headers()
uid = L.kc_user_id(H, "alice")
t0 = time.time()
r = L.S.post("%s/admin/realms/%s/users/%s/logout" % (L.KC, L.REALM, uid), headers=H, timeout=30)
rep.check("Keycloak admin logout of alice", r.status_code == 204, r.status_code)
tok = alice.access
end = None
refreshed = None
while time.time() < t0 + 240:
    if L.S.get(L.HS + "/_matrix/client/v3/account/whoami", headers={"Authorization": "Bearer " + tok}, timeout=30).status_code != 200:
        end = time.time() - t0
        break
    time.sleep(1)
rep.check("Matrix access token rejected after ONLY a Keycloak logout (no MAS admin call)", end is not None,
          ("after %.0fs" % end) if end is not None else "still valid after 240s")
rf = alice.do_refresh()
rep.check("refresh token refused after back-channel logout", rf.status_code != 200, "HTTP %s" % rf.status_code)
c2 = M.login("alice", pw, log=lambda *a: None)
rep.check("alice (not disabled) can sign in again", bool(c2.mxid))
rep.finish()
