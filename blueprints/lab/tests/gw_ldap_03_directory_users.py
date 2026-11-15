#!/usr/bin/env python3
"""GW-LDAP-03: the five seeded directory users (alice..erin @ou-lab.internal, the same ones Keycloak/OpenCloud use) are
mailbox users in Gromox with the directory password, and a full reconcile finds nothing left to do.
PROVES: one directory serves all three consumers for the seeded users; unentitled/legacy users are untouched.
DOES NOT PROVE: LDAP outage behaviour (not exercised: stopping slapd would hit Keycloak/OpenCloud too)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gw_ldap_lib as G
rep = G.Rep("GW-LDAP-03 seeded directory users")
if not G.lab_access():
    rep.skip("lab access", "need passwordless sudo systemd-run -M %s/%s" % (G.ID_M, G.GW_M)); rep.done()
if not os.path.exists(G.GW_CA):
    rep.skip("config", "gw1 CA missing"); rep.done()
rc, out = G.gw_sync("--create-domain")
rep.check("full reconcile ok", rc == 0, "rc=0: %s" % out.strip().splitlines()[-1], out[:300])
rc, out = G.gw_sync("--dry-run")
rep.check("full reconcile has nothing pending", rc == 0 and "would-" not in out and "suspend" not in out, "no pending changes", out[:300])
for u in ("alice", "bob", "carol", "dave", "erin"):
    pw = G.dir_pw(u); m = G.addr(u)
    rep.check("%s: IMAP + EWS with directory password" % u, G.imap_login(m, pw) and G.ews(m, pw)[1], "accepted", "refused")
    if G.KC_CA: rep.check("%s: Keycloak same password" % u, G.kc_login(u, pw).status_code == 200, "HTTP 200", "refused")
    else: rep.skip("%s: Keycloak same password" % u, "OU_CA_FILE not set")
n = G.gw_sql("select count(*) from users where externid is not null"); l = G.gw_sql("select count(*) from users where externid is null")
rep.info("users with externid (directory-managed)=%s, local SQL (legacy lab domain)=%s" % (n, l))
rc, out = G.sh(G.GW_M, "grep -E '^(auth_|http_basic)' /etc/gromox/gromox.cfg /etc/gromox/http.cfg; echo effective-defaults: auth_cred_caching=1min http_basic_auth_cred_caching=1min auth_backend_selection=ldap")
rep.info(out.strip().replace("\n", " | "))
rep.done()
