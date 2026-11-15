#!/usr/bin/env python3
"""GW-LDAP-01: ONE user store. Create a brand-new user ONLY in OpenLDAP (ldap-user.sh), run the Gromox reconcile step
(gw-ldap-sync.py), then the same password must work for Keycloak, OpenCloud, IMAPS, EWS, ActiveSync, MAPI/HTTP and mail
must be received. Also: TLS to LDAP is verified, the bind account is read-only/limited, legacy SQL users stay separate,
the sync is idempotent and refuses to touch local users.
PROVES (lab, one run): the above for one user. DOES NOT PROVE: Outlook/phone clients, group-to-DL sync, many users,
LDAP outage behaviour (see gw_ldap_03)."""
import os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gw_ldap_lib as G
rep = G.Rep("GW-LDAP-01 provision from OpenLDAP -> Gromox")
if not G.lab_access():
    rep.skip("lab access", "need passwordless sudo systemd-run -M %s/%s" % (G.ID_M, G.GW_M)); rep.done()
if not os.path.exists(G.GW_CA):
    rep.skip("config", "gw1 CA %s missing" % G.GW_CA); rep.done()
import requests
if not G.wait_imap_active(rep, 120): rep.fail("precondition", "gromox-imap inactive"); rep.done()

# 1. LDAP transport + bind account
rc, out = G.sh(G.GW_M, "OU_LDAP_CA=/etc/ssl/certs/ca-certificates.crt %s --dry-run" % G.SYNC)
rep.check("LDAPS certificate verification enforced", rc == 2 and "CERTIFICATE_VERIFY_FAILED" in out, "sync with wrong CA refused (rc=2, CERTIFICATE_VERIFY_FAILED)", "rc=%s %s" % (rc, out[:200]))
rc, out = G.sh(G.GW_M, "grep -E '^ldap_host=ldaps://' /etc/gromox/ldap_adaptor.cfg; grep -c ldap_start_tls=false /etc/gromox/ldap_adaptor.cfg; stat -c '%a %U:%G' /etc/gromox/ldap_adaptor.cfg")
rep.check("ldap_adaptor.cfg uses ldaps, 0640", "ldaps://" in out and "640 root:gromoxcf" in out, "ldaps:// + mode 640 root:gromoxcf", out[:200])
rc, out = G.sh(G.ID_M, "export LDAPTLS_CACERT=/etc/ou-lab/tls/ca.crt; B=dc=ou-lab,dc=internal; S='ldapsearch -LLL -x -H ldaps://ldap.ou-lab.internal -D cn=svc-gromox,ou=system,'$B' -y /root/ou-lab-secrets/ldap-gromox-password'; "
                "echo PW:$($S -b ou=people,$B -s one '(uid=alice)' userPassword | grep -c userPassword); echo GRP:$($S -b ou=groups,$B 2>&1 | grep -c -i 'No such object'); "
                "echo MOD:$(printf 'dn: uid=alice,ou=people,'$B'\\nchangetype: modify\\nreplace: displayName\\ndisplayName: x\\n' | ldapmodify -x -H ldaps://ldap.ou-lab.internal -D cn=svc-gromox,ou=system,$B -y /root/ou-lab-secrets/ldap-gromox-password 2>&1 | grep -c -i 'insufficient')")
rep.check("svc-gromox is read-only and limited", "PW:0" in out and "GRP:1" in out and "MOD:1" in out, "cannot read userPassword, cannot see ou=groups, cannot write (Insufficient access)", out[:200])

# 2. new user, directory only
u = G.new_user(); mail = G.addr(u)
rc, out = G.dir_cmd("add", u, "opencloudUser")
if not rep.check("ldap-user.sh add %s" % u, rc == 0, "added to OpenLDAP (mail-users + opencloudUser)", out[:200]): rep.done()
pw = G.dir_pw(u)
rep.check("pre-sync: gromox does not know the user", G.gw_sql("select count(*) from users where username='%s'" % mail) == "0" and not G.imap_login(mail, pw),
          "no SQL row, IMAP login refused before sync", "user visible before sync")
rc, out = G.gw_sync("--dry-run --user %s" % mail)
rep.check("sync --dry-run", "would-create" in out and G.gw_sql("select count(*) from users where username='%s'" % mail) == "0", "would-create, nothing written", out[:200])
# a pre-existing LOCAL (externid NULL) row with the same address must NOT be silently taken over
G.sh(G.GW_M, "mysql email -e \"insert into users (username,password,domain_id,group_id,maildir,privilege_bits,address_status) select '%s','!',id,0,'/nonexistent',15,0 from domains where domainname='%s'\"" % (mail, G.MAIL_DOMAIN))
rc, out = G.gw_sync("--user %s" % mail)
rep.check("sync refuses to adopt local user", rc == 1 and "conflict" in out and G.gw_sql("select count(*) from users where username='%s' and externid is null" % mail) == "1", "conflict reported, rc=1, row untouched", "rc=%s %s" % (rc, out[:200]))
G.sh(G.GW_M, "mysql email -e \"delete from users where username='%s'\"" % mail)
t0 = time.time(); rc, out = G.gw_sync("--user %s" % mail); dt = time.time() - t0
rep.check("sync creates user", rc == 0 and "created" in out, "created in %.1fs: %s" % (dt, out.strip().splitlines()[0][:100]), "rc=%s %s" % (rc, out[:300]))
row = G.gw_sql("select address_status, cast(externid as char), maildir from users where username='%s'" % mail).split("\t")
rc, ldapid = G.sh(G.ID_M, "export LDAPTLS_CACERT=/etc/ou-lab/tls/ca.crt; ldapsearch -LLL -x -H ldaps://ldap.ou-lab.internal -D cn=admin,dc=ou-lab,dc=internal -y /root/ou-lab-secrets/ldap-admin-password -b uid=%s,ou=people,dc=ou-lab,dc=internal entryUUID | awk '/^entryUUID/{print $2}'" % u)
rep.check("externid == LDAP entryUUID, status active", len(row) == 3 and row[0] == "0" and row[1] == ldapid.strip() and ldapid.strip(), "externid=%s status=0" % row[1] if len(row) == 3 else "", "row=%s ldap=%s" % (row, ldapid.strip()))
rc, out = G.gw_sync("--user %s" % mail)
rep.check("sync idempotent", "unchanged" in out, "second run: unchanged", out[:200])

# 3. same password everywhere
if G.KC_CA:
    r = G.kc_login(u, pw)
    rep.check("Keycloak password grant", r.status_code == 200, "HTTP 200 (LDAP federation, user imported on first login)", "HTTP %s %s" % (r.status_code, r.text[:120]))
    if r.status_code == 200:
        me = requests.get("https://%s/graph/v1.0/me" % G.OC_HOST, headers={"Authorization": "Bearer " + r.json()["access_token"]}, verify=G.KC_CA, timeout=30)
        rep.check("OpenCloud accepts the token (same LDAP)", me.status_code == 200, "graph /me 200 mail=%s" % (me.json().get("mail") if me.status_code == 200 else ""), "HTTP %s %s" % (me.status_code, me.text[:120]))
else:
    rep.skip("Keycloak/OpenCloud login", "OU_CA_FILE not set"); rep.skip("OpenCloud token", "OU_CA_FILE not set")
rep.check("IMAPS login", G.imap_login(mail, pw), "same password accepted", "refused")
rep.check("IMAPS wrong password refused", not G.imap_login(mail, pw + "x"), "refused", "accepted!")
st, ok = G.ews(mail, pw); rep.check("EWS GetFolder inbox", ok, "HTTP 200 Success", "HTTP %s" % st)
st, ok = G.ews(mail, pw + "x"); rep.check("EWS wrong password -> 401", st == 401, "401", "HTTP %s" % st)
st, ok = G.eas_options(mail, pw); rep.check("ActiveSync OPTIONS", ok, "HTTP 200", "HTTP %s" % st)
mc = G.mapi_connect(mail, pw); rep.check("MAPI/HTTP Connect", mc is not None and mc[0] == "0", "X-ResponseCode=0 status/err=%s" % (mc[1],), "result=%s" % (mc,))
tok = "OU-LDAP-%s" % G.RUN
try:
    refused = G.send_mail("alice@ou-lab.internal", mail, "ldap probe " + tok)
    rep.check("SMTP :25 accepts new recipient", not refused, "accepted (postfix SQL map)", str(refused))
except Exception as e: rep.fail("SMTP :25 accepts new recipient", str(e)[:200])
rep.check("mail received (IMAP)", G.imap_fetch_subject(mail, pw, tok), "token found in INBOX", "not delivered")

# 4. single store / separation from legacy SQL users
cnt = G.gw_sql("select count(*) from users where externid is null and username not like '%@ou-lab.internal' ")
dom_local = G.gw_sql("select count(*) from users where externid is null and username like '%@ou-lab.internal'")
rep.check("legacy SQL users separate", dom_local == "0" and int(cnt) >= 8, "%s local-password users, all in legacy domain gw1.ou-lab.internal; 0 local users in %s" % (cnt, G.MAIL_DOMAIN), "local=%s inLDAPdomain=%s" % (cnt, dom_local))
import re
env = dict(l.strip().split("=", 1) for l in open("/etc/office-unbound/lab/gw1-users.env") if l.startswith("OU_GW1_PW_"))
lp = env.get("OU_GW1_PW_alice")
if lp:
    rep.check("legacy user still works (SQL password)", G.imap_login("alice@gw1.ou-lab.internal", lp), "alice@gw1 SQL login ok", "refused")
    rep.check("legacy user cannot use LDAP password", not G.imap_login("alice@gw1.ou-lab.internal", G.dir_pw("alice")), "refused", "accepted")

# cleanup: delete in directory, reconcile -> suspended; remove KC shadow user if admin pw is set
G.dir_cmd("delete", u); rc, out = G.gw_sync()
rep.check("cleanup: LDAP delete -> sync suspends", "suspend" in out and G.gw_sql("select address_status from users where username='%s'" % mail) == "1", "address_status=1 (mailbox data kept)", out[:200])
rep.check("cleanup: deleted user refused", not G.imap_login(mail, pw), "IMAP refused", "still accepted")
rep.done()
