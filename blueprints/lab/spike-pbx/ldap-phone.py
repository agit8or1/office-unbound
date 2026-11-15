#!/usr/bin/env python3
"""Directory-side phone attribute helper (blueprints/lab/spike-identity-files/kc/ldap-user.sh has no attribute support).
  ldap-phone.py set <uid> <ext4>   |   clear <uid>   |   show <uid>
Binds as svc-ics (may modify ou=people only; ACL from ldap-ics-bind.sh). Env: LDAP_HOST, LDAP_CA, LDAP_ICS_PW_FILE. Secret never printed."""
import os, ssl, sys
import ldap3

host = os.environ.get("LDAP_HOST", "ldap.ou-lab.internal")
tls = ldap3.Tls(ca_certs_file=os.environ["LDAP_CA"], validate=ssl.CERT_REQUIRED)
c = ldap3.Connection(ldap3.Server(host, use_ssl=True, tls=tls), "cn=svc-ics,ou=system,dc=ou-lab,dc=internal",
                     open(os.environ["LDAP_ICS_PW_FILE"]).read().strip(), auto_bind=True)
cmd, uid = sys.argv[1], sys.argv[2]
import re
if not re.fullmatch(r"[a-z][a-z0-9_-]{0,30}", uid):          # explicit check (not assert: survives python -O), and no DN metacharacters can get in
    sys.exit("invalid uid")
dn = "uid=%s,ou=people,dc=ou-lab,dc=internal" % uid
if cmd == "set":
    ext = sys.argv[3]
    if not (ext.isdigit() and len(ext) == 4):
        sys.exit("extension must be 4 digits")
    ok = c.modify(dn, {"telephoneNumber": [(ldap3.MODIFY_REPLACE, [ext])]})
elif cmd == "clear":
    ok = c.modify(dn, {"telephoneNumber": [(ldap3.MODIFY_REPLACE, [])]})
else:
    c.search(dn, "(objectClass=*)", search_scope=ldap3.BASE, attributes=["telephoneNumber", "pwdAccountLockedTime"])
    print(c.entries[0].entry_attributes_as_dict if c.entries else "not found"); sys.exit(0)
print(cmd, uid, "ok" if ok else c.result)
