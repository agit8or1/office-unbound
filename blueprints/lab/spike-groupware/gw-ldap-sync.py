#!/usr/bin/env python3
"""Office Unbound: directory -> Gromox user reconciliation ("ldap sync"), the future ICS `groupware.sync_users` action.

Why this exists: Gromox authenticates against LDAP (ldap_adaptor) but only for users that already have a row in its SQL
`users` table (the SQL DB stays the lookup table; LDAP is only the password check, see ldap_adaptor(4gx)). Upstream the row +
mailbox are created by grommunio-admin-api (`grommunio-admin ldap downsync/sync`), which is Python/Flask, needs its own
config + systemd + licence-cap patch, and is not the interface we want. This script does the same minimum for the OU stack:

  * reads people from the authoritative OpenLDAP (same settings file as gromox's ldap_adaptor: /etc/gromox/ldap_adaptor.cfg,
    read-only bind account svc-gromox, LDAPS with certificate verification against the lab CA)
  * creates, per entitled user: users row (externid = entryUUID => authmgr uses LDAP), user_properties (display type, name),
    mailbox directories, gromox-mkprivate + gromox-mkmidb
  * keeps display name in sync
  * deprovision: a user that is locked (ppolicy pwdAccountLockedTime), no longer in the entitlement group, or gone from LDAP
    gets address_status=1 (suspended: authmgr rejects it before any credential cache, postfix stops delivering). Nothing is
    deleted (mailbox data stays; purging is a separate, explicit action).
  * refuses to touch users that exist locally (externid NULL) unless --adopt is given: no silent takeover of the legacy SQL users.

Usage (as root on the gromox host):
  gw-ldap-sync.py [--dry-run] [--user mail@dom] [--create-domain] [--adopt] [--json]
Exit code 0 = reconciled without errors, 1 = errors, 2 = configuration problem.
AGPL note: no admin-api code is used; behaviour was cross-checked against its orm/tools sources only.
"""
import argparse, json, os, re, subprocess, sys

CFG = os.environ.get("OU_LDAP_CFG", "/etc/gromox/ldap_adaptor.cfg")
MYCFG = "/etc/gromox/mysql_adaptor.cfg"
CA = os.environ.get("OU_LDAP_CA", "/etc/ou-lab-ldap/ca.crt")
USERDIR = "/var/lib/gromox/user"
DOMDIR = "/var/lib/gromox/domain"
PR_DISPLAY_TYPE_EX, PR_DISPLAY_NAME = 0x39050003, 0x3001001F
ACTIVE, SUSPENDED = 0, 1


def readcfg(path):
    d = {}
    for ln in open(path):
        ln = ln.strip()
        if ln and not ln.startswith("#") and "=" in ln:
            k, v = ln.split("=", 1)
            d[k.strip()] = v.strip()
    return d


def run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError("%s: %s" % (" ".join(cmd), (p.stderr or p.stdout).strip()[:300]))


def connect_ldap(c):
    import ssl
    from ldap3 import Server, Connection, Tls
    tls = Tls(validate=ssl.CERT_REQUIRED, version=ssl.PROTOCOL_TLS_CLIENT, ca_certs_file=CA)
    srv = Server(c["ldap_host"].split()[0], use_ssl=c["ldap_host"].startswith("ldaps"), tls=tls, connect_timeout=10)
    pw = c.get("ldap_bind_pass") or open(c["ou_bind_pass_file"]).read().strip()
    return Connection(srv, user=c["ldap_bind_user"], password=pw, auto_bind=True, receive_timeout=20)


def fetch_people(conn, c, only=None):
    attrs = ["mail", "entryUUID", "displayName", "cn", "memberOf", "pwdAccountLockedTime"]
    flt = c.get("ldap_user_filter") or "(objectClass=inetOrgPerson)"
    if only:
        from ldap3.utils.conv import escape_filter_chars
        flt = "(&%s(%s=%s))" % (flt, c.get("ldap_mail_attr", "mail"), escape_filter_chars(only))
    conn.search(c["ldap_search_base"], flt, attributes=attrs)
    out = []
    for e in conn.entries:
        a = e.entry_attributes_as_dict
        mail = [m for m in a.get("mail", [])]
        if not mail:
            continue
        locked = bool(a.get("pwdAccountLockedTime"))
        out.append(dict(dn=e.entry_dn, mail=str(mail[0]).lower(), uuid=str(a["entryUUID"][0]),
                        name=str((a.get("displayName") or a.get("cn") or [mail[0]])[0]),
                        groups={g.lower() for g in a.get("memberOf", [])}, locked=locked))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--user", help="reconcile only this mail address")
    ap.add_argument("--create-domain", action="store_true", help="create the gromox domain (+public store) if missing")
    ap.add_argument("--adopt", action="store_true", help="link an existing local (externid NULL) user to the LDAP entry with same mail")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    try:
        import pymysql
        c = readcfg(CFG); m = readcfg(MYCFG)
        for k in ("ldap_host", "ldap_bind_user", "ldap_search_base"):
            c[k]
        group = c["ou_entitlement_group"].lower()
        conn = connect_ldap(c)
        db = pymysql.connect(unix_socket="/run/mysqld/mysqld.sock", user=m["mysql_username"], password=m["mysql_password"],
                             database=m["mysql_dbname"], autocommit=False)
    except Exception as e:
        print("config/connect error: %s: %s" % (type(e).__name__, e), file=sys.stderr); return 2
    cur = db.cursor()
    res, errors = [], 0
    people = fetch_people(conn, c, a.user)
    seen = set()
    for p in people:
        mail, uuid = p["mail"], p["uuid"]
        seen.add(mail)
        entitled = group in p["groups"] and not p["locked"]
        want = ACTIVE if entitled else SUSPENDED
        why = "locked" if p["locked"] else ("not in %s" % group if group not in p["groups"] else "ok")
        try:
            cur.execute("SELECT id,externid,address_status,domain_id FROM users WHERE username=%s", (mail,))
            row = cur.fetchone()
            if row is None:
                if not entitled:
                    res.append(dict(user=mail, action="skip", detail="not entitled (%s)" % why)); continue
                dom = mail.split("@", 1)[1]
                cur.execute("SELECT id FROM domains WHERE domainname=%s", (dom,))
                d = cur.fetchone()
                if d is None:
                    if not a.create_domain:
                        res.append(dict(user=mail, action="error", detail="domain %s unknown (use --create-domain)" % dom)); errors += 1; continue
                    if not a.dry_run:
                        cur.execute("INSERT INTO domains (org_id,domainname,homedir,max_user,title,end_day,domain_status) "
                                    "VALUES (1,%s,%s,0,%s,'2099-01-01',0)", (dom, "%s/%s" % (DOMDIR, dom), dom))
                        d = (cur.lastrowid,)
                        os.makedirs("%s/%s/exmdb" % (DOMDIR, dom), exist_ok=True)
                        db.commit()
                        run(["gromox-mkpublic", dom])
                        run(["chown", "-R", "gromox:gromox", "%s/%s" % (DOMDIR, dom)])
                    else:
                        d = (0,)
                if a.dry_run:
                    res.append(dict(user=mail, action="would-create", detail=p["name"])); continue
                md = "%s/%s" % (USERDIR, mail)
                # password '!' never matches a crypt hash: with externid set authmgr never uses it anyway
                cur.execute("INSERT INTO users (username,password,domain_id,group_id,maildir,privilege_bits,address_status,lang,timezone,externid) "
                            "VALUES (%s,'!',%s,0,%s,15,0,'en','UTC',%s)", (mail, d[0], md, uuid.encode()))
                uid = cur.lastrowid
                cur.execute("INSERT INTO user_properties (user_id,proptag,propval_str) VALUES (%s,%s,'0'),(%s,%s,%s)",
                            (uid, PR_DISPLAY_TYPE_EX, uid, PR_DISPLAY_NAME, p["name"]))
                db.commit()
                for sub in ("", "/exmdb", "/tmp", "/tmp/imap.rfc822", "/config", "/cid"):
                    os.makedirs(md + sub, exist_ok=True)
                run(["chown", "-R", "gromox:gromox", md]); os.chmod(md, 0o770)
                if not os.path.exists(md + "/exmdb/exchange.sqlite3"):
                    run(["gromox-mkprivate", mail])
                if not os.path.exists(md + "/exmdb/midb.sqlite3"):
                    run(["gromox-mkmidb", mail])
                run(["chown", "-R", "gromox:gromox", md])
                res.append(dict(user=mail, action="created", detail="externid=%s" % uuid)); continue
            uid, xid, st, _ = row
            if xid is None:
                if not a.adopt:
                    res.append(dict(user=mail, action="conflict", detail="local SQL user (externid NULL); not touched (use --adopt)")); errors += 1; continue
                if not a.dry_run:
                    cur.execute("UPDATE users SET externid=%s WHERE id=%s", (uuid.encode(), uid)); db.commit()
                res.append(dict(user=mail, action="adopted", detail="externid=%s" % uuid)); continue
            if xid.decode() != uuid:
                res.append(dict(user=mail, action="conflict", detail="externid differs from LDAP entryUUID")); errors += 1; continue
            acts = []
            if st in (ACTIVE, SUSPENDED) and st != want:
                acts.append("%s (%s)" % ("suspend" if want else "reactivate", why))
                if not a.dry_run:
                    cur.execute("UPDATE users SET address_status=%s WHERE id=%s", (want, uid))
            cur.execute("SELECT propval_str FROM user_properties WHERE user_id=%s AND proptag=%s", (uid, PR_DISPLAY_NAME))
            r = cur.fetchone()
            if r is None or r[0] != p["name"]:
                acts.append("name")
                if not a.dry_run:
                    cur.execute("REPLACE INTO user_properties (user_id,proptag,propval_str) VALUES (%s,%s,%s)", (uid, PR_DISPLAY_NAME, p["name"]))
            if not a.dry_run:
                db.commit()
            res.append(dict(user=mail, action=",".join(acts) or "unchanged", detail=why))
        except Exception as e:
            db.rollback(); errors += 1
            res.append(dict(user=mail, action="error", detail="%s: %s" % (type(e).__name__, e)))
    # users linked to LDAP (externid set) that vanished from LDAP -> suspend
    if not a.user:
        cur.execute("SELECT id,username,address_status FROM users WHERE externid IS NOT NULL")
        for uid, un, st in cur.fetchall():
            if un not in seen and st == ACTIVE:
                if not a.dry_run:
                    cur.execute("UPDATE users SET address_status=%s WHERE id=%s", (SUSPENDED, uid)); db.commit()
                res.append(dict(user=un, action="suspend", detail="no longer in LDAP"))
    if a.json:
        print(json.dumps(dict(dry_run=a.dry_run, errors=errors, results=res)))
    else:
        for r in res:
            print("%-14s %-34s %s" % (r["action"], r["user"], r["detail"]))
        print("-- %d objects, %d errors%s" % (len(res), errors, " (dry run)" if a.dry_run else ""))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
