"""Node-side executor of the Gromox mailbox-administration runbooks (see mbxspec). Started ONLY by the fixed template unit
ou-rb-gromox-mbx@<rid>.service (User=gromox, group gromoxcf for the SQL credentials: NOT root), which the agent may start through polkit.
usage: python3 -m ou_agent.mbxhelper <rid>
The spool file is never trusted: parameters are re-validated with mbxspec. SQL uses bound parameters; the only subprocesses are
gromox-mkprivate / gromox-mkmidb with a validated address as the single argument (argv, no shell). Config (root-owned): /etc/ou-rb/gromox.json
{"mail_domain": "...", "alias_domains": ["..."]}. Result: JSON in /run/ou-rb-gromox-mbx/<rid>.json."""
import glob
import json
import os
import re
import sqlite3
import subprocess
import sys
import time

from . import mbxspec as S
from .proto import Reject

CFG = "/etc/ou-rb/gromox.json"
SPOOLS = tuple(sorted(glob.glob("/run/ou-agent*-spool")))   # the agent (or a lab sidecar) drops the validated request into its own spool directory
RESULT_DIR = "/run/ou-rb-gromox-mbx"
USERDIR = "/var/lib/gromox/user"
MYCFG = "/etc/gromox/mysql_adaptor.cfg"
RID_RE = re.compile(r"^r[0-9a-f]{16}$")
SHARED, ACTIVE = 4, 0
PR_DISPLAY_TYPE_EX, PR_DISPLAY_NAME = 0x39050003, 0x3001001F
QUOTA_TAGS = {"storage_kb": 0x3FF50003, "send_kb": 0x666E0003, "receive_kb": 0x666A0003}
PR_MESSAGE_SIZE_EXTENDED = 0x0E080014
FILES = {"send_on_behalf": "delegates.txt", "send_as": "sendas.txt"}


def _cfg() -> dict:
    with open(CFG) as f:
        c = json.load(f)
    doms = [c["mail_domain"], *c.get("alias_domains", [])]
    if not all(isinstance(d, str) and re.fullmatch(r"[a-z0-9.-]{3,200}", d) for d in doms):
        raise ValueError("bad config")
    return {"mail_domain": c["mail_domain"], "domains": set(doms)}


def _db():
    import pymysql
    m = {}
    for ln in open(MYCFG):
        if "=" in ln and not ln.lstrip().startswith("#"):
            k, v = ln.split("=", 1)
            m[k.strip()] = v.strip()
    return pymysql.connect(unix_socket="/run/mysqld/mysqld.sock", user=m["mysql_username"], password=m.get("mysql_password", ""), database=m["mysql_dbname"])


def _row(cur, mail):
    cur.execute("SELECT id, address_status, externid, maildir FROM users WHERE username=%s", (mail,))
    return cur.fetchone()


def _need(cur, mail, shared=None, what="mailbox"):
    r = _row(cur, mail)
    if r is None:
        raise Reject("not_found", f"{what} does not exist")
    if shared is True and r[1] != SHARED:
        raise Reject("not_shared", f"{what} is not a shared mailbox")
    if shared is False and r[1] != ACTIVE:
        raise Reject("not_active", f"{what} is not an active user mailbox")
    return r


def _store(maildir: str) -> str:
    if not maildir.startswith(USERDIR + "/") or ".." in maildir:
        raise Reject("bad_state", "unexpected maildir")
    return maildir


def _atomic_lines(path: str, lines: list[str]) -> None:
    os.makedirs(os.path.dirname(path), mode=0o770, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write("".join(x + "\n" for x in lines))
    os.chmod(tmp, 0o660)
    os.replace(tmp, path)


def _read_lines(path: str) -> list[str]:
    try:
        return [x.strip() for x in open(path) if x.strip()]
    except FileNotFoundError:
        return []


def _perm_folders(con) -> list[int]:
    """Folder 1 (root), IPM subtree (9) and everything below it that is not a search folder."""
    rows = con.execute("WITH RECURSIVE t(id) AS (SELECT 9 UNION ALL SELECT f.folder_id FROM folders f JOIN t ON f.parent_id = t.id WHERE f.is_search = 0) "
                       "SELECT id FROM t").fetchall()
    return sorted({1, *(r[0] for r in rows)})


def _sqlite(maildir: str) -> sqlite3.Connection:
    con = sqlite3.connect(os.path.join(_store(maildir), "exmdb", "exchange.sqlite3"), timeout=15)
    con.execute("PRAGMA foreign_keys=ON")
    return con


# ---- runbooks -----------------------------------------------------------------------------------------------------------------
def set_aliases(p, cfg):
    mail = f"{p['user']}@{cfg['mail_domain']}"
    for a in p["aliases"]:
        if a.split("@", 1)[1] not in cfg["domains"]:
            raise Reject("domain_not_allowed", "alias domain is not one of this mailbox system's domains")
    db = _db()
    try:
        cur = db.cursor()
        _need(cur, mail, shared=False, what="user")
        for a in p["aliases"]:
            if _row(cur, a) is not None:
                raise Reject("address_taken", "an alias equals an existing mailbox address")
            cur.execute("SELECT mainname FROM aliases WHERE aliasname=%s", (a,))
            o = cur.fetchone()
            if o and o[0] != mail:
                raise Reject("address_taken", "an alias belongs to another mailbox")
        cur.execute("SELECT aliasname FROM aliases WHERE mainname=%s", (mail,))
        have = {r[0] for r in cur.fetchall()}
        for a in sorted(have - set(p["aliases"])):
            cur.execute("DELETE FROM aliases WHERE aliasname=%s AND mainname=%s", (a, mail))
        for a in sorted(set(p["aliases"]) - have):
            cur.execute("INSERT INTO aliases (aliasname, mainname) VALUES (%s, %s)", (a, mail))
        db.commit()
        cur.execute("SELECT aliasname FROM aliases WHERE mainname=%s ORDER BY aliasname", (mail,))
        return {"mail": mail, "aliases": [r[0] for r in cur.fetchall()]}
    finally:
        db.close()


def shared_create(p, cfg):
    mail = f"{p['name']}@{cfg['mail_domain']}"
    md = f"{USERDIR}/{mail}"
    db = _db()
    try:
        cur = db.cursor()
        if _row(cur, mail) is not None:
            raise Reject("exists", "a mailbox with this name already exists")
        cur.execute("SELECT 1 FROM aliases WHERE aliasname=%s", (mail,))
        if cur.fetchone():
            raise Reject("exists", "the address is in use as an alias")
        cur.execute("SELECT id FROM domains WHERE domainname=%s AND domain_status=0", (cfg["mail_domain"],))
        d = cur.fetchone()
        if d is None:
            raise Reject("no_domain", "mail domain is not active in Gromox")
        # password '!' never matches a crypt hash and address_status 4 is refused by authmgr: a shared mailbox has no login
        cur.execute("INSERT INTO users (username,password,domain_id,group_id,maildir,privilege_bits,address_status,lang,timezone) "
                    "VALUES (%s,'!',%s,0,%s,0,%s,'en','UTC')", (mail, d[0], md, SHARED))
        uid = cur.lastrowid
        cur.execute("INSERT INTO user_properties (user_id,proptag,propval_str) VALUES (%s,%s,'7'),(%s,%s,%s)", (uid, PR_DISPLAY_TYPE_EX, uid, PR_DISPLAY_NAME, p["display_name"]))
        db.commit()
    finally:
        db.close()
    for sub in ("", "/exmdb", "/tmp", "/tmp/imap.rfc822", "/config", "/cid"):
        os.makedirs(md + sub, mode=0o770, exist_ok=True)
    for exe, fn in (("/usr/sbin/gromox-mkprivate", "exchange.sqlite3"), ("/usr/sbin/gromox-mkmidb", "midb.sqlite3")):
        if not os.path.exists(f"{md}/exmdb/{fn}"):
            r = subprocess.run([exe, mail], capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL, env={"PATH": "/usr/bin:/bin", "LANG": "C"})
            if r.returncode != 0:
                raise RuntimeError(f"{os.path.basename(exe)} failed")
    return {"mail": mail, "address_status": SHARED}


def shared_delete(p, cfg):
    """Suspend (address_status 1) and drop every grant. Mailbox data is RETAINED (the lifecycle has no purge action)."""
    mail = f"{p['name']}@{cfg['mail_domain']}"
    db = _db()
    try:
        cur = db.cursor()
        r = _need(cur, mail, shared=True, what="shared mailbox")
        _drop_all(r[3])
        cur.execute("DELETE FROM aliases WHERE mainname=%s", (mail,))
        cur.execute("UPDATE users SET address_status=1 WHERE id=%s", (r[0],))
        db.commit()
        return {"mail": mail, "suspended": True, "data_retained": True}
    finally:
        db.close()


def _drop_all(maildir):
    for fn in FILES.values():
        _atomic_lines(f"{_store(maildir)}/config/{fn}", [])
    con = _sqlite(maildir)
    try:
        with con:
            con.execute("DELETE FROM permissions WHERE username <> 'default'")
    finally:
        con.close()


def _members(maildir):
    con = _sqlite(maildir)
    try:
        full = sorted({r[0] for r in con.execute("SELECT username FROM permissions WHERE username <> 'default' AND folder_id = 9 AND (permission & ?) = ?",
                                                  (S.RIGHTS_FULL, S.RIGHTS_FULL))})
    finally:
        con.close()
    return {"full_access": full, "send_as": sorted(_read_lines(f"{maildir}/config/sendas.txt")),
            "send_on_behalf": sorted(_read_lines(f"{maildir}/config/delegates.txt"))}


def shared_access(p, cfg):
    mail, who = f"{p['name']}@{cfg['mail_domain']}", f"{p['user']}@{cfg['mail_domain']}"
    db = _db()
    try:
        cur = db.cursor()
        r = _need(cur, mail, shared=True, what="shared mailbox")
        if p["grant"]:
            _need(cur, who, shared=False, what="user")
    finally:
        db.close()
    md = _store(r[3])
    if p["kind"] == "full_access":
        con = _sqlite(md)
        try:
            with con:
                folders = _perm_folders(con)
                con.execute("DELETE FROM permissions WHERE username = ? AND folder_id IN (%s)" % ",".join("?" * len(folders)), (who, *folders))
                if p["grant"]:
                    con.executemany("INSERT INTO permissions (folder_id, username, permission) VALUES (?, ?, ?)", [(f, who, S.RIGHTS_FULL) for f in folders])
        finally:
            con.close()
    else:
        path = f"{md}/config/{FILES[p['kind']]}"
        cur_ = [x for x in _read_lines(path) if x.lower() != who]
        _atomic_lines(path, sorted({*cur_, who}) if p["grant"] else cur_)
    return {"mail": mail, "user": who, "kind": p["kind"], "granted": p["grant"], "members": _members(md)}


def shared_state(p, cfg):
    mail = f"{p['name']}@{cfg['mail_domain']}"
    db = _db()
    try:
        cur = db.cursor()
        r = _row(cur, mail)
    finally:
        db.close()
    if r is None:
        return {"mail": mail, "exists": False}
    out = {"mail": mail, "exists": True, "address_status": int(r[1]), "has_login": r[2] is not None}
    if r[1] == SHARED:
        out["members"] = _members(r[3])
    return out


def set_quota(p, cfg):
    mail = f"{p['user']}@{cfg['mail_domain']}"
    db = _db()
    try:
        cur = db.cursor()
        r = _need(cur, mail, what="mailbox")
        if r[1] not in (ACTIVE, SHARED):
            raise Reject("not_active", "mailbox is suspended")
    finally:
        db.close()
    con = _sqlite(r[3])
    try:
        with con:
            for key, tag in QUOTA_TAGS.items():
                con.execute("DELETE FROM store_properties WHERE proptag = ?", (tag,))
                if p[key] is not None:
                    con.execute("INSERT INTO store_properties (proptag, propval) VALUES (?, ?)", (tag, p[key]))
        return {"mail": mail, **_quota_of(con)}
    finally:
        con.close()


def _quota_of(con) -> dict:
    out = {k: None for k in QUOTA_TAGS}
    for k, tag in QUOTA_TAGS.items():
        r = con.execute("SELECT propval FROM store_properties WHERE proptag = ?", (tag,)).fetchone()
        out[k] = int(r[0]) if r is not None else None
    r = con.execute("SELECT propval FROM store_properties WHERE proptag = ?", (PR_MESSAGE_SIZE_EXTENDED,)).fetchone()
    out["used_bytes"] = int(r[0]) if r is not None else 0
    return out


def mail_usage(p, cfg):
    db = _db()
    res = {}
    try:
        cur = db.cursor()
        for u in p["users"]:
            mail = f"{u}@{cfg['mail_domain']}"
            r = _row(cur, mail)
            if r is None:
                res[u] = None
                continue
            try:
                con = _sqlite(r[3])
                try:
                    res[u] = _quota_of(con)
                finally:
                    con.close()
            except (sqlite3.Error, Reject, OSError):
                res[u] = None
    finally:
        db.close()
    return {"usage": res}


DISPATCH = {"gromox.set_aliases": set_aliases, "gromox.shared_create": shared_create, "gromox.shared_delete": shared_delete,
            "gromox.shared_access": shared_access, "gromox.shared_state": shared_state, "gromox.set_quota": set_quota, "gromox.mail_usage": mail_usage}


def main(argv):
    if len(argv) != 1 or not RID_RE.fullmatch(argv[0]):
        print("usage: mbxhelper <rid>", file=sys.stderr)
        return 2
    rid = argv[0]
    req = None
    for d in SPOOLS:
        try:
            fd = os.open(os.path.join(d, rid + ".json"), os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            continue
        with os.fdopen(fd) as f:
            req = json.loads(f.read(16384))
        break
    if req is None:
        return 2
    result = {"rid": rid, "ts": int(time.time())}
    try:
        action = req["action"]
        if action not in S.MBX_RUNBOOKS:
            raise Reject("not_allowed", "action not allowed for this helper")
        params = S.CHECKS[action](req["params"])
        result["result"] = DISPATCH[action](params, _cfg())
    except Reject as r:
        result["rejected"] = {"code": r.code, "message": r.msg}
    except Exception as e:  # noqa: BLE001
        result["error"] = type(e).__name__
    os.makedirs(RESULT_DIR, mode=0o755, exist_ok=True)
    out = os.path.join(RESULT_DIR, rid + ".json")
    tmp = out + ".tmp"
    with open(tmp, "w") as f:
        json.dump(result, f)
    os.chmod(tmp, 0o644)
    os.replace(tmp, out)
    for fn in os.listdir(RESULT_DIR):
        pth = os.path.join(RESULT_DIR, fn)
        try:
            if fn.endswith(".json") and fn != rid + ".json" and time.time() - os.stat(pth).st_mtime > 600:
                os.unlink(pth)
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
