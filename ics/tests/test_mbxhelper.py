"""Node-side helper of the mailbox runbooks (agent/ou_agent/mbxhelper.py) against a real sqlite store (same schema as Gromox's exchange.sqlite3 for the
tables it touches) and a sqlite stand-in for the Gromox MySQL tables. Proves the rules: domains, uniqueness, shared-only operations, folder rights,
sendas/delegates files, quota properties, retained data, result file shape."""
import json
import os
import sqlite3
import subprocess

import pytest

from ou_agent import mbxhelper as h
from ou_agent import mbxspec as S
from ou_agent.proto import Reject

SCHEMA = """
CREATE TABLE domains (id INTEGER PRIMARY KEY, domainname TEXT, domain_status INTEGER);
CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, domain_id INT, group_id INT, maildir TEXT, privilege_bits INT,
                    address_status INT, lang TEXT, timezone TEXT, externid BLOB);
CREATE TABLE aliases (aliasname TEXT PRIMARY KEY, mainname TEXT);
CREATE TABLE user_properties (user_id INT, proptag INT, propval_str TEXT);
"""
STORE = """
CREATE TABLE folders (folder_id INTEGER PRIMARY KEY, parent_id INTEGER, is_search INTEGER DEFAULT 0);
CREATE TABLE permissions (member_id INTEGER PRIMARY KEY AUTOINCREMENT, folder_id INTEGER NOT NULL, username TEXT COLLATE NOCASE NOT NULL, permission INTEGER NOT NULL,
                          FOREIGN KEY (folder_id) REFERENCES folders (folder_id) ON DELETE CASCADE);
CREATE TABLE store_properties (proptag INTEGER UNIQUE NOT NULL, propval BLOB NOT NULL);
"""


class Cur:
    def __init__(self, c):
        self.c, self.cur = c, c.cursor()

    def execute(self, q, a=()):
        self.cur.execute(q.replace("%s", "?"), a)
        return self

    def fetchone(self):
        return self.cur.fetchone()

    def fetchall(self):
        return self.cur.fetchall()

    @property
    def lastrowid(self):
        return self.cur.lastrowid


class Db:
    def __init__(self, c):
        self.c = c

    def cursor(self):
        return Cur(self.c)

    def commit(self):
        self.c.commit()

    def close(self):
        pass


def make_store(md):
    os.makedirs(f"{md}/exmdb", exist_ok=True)
    con = sqlite3.connect(f"{md}/exmdb/exchange.sqlite3")
    con.executescript(STORE)
    con.executemany("INSERT INTO folders VALUES (?,?,?)", [(1, None, 0), (9, 1, 0), (10, 9, 0), (13, 9, 0), (15, 9, 0), (30, 13, 0), (99, 9, 1)])
    con.commit()
    con.close()


@pytest.fixture()
def node(tmp_path, monkeypatch):
    c = sqlite3.connect(":memory:")
    c.executescript(SCHEMA)
    c.execute("INSERT INTO domains VALUES (1, 'x.test', 0)")
    for u in ("alice", "bob"):
        md = f"{tmp_path}/{u}@x.test"
        c.execute("INSERT INTO users (username, domain_id, maildir, address_status, externid) VALUES (?, 1, ?, 0, X'01')", (f"{u}@x.test", md))
        make_store(md)
    c.execute("INSERT INTO users (username, domain_id, maildir, address_status, externid) VALUES ('legacy@x.test', 1, ?, 1, NULL)", (f"{tmp_path}/legacy@x.test",))
    c.commit()
    monkeypatch.setattr(h, "_db", lambda: Db(c))
    monkeypatch.setattr(h, "USERDIR", str(tmp_path))
    cfg = {"mail_domain": "x.test", "domains": {"x.test", "alt.test"}}

    def fake_run(argv, **kw):   # gromox-mkprivate / mkmidb: create the store the way the tool does
        assert argv[0] in ("/usr/sbin/gromox-mkprivate", "/usr/sbin/gromox-mkmidb") and len(argv) == 2 and kw.get("shell") is None
        if argv[0].endswith("mkprivate"):
            con = sqlite3.connect(f"{tmp_path}/{argv[1]}/exmdb/exchange.sqlite3")
            con.executescript(STORE)
            con.executemany("INSERT INTO folders VALUES (?,?,?)", [(1, None, 0), (9, 1, 0), (13, 9, 0)])
            con.commit()
            con.close()
        else:
            open(f"{tmp_path}/{argv[1]}/exmdb/midb.sqlite3", "w").close()
        return subprocess.CompletedProcess(argv, 0, "", "")
    monkeypatch.setattr(h.subprocess, "run", fake_run)
    return c, cfg, tmp_path


def run(action, params, cfg):
    return h.DISPATCH[action](S.CHECKS[action](params), cfg)


def test_aliases_rules(node):
    c, cfg, _ = node
    r = run("gromox.set_aliases", {"user": "alice", "aliases": ["a1@x.test", "a2@alt.test"]}, cfg)
    assert r["aliases"] == ["a1@x.test", "a2@alt.test"]
    with pytest.raises(Reject) as e:
        run("gromox.set_aliases", {"user": "alice", "aliases": ["a1@evil.test"]}, cfg)
    assert e.value.code == "domain_not_allowed"
    with pytest.raises(Reject) as e:
        run("gromox.set_aliases", {"user": "bob", "aliases": ["a1@x.test"]}, cfg)               # belongs to alice
    assert e.value.code == "address_taken"
    with pytest.raises(Reject):
        run("gromox.set_aliases", {"user": "bob", "aliases": ["alice@x.test"]}, cfg)             # an existing mailbox address
    with pytest.raises(Reject) as e:
        run("gromox.set_aliases", {"user": "nobody", "aliases": []}, cfg)
    assert e.value.code == "not_found"
    with pytest.raises(Reject):
        run("gromox.set_aliases", {"user": "legacy", "aliases": []}, cfg)                          # suspended mailbox
    r = run("gromox.set_aliases", {"user": "alice", "aliases": ["a2@alt.test"]}, cfg)            # replace semantics: a1 removed
    assert r["aliases"] == ["a2@alt.test"] and c.execute("SELECT count(*) FROM aliases").fetchone()[0] == 1


def test_shared_mailbox_create_grants_and_delete(node):
    c, cfg, tmp = node
    r = run("gromox.shared_create", {"name": "support", "display_name": "Support"}, cfg)
    assert r == {"mail": "support@x.test", "address_status": 4}
    row = c.execute("SELECT password, address_status, externid FROM users WHERE username='support@x.test'").fetchone()
    assert row == ("!", 4, None)                                               # no usable password, no directory identity: nobody can log in
    with pytest.raises(Reject):
        run("gromox.shared_create", {"name": "support", "display_name": "dup"}, cfg)
    with pytest.raises(Reject):
        run("gromox.shared_create", {"name": "alice", "display_name": "dup"}, cfg)
    run("gromox.set_aliases", {"user": "alice", "aliases": ["help@x.test"]}, cfg)
    with pytest.raises(Reject):
        run("gromox.shared_create", {"name": "help", "display_name": "dup"}, cfg)               # alias address in use
    md = f"{tmp}/support@x.test"
    r = run("gromox.shared_access", {"name": "support", "user": "bob", "kind": "full_access", "grant": True}, cfg)
    assert r["members"]["full_access"] == ["bob@x.test"]
    con = sqlite3.connect(f"{md}/exmdb/exchange.sqlite3")
    rows = con.execute("SELECT folder_id, permission FROM permissions WHERE username='bob@x.test' ORDER BY folder_id").fetchall()
    assert rows == [(1, S.RIGHTS_FULL), (9, S.RIGHTS_FULL), (13, S.RIGHTS_FULL)] and S.RIGHTS_FULL == 1531
    run("gromox.shared_access", {"name": "support", "user": "bob", "kind": "full_access", "grant": True}, cfg)    # idempotent
    assert con.execute("SELECT count(*) FROM permissions WHERE username='bob@x.test'").fetchone()[0] == 3
    run("gromox.shared_access", {"name": "support", "user": "bob", "kind": "send_as", "grant": True}, cfg)
    r = run("gromox.shared_access", {"name": "support", "user": "alice", "kind": "send_on_behalf", "grant": True}, cfg)
    assert open(f"{md}/config/sendas.txt").read() == "bob@x.test\n" and open(f"{md}/config/delegates.txt").read() == "alice@x.test\n"
    assert os.stat(f"{md}/config/sendas.txt").st_mode & 0o777 == 0o660
    assert r["members"] == {"full_access": ["bob@x.test"], "send_as": ["bob@x.test"], "send_on_behalf": ["alice@x.test"]}
    for who, kind in (("legacy", "send_as"), ("ghost", "full_access")):
        with pytest.raises(Reject):
            run("gromox.shared_access", {"name": "support", "user": who, "kind": kind, "grant": True}, cfg)    # suspended / unknown user
    with pytest.raises(Reject) as e:
        run("gromox.shared_access", {"name": "alice", "user": "bob", "kind": "send_as", "grant": True}, cfg)   # a PERSONAL mailbox is never touched
    assert e.value.code == "not_shared"
    r = run("gromox.shared_access", {"name": "support", "user": "bob", "kind": "full_access", "grant": False}, cfg)
    assert r["members"]["full_access"] == [] and r["members"]["send_as"] == ["bob@x.test"]
    assert con.execute("SELECT count(*) FROM permissions WHERE username='bob@x.test'").fetchone()[0] == 0
    st = run("gromox.shared_state", {"name": "support"}, cfg)
    assert st["address_status"] == 4 and st["has_login"] is False and st["members"]["send_on_behalf"] == ["alice@x.test"]
    assert run("gromox.shared_state", {"name": "nothere"}, cfg) == {"mail": "nothere@x.test", "exists": False}
    with pytest.raises(Reject):
        run("gromox.shared_delete", {"name": "alice"}, cfg)                                       # personal mailbox cannot be deleted by this runbook
    r = run("gromox.shared_delete", {"name": "support"}, cfg)
    assert r == {"mail": "support@x.test", "suspended": True, "data_retained": True}
    assert c.execute("SELECT address_status FROM users WHERE username='support@x.test'").fetchone()[0] == 1 and os.path.exists(f"{md}/exmdb/exchange.sqlite3")
    assert open(f"{md}/config/sendas.txt").read() == "" and con.execute("SELECT count(*) FROM permissions").fetchone()[0] == 0


def test_quota_properties_and_usage(node):
    c, cfg, tmp = node
    r = run("gromox.set_quota", {"user": "alice", "send_kb": 2048, "receive_kb": 4096, "storage_kb": 1024}, cfg)
    assert (r["send_kb"], r["receive_kb"], r["storage_kb"]) == (2048, 4096, 1024)
    con = sqlite3.connect(f"{tmp}/alice@x.test/exmdb/exchange.sqlite3")
    assert dict(con.execute("SELECT proptag, propval FROM store_properties").fetchall()) == {0x666E0003: 2048, 0x666A0003: 4096, 0x3FF50003: 1024}
    con.execute("INSERT INTO store_properties VALUES (?, ?)", (h.PR_MESSAGE_SIZE_EXTENDED, 777))
    con.commit()
    u = run("gromox.mail_usage", {"users": ["alice", "bob", "ghost"]}, cfg)["usage"]
    assert u["alice"]["used_bytes"] == 777 and u["alice"]["storage_kb"] == 1024 and u["bob"]["storage_kb"] is None and u["ghost"] is None
    r = run("gromox.set_quota", {"user": "alice", "send_kb": None, "receive_kb": None, "storage_kb": None}, cfg)
    assert r["send_kb"] is None and con.execute("SELECT count(*) FROM store_properties WHERE proptag <> ?", (h.PR_MESSAGE_SIZE_EXTENDED,)).fetchone()[0] == 0
    with pytest.raises(Reject):
        run("gromox.set_quota", {"user": "ghost", "send_kb": 1, "receive_kb": None, "storage_kb": None}, cfg)


def test_main_rejects_bad_requests_and_writes_result(node, tmp_path, monkeypatch):
    c, cfg, tmp = node
    spool = tmp_path / "spool"
    spool.mkdir()
    monkeypatch.setattr(h, "SPOOLS", (str(spool),))
    monkeypatch.setattr(h, "RESULT_DIR", str(tmp_path / "res"))
    monkeypatch.setattr(h, "_cfg", lambda: cfg)
    rid = "r" + "0" * 16
    (spool / f"{rid}.json").write_text(json.dumps({"action": "gromox.set_aliases", "params": {"user": "alice", "aliases": ["x@evil.test; id"]}}))
    assert h.main([rid]) == 0
    assert json.load(open(tmp_path / "res" / f"{rid}.json"))["rejected"]["code"] == "bad_params"          # re-validated: the spool is not trusted
    (spool / f"{rid}.json").write_text(json.dumps({"action": "service.restart", "params": {"unit": "x"}}))
    h.main([rid])
    assert json.load(open(tmp_path / "res" / f"{rid}.json"))["rejected"]["code"] == "not_allowed"
    (spool / f"{rid}.json").write_text(json.dumps({"action": "gromox.set_aliases", "params": {"user": "alice", "aliases": ["ok@x.test"]}}))
    h.main([rid])
    assert json.load(open(tmp_path / "res" / f"{rid}.json"))["result"]["aliases"] == ["ok@x.test"]
    assert h.main(["../../etc/passwd"]) == 2


def test_runbook_wiring_in_agent():
    from ou_agent import runbooks
    cfg = runbooks.validate_config({"listen": {"address": "127.0.0.1", "port": 1}, "runbooks": {"gromox.set_aliases": {"enabled": True}, "gromox.set_quota": {"enabled": True}}})
    assert runbooks.capabilities(cfg)["gromox.set_quota"] == {"enabled": True}
    assert runbooks.check_allowed(cfg, "gromox.set_quota", {"user": "alice", "send_kb": 1, "receive_kb": None, "storage_kb": None})["user"] == "alice"
    with pytest.raises(Reject):
        runbooks.check_allowed(cfg, "gromox.shared_create", {"name": "x1", "display_name": "x"})   # not enabled on this node
    with pytest.raises(Reject):
        runbooks.check_allowed(cfg, "gromox.set_quota", {"user": "alice; id", "send_kb": 1, "receive_kb": None, "storage_kb": None})
    with pytest.raises(ValueError):
        runbooks.validate_config({"runbooks": {"gromox.set_quota": {"enabled": False}}})
    rp = open(os.path.join(os.path.dirname(__file__), "..", "agent", "deploy", "render_polkit.py")).read()
    assert "ou-rb-gromox-mbx" in rp
