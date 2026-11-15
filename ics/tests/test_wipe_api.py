"""ou-wipe-api (security review 4, L2): token / peer-credential auth, ACK state machine, body clamp, no stall."""
import http.client
import importlib.machinery
import importlib.util
import json
import os
import socket
import sys
import threading
import types

import pytest

SCRIPT = os.path.join(os.path.dirname(__file__), "..", "agent", "deploy", "runbooks", "ou-wipe-api")
TOKEN = "t" * 40


class FakeDB:
    """users: {name: id}; devices: {(uid, dev): [rowid, status]}"""

    def __init__(self):
        self.users = {"a@x.org": 1}
        self.dev = {(1, "d1"): [10, 2], (1, "d2"): [11, 16], (1, "d3"): [12, 0]}
        self.hist = []

    def cursor(self):
        return self

    def execute(self, sql, p=()):
        s = " ".join(sql.split())
        self._r = []
        if s.startswith("SELECT id FROM users"):
            self._r = [(self.users[p[0]],)] if p[0] in self.users else []
        elif s.startswith("SELECT id, status FROM user_devices"):
            r = self.dev.get((p[0], p[1]))
            self._r = [(r[0], r[1])] if r else []
        elif s.startswith("SELECT device_id, status"):
            self._r = [(d, v[1]) for (u, d), v in self.dev.items() if u == p[0]]
        elif s.startswith("UPDATE user_devices SET status=%s"):
            for v in self.dev.values():
                if v[0] == p[1]:
                    v[1] = p[0]
        elif s.startswith("UPDATE user_devices SET status=1"):
            for v in self.dev.values():
                if v[0] == p[0]:
                    v[1] = 1
        elif s.startswith("INSERT INTO user_device_history"):
            self.hist.append(p)
        elif s.startswith("INSERT INTO user_devices"):
            self.dev[(p[0], p[1])] = [99, 1]

    def fetchone(self):
        return self._r[0] if self._r else None

    def fetchall(self):
        return self._r

    def commit(self):
        pass

    def close(self):
        pass


@pytest.fixture
def api(tmp_path, monkeypatch):
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({"db_user": "u", "db_password": "p", "db_name": "n", "token": TOKEN}))
    monkeypatch.setenv("OU_WIPE_API_CONFIG", str(cfg))
    monkeypatch.setitem(sys.modules, "pymysql", types.ModuleType("pymysql"))
    loader = importlib.machinery.SourceFileLoader("ou_wipe_api_t", SCRIPT)
    mod = types.ModuleType("ou_wipe_api_t")
    mod.__file__ = SCRIPT
    loader.exec_module(mod)
    fake = FakeDB()
    mod.db = lambda: fake
    srv = mod.ThreadingHTTPServer(("127.0.0.1", 0), mod.H)       # v4 loopback for the test (same handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield mod, fake, srv.server_address[1]
    srv.shutdown()


def req(port, method, path, body=None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request(method, path, body=json.dumps(body) if body is not None else None, headers=headers or {})
    r = c.getresponse()
    return r.status, r.read()


P = f"/{TOKEN}/api/v1/service/wipe/a@x.org"


def test_no_token_or_wrong_token_is_404_even_for_get(api):
    mod, fake, port = api
    assert req(port, "GET", "/api/v1/service/wipe/a@x.org")[0] == 404
    assert req(port, "GET", "/" + "x" * 40 + "/api/v1/service/wipe/a@x.org")[0] == 404
    assert req(port, "POST", "/api/v1/service/wipe/a@x.org?devices=d1", {"status": 8})[0] == 404
    assert fake.dev[(1, "d1")][1] == 2
    st, body = req(port, "GET", P + "?devices=d1")
    assert st == 200 and json.loads(body)["data"]["d1"]["status"] == 2


def test_ack_must_be_next_state_of_same_wipe_type(api):
    mod, fake, port = api
    # full wipe (2) can not be turned into an account-only wipe, account-only (16) not into a factory reset
    assert req(port, "POST", P + "?devices=d1", {"status": 32})[0] == 403 and fake.dev[(1, "d1")][1] == 2
    assert req(port, "POST", P + "?devices=d1", {"status": 64})[0] == 403 and fake.dev[(1, "d1")][1] == 2
    assert req(port, "POST", P + "?devices=d2", {"status": 8})[0] == 403 and fake.dev[(1, "d2")][1] == 16
    assert req(port, "POST", P + "?devices=d1", {"status": 4})[0] == 201 and fake.dev[(1, "d1")][1] == 4
    assert req(port, "POST", P + "?devices=d1", {"status": 8})[0] == 201 and fake.dev[(1, "d1")][1] == 8
    assert req(port, "POST", P + "?devices=d2", {"status": 32})[0] == 201 and fake.dev[(1, "d2")][1] == 32
    # a wipe can not be requested over HTTP and the status never goes back
    assert req(port, "POST", P + "?devices=d3", {"status": 8})[0] == 403 and fake.dev[(1, "d3")][1] == 0
    assert req(port, "POST", P + "?devices=d1", {"status": 4})[0] == 403 and fake.dev[(1, "d1")][1] == 8


def test_policy_ack_for_new_device_inserts(api):
    mod, fake, port = api
    assert req(port, "POST", P + "?devices=newdev", {"status": 1})[0] == 201 and fake.dev[(1, "newdev")][1] == 1


def test_negative_or_huge_content_length_does_not_stall(api):
    mod, fake, port = api
    for cl in ("-1", "999999"):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        c.putrequest("POST", P + "?devices=d1")
        c.putheader("Content-Length", cl)
        c.endheaders()
        assert c.getresponse().status == 413


def test_one_stalled_client_does_not_block_others(api):
    mod, fake, port = api
    stuck = socket.create_connection(("127.0.0.1", port))
    stuck.sendall(b"POST " + P.encode() + b"?devices=d1 HTTP/1.1\r\nContent-Length: 100\r\n\r\n")   # body never arrives
    assert req(port, "GET", P + "?devices=d1")[0] == 200
    stuck.close()


def test_refuses_to_start_without_auth(tmp_path, monkeypatch):
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({"db_user": "u", "db_password": "p", "db_name": "n"}))
    monkeypatch.setenv("OU_WIPE_API_CONFIG", str(cfg))
    monkeypatch.setitem(sys.modules, "pymysql", types.ModuleType("pymysql"))
    mod = types.ModuleType("m")
    importlib.machinery.SourceFileLoader("m", SCRIPT).exec_module(mod)
    with pytest.raises(SystemExit):
        mod.make_server()


def test_unix_socket_accepts_only_allowed_peer_uid(tmp_path, monkeypatch):
    import pwd
    me = pwd.getpwuid(os.getuid()).pw_name
    sock = str(tmp_path / "w.sock")
    for allowed, ok in (([me], True), (["nobody"], False)):
        cfg = tmp_path / "c.json"
        cfg.write_text(json.dumps({"db_user": "u", "db_password": "p", "db_name": "n", "unix_socket": sock, "allowed_users": allowed}))
        monkeypatch.setenv("OU_WIPE_API_CONFIG", str(cfg))
        monkeypatch.setitem(sys.modules, "pymysql", types.ModuleType("pymysql"))
        mod = types.ModuleType("m")
        importlib.machinery.SourceFileLoader("m", SCRIPT).exec_module(mod)
        fake = FakeDB()
        mod.db = lambda: fake
        srv = mod.make_server()
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            c = socket.socket(socket.AF_UNIX)
            c.settimeout(5)
            c.connect(sock)
            c.sendall(b"GET /api/v1/service/wipe/a@x.org?devices=d1 HTTP/1.0\r\n\r\n")
            data = b""
            while chunk := c.recv(4096):
                data += chunk
            assert (b" 200 " in data.split(b"\r\n")[0]) is ok, data[:80]
        finally:
            srv.shutdown()
            srv.server_close()
