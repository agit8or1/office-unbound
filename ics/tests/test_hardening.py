"""Production hardening: shared (multi-process) rate limiting, the dedicated guest-bootstrap listener, the single background-worker leader."""
import dataclasses
import os
import pathlib
import socket
import subprocess
import sys
import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from ics import ratelimit
from ics.guest import callback
from ics import serve_callback
from ics.main import create_app

ROOT = pathlib.Path(__file__).resolve().parents[2]
ICS = ROOT / "ics"


# ------------------------------------------------------------------------------------------------ shared limiter
def test_bucket_semantics(rt):
    assert [ratelimit.allow(rt, "k", 3, 3600) for _ in range(5)] == [True, True, True, False, False]
    assert ratelimit.allow(rt, "other", 3, 3600)                                   # independent keys
    assert [ratelimit.allow(rt, "fast", 2, 1.0) for _ in range(3)] == [True, True, False]
    time.sleep(0.7)                                                                  # refill 2/s: one token is back
    assert ratelimit.allow(rt, "fast", 2, 1.0)


def test_denied_calls_do_not_consume_or_extend(rt):
    for _ in range(2):
        ratelimit.allow(rt, "flood", 2, 1.0)
    for _ in range(50):                                                              # a flood while empty ...
        assert not ratelimit.allow(rt, "flood", 2, 1.0)
    time.sleep(1.1)
    assert ratelimit.allow(rt, "flood", 2, 1.0)                                      # ... does not delay the refill


_CHILD = """
import sys, types
from sqlalchemy import create_engine
from ics import ratelimit
rt = types.SimpleNamespace(engine=create_engine(sys.argv[1], pool_size=2))
n = sum(ratelimit.allow(rt, 'shared', 30, 3600.0) for _ in range(int(sys.argv[2])))
print(n)
"""


def test_limit_holds_across_processes(rt, base_settings):
    """Six OS processes x 40 attempts hit one key concurrently (limit 30/h): exactly 30 pass in total. The old in-process limiter would have allowed 6 x 30."""
    env = {**os.environ, "PYTHONPATH": str(ICS)}
    procs = [subprocess.Popen([sys.executable, "-c", _CHILD, base_settings.database_url, "40"], stdout=subprocess.PIPE, text=True, env=env, cwd=ICS)
             for _ in range(6)]
    allowed = [int(p.communicate(timeout=120)[0].strip()) for p in procs]
    assert all(p.returncode == 0 for p in procs)
    assert sum(allowed) == 30, allowed


def test_limit_holds_across_threads(rt):
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(8) as ex:
        res = list(ex.map(lambda _: ratelimit.allow(rt, "thr", 25, 3600.0), range(100)))
    assert sum(res) == 25


def test_purge_removes_old_rows(rt, monkeypatch):
    ratelimit.allow(rt, "old", 5, 60.0)
    with rt.engine.begin() as c:
        c.execute(text("UPDATE rate_limits SET ts = now() - interval '2 hours'"))
    monkeypatch.setattr(ratelimit.random, "randrange", lambda n: 0)
    ratelimit.allow(rt, "new", 5, 60.0)
    with rt.engine.begin() as c:
        assert c.execute(text("SELECT array_agg(key) FROM rate_limits")).scalar() == ["new"]


def test_console_buckets_use_the_shared_table(rt, client):
    for _ in range(25):
        client.post("/api/v1/identity/enroll", json={"stack": "x", "uid": "u", "token": "t" * 20, "password": "p" * 20})
    with rt.engine.begin() as c:
        keys = [r[0] for r in c.execute(text("SELECT key FROM rate_limits"))]
    assert any(k.startswith("enroll-ip:") for k in keys)


# ------------------------------------------------------------------------------------------------ the listener app
@pytest.fixture()
def listener(rt, base_settings, monkeypatch):
    import ics.config
    import ics.runtime
    monkeypatch.setattr(ics.runtime, "Runtime", lambda *a, **k: rt)
    monkeypatch.setattr(ics.config, "load_settings", lambda *a, **k: base_settings)
    return TestClient(serve_callback.create_limited_app(), base_url="https://testserver")


def test_listener_serves_only_the_callback_route_and_health(rt, base_settings, monkeypatch):
    import ics.config
    import ics.runtime
    monkeypatch.setattr(ics.runtime, "Runtime", lambda *a, **k: rt)
    monkeypatch.setattr(ics.config, "load_settings", lambda *a, **k: base_settings)
    app = callback.create_callback_app()
    paths = sorted(r.path for r in app.routes)
    assert paths == ["/api/v1/guest-bootstrap/report", "/healthz"]
    assert app.user_middleware == []                                                 # no session / CSRF / CORS middleware


def test_listener_isolation_and_no_cookies(listener):
    assert listener.get("/healthz").json() == {"ok": True}
    for p in ("/", "/docs", "/openapi.json", "/redoc", "/api/v1/auth/login", "/api/v1/plans", "/readyz", "/api/v1/version", "/static/x", "/assets/app.js"):
        assert listener.get(p).status_code == 404, p
        assert listener.post(p, json={}).status_code in (404, 405), p
    r = listener.get("/healthz")
    assert "set-cookie" not in r.headers
    assert listener.get(callback.PATH).status_code == 405


def test_the_console_no_longer_serves_the_callback_when_dedicated(rt, base_settings):
    app = create_app(runtime=type("R", (), {})() if False else rt)
    assert callback.PATH in {r.path for r in app.routes}                              # transition default: still served
    rt2 = type(rt)(dataclasses.replace(base_settings, guest_callback_dedicated=True))
    try:
        app2 = create_app(runtime=rt2)
        assert callback.PATH not in {r.path for r in app2.routes}
    finally:
        rt2.engine.dispose()


def test_body_cap_content_length_and_chunked(listener):
    big = b"x" * (serve_callback.MAX_BODY + 1)
    assert listener.post(callback.PATH, content=big, headers={"content-type": "application/json"}).status_code == 413

    def gen():
        for _ in range(10):
            yield b"y" * 1000
    assert listener.post(callback.PATH, content=gen(), headers={"content-type": "application/json"}).status_code == 413
    assert listener.post(callback.PATH, content=b"{}", headers={"content-type": "application/json", "content-length": "abc"}).status_code in (400, 422)
    assert listener.post(callback.PATH, content=b"{}", headers={"content-type": "application/json"}).status_code == 422   # a small body still reaches the route


def test_request_deadline_answers_408():
    import asyncio

    async def slow(scope, receive, send):
        await asyncio.sleep(5)
    app = serve_callback.RequestLimits(slow, timeout=0.2)
    c = TestClient(app, base_url="https://testserver")
    assert c.get("/x").status_code == 408


def test_non_loopback_listener_requires_tls():
    with pytest.raises(SystemExit):
        serve_callback.make_config({"ICS_GUEST_CALLBACK_LISTEN": "192.0.2.5:8444"})
    cfg = serve_callback.make_config({"ICS_GUEST_CALLBACK_LISTEN": "192.0.2.5:8444", "ICS_GUEST_CALLBACK_TLS_CERT": "/c", "ICS_GUEST_CALLBACK_TLS_KEY": "/k"})
    assert (cfg.host, cfg.port, cfg.limit_concurrency, cfg.ws, cfg.http) == ("192.0.2.5", 8444, serve_callback.MAX_CONCURRENCY, "none", "h11")


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_real_tls_listener_process(rt, base_settings, tmp_path):
    """The actual `python -m ics.serve_callback` process over TLS (own certificate): health, 404 elsewhere, body cap, cert is the one configured."""
    import hashlib
    import ssl
    import http.client
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    import datetime as dt
    import ipaddress
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "ics-bootstrap")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=1)).not_valid_after(now + dt.timedelta(days=2))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False).sign(key, hashes.SHA256()))
    (tmp_path / "c.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "c.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    port = _free_port()
    env = {**os.environ, "PYTHONPATH": str(ICS), "ICS_ENV_FILE": str(tmp_path / "none.env"), "ICS_DATABASE_URL": base_settings.database_url, "ICS_VAULT_KEY_FILE": base_settings.vault_key_file,
           "ICS_AUDIT_KEY_FILE": base_settings.audit_key_file, "ICS_GUEST_CALLBACK_LISTEN": f"127.0.0.1:{port}",
           "ICS_GUEST_CALLBACK_TLS_CERT": str(tmp_path / "c.crt"), "ICS_GUEST_CALLBACK_TLS_KEY": str(tmp_path / "c.key")}
    p = subprocess.Popen([sys.executable, "-m", "ics.serve_callback"], env=env, cwd=ICS, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        ctx = ssl.create_default_context(cafile=str(tmp_path / "c.crt"))
        for _ in range(100):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1):
                    break
            except OSError:
                assert p.poll() is None, p.stdout.read().decode()
                time.sleep(0.2)

        def req(method, path, body=None, headers=None):
            c = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=10)
            c.request(method, path, body=body, headers=headers or {})
            r = c.getresponse()
            out = (r.status, r.read(), r.getheader("server"))
            c.close()
            return out
        assert req("GET", "/healthz")[:2] == (200, b'{"ok":true}')
        assert req("GET", "/healthz")[2] is None                                      # no Server header
        assert req("GET", "/api/v1/auth/login")[0] == 404
        assert req("GET", "/docs")[0] == 404
        assert req("POST", callback.PATH, b"z" * 5000, {"content-type": "application/json"})[0] == 413
        assert req("POST", callback.PATH, b"{}", {"content-type": "application/json"})[0] == 422
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw, ctx.wrap_socket(raw, server_hostname="127.0.0.1") as tls:
            der = tls.getpeercert(binary_form=True)
        assert hashlib.sha256(der).hexdigest() == hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
        with socket.create_connection(("127.0.0.1", port), timeout=5) as plain:       # plaintext HTTP on the TLS port gets nothing useful
            plain.sendall(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
            plain.settimeout(3)
            try:
                assert b"200 OK" not in plain.recv(200)
            except (ConnectionError, socket.timeout):
                pass
    finally:
        p.terminate()
        p.wait(10)


# ------------------------------------------------------------------------------------------------ several workers
def test_only_one_process_runs_the_background_worker(rt, base_settings, monkeypatch):
    started, stopped = [], []

    class FakeWorker:
        def __init__(self, r):
            pass

        def start(self):
            started.append(1)

        def stop(self):
            stopped.append(1)
    import ics.main
    monkeypatch.setattr(ics.main, "Worker", FakeWorker)
    monkeypatch.setattr(ics.main.cred_service, "adopt_all", lambda r: None)
    rts = [type(rt)(dataclasses.replace(base_settings, worker_enabled=True)) for _ in range(3)]
    try:
        apps = [create_app(runtime=r) for r in rts]
        clients = [TestClient(a) for a in apps]
        for c in clients:
            c.__enter__()
        assert len(started) == 1                                                       # one leader among three "workers"
        clients[0].__exit__(None, None, None)                                          # whichever was first; the leader hands the lock back when it stops
        clients[1].__exit__(None, None, None)
        clients[2].__exit__(None, None, None)
        assert len(stopped) == 1
        c4 = TestClient(create_app(runtime=rts[0]))                                    # a restarted process takes over
        with c4:
            assert len(started) == 2
    finally:
        for r in rts:
            r.engine.dispose()


# ------------------------------------------------------------------------------------------------ install
def test_installer_deploys_both_units_and_backup_includes_the_listener():
    inst = (ICS / "deploy" / "install.sh").read_text()
    assert "ics-bootstrap.service" in inst and "systemctl enable ics-migrate.service ics.service ics-bootstrap.service" in inst
    unit = (ICS / "deploy" / "ics-bootstrap.service").read_text()
    assert "ConditionPathExists=/etc/office-unbound/callback.env" in unit and "ics.serve_callback" in unit and "LoadCredential=callback.key" in unit
    assert "ICS_WORKERS" in (ICS / "deploy" / "ics.service").read_text()
    bs = (ICS / "deploy" / "bootstrap.sh").read_text()
    assert "--callback-listen" in bs and "--callback-allow-cidr" in bs and "ics_callback" in bs and "ICS_GUEST_CALLBACK_DEDICATED" in bs
    bk = (ICS / "deploy" / "backup" / "ics-backup.sh").read_text()
    assert "callback.env" in bk and "callback-tls" in bk and "ics-bootstrap.service" in bk
