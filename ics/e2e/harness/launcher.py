"""E2E launcher: real ICS backend (127.0.0.1:8108) on database ics_test_h + deterministic seed through the real API/CLI.

usage: python launcher.py --app-dir <copy of ics/ with built ics/static> --work <dir> [--env-file /etc/office-unbound/ics-test-h.env]
Writes <work>/state.json when ready, then runs until SIGTERM. Business data is created ONLY via the HTTP API and `ics.cli`
(the schema reset/migration is the only direct DB access, as in tests/conftest.py). Test credentials are throwaway.
"""
import argparse, base64, datetime, hashlib, hmac, ipaddress, json, os, re, secrets, signal, socket, ssl, struct, subprocess, sys, threading, time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

PORT = 8108
BASE = f"http://127.0.0.1:{PORT}"


def totp(secret: str, step: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    h = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    o = h[-1] & 15
    return f"{(struct.unpack('>I', h[o:o + 4])[0] & 0x7fffffff) % 1000000:06d}"


def load_env(p):
    out = {}
    for line in Path(p).read_text().splitlines():
        if "=" in line and not line.strip().startswith("#"):
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def selfsigned(work: Path) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(key, hashes.SHA256()))
    (work / "tls.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (work / "tls.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                     serialization.NoEncryption()))
    return (work / "tls.crt").read_text()


def listener(tls_ctx):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(16)

    def handle(c):
        try:
            if tls_ctx:
                c = tls_ctx.wrap_socket(c, server_side=True)
            else:
                c.sendall(b"not tls\r\n")
        except Exception:
            pass
        finally:
            try:
                c.close()
            except Exception:
                pass

    def loop():
        while True:
            try:
                c, _ = s.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()
    return s.getsockname()[1]


def sha(c: str) -> str:
    return c * 64


def release_fixture(work: Path) -> tuple[Path, Path]:
    """A real directory tree in the layout of the signed repo (dists/<suite>/main/binary-amd64/Packages + the signer's records/<sha>.json).
    Real files read by the real GET /releases; only the content is fixed. Components: ou-agent (staging newer than stable, tested), ou-mail (dev only, untested)."""
    repo, recs = work / "relrepo", work / "relrecords"
    for d in (repo, recs):
        if d.exists():
            import shutil
            shutil.rmtree(d)
    recs.mkdir(parents=True)

    def stanza(suite, comp, name, ver, h):
        return f"Package: {name}\nVersion: {ver}\nArchitecture: amd64\nFilename: pool/{suite}/{comp}/{name}_{ver}_amd64.deb\nSHA256: {h}\n"
    suites = {
        "dev": [("ou-agent", "ou-agent", "1.2.0", sha("c")), ("ou-mail", "ou-mail", "0.9.0", sha("d"))],
        "staging": [("ou-agent", "ou-agent", "1.1.0", sha("b"))],
        "stable": [("ou-agent", "ou-agent", "1.0.0", sha("a"))],
    }
    for suite, items in suites.items():
        d = repo / "dists" / suite / "main" / "binary-amd64"
        d.mkdir(parents=True)
        (d / "Packages").write_text("\n".join(stanza(suite, c, n, v, h) for c, n, v, h in items))
    for c in ("a", "b", "c"):   # ou-mail (d) has no record: shows as untested and blocks its promotion
        (recs / (sha(c) + ".json")).write_text(json.dumps({"results": {"install-smoke": {"result": "pass", "attestation_sha256": sha("e"), "at": "2026-11-10T09:00:00Z"}}}))
    return repo, recs


def seed_bootstrap(owner_url: str) -> str:
    """One deployment with VMs in every bootstrap state the page explains (rows only in the test database; the audit alarm goes through audit.append)."""
    from sqlalchemy import create_engine, text
    eng = create_engine(owner_url, isolation_level="AUTOCOMMIT")
    did = "00000000-0000-0000-0000-00000000e2e1"
    with eng.connect() as c:
        c.execute(text("INSERT INTO deployments (id, slug, customer_id, profile, profile_version, status, desired_spec) VALUES (:i, 'e2e-boot', 'c', 'mail', '1', 'active', '{}')"), {"i": did})
        for bid, vm, vmid, state, exp in (("a1" * 8, "mail-01", 201, "enrolled", "1 hour"), ("b2" * 8, "web-01", 202, "pending", "1 hour"),
                                          ("c3" * 8, "db-01", 203, "pending", "-1 hour"), ("d4" * 8, "dav-01", 204, "enrolled", "1 hour")):
            c.execute(text("INSERT INTO guest_bootstrap (bid, deployment_id, vm, vmid, mode, state, attempts, expires_at) VALUES (:b, :d, :v, :n, 'callback', :s, :a, now() + CAST(:e AS interval))"),
                      {"b": bid, "d": did, "v": vm, "n": vmid, "s": state, "e": exp, "a": 2 if vm == "web-01" else 0})
    eng.dispose()
    return "e2e-boot"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--app-dir", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--env-file", default="/etc/office-unbound/ics-test-h.env")
    a = ap.parse_args()
    app_dir, work = Path(a.app_dir).resolve(), Path(a.work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    env = load_env(a.env_file)
    app_url, owner_url = env["ICS_TEST_DATABASE_URL"], env["ICS_TEST_OWNER_DATABASE_URL"]
    assert re.search(r"/ics_test_[a-z0-9]{1,12}$", owner_url), "refusing: not a test database"
    state = work / "state.json"
    state.unlink(missing_ok=True)

    keys = work / "keys"
    keys.mkdir(exist_ok=True)
    for n in ("vault.key", "audit.key", "signing.key"):
        (keys / n).write_bytes(os.urandom(32))
        (keys / n).chmod(0o600)

    sys.path.insert(0, str(app_dir))
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, text
    eng = create_engine(owner_url, isolation_level="AUTOCOMMIT")
    with eng.connect() as c:
        c.execute(text("DROP SCHEMA public CASCADE"))
        c.execute(text("CREATE SCHEMA public"))
    cfg = Config(str(app_dir / "alembic.ini"))
    cfg.set_main_option("script_location", str(app_dir / "migrations"))
    cfg.attributes["url"] = owner_url
    cfg.attributes["app_role"] = "ics_test_app"
    command.upgrade(cfg, "head")
    eng.dispose()

    relrepo, relrecs = release_fixture(work)
    boot_slug = seed_bootstrap(owner_url)
    senv = {**os.environ, "ICS_RELEASE_REPO_DIR": str(relrepo), "ICS_RELEASE_RECORDS_DIR": str(relrecs), "ICS_RELEASE_PROMOTE_CMD": "/bin/true", "PYTHONPATH": str(app_dir), "ICS_ENV_FILE": "/nonexistent", "ICS_DATABASE_URL": app_url,
            "ICS_VAULT_KEY_FILE": str(keys / "vault.key"), "ICS_AUDIT_KEY_FILE": str(keys / "audit.key"),
            "ICS_SIGNING_KEY_FILE": str(keys / "signing.key"), "ICS_WORKER_ENABLED": "true", "ICS_MONITOR_ENABLED": "true",
            "ICS_ALLOW_LOOPBACK_ENDPOINTS": "true", "ICS_LOGIN_MAX_FAILURES": "50"}
    log = open(work / "server.log", "wb")
    srv = subprocess.Popen([sys.executable, "-c",
                            f"import uvicorn;from ics.serve import make_config;uvicorn.Server(make_config(port={PORT})).run()"],
                           env=senv, cwd=app_dir, stdout=log, stderr=log)

    def stop(*_):
        srv.terminate()
        sys.exit(0)
    import atexit
    atexit.register(srv.terminate)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    import httpx
    for _ in range(60):
        try:
            if httpx.get(BASE + "/healthz", timeout=1).status_code == 200:
                break
        except Exception:
            time.sleep(0.5)
    else:
        raise SystemExit("backend did not start; see server.log")

    def cli(*args):
        r = subprocess.run([sys.executable, "-m", "ics.cli", *args], env=senv, cwd=app_dir, capture_output=True, text=True)
        if r.returncode:
            raise SystemExit("cli failed: " + r.stderr[-300:])
        return r.stdout.strip().splitlines()[-2]  # one-time token: line before the usage hint

    password = "E2e-Test-Password-" + secrets.token_hex(4)
    users: dict = {}

    def enroll(user, role, token):
        r = httpx.post(BASE + "/api/v1/auth/enroll", json={"username": user, "token": token, "password": password})
        r.raise_for_status()
        sec = parse_qs(urlparse(r.json()["totp_provisioning_uri"]).query)["secret"][0]
        step = int(time.time() // 30)
        httpx.post(BASE + "/api/v1/auth/enroll/confirm",
                   json={"username": user, "token": token, "totp_code": totp(sec, step)}).raise_for_status()
        users[user] = {"role": role, "password": password, "totp_secret": sec, "last_step": step}

    for name, role in (("e2e-admin", "admin"), ("e2e-approver", "approver"), ("e2e-approver2", "approver")):
        enroll(name, role, cli("create-admin", "--username", name, "--role", role))

    def login(user):
        u = users[user]
        step = int(time.time() // 30)
        while step <= u["last_step"]:
            time.sleep(1)
            step = int(time.time() // 30)
        c = httpx.Client(base_url=BASE)
        r = c.post("/api/v1/auth/login", json={"username": user, "password": u["password"], "totp_code": totp(u["totp_secret"], step)})
        r.raise_for_status()
        u["last_step"] = step
        c.headers["X-CSRF-Token"] = r.json()["csrf_token"]
        # the session cookie is Secure (__Host-); httpx will not replay it over http, browsers accept it for loopback
        c.headers["Cookie"] = r.headers["set-cookie"].split(";")[0]
        return c
    admin = login("e2e-admin")
    for name, role in (("e2e-operator", "operator"), ("e2e-viewer", "viewer"), ("e2e-invitee", "viewer")):
        admin.post("/api/v1/users", json={"username": name, "role": role}).raise_for_status()
        tok = cli("issue-enrollment", "--username", name)
        if name == "e2e-invitee":  # enrolled through the UI by the login spec
            users[name] = {"role": role, "password": password, "enrollment_token": tok}
        else:
            enroll(name, role, tok)

    crt = selfsigned(work)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(work / "tls.crt", work / "tls.key")
    tls_port, plain_port = listener(ctx), listener(None)

    op, ap1 = login("e2e-operator"), login("e2e-approver")

    def plan(client, action, params):
        r = client.post("/api/v1/plans", json={"action": action, "params": params})
        r.raise_for_status()
        return r.json()
    base_chk = {"interval_seconds": 15, "fail_threshold": 1, "recover_threshold": 1, "kind": "tcp_tls"}
    p1 = plan(op, "check.create", {**base_chk, "name": "e2e-tls-ok", "config": {"host": "127.0.0.1", "port": tls_port, "ca_pem": crt}})
    p2 = plan(op, "check.create", {**base_chk, "name": "e2e-listener-down", "config": {"host": "127.0.0.1", "port": plain_port, "ca_pem": crt}})
    for p in (p1, p2):  # low-risk plans may be auto-approved by the server; only approve those still pending
        if p.get("status") == "pending_approval":
            ap1.post(f"/api/v1/plans/{p['plan_id']}/approve").raise_for_status()
    # high-risk plans stay pending (2 approvers); one is rejected so Plans shows every status
    pend = [plan(admin, "user.create", {"username": f"e2e-pending-{i}", "role": "viewer"}) for i in range(4)]
    rej = plan(admin, "user.create", {"username": "e2e-rejected", "role": "viewer"})
    ap1.post(f"/api/v1/plans/{rej['plan_id']}/reject").raise_for_status()

    deadline = time.time() + 90
    while time.time() < deadline:
        inc = admin.get("/api/v1/incidents").json()
        chk = admin.get("/api/v1/checks").json()
        if inc and len(chk) == 2 and all(c["last_run_at"] for c in chk):
            break
        time.sleep(1)
    else:
        raise SystemExit("seed: no incident appeared within 90s (monitor/worker not running? see server.log)")

    state.write_text(json.dumps({"base": BASE, "users": users, "tls_port": tls_port, "plain_port": plain_port,
                                 "pending_plan_ids": [p["plan_id"] for p in pend], "boot_slug": boot_slug}, indent=1))
    state.chmod(0o600)
    print("READY", flush=True)
    srv.wait()


if __name__ == "__main__":
    main()
