import os
import re
import stat
import sys
import threading

import pyotp

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text

from ics import auth
from ics.config import Settings, _load_env_file
from ics.main import create_app
from ics.runtime import Runtime
from ics.vault import Vault

from .pve_mock import MockPVE

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))


TEST_ENV_FILE = os.environ.get("ICS_TEST_ENV_FILE", "/etc/office-unbound/ics-test.env")


def _test_env() -> dict:
    env = _load_env_file(TEST_ENV_FILE)
    env.update({k: v for k, v in os.environ.items() if k.startswith("ICS_TEST_")})
    for k in ("ICS_TEST_DATABASE_URL", "ICS_TEST_OWNER_DATABASE_URL"):
        assert k in env, f"{k} missing (see README: test configuration)"
        assert re.search(r"/ics_test(_[a-z0-9]{1,12})?$", env[k]), "refusing to run tests against a non-test database"
    return env


@pytest.fixture(scope="session")
def base_settings(tmp_path_factory):
    """Own throwaway vault+audit keys in a temp dir; ics_test database with its own roles (never the production env file)."""
    env = _test_env()
    d = tmp_path_factory.mktemp("keys")
    for n in ("vault.key", "audit.key", "signing.key"):
        (d / n).write_bytes(os.urandom(32))
        (d / n).chmod(0o600)
    from ics import experimental   # the suite exercises every experimental feature; test_experimental.py covers the gating (off by default)
    return Settings(database_url=env["ICS_TEST_DATABASE_URL"], vault_key_file=str(d / "vault.key"), experimental=frozenset(experimental.FEATURES),
                    audit_key_file=str(d / "audit.key"), worker_enabled=False, allow_loopback_endpoints=True,
                    signing_key_file=str(d / "signing.key"), incident_renotify_seconds=0, notify_max_attempts=2,
                    # the production floors (30 s backoff, 300 s window, 15/30 s check intervals) are exercised explicitly in tests/test_review_fixes.py
                    remediation_min_backoff_seconds=0, remediation_min_window_seconds=60, check_min_interval_seconds=5,
                    check_min_interval_credentialed_seconds=5,
                    desktop_sync_enabled=False)   # test workers never touch this host's artifact tree (tests/test_desktop_sync.py drives it)


@pytest.fixture(scope="session")
def owner_engine(base_settings):
    url = _test_env()["ICS_TEST_OWNER_DATABASE_URL"]
    # lock_timeout: the TRUNCATE/DROP SCHEMA below need ACCESS EXCLUSIVE locks. Without a timeout a second pytest run on the same test DB (or an
    # orphaned idle-in-transaction connection of a killed run) made them wait forever: the "hang" of tests/test_tenant_admin.py seen in security review 6.
    eng = create_engine(url, isolation_level="AUTOCOMMIT", connect_args={"options": "-c lock_timeout=60000"})
    with eng.connect() as c:
        c.execute(text("DROP SCHEMA public CASCADE"))
        c.execute(text("CREATE SCHEMA public"))
    cfg = Config(os.path.join(os.path.dirname(__file__), "..", "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(os.path.dirname(__file__), "..", "migrations"))
    cfg.attributes["url"] = url
    cfg.attributes["app_role"] = "ics_test_app"
    command.upgrade(cfg, "head")
    return eng


@pytest.fixture()
def rt(base_settings, owner_engine):
    with owner_engine.connect() as c:
        c.execute(text("TRUNCATE users, sessions, login_attempts, rate_limits, audit_events, endpoints, plans, jobs, "
                       "worker_heartbeat, inventory_snapshots, plan_approvals, nodes, agent_requests, checks, check_results, incidents, "
                       "maintenance_windows, alert_channels, notifications, remediation_attempts, idm_stacks, idm_users, idm_enrollments, idm_reconcile_runs, "
                       "guest_bootstrap, customers, credentials, credential_events, credential_alerts, customer_approvals, operator_customers, tenant_admin_bindings, tenant_requests, backup_policies, backup_runs, backup_verifications, system_settings RESTART IDENTITY CASCADE"))
        c.execute(text("INSERT INTO customers (id, name, msp_owned, provisioning_mode) VALUES ('00000000-0000-0000-0000-00000000a001', 'MSP (internal)', true, 'auto')"))
        # every test starts as the active primary at epoch 1 (a test that fences the controller must not leak into the next one)
        c.execute(text("ALTER TABLE controller_state DISABLE TRIGGER controller_state_guard"))
        c.execute(text("UPDATE controller_state SET epoch = 1, role = 'primary', note = NULL WHERE id = 1"))
        c.execute(text("ALTER TABLE controller_state ENABLE TRIGGER controller_state_guard"))
    r = Runtime(base_settings)
    yield r
    r.engine.dispose()


@pytest.fixture()
def client(rt):
    app = create_app(runtime=rt)  # share the fixture runtime
    return TestClient(app, base_url="https://testserver")


@pytest.fixture()
def mk_user(rt):
    """Creates an account the way production does: invite, host-issued enrollment token, user-chosen password + TOTP."""
    def make(username, role, password="correct horse battery", created_by=None):
        with rt.session() as db:
            auth.create_invite(db, rt, username, role, created_by=created_by, actor="test")
            token = auth.issue_enrollment_token(db, rt, username, actor="test")
            uri = auth.enroll_begin(db, rt, username, token, password, "127.0.0.1")
            u = {"username": username, "password": password, "secret": re.search(r"secret=([A-Z2-7]+)", uri).group(1), "token": token}
            auth.enroll_confirm(db, rt, username, token, totp_for(u), "127.0.0.1")
            u["id"] = str(db.execute(text("SELECT id FROM users WHERE username = :u"), {"u": username}).scalar())
        return u
    return make


_last: dict = {}


def totp_for(u):
    """A fresh valid code, never the same step twice for one user (replay protection)."""
    import time
    t = pyotp.TOTP(u["secret"])
    step = int(time.time() // 30)
    s = max(step + 1, _last.get(u["secret"], 0) + 1) if _last.get(u["secret"], 0) >= step else step
    _last[u["secret"]] = s
    return t.at(s * 30)


@pytest.fixture()
def login(client):
    """login(user) -> TestClient-like (client, headers). Separate cookie jars per user."""
    def do(u):
        c = TestClient(client.app, base_url="https://testserver")
        r = c.post("/api/v1/auth/login", json={"username": u["username"], "password": u["password"], "totp_code": totp_for(u)})
        assert r.status_code == 200, r.text
        return c, {"X-CSRF-Token": r.json()["csrf_token"]}
    return do


@pytest.fixture(scope="session")
def pve():
    m = MockPVE()
    yield m
    m.stop()


@pytest.fixture(scope="session")
def other_vault():
    return Vault(b"\x07" * 32)


class FakeAgent:
    """A REAL ou_agent (HTTPS server + signed protocol + journal) on 127.0.0.1 with a stub `systemctl` that logs its argv."""

    def __init__(self, tmp_path, units=("gromox-imap", "nginx", "mariadb"), paths=("/",), extra=None):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from ou_agent import cli, runbooks, server
        self.runbooks = runbooks
        self.state = str(tmp_path / "agent-state")
        os.makedirs(self.state, mode=0o700)
        self.log = tmp_path / "systemctl.log"
        stub = tmp_path / "systemctl"
        stub.write_text(f'#!/bin/sh\necho "$@" >> {self.log}\ncase "$2" in show) echo ActiveState=active; echo SubState=running;; esac\n')
        stub.chmod(0o755)
        self._orig = runbooks.SYSTEMCTL
        runbooks.SYSTEMCTL = str(stub)
        with open(os.path.join(self.state, "agent_key.pem"), "wb") as f:
            f.write(Ed25519PrivateKey.generate().private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                               serialization.NoEncryption()))
        os.chmod(os.path.join(self.state, "agent_key.pem"), 0o600)
        self.tls_fp = cli.make_tls(self.state, "127.0.0.1", "localhost")
        self.cfg = {"listen": {"address": "127.0.0.1", "port": 0},
                    "runbooks": {"service.restart": {"units": list(units)}, "service.status": {"units": list(units)},
                                 "disk.usage": {"paths": list(paths)}, **(extra or {})}}
        self.token = cli.arm_enroll(self.state)
        _, self.key_fp = cli.fingerprints(self.state)
        self.srv, self.agent = server.build_server(self.cfg, self.state)
        self.agent.enroll_fail_delay = 0.0
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.runbooks.SYSTEMCTL = self._orig


@pytest.fixture()
def fake_agent(tmp_path):
    a = FakeAgent(tmp_path)
    yield a
    a.stop()


@pytest.fixture()
def no_vm_floor(monkeypatch):
    """Per-component sizing arithmetic without the owner's per-VM floor (catalog meta.vm_minimum; tested in test_deploy_vm_minimum.py)."""
    from ics.deploy import catalog, plan
    monkeypatch.setattr(plan, "vm_minimum", lambda cat: catalog.VmMinimum())


@pytest.fixture(scope="session", autouse=True)
def _no_gpg_agents_left_behind(tmp_path_factory):
    """Tests that sign (artifacts, release signer, golden image) start a gpg-agent per throw-away GNUPGHOME; gpg never stops it. Stop every
    agent whose home is under this session's temp directory (2026-11-22: 453 leaked agents had accumulated on the ICS host)."""
    yield
    import subprocess
    base = str(tmp_path_factory.getbasetemp())
    out = subprocess.run(["ps", "-u", str(os.getuid()), "-o", "pid=,args="], capture_output=True, text=True).stdout
    for line in out.splitlines():
        pid, _, args = line.strip().partition(" ")
        a = args.split()
        if a[:1] == ["gpg-agent"] and "--homedir" in a and a.index("--homedir") + 1 < len(a) and a[a.index("--homedir") + 1].startswith(base):
            try:
                os.kill(int(pid), 15)
            except (OSError, ValueError):
                pass



@pytest.fixture(autouse=True)
def _experimental_features_on():
    """The suite exercises meetings, telephony, multi-tenant plans and remote wipe as machinery; the gating itself (all off by default,
    refused with the reason) is tested in test_experimental.py, which turns them off explicitly."""
    from ics import experimental
    experimental.configure(experimental.FEATURES)
    yield
    experimental.configure(())
