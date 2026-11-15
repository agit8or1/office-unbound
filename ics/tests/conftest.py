import os
import re

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


TEST_ENV_FILE = os.environ.get("ICS_TEST_ENV_FILE", "/etc/office-unbound/ics-test.env")


def _test_env() -> dict:
    env = _load_env_file(TEST_ENV_FILE)
    env.update({k: v for k, v in os.environ.items() if k.startswith("ICS_TEST_")})
    for k in ("ICS_TEST_DATABASE_URL", "ICS_TEST_OWNER_DATABASE_URL"):
        assert k in env, f"{k} missing (see README: test configuration)"
        assert env[k].endswith("/ics_test"), "refusing to run tests against a non-test database"
    return env


@pytest.fixture(scope="session")
def base_settings(tmp_path_factory):
    """Own throwaway vault+audit keys in a temp dir; ics_test database with its own roles (never the production env file)."""
    env = _test_env()
    d = tmp_path_factory.mktemp("keys")
    for n in ("vault.key", "audit.key"):
        (d / n).write_bytes(os.urandom(32))
        (d / n).chmod(0o600)
    return Settings(database_url=env["ICS_TEST_DATABASE_URL"], vault_key_file=str(d / "vault.key"),
                    audit_key_file=str(d / "audit.key"), worker_enabled=False, allow_loopback_endpoints=True)


@pytest.fixture(scope="session")
def owner_engine(base_settings):
    url = _test_env()["ICS_TEST_OWNER_DATABASE_URL"]
    eng = create_engine(url, isolation_level="AUTOCOMMIT")
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
        c.execute(text("TRUNCATE users, sessions, login_attempts, audit_events, endpoints, plans, jobs, "
                       "worker_heartbeat, inventory_snapshots, plan_approvals RESTART IDENTITY CASCADE"))
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
