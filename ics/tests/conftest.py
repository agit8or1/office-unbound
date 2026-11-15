import os
import re

import pyotp
import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text

from ics import auth
from ics.config import load_settings
from ics.main import create_app
from ics.runtime import Runtime
from ics.vault import Vault

from .pve_mock import MockPVE


def _test_url(u: str) -> str:
    n = re.sub(r"/ics$", "/ics_test", u)
    assert n.endswith("/ics_test") and n != u, "refusing to run tests against a non-test database"
    return n


@pytest.fixture(scope="session")
def base_settings():
    s = load_settings()
    return type(s)(**{**s.__dict__, "database_url": _test_url(s.database_url),
                      "migrate_database_url": _test_url(s.migrate_database_url),
                      "worker_enabled": False})


@pytest.fixture(scope="session")
def owner_engine(base_settings):
    eng = create_engine(base_settings.migrate_database_url, isolation_level="AUTOCOMMIT")
    with eng.connect() as c:
        c.execute(text("DROP SCHEMA public CASCADE"))
        c.execute(text("CREATE SCHEMA public"))
    cfg = Config(os.path.join(os.path.dirname(__file__), "..", "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(os.path.dirname(__file__), "..", "migrations"))
    cfg.attributes["url"] = base_settings.migrate_database_url
    command.upgrade(cfg, "head")
    return eng


@pytest.fixture()
def rt(base_settings, owner_engine):
    with owner_engine.connect() as c:
        c.execute(text("TRUNCATE users, sessions, login_attempts, audit_events, endpoints, plans, jobs, "
                       "worker_heartbeat, inventory_snapshots RESTART IDENTITY CASCADE"))
    r = Runtime(base_settings)
    yield r
    r.engine.dispose()


@pytest.fixture()
def client(rt):
    app = create_app(rt.settings)
    app.state.rt.engine.dispose()
    app.state.rt = rt  # share the fixture runtime
    return TestClient(app, base_url="https://testserver")


@pytest.fixture()
def mk_user(rt):
    def make(username, role, password="correct horse battery"):
        with rt.session() as db:
            uri = auth.create_user(db, rt, username, password, role)
        return {"username": username, "password": password, "secret": re.search(r"secret=([A-Z2-7]+)", uri).group(1)}
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
