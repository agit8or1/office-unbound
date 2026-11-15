import datetime as dt
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from fakeserver import GRAPH_SECRET, GRAPH_TOKEN, TENANT, FakeServer, install_google, install_graph  # noqa: E402

from ou_migration.auth import GoogleAuth, GraphAuth  # noqa: E402
from ou_migration.checkpoint import Checkpoint  # noqa: E402
from ou_migration.http import HttpClient  # noqa: E402

TODAY = dt.date(2026, 11, 15)
A = "https://www.googleapis.com/auth/"
ALL_SCOPES = {A + s for s in ("admin.directory.user.readonly", "admin.directory.group.readonly", "admin.directory.domain.readonly",
                              "admin.directory.customer.readonly", "admin.reports.usage.readonly",
                              "admin.directory.resource.calendar.readonly", "gmail.metadata", "drive.metadata.readonly")}


class Sleeper:
    def __init__(self):
        self.calls = []

    def __call__(self, s):
        self.calls.append(s)


@pytest.fixture
def sleeper():
    return Sleeper()


@pytest.fixture
def http(sleeper):
    return HttpClient(allow_loopback_http=True, sleep=sleeper, base_delay=0.01, max_retries=4, rng=lambda: 0.5)


@pytest.fixture
def server():
    s = FakeServer().start()
    yield s
    s.stop()


@pytest.fixture
def graph(server):
    install_graph(server)
    return server


@pytest.fixture
def graph_auth(http, graph):
    return GraphAuth(http, TENANT, "client-id-1", GRAPH_SECRET, login_base=graph.base + "/login")


@pytest.fixture
def ckpt_path(tmp_path):
    return str(tmp_path / "ckpt.json")


@pytest.fixture
def rsa_key():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    return pem, k.public_key()


@pytest.fixture
def google(server, rsa_key):
    pem, pub = rsa_key
    server.data_date = install_google(server, pub, today=TODAY)
    server.dwd_allowed = set(ALL_SCOPES)
    return server


@pytest.fixture
def google_auth(http, google, rsa_key):
    return GoogleAuth(http, "sa@proj.iam.gserviceaccount.example", rsa_key[0], "admin@example.test", token_uri=google.base + "/gtoken")


@pytest.fixture
def google_keyfile(tmp_path, rsa_key, google):
    p = tmp_path / "sa.json"
    p.write_text(json.dumps({"client_email": "sa@proj.iam.gserviceaccount.example", "private_key": rsa_key[0], "token_uri": google.base + "/gtoken"}))
    os.chmod(p, 0o600)
    return str(p)


def make_ckpt(path, provider="m365", tenant=TENANT):
    return Checkpoint(path, provider, tenant)
