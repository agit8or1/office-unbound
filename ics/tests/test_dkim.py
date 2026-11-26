"""Outgoing-mail signing with the deployment's DKIM key (owner 2026-11-26: the DNS checker must give the DKIM record): the ICS makes the key
(configure.dkim_key), sends it only to agents with the `dkim` feature (cfg.gromox), the agent runs OpenDKIM as Postfix's milter, and both
DNS checkers show the exact TXT record and compare the published key."""
import os
import sys
import types

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))
from ou_agent import cfghelper as h  # noqa: E402
from ou_agent import cfgspec as c  # noqa: E402
from ou_agent.proto import Reject  # noqa: E402

from ics.deploy import configure  # noqa: E402
from ics.deploy.catalog import load_catalog  # noqa: E402

from .test_desktop_server import _ctx  # noqa: E402

KEY = configure._rsa_key()


def test_the_record_is_the_public_half_of_the_signing_key():
    from cryptography.hazmat.primitives import serialization
    import base64
    v = configure.dkim_txt(KEY)
    assert v.startswith("v=DKIM1; k=rsa; p=")
    pub = serialization.load_der_public_key(base64.b64decode(v.split("p=", 1)[1]))
    priv = serialization.load_pem_private_key(KEY.encode(), password=None)
    assert pub.public_numbers() == priv.public_key().public_numbers() and pub.key_size == 2048


def test_cfg_gromox_sends_the_key_only_to_agents_that_sign_and_the_audit_never_records_it(monkeypatch):
    monkeypatch.setattr(configure, "dkim_key", lambda rt, dep, t=None: KEY)
    g = next(r["params"] for r in configure.groupware_runbooks(_ctx(monkeypatch, ["brand_fonts", "client_document"]), "gw") if r["runbook"] == "cfg.gromox")
    assert "dkim" not in g                                                    # an older agent's closed schema would refuse it
    g = next(r["params"] for r in configure.groupware_runbooks(_ctx(monkeypatch, ["brand_fonts", "client_document", "dkim"]), "gw")
             if r["runbook"] == "cfg.gromox")
    assert g["dkim"] == {"domain": g["domain"], "selector": configure.DKIM_SELECTOR, "key_pem": KEY}
    assert c.check_gromox(g, {"enabled": True})["dkim"] == g["dkim"]          # what the ICS sends is what the agent accepts
    red = configure.redact("cfg.gromox", g)
    assert red["dkim"]["key_pem"] == "[redacted]" and KEY not in str(red)
    assert "dkim" in c.FEATURES["cfg.gromox"] and configure.DKIM_FEATURE == "dkim"


@pytest.mark.parametrize("change", [{"domain": "other.example"}, {"selector": "Bad_Sel"}, {"selector": ""}, {"key_pem": "not a key"},
                                    {"extra": 1}, {"key_pem": None}])
def test_the_agent_refuses_dkim_parameters_outside_its_schema(change):
    d = {"domain": "e2e.example", "selector": "ou1", "key_pem": KEY, **change}
    if d.get("key_pem", "") is None:
        del d["key_pem"]
    with pytest.raises(Reject):
        c.check_dkim(d, "e2e.example")


def test_the_agent_configures_opendkim_as_postfixs_milter_and_removes_it(tmp_path, monkeypatch):
    runs = []
    x = types.SimpleNamespace(run=lambda argv, **k: runs.append(argv) or types.SimpleNamespace(returncode=0, stdout="install ok installed"))
    monkeypatch.setattr(h, "DKIM_KEYDIR", str(tmp_path / "keys"))
    monkeypatch.setattr(h, "OPENDKIM_CONF", str(tmp_path / "opendkim.conf"))
    monkeypatch.setattr(h, "_uid", lambda n: os.getuid())
    monkeypatch.setattr(h, "_gid", lambda n: os.getgid())
    monkeypatch.setattr(h.os, "chown", lambda *a, **k: None)
    real_makedirs = os.makedirs
    monkeypatch.setattr(h.os, "makedirs", lambda p, *a, **k: real_makedirs(str(tmp_path / "keys") if p == h.DKIM_KEYDIR else p, *a, **k))
    monkeypatch.setattr(h.os, "chmod", lambda *a, **k: None)
    d = c.check_dkim({"domain": "e2e.example", "selector": "ou1", "key_pem": KEY}, "e2e.example")
    assert h._dkim(d, x) == ["opendkim"]
    kf = tmp_path / "keys" / "ou1.private"
    assert kf.read_text() == KEY and oct(kf.stat().st_mode & 0o777) == "0o600"
    conf = (tmp_path / "opendkim.conf").read_text()
    for line in ("Mode s", "Domain e2e.example", "Selector ou1", f"KeyFile {kf}", "Socket inet:8891@127.0.0.1", "InternalHosts 127.0.0.1",
                 "MacroList daemon_name|ORIGINATING"):
        assert line in conf.splitlines(), line
    pc = next(a for a in runs if "smtpd_milters=inet:127.0.0.1:8891" in a)
    assert "non_smtpd_milters=$smtpd_milters" in pc and "milter_default_action=accept" in pc
    assert "-o milter_macro_daemon_name=ORIGINATING" in h.SUBMISSION     # authenticated submission is signed, internet mail is not
    runs.clear()
    assert h._dkim(None, x) == [] and any("smtpd_milters=" in a for a in runs)


def test_running_deployments_get_signing_with_their_next_change():
    cat = load_catalog()
    g = cat.components["groupware"]
    assert g.config_revision >= 3
    assert any(a.kind == "package" and a.package == "opendkim" and a.version == "2.11.0~beta2-9build4" for a in g.artifacts)
