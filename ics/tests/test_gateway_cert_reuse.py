"""Public certificate reuse (ics/gateway.py, agent cfg.acme feature `reuse`, ADR-0018 section 11 amendment 2026-11-22): the lineage a gateway
serves is captured after a production issuance, stored vault-encrypted by name set, and restored on a rebuilt gateway so no new certificate is
ordered; only data crosses (the agent writes certbot's renewal configuration itself); the private key never reaches a result, an audit record or
a world-readable file."""
import datetime
import json
import os
import sys
import types

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from sqlalchemy import text

from ics import gateway, worker
from ics.deploy import appaccess, configure

from .test_gateway_certs import _plan

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))
from ou_agent import cfghelper as h  # noqa: E402
from ou_agent import cfgspec as c  # noqa: E402
from ou_agent import runbooks as rbk  # noqa: E402
from ou_agent.proto import Reject  # noqa: E402

ACCT = "0123456789abcdef0123456789abcdef"


def _pem_pair(days: int, cn: str = "app.acme.example") -> tuple[str, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=days)).sign(key, hashes.SHA256()))
    kp = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    return cert.public_bytes(serialization.Encoding.PEM).decode(), kp


def bundle(days: int = 80) -> dict:
    leaf, key = _pem_pair(days)
    issuer, _ = _pem_pair(900, "R11")
    return {"account_id": ACCT, "account": {"meta": '{"creation_host": "gw"}', "regr": '{"body": {}, "uri": "https://acme/acct/1"}',
                                            "private_key": '{"kty": "RSA", "n": "x", "e": "AQAB", "d": "y"}'},
            "cert": leaf, "chain": issuer, "fullchain": leaf + issuer, "privkey": key}


BASE = {"names": ["app.acme.example", "auth.acme.example"], "directory": "production", "cert_name": "public"}


def test_the_agent_accepts_a_lineage_as_data_only():
    b = bundle()
    assert c.check_acme({**BASE, "export": True, "restore": b}, {}) == {**BASE, "export": True, "restore": b}
    assert c.check_acme(dict(BASE), {}) == BASE                                          # the old request shape still works
    assert "reuse" in c.FEATURES["cfg.acme"]
    for bad in ({"directory": "staging", "export": True}, {"export": "yes"},
                {"restore": {**b, "renewal_conf": "pre_hook = /bin/sh -c id"}},           # certbot configuration (hooks run as root) never crosses
                {"restore": {**b, "privkey": b["cert"]}}, {"restore": {**b, "cert": b["privkey"]}},
                {"restore": {**b, "fullchain": b["chain"]}}, {"restore": {**b, "account_id": "../../etc"}},
                {"restore": {**b, "account": {**b["account"], "meta": "[1]"}}}, {"restore": {**b, "account": {"meta": "{}"}}}):
        with pytest.raises(Reject):
            c.check_acme({**BASE, **bad}, {})


def _fake_x():
    return types.SimpleNamespace(run=lambda argv, **k: types.SimpleNamespace(stdout="certbot 2.9.0\n", returncode=0))


def test_restore_writes_certbots_lineage_and_export_reads_it_back(tmp_path, monkeypatch):
    monkeypatch.setattr(h.os, "chown", lambda *a, **k: None)
    b = bundle()
    p = {**BASE, "restore": b}
    assert h.acme_restore(p, _fake_x(), etc=str(tmp_path)) is True
    conf = (tmp_path / "renewal/public.conf").read_text()
    assert f"account = {ACCT}" in conf and "server = https://acme-v02.api.letsencrypt.org/directory" in conf and "version = 2.9.0" in conf
    assert "app.acme.example = /var/lib/ou-acme/webroot" in conf and "hook" not in conf.split("[renewalparams]")[1]
    assert os.readlink(tmp_path / "live/public/privkey.pem") == "../../archive/public/privkey1.pem"
    assert (tmp_path / "archive/public/privkey1.pem").stat().st_mode & 0o777 == 0o600
    acct = tmp_path / "accounts/acme-v02.api.letsencrypt.org/directory" / ACCT
    assert (acct / "private_key.json").stat().st_mode & 0o777 == 0o400 and (acct.stat().st_mode & 0o777) == 0o700
    assert h.acme_export("public", etc=str(tmp_path)) == b
    assert h.acme_restore(p, _fake_x(), etc=str(tmp_path)) is False                      # never overwrites a lineage the gateway already has


def test_export_refuses_a_staging_lineage(tmp_path):
    (tmp_path / "renewal").mkdir()
    (tmp_path / "renewal/public.conf").write_text(f"account = {ACCT}\nserver = https://acme-staging-v02.api.letsencrypt.org/directory\n")
    with pytest.raises(h.Failed):
        h.acme_export("public", etc=str(tmp_path))


def test_the_agent_reads_the_secret_result_once(tmp_path):
    (tmp_path / "cfg-r1.json").write_text(json.dumps({"rid": "r1", "bundle": {"privkey": "k"}}))
    assert rbk._cfg_secret("r1", str(tmp_path)) == {"privkey": "k"}
    assert not (tmp_path / "cfg-r1.json").exists()                                       # unlinked at once
    (tmp_path / "cfg-r2.json").write_text(json.dumps({"rid": "other", "bundle": {}}))
    with pytest.raises(RuntimeError):
        rbk._cfg_secret("r2", str(tmp_path))
    assert not (tmp_path / "cfg-r2.json").exists()
    with pytest.raises(RuntimeError):
        rbk._cfg_secret("r3", str(tmp_path))


def test_the_restore_bundle_is_redacted_from_the_audit():
    r = configure.redact("cfg.acme", {**BASE, "export": True, "restore": bundle()})
    assert r["restore"] == "[certificate bundle]" and "PRIVATE KEY" not in json.dumps(r)


def _setup(rt, monkeypatch, slugs, features):
    with rt.session() as db:
        for s in slugs:
            db.execute(text("INSERT INTO deployments (slug, customer_id, profile, profile_version, status, desired_spec) "
                            "VALUES (:s, 'c-000000000000', 'small', '1', 'active', '{}'::jsonb)"), {"s": s})
        db.commit()
    p = _plan()
    monkeypatch.setattr(appaccess, "_applied_plan", lambda db, d: p)
    monkeypatch.setattr(appaccess, "_addresses", lambda db, d: {v["name"]: f"10.0.0.{i + 10}" for i, v in enumerate(p["vms"])})
    monkeypatch.setattr(gateway, "_edge_node", lambda db, d, edge: "node-1")
    monkeypatch.setattr(gateway, "_node_features", lambda db, node, rb: list(features) if rb == "cfg.acme" else [])
    monkeypatch.setattr(gateway, "convert_checks", lambda db, d, names, roots=None: [])
    monkeypatch.setattr(configure, "secret", lambda rt_, dep, name, make=None: (make() if make else name + "-" + "x" * 24))
    return p


def _issue(rt, adm, ah, apr, aph, params):
    r = adm.post("/api/v1/plans", json={"action": "gateway.certificates.issue", "params": params}, headers=ah)
    jid = r.json().get("job_id")
    if r.json()["status"] != "approved":
        jid = apr.post(f"/api/v1/plans/{r.json()['plan_id']}/approve", headers=aph).json()["job_id"]
    assert worker.run_once(rt)
    job = adm.get(f"/api/v1/jobs/{jid}").json()
    assert job["status"] == "succeeded", job
    return job


def test_a_rebuilt_gateway_gets_the_captured_certificate_back(rt, client, mk_user, login, monkeypatch):
    adm, ah = login(mk_user("boss", "admin"))
    apr, aph = login(mk_user("second", "approver"))
    p = _setup(rt, monkeypatch, ["ou6", "ou7"], ["reuse"])
    names = gateway.web_names(p)
    b = bundle(80)
    calls = []

    def execute(rt_, node, rb, params, deadline=0):
        calls.append((rb, json.loads(json.dumps(params))))
        if rb == "cfg.acme":
            return {"status": "ok", "result": {"result": {"certificate": "notAfter=...", "restored": "restore" in params,
                                                          **({"bundle": b} if params.get("export") else {})}}}
        return {"status": "ok", "result": {"result": {"ok": True}}}
    monkeypatch.setattr(gateway.agentcall, "execute", execute)

    job = _issue(rt, adm, ah, apr, aph, {"deployment": "ou6", "directory": "production"})        # first gateway: new order, lineage captured
    acme = [x[1] for x in calls if x[0] == "cfg.acme"]
    assert acme[-1] == {"names": names, "directory": "production", "cert_name": "public", "export": True}
    assert job["result"]["reuse"]["captured"] and not job["result"]["reuse"]["offered"]
    with rt.session() as db:
        row = db.execute(text("SELECT names, bundle_enc, source_deployment FROM public_certificates")).one()
        assert row.names == sorted(names) and row.source_deployment == "ou6" and b"PRIVATE KEY" not in bytes(row.bundle_enc)

    calls.clear()
    job = _issue(rt, adm, ah, apr, aph, {"deployment": "ou7", "directory": "production"})        # the rebuild: same names, lineage restored
    acme = [x[1] for x in calls if x[0] == "cfg.acme"][-1]
    assert acme["restore"] == b and acme["export"] is True
    assert job["result"]["reuse"] == {**job["result"]["reuse"], "offered": True, "restored": True, "captured": True}

    calls.clear()
    _issue(rt, adm, ah, apr, aph, {"deployment": "ou7", "directory": "production", "force_new": True})
    assert "restore" not in [x[1] for x in calls if x[0] == "cfg.acme"][-1]                    # force_new: no restore

    with rt.session() as db:
        audit_rows = db.execute(text("SELECT details::text FROM audit_events")).scalars().all()
        results = db.execute(text("SELECT coalesce(result::text, '') FROM jobs")).scalars().all()
    assert not any("PRIVATE KEY" in t for t in audit_rows + results)                          # never in an audit record or a job result


def test_no_reuse_for_an_expiring_certificate_or_an_older_agent(rt, client, mk_user, login, monkeypatch):
    adm, ah = login(mk_user("boss", "admin"))
    apr, aph = login(mk_user("second", "approver"))
    p = _setup(rt, monkeypatch, ["ou8"], [])
    names = gateway.web_names(p)
    with rt.session() as db:
        gateway.store_bundle(rt, db, names, bundle(20), "ou-old")                              # valid 20 days: below REUSE_MIN_DAYS
        db.commit()
        assert gateway.stored_bundle(rt, db, names) is None
        assert gateway.stored_bundle(rt, db, names, min_days=10) is not None
    calls = []

    def execute(rt_, node, rb, params, deadline=0):
        calls.append((rb, params))
        return {"status": "ok", "result": {"result": {"certificate": "notAfter=..."}}}
    monkeypatch.setattr(gateway.agentcall, "execute", execute)
    job = _issue(rt, adm, ah, apr, aph, {"deployment": "ou8", "directory": "production"})
    assert [x[1] for x in calls if x[0] == "cfg.acme"][-1] == {"names": names, "directory": "production", "cert_name": "public"}   # older agent
    assert job["result"]["reuse"] == {"supported": False, "offered": False, "restored": False, "captured": False}
