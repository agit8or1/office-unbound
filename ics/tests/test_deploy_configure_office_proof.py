"""Collabora's WOPI proof key (2026-11-21: documents blank, "Unauthorized WOPI host"; OpenCloud's collaboration service refused every WOPI call with
"ProofKeys verification failed: Invalid timestamp" because coolwsd had no /etc/coolwsd/proof_key and sent no X-WOPI-Proof headers).
The ICS makes one RSA key per deployment (per tenant), keeps it as a deployment secret and writes it 0600 into the office tls volume; the image
links /etc/coolwsd/proof_key to it (read-only rootfs) and never carries a key of its own."""
import json
import os
import pathlib
import shutil
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import text

from ics.deploy import configure

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))
from ou_agent import cfgspec as c  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
OCI = ROOT / "blueprints" / "build" / "collabora" / "oci"
CA = {"cert": "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", "key": "unused"}
IMG = "registry.example/ou/office@sha256:" + "a" * 64


def _plan(tenant=None):
    return {"vms": [{"name": "fo", "components": ["files", "office"], **({"tenant": tenant} if tenant else {})}],
            "containers": [{"vm": "fo", "component": "office", "image": "registry.example/ou/office", "digest": "sha256:" + "a" * 64}],
            "input": {"domain": "acme.example"}, "dns": []}


def _ctx(monkeypatch, plan, store, made):
    def secret(rt, dep, name, make=None):
        if (dep, name) not in store:
            made.append(name)
            store[(dep, name)] = make() if make else "x" * 24
        return store[(dep, name)]
    monkeypatch.setattr(configure, "secret", secret)
    monkeypatch.setattr(configure, "scope_ca", lambda ctx, t: CA)
    monkeypatch.setattr(configure, "_local_sites", lambda *a, **k: [])
    return type("Ctx", (), {"deployment_id": "d1", "rt": None, "slug": "prod", "plan": plan})()


def _proof_file(rb):
    tls = next(r for r in rb if r["runbook"] == "cfg.volume_files" and r["params"]["volume"] == "tls")
    return tls, next(f for f in tls["params"]["files"] if f["path"] == "proof_key")


def test_the_office_gets_its_proof_key_0600_in_the_tls_volume_made_once(monkeypatch):
    store, made = {}, []
    ctx = _ctx(monkeypatch, _plan(), store, made)
    rb1 = configure.office_runbooks(ctx, "fo")
    rb2 = configure.office_runbooks(ctx, "fo")                       # a second configuration run (redeploy, change) reuses the key
    tls, f = _proof_file(rb1)
    assert made.count("office-proof-key") == 1 and _proof_file(rb2)[1]["content"] == f["content"]
    assert f["mode"] == 0o600 and tls["params"]["owner"] == configure.DOCS_UID and tls["params"]["component"] == "office"
    assert {x["path"] for x in tls["params"]["files"]} == {"ca.crt", "trust.crt", "proof_key"}   # 0.8.1 trust bundle unchanged
    assert f["content"].startswith("-----BEGIN RSA PRIVATE KEY-----\n")                          # PKCS#1, as `ssh-keygen -m PEM` (ProofKey.cpp)
    k = serialization.load_pem_private_key(f["content"].encode(), password=None)
    assert isinstance(k, rsa.RSAPrivateKey) and k.key_size == 2048
    for r in rb1:                                                     # what the ICS sends is what the agent accepts
        if r["runbook"] in c.CHECKS:
            c.CHECKS[r["runbook"]](r["params"], {"enabled": True})


def test_each_deployment_and_tenant_has_its_own_key(monkeypatch):
    store, made = {}, []
    ctx = _ctx(monkeypatch, _plan(), store, made)
    a = _proof_file(configure.office_runbooks(ctx, "fo"))[1]["content"]
    ctx.deployment_id = "d2"
    b = _proof_file(configure.office_runbooks(ctx, "fo"))[1]["content"]
    ctx2 = _ctx(monkeypatch, _plan("t01"), store, made)
    t = _proof_file(configure.office_runbooks(ctx2, "fo"))[1]["content"]
    assert len({a, b, t}) == 3 and ("d1", "t01-office-proof-key") in store


def test_the_proof_key_never_reaches_the_audit(monkeypatch):
    ctx = _ctx(monkeypatch, _plan(), {}, [])
    tls, f = _proof_file(configure.office_runbooks(ctx, "fo"))
    s = json.dumps(configure.redact("cfg.volume_files", tls["params"]))
    body = f["content"].splitlines()[1]
    assert "PRIVATE KEY" not in s and body not in s and {"path": "proof_key", "mode": 0o600, "bytes": len(f["content"])} in json.loads(s)["files"]


def test_the_secret_is_stored_encrypted_and_reused(rt):
    with rt.session() as db:
        db.execute(text("DELETE FROM deployments WHERE slug = 'pkey'"))
        dep = str(db.execute(text("INSERT INTO deployments (slug, customer_id, profile, profile_version, status, desired_spec) "
                                  "VALUES ('pkey', 'c-000000000000', 'small', '1', 'active', '{}'::jsonb) RETURNING id")).scalar())
        db.commit()
    k1 = configure.office_proof_key(rt, dep)
    assert configure.office_proof_key(rt, dep) == k1
    with rt.session() as db:
        raw = db.execute(text("SELECT value_enc FROM deployment_secrets WHERE deployment_id = :d AND name = 'office-proof-key'"), {"d": dep}).scalar()
        assert raw and b"PRIVATE KEY" not in bytes(raw)
        configure.wipe(db, dep)
        db.commit()


# ---- the image ---------------------------------------------------------------------------------------------------

def test_the_image_links_the_key_and_bakes_none():
    cf = (OCI / "Containerfile").read_text()
    assert "ARG OU_VERSION=26.04.6-ou6" in cf   # the recipe of the next image; the catalog pin (below) moves when it is built
    assert "rm -f /etc/coolwsd/proof_key /etc/coolwsd/proof_key.pub" in cf and "ln -s /opt/ou-tls/proof_key /etc/coolwsd/proof_key" in cf
    assert cf.index("ln -s /opt/ou-tls/proof_key") < cf.index("chown -R cool:cool /opt/ou-docs /etc/coolwsd")


@pytest.fixture()
def entry(tmp_path):
    """entrypoint.sh with its fixed paths moved under tmp_path and a stub coolwsd that prints its arguments."""
    if not shutil.which("sh"):
        pytest.skip("no sh")
    tls, etc = tmp_path / "tls", tmp_path / "etc"
    tls.mkdir(), etc.mkdir()
    stub = tmp_path / "coolwsd"
    stub.write_text("#!/bin/sh\nprintf '%s\\n' \"$@\"\n")
    stub.chmod(0o755)
    s = (OCI / "entrypoint.sh").read_text()
    s = s.replace("/opt/ou-tls", str(tls)).replace("/etc/coolwsd", str(etc)).replace("/opt/ou-docs/work", str(tmp_path / "work"))
    s = s.replace("/usr/bin/coolwsd", str(stub))
    ep = tmp_path / "ep.sh"
    ep.write_text(s)
    (etc / "proof_key").symlink_to(tls / "proof_key")

    def run(**env):
        e = {"PATH": os.environ["PATH"], "OU_WOPI_HOST": "https://cloud.acme.example:443", **env}
        return subprocess.run(["sh", str(ep)], env=e, capture_output=True, text=True, timeout=20)
    return run, tls


def test_entrypoint_accepts_the_key_and_keeps_the_ca_bundle(entry):
    run, tls = entry
    (tls / "proof_key").write_text(configure._proof_key())
    (tls / "proof_key").chmod(0o600)
    r = run(OU_CA_FILE="/opt/ou-tls/trust.crt")
    assert r.returncode == 0, r.stderr
    assert "WARNING" not in r.stderr and "--o:ssl.ca_file_path=/opt/ou-tls/trust.crt" in r.stdout.splitlines()
    assert "PRIVATE" not in r.stdout + r.stderr


def test_entrypoint_warns_without_a_key_and_starts_as_before(entry):
    run, _ = entry
    r = run()
    assert r.returncode == 0 and "WARNING: no WOPI proof key" in r.stderr and "--o:ssl.enable=false" in r.stdout


@pytest.mark.parametrize("content", ["not a key\n", "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n", "-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----\n",
                                     "$(touch /tmp/ou-pwn)\n-----END RSA PRIVATE KEY-----\n"])
def test_entrypoint_refuses_a_file_that_is_no_pem_key(entry, content):
    run, tls = entry
    (tls / "proof_key").write_text(content)
    r = run()
    assert r.returncode == 64 and "proof_key" in r.stderr and r.stdout == "" and not os.path.exists("/tmp/ou-pwn")


def test_the_image_turns_the_tour_autostart_off_and_the_catalog_pins_it():
    # owner 2026-11-23: no automatic onboarding tour (Help keeps it). The build fails unless the expression occurs exactly once.
    cf = (OCI / "Containerfile").read_text()
    assert 'getBooleanDocTypePref("onboardingTourSeen",!1)' in cf and 'getBooleanDocTypePref("onboardingTourSeen",!0)' in cf
    assert cf.index("onboardingTourSeen") < cf.index("USER 10001:10001")
    cat = (OCI.parents[2] / "catalog" / "components" / "office.yaml").read_text()
    assert 'version: "26.04.6-ou5"' in cat
    patch = (OCI.parent / "patches" / "0004-office-unbound-no-tour-autostart.patch").read_text()
    assert "getBooleanDocTypePref('onboardingTourSeen', true)" in patch
