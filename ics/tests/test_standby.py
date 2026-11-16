"""Warm standby (ADR-0012): role/epoch decisions, passive guard, key bundle, promotion helpers. Fakes only; the real streaming
replication + promotion + fencing proof is docs/status/ics-standby-results.md (lab)."""
import dataclasses

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from ics import epoch, keybundle, promote
from ics.agentclient import AgentError
from ics.main import create_app


def _reset(owner_engine):
    with owner_engine.connect() as c:   # leave the shared test DB at epoch 1 / primary
        c.execute(text("ALTER TABLE controller_state DISABLE TRIGGER controller_state_guard"))
        c.execute(text("UPDATE controller_state SET epoch = 1, role = 'primary', note = NULL"))
        c.execute(text("ALTER TABLE controller_state ENABLE TRIGGER controller_state_guard"))


def test_check_active_decisions():
    st = {"epoch": 3, "role": "primary"}
    assert epoch.check_active(configured_role="primary", state=st) == 3
    with pytest.raises(epoch.NotActive, match="STANDBY"):
        epoch.check_active(configured_role="standby", state=st)
    with pytest.raises(epoch.NotActive, match="fenced"):
        epoch.check_active(configured_role="primary", state={"epoch": 3, "role": "fenced"})
    assert issubclass(epoch.NotActive, AgentError)


def test_epoch_is_monotonic_in_the_database(rt, owner_engine):
    try:
        with rt.session() as db:
            old, new = epoch.bump_for_promotion(db, "h", "t")
            db.commit()
        assert new == old + 1 and rt.agent_epoch() == new
        with pytest.raises(Exception, match="monotonic"):
            with rt.session() as db:
                db.execute(text("UPDATE controller_state SET epoch = 1 WHERE id = 1"))
                db.commit()
        with pytest.raises(Exception):
            with rt.session() as db:
                db.execute(text("DELETE FROM controller_state"))
                db.commit()
    finally:
        _reset(owner_engine)


def test_self_fence_blocks_signing_and_is_audited(rt, owner_engine):
    try:
        e = rt.agent_epoch()
        assert epoch.self_fence(rt, e) is False                    # an agent at our own epoch is not a fence
        assert epoch.self_fence(rt, e + 1) is True
        with pytest.raises(epoch.NotActive, match="fenced"):
            rt.agent_epoch()
        with rt.session() as db:
            assert db.execute(text("SELECT count(*) FROM audit_events WHERE action = 'controller.self_fenced'")).scalar() == 1
    finally:
        _reset(owner_engine)


def test_standby_refuses_to_sign_even_with_a_primary_db(rt, base_settings):
    rt.settings = dataclasses.replace(base_settings, role="standby")
    with pytest.raises(epoch.NotActive, match="STANDBY"):
        rt.agent_epoch()


def test_standby_api_is_read_only_with_banner(rt, base_settings):
    rt.settings = dataclasses.replace(base_settings, role="standby", worker_enabled=True)
    with TestClient(create_app(rt.settings, rt)) as c:
        r = c.post("/api/v1/auth/login", json={"username": "a", "password": "b", "totp_code": "c"})
        assert r.status_code == 503 and r.headers["x-ou-role"] == "standby" and "STANDBY" in r.json()["detail"]
        assert c.delete("/api/v1/plans/x").status_code == 503
        page = c.get("/", headers={"accept": "text/html"})
        assert page.status_code == 200 and "STANDBY CONTROLLER" in page.text and page.headers["x-ou-role"] == "standby"
        assert "style-src 'self'" in page.headers["content-security-policy"]
        ready = c.get("/readyz")
        body = ready.json()
        assert body["role"] == "standby" and "replication" in body["checks"] and "worker" not in body["checks"]
        assert ready.status_code == 503 and body["checks"]["replication"]["in_recovery"] is False   # a non-replica is NOT a healthy standby


def test_primary_readyz_reports_role_and_epoch(rt):
    with TestClient(create_app(rt.settings, rt)) as c:
        body = c.get("/readyz").json()
        assert body["role"] == "primary" and body["epoch"] >= 1 and body["fenced"] is False


def test_key_bundle_roundtrip_and_tamper():
    files = {"vault.key": b"v" * 32, "audit.key": b"a" * 32, "replicator.pw": b"pw"}
    pw = keybundle.new_passphrase()
    assert len(pw.replace("-", "")) == 32
    blob = keybundle.seal(files, {"primary_ip": "10.0.0.1"}, pw)
    assert b"v" * 32 not in blob
    meta, out = keybundle.unseal(blob, pw)
    assert out == files and meta["primary_ip"] == "10.0.0.1"
    with pytest.raises(keybundle.BundleError):
        keybundle.unseal(blob, keybundle.new_passphrase())
    bad = bytearray(blob)
    bad[-3] ^= 1
    with pytest.raises(keybundle.BundleError):
        keybundle.unseal(bytes(bad), pw)
    with pytest.raises(keybundle.BundleError, match="not allowed"):
        keybundle.seal({"../../etc/passwd": b"x"}, {}, pw)


def test_set_env_updates_in_place_and_keeps_mode(tmp_path):
    p = tmp_path / "ics.env"
    p.write_text("A=1\nICS_ROLE=standby\nICS_WORKER_ENABLED=false\n")
    p.chmod(0o640)
    promote.set_env(str(p), {"ICS_ROLE": "primary", "ICS_WORKER_ENABLED": "true", "ICS_MONITOR_ENABLED": "true"})
    assert p.read_text().splitlines() == ["A=1", "ICS_ROLE=primary", "ICS_WORKER_ENABLED=true", "ICS_MONITOR_ENABLED=true"]
    assert oct(p.stat().st_mode & 0o777) == "0o640"
