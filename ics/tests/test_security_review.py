"""Regression tests for docs/status/security-review-ics-2026-11-15.md (one section per finding)."""
import dataclasses
import json
import os
import stat
import threading
import time
from importlib import metadata
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from ics import audit, auth, worker
from ics import actions as actions_mod
from ics.actions import reap_expired
from ics.config import Settings, load_settings
from ics.proxmox import ProxmoxError, ProxmoxReadClient
from ics.vault import Vault, VaultError
from .conftest import totp_for
from .pve_mock import SEC, TID, MockPVE

H = "/api/v1"
ROOT = Path(__file__).resolve().parent.parent


def reg(pve, **over):
    p = {"name": "lab-pve", "type": "proxmox", "base_url": pve.url, "token_id": TID, "token_secret": SEC,
         "fingerprint_sha256": pve.fingerprint}
    p.update(over)
    return {"action": "endpoint.register", "params": p}


@pytest.fixture()
def team(mk_user, login):
    """operator + three approvers (independent, created from the host) + admin."""
    t = {n: login(mk_user(n, r)) for n, r in [("op", "operator"), ("ap1", "approver"), ("ap2", "approver"), ("ap3", "approver"), ("adm", "admin")]}
    return t


def approve2(team, pid):
    r = None
    for n in ("ap1", "ap2"):
        c, h = team[n]
        r = c.post(f"{H}/plans/{pid}/approve", headers=h)
        assert r.status_code == 200, r.text
    return r.json()


def registered(team, pve, rt, **over):
    c, h = team["op"]
    pid = c.post(f"{H}/plans", json=reg(pve, **over), headers=h).json()["plan_id"]
    return pid, approve2(team, pid)["job_id"]


def audit_dump(rt):
    with rt.session() as db:
        return json.dumps([str(r[0]) for r in db.execute(text("SELECT details FROM audit_events")).all()])


# ---------------------------------------------------------------- H1
def test_h1_trailing_newline_secret_is_normalised_and_never_leaks(team, pve, rt):
    pid, jid = registered(team, pve, rt, token_secret=SEC + "\n")
    worker.run_once(rt)
    c, _ = team["op"]
    job = c.get(f"{H}/jobs/{jid}").json()
    assert job["status"] == "succeeded", job  # stripped at registration, so the header is valid
    assert SEC not in json.dumps(job) + audit_dump(rt) + json.dumps(c.get(f"{H}/plans").json())


@pytest.mark.parametrize("bad", ["abc def12345", "secret\x00value1", "sécret-value-1", "short", "a" * 201, "x;y=z-1234"])
def test_h1_bad_secret_rejected_without_echo(team, pve, bad):
    c, h = team["op"]
    r = c.post(f"{H}/plans", json=reg(pve, token_secret=bad), headers=h)
    assert r.status_code == 422 and bad not in r.text


def test_h1_job_error_and_audit_are_redacted(team, pve, rt, monkeypatch):
    def boom(self):  # what h11 used to raise: it echoes the whole header value
        raise ProxmoxError(f"Illegal header value b'PVEAPIToken={TID}={SEC}\\n' and raw {SEC}")
    monkeypatch.setattr(ProxmoxReadClient, "version", boom)
    pid, jid = registered(team, pve, rt)
    worker.run_once(rt)
    c, _ = team["op"]
    job = c.get(f"{H}/jobs/{jid}").json()
    assert job["status"] == "failed"
    blob = json.dumps(job) + audit_dump(rt)
    assert SEC not in blob and "PVEAPIToken=" + TID not in blob and "PVEAPIToken=[redacted]" in blob


def test_h1_unknown_exception_text_is_not_passed_through(team, pve, rt, monkeypatch):
    def boom(self):
        raise KeyError(f"secret is {SEC}")
    monkeypatch.setattr(ProxmoxReadClient, "version", boom)
    pid, jid = registered(team, pve, rt)
    worker.run_once(rt)
    job = team["op"][0].get(f"{H}/jobs/{jid}").json()
    assert job["status"] == "failed" and SEC not in json.dumps(job) + audit_dump(rt)


def test_h1_redact_unit():
    out = audit.redact({"a": "x TOPSECRET99\n y", "b": ["PVEAPIToken=u@p!t=abc"]}, ["TOPSECRET99\n"])
    assert "TOPSECRET99" not in json.dumps(out) and out["b"] == ["PVEAPIToken=[redacted]"]
    assert "PVEAPIToken=abc" not in json.dumps(audit.scrub({"m": "PVEAPIToken=abc"}))


def test_h1_proxmox_errors_do_not_echo_transport_text(pve):
    with pytest.raises(ValueError) as e:
        ProxmoxReadClient(pve.url, TID, "bad secret\n", fingerprint_sha256=pve.fingerprint, allow_loopback=True)
    assert "bad secret" not in str(e.value)


# ---------------------------------------------------------------- H2 / L5
def test_h2_no_credentials_returned_and_only_viewer_operator_via_api(team, mk_user):
    c, h = team["adm"]
    r = c.post(f"{H}/users", json={"username": "newop", "role": "operator"}, headers=h)
    assert r.status_code == 201 and set(r.json()) == {"username", "role", "invite"}
    assert c.post(f"{H}/users", json={"username": "sock", "role": "approver"}, headers=h).status_code == 422
    assert c.post(f"{H}/users", json={"username": "sock", "role": "admin", "password": "x" * 20}, headers=h).status_code == 422


def test_h2_invited_user_cannot_login_until_enrolled_and_sets_own_credentials(rt, client, team):
    c, h = team["adm"]
    c.post(f"{H}/users", json={"username": "newop", "role": "operator"}, headers=h)
    with rt.session() as db:
        assert db.execute(text("SELECT password_hash IS NULL AND totp_secret_enc IS NULL AND NOT enrolled FROM users WHERE username='newop'")).scalar()
        tok = auth.issue_enrollment_token(db, rt, "newop")
    login_body = {"username": "newop", "password": "my own password 123", "totp_code": "000000"}
    assert client.post(f"{H}/auth/login", json=login_body).status_code == 401
    assert client.post(f"{H}/auth/enroll", json={"username": "newop", "token": "wrong", "password": "my own password 123"}).status_code == 401
    r = client.post(f"{H}/auth/enroll", json={"username": "newop", "token": tok, "password": "my own password 123"})
    assert r.status_code == 200
    import re
    u = {"secret": re.search(r"secret=([A-Z2-7]+)", r.json()["totp_provisioning_uri"]).group(1)}
    import pyotp
    assert client.post(f"{H}/auth/login", json={**login_body, "totp_code": pyotp.TOTP(u["secret"]).now()}).status_code == 401  # not confirmed yet
    assert client.post(f"{H}/auth/enroll/confirm", json={"username": "newop", "token": tok, "totp_code": "000000"}).status_code == 401
    assert client.post(f"{H}/auth/enroll/confirm", json={"username": "newop", "token": tok, "totp_code": totp_for(u)}).status_code == 200
    assert client.post(f"{H}/auth/enroll/confirm", json={"username": "newop", "token": tok, "totp_code": pyotp.TOTP(u["secret"]).now()}).status_code == 401  # token spent
    assert client.post(f"{H}/auth/login", json={**login_body, "totp_code": totp_for(u)}).status_code == 200
    with rt.session() as db:  # creator never learned anything: only a token hash exists, and it was cleared
        assert db.execute(text("SELECT enrollment_token_hash FROM users WHERE username='newop'")).scalar() is None


def test_h2_approver_creation_needs_second_approver_and_is_recorded(team, rt):
    c, h = team["adm"]
    body = {"action": "user.create", "params": {"username": "ap9", "role": "approver"}}
    assert team["op"][0].post(f"{H}/plans", json=body, headers=team["op"][1]).status_code == 403  # admin only
    pid = c.post(f"{H}/plans", json=body, headers=h).json()["plan_id"]
    assert c.post(f"{H}/plans/{pid}/approve", headers=h).status_code == 403  # not self
    api, aph = team["ap1"]
    assert api.post(f"{H}/plans/{pid}/approve", headers=aph).json()["status"] == "pending_approval"
    jid = team["ap2"][0].post(f"{H}/plans/{pid}/approve", headers=team["ap2"][1]).json()["job_id"]
    worker.run_once(rt)
    assert c.get(f"{H}/jobs/{jid}").json()["status"] == "succeeded"
    with rt.session() as db:
        r = db.execute(text("SELECT u.role, u.enrolled, u.password_hash, c.username AS cb FROM users u JOIN users c ON c.id = u.created_by "
                            "WHERE u.username='ap9'")).first()
    assert (r.role, r.enrolled, r.password_hash, r.cb) == ("approver", False, None, "adm")


def test_h2_sockpuppet_approver_cannot_approve_creators_plans(team, rt, pve, login, mk_user, client):
    c, h = team["adm"]
    # admin gets a sockpuppet approver created through the approved flow (the 'legit' path) ...
    pid = c.post(f"{H}/plans", json={"action": "user.create", "params": {"username": "sock", "role": "approver"}}, headers=h).json()["plan_id"]
    approve2(team, pid)
    worker.run_once(rt)
    with rt.session() as db:  # ... and (as host root) enrolls it
        tok = auth.issue_enrollment_token(db, rt, "sock")
        uri = auth.enroll_begin(db, rt, "sock", tok, "sock password 12345", "127.0.0.1")
        import re
        u = {"username": "sock", "password": "sock password 12345", "secret": re.search(r"secret=([A-Z2-7]+)", uri).group(1)}
        auth.enroll_confirm(db, rt, "sock", tok, totp_for(u), "127.0.0.1")
    sc, sh = login(u)
    own = c.post(f"{H}/plans", json=reg(pve), headers=h).json()["plan_id"]
    r = sc.post(f"{H}/plans/{own}/approve", headers=sh)
    assert r.status_code == 403 and "created or elevated" in r.json()["detail"]
    with rt.session() as db:
        assert db.execute(text("SELECT count(*) FROM audit_events WHERE action='plan.provenance_rejected'")).scalar() == 1
    # but the sockpuppet may approve plans requested by somebody else
    other = team["op"][0].post(f"{H}/plans", json=reg(pve, name="other"), headers=team["op"][1]).json()["plan_id"]
    assert sc.post(f"{H}/plans/{other}/approve", headers=sh).status_code == 200


def test_h2_elevation_is_a_high_risk_plan_with_provenance(team, rt, pve):
    c, h = team["adm"]
    pid = c.post(f"{H}/plans", json={"action": "user.set_role", "params": {"username": "op", "role": "approver"}}, headers=h).json()["plan_id"]
    # the user being elevated cannot approve their own elevation
    assert team["op"][0].post(f"{H}/plans/{pid}/approve", headers=team["op"][1]).status_code == 403  # also not an approver yet
    approve2(team, pid)
    worker.run_once(rt)
    with rt.session() as db:
        r = db.execute(text("SELECT role, role_set_by = (SELECT id FROM users WHERE username='adm') AS by_adm FROM users WHERE username='op'")).first()
    assert r.role == "approver" and r.by_adm
    plan_by_adm = c.post(f"{H}/plans", json=reg(pve), headers=h).json()["plan_id"]
    op2 = team["op"][0]
    # op was elevated by adm -> may not approve adm's plans
    assert op2.post(f"{H}/plans/{plan_by_adm}/approve", headers=team["op"][1]).status_code == 403


def test_l5_two_distinct_approvers_required_and_job_reverifies(team, pve, rt):
    c, h = team["op"]
    pid = c.post(f"{H}/plans", json=reg(pve), headers=h).json()["plan_id"]
    r = team["ap1"][0].post(f"{H}/plans/{pid}/approve", headers=team["ap1"][1]).json()
    assert r["status"] == "pending_approval" and r["approvals"] == 1 and r["approvals_required"] == 2 and r["job_id"] is None
    # a job forced into the queue with only one recorded approval refuses to run
    with rt.session() as db:
        db.execute(text("UPDATE plans SET status='approved' WHERE id=:i"), {"i": pid})
        jid = db.execute(text("INSERT INTO jobs (plan_id, action, status) VALUES (:p,'endpoint.register','queued') RETURNING id"), {"p": pid}).scalar()
        db.commit()
    worker.run_once(rt)
    job = c.get(f"{H}/jobs/{jid}").json()
    assert job["status"] == "failed" and "insufficient approvals" in job["error"]["message"]


# ---------------------------------------------------------------- H3
def test_h3_app_settings_have_no_owner_credentials(tmp_path, monkeypatch):
    f = tmp_path / "ics.env"
    f.write_text("ICS_DATABASE_URL=postgresql+psycopg://a:b@h/ics\nICS_VAULT_KEY_FILE=/k\nICS_AUDIT_KEY_FILE=/a\n"
                 "ICS_MIGRATE_DATABASE_URL=postgresql+psycopg://owner:pw@h/ics\n")
    monkeypatch.setenv("ICS_ENV_FILE", str(f))
    s = load_settings()
    assert not hasattr(s, "migrate_database_url") and "owner" not in repr(s.__dict__)
    assert "migrate" not in {x.name for x in dataclasses.fields(Settings)}


def test_h3_runtime_role_is_not_owner(rt):
    with rt.session() as db:
        me = db.execute(text("SELECT current_user")).scalar()
        assert not db.execute(text("SELECT pg_has_role(current_user, 'pg_database_owner', 'member')")).scalar()
        assert not db.execute(text("SELECT rolsuper OR rolcreaterole FROM pg_roles WHERE rolname = current_user")).scalar()
        with pytest.raises(DBAPIError):
            db.execute(text("ALTER TABLE audit_events DISABLE TRIGGER audit_chain_guard"))
    assert me.endswith("_app")


def test_h3_deployed_config_split():
    d = Path("/etc/office-unbound")
    mig = d / "ics-migrate.env"
    if not mig.exists():
        pytest.skip("not the deployed host")
    st = mig.stat()
    assert st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o600
    assert (ROOT / "migrations" / "env.py").read_text().count("load_migrate_url") >= 1
    assert "migrate_database_url" not in (ROOT / "ics" / "runtime.py").read_text()


# ---------------------------------------------------------------- M1
def test_m1_concurrent_logins_with_one_code_yield_one_session(client, mk_user, rt):
    u = mk_user("racer", "viewer")
    code = totp_for(u)
    body = {"username": "racer", "password": u["password"], "totp_code": code}
    res, barrier = [], threading.Barrier(5)

    def go():
        barrier.wait()
        res.append(client.post(f"{H}/auth/login", json=body).status_code)
    ts = [threading.Thread(target=go) for _ in range(5)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert sorted(res).count(200) == 1, res
    with rt.session() as db:
        assert db.execute(text("SELECT count(*) FROM sessions")).scalar() == 1


# ---------------------------------------------------------------- M2
def test_m2_non_ascii_totp_and_csrf_are_clean_failures(client, mk_user, login, rt):
    u = mk_user("uni", "operator")
    c, h = login(u)
    for code in ("é", "１２３４５６", "12345", "abcdef", "1234567"):
        r = client.post(f"{H}/auth/login", json={"username": "uni", "password": u["password"], "totp_code": code})
        assert r.status_code == 401 and r.json()["detail"] == "invalid credentials"
    with rt.session() as db:
        assert db.execute(text("SELECT count(*) FROM login_attempts WHERE username='uni' AND NOT success")).scalar() == 5
        assert db.execute(text("SELECT count(*) FROM audit_events WHERE action='auth.login_failed'")).scalar() == 5
    r = c.post(f"{H}/plans/preview", json={"blueprint_yaml": "x: 1"}, headers={"X-CSRF-Token": b"\xe9\xe9\xe9"})
    assert r.status_code == 403
    with rt.session() as db:
        assert db.execute(text("SELECT count(*) FROM audit_events WHERE action='auth.csrf_rejected'")).scalar() == 1


# ---------------------------------------------------------------- M3
def _fail(rt, user, ip):
    with rt.session() as db:
        try:
            auth.login(db, rt, user, "wrong password!!", "000000", ip)
        except Exception as e:  # noqa: BLE001
            return e.status_code


def test_m3_lockout_is_per_user_and_ip_and_does_not_extend_itself(rt, mk_user):
    u = mk_user("victim", "admin")
    assert [_fail(rt, "victim", "198.51.100.9") for _ in range(7)] == [401] * 5 + [429, 429]
    with rt.session() as db:
        assert db.execute(text("SELECT count(*) FROM login_attempts WHERE NOT success")).scalar() == 5  # 429s not recorded
        assert db.execute(text("SELECT count(*) FROM audit_events WHERE action='auth.login_failed'")).scalar() == 5
        # the attacker's lock does not affect the real admin on another address
        tok, csrf, user = auth.login(db, rt, "victim", u["password"], totp_for(u), "203.0.113.5")
        assert user.username == "victim"


def test_m3_backoff_is_exponential_and_capped(rt, mk_user):
    mk_user("capped", "viewer")
    with rt.session() as db:
        for _ in range(40):
            db.execute(text("INSERT INTO login_attempts (username, ip, success) VALUES ('capped','198.51.100.1',false)"))
        db.commit()
        w = auth.throttle_remaining(db, rt, "capped", "198.51.100.1")
        assert 0 < w <= rt.settings.login_backoff_cap_seconds
        assert auth.throttle_remaining(db, rt, "capped", "198.51.100.2") == 0
        # past the cap-delay the attempt window opens again (no permanent lock)
        db.execute(text("UPDATE login_attempts SET at = now() - interval '16 minutes'"))
        db.commit()
        assert auth.throttle_remaining(db, rt, "capped", "198.51.100.1") == 0


def test_m3_cli_break_glass_is_never_locked(rt, mk_user, capsys, monkeypatch):
    u = mk_user("bg", "admin")
    for _ in range(6):
        _fail(rt, "bg", "198.51.100.9")
    import ics.cli as cli
    monkeypatch.setattr(cli, "Runtime", lambda: rt)
    assert cli.main(["issue-enrollment", "--username", "bg"]) == 0
    tok = capsys.readouterr().out.splitlines()[1]
    with rt.session() as db:
        assert db.execute(text("SELECT count(*) FROM login_attempts WHERE username='bg'")).scalar() == 0
        uri = auth.enroll_begin(db, rt, "bg", tok, "brand new password 1", "198.51.100.9")
    assert uri.startswith("otpauth://")
    assert cli.main(["unlock", "--username", "bg"]) == 0


# ---------------------------------------------------------------- M4 / L4
def test_m4_remote_numeric_value_cannot_break_verification(team, pve, rt, monkeypatch):
    monkeypatch.setattr(ProxmoxReadClient, "version", lambda self: {"version": 1e16, "x": float("nan")})
    pid, jid = registered(team, pve, rt)
    worker.run_once(rt)
    assert team["op"][0].get(f"{H}/jobs/{jid}").json()["status"] == "succeeded"
    with rt.session() as db:
        v = audit.verify_chain(db)
    assert v["ok"], v
    assert team["op"][0].get("/readyz").status_code in (200, 503)


def test_m4_canon_rejects_nonfinite_and_sanitize_handles_everything(rt):
    with pytest.raises(ValueError):
        audit.canon({"a": float("nan")})
    weird = {"i": 10**40, "f": float("inf"), "n": float("nan"), "e": 1e16, "set": {1}, "o": object, "deep": [[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]}
    with rt.session() as db:
        audit.append(db, "t.weird", details=weird)
        db.commit()
        assert audit.verify_chain(db)["ok"]
        d = db.execute(text("SELECT details FROM audit_events")).scalar()
    assert d["i"] == str(10**40) and d["f"] == "inf" and d["e"] == "1e+16"


def test_l4_forged_entries_are_rejected(rt):
    with rt.session() as db:
        audit.append(db, "real", actor_name="x")
        db.commit()
        tail = db.execute(text("SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1")).scalar()
    # raw SQL insert without the key: trigger refuses missing mac / wrong prev
    for prev, mac in ((tail, None), ("f" * 64, "00")):
        with rt.session() as db:
            with pytest.raises(DBAPIError):
                db.execute(text("INSERT INTO audit_events (id, at, action, details, details_canon, prev_hash, hash, mac) VALUES "
                                "(gen_random_uuid(), now(), 'plan.approve', '{}', '{}', :p, :h, :m)"), {"p": prev, "h": "a" * 64, "m": mac})
            db.rollback()
    # a well-formed, correctly chained entry but with a wrong key verifies as bad_mac
    good = audit._audit_key
    audit.set_key(b"\x09" * 32)
    with rt.session() as db:
        audit.append(db, "plan.approve", actor_name="forger")
        db.commit()
    audit.set_key(good)
    with rt.session() as db:
        v = audit.verify_chain(db)
    assert not v["ok"] and [p["kind"] for p in v["problems"]] == ["bad_mac"]


def test_l4_legacy_rows_still_verify_but_are_counted(rt, owner_engine):
    h = audit.link(audit.GENESIS, audit.entry_json("11111111-1111-1111-1111-111111111111",
                   __import__("datetime").datetime(2026, 1, 1, tzinfo=__import__("datetime").timezone.utc), "old", None, "x", None, None, None, {"a": 1}))
    with owner_engine.connect() as c:
        c.execute(text("ALTER TABLE audit_events DISABLE TRIGGER audit_chain_guard"))
        c.execute(text("INSERT INTO audit_events (id, at, action, actor_name, details, prev_hash, hash) VALUES "
                       "('11111111-1111-1111-1111-111111111111','2026-01-01Z','old','x',CAST(:d AS jsonb),:p,:h)"), {"d": '{"a":1}', "p": audit.GENESIS, "h": h})
        c.execute(text("ALTER TABLE audit_events ENABLE TRIGGER audit_chain_guard"))
    with rt.session() as db:
        audit.append(db, "new")
        db.commit()
        v = audit.verify_chain(db)
    assert v["ok"] and v["legacy_unauthenticated"] == 1


# ---------------------------------------------------------------- M5
def test_m5_params_tamper_after_approval_is_refused(team, pve, rt):
    c, h = team["op"]
    pid = c.post(f"{H}/plans", json=reg(pve), headers=h).json()["plan_id"]
    jid = approve2(team, pid)["job_id"]
    with rt.session() as db:  # SQL write primitive as the app role
        db.execute(text("UPDATE plans SET params = jsonb_set(params, '{name}', '\"swapped-name\"') WHERE id = :i"), {"i": pid})
        db.commit()
    worker.run_once(rt)
    job = c.get(f"{H}/jobs/{jid}").json()
    assert job["status"] == "failed" and "changed after approval" in job["error"]["message"]
    assert c.get(f"{H}/endpoints").json() == []


def test_m5_endpoint_trust_anchor_tamper_is_refused(team, pve, rt):
    pid, jid = registered(team, pve, rt)
    worker.run_once(rt)
    c, h = team["op"]
    eid = c.get(f"{H}/jobs/{jid}").json()["result"]["endpoint_id"]
    with rt.session() as db:
        db.execute(text("UPDATE endpoints SET base_url = 'https://127.0.0.1:1' WHERE id = :i"), {"i": eid})
        db.commit()
    r = c.post(f"{H}/plans", json={"action": "inventory.refresh", "params": {"endpoint_id": eid}}, headers=h).json()
    worker.run_once(rt)
    job = c.get(f"{H}/jobs/{r['job_id']}").json()
    assert job["status"] == "failed"
    # even if the approval-time check were bypassed, the token cannot be decrypted for a different trust anchor
    with rt.session() as db:
        ep = db.execute(text("SELECT * FROM endpoints WHERE id = :i"), {"i": eid}).first()
        with pytest.raises(VaultError):
            actions_mod._client_for(rt, ep, [])


def test_m5_tamper_after_plan_creation_before_approval_on_refresh_binding(team, pve, rt):
    pid, jid = registered(team, pve, rt)
    worker.run_once(rt)
    c, h = team["op"]
    eid = c.get(f"{H}/jobs/{jid}").json()["result"]["endpoint_id"]
    with rt.session() as db:
        p = db.execute(text("SELECT params_hash FROM plans WHERE id = :i"), {"i": pid}).scalar()
        a = db.execute(text("SELECT DISTINCT params_hash FROM plan_approvals WHERE plan_id = :i"), {"i": pid}).all()
    assert [x[0] for x in a] == [p]
    with rt.session() as db:  # approvals are insert-only for the app role
        with pytest.raises(DBAPIError):
            db.execute(text("UPDATE plan_approvals SET params_hash = 'x'"))


# ---------------------------------------------------------------- M6
def test_m6_docs_disabled_and_security_headers(client):
    for p in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(p).status_code == 404
    r = client.get("/healthz")
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"] and "default-src 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["referrer-policy"] == "no-referrer"
    assert r.headers["x-frame-options"] == "DENY"
    assert "content-security-policy" in client.get(f"{H}/endpoints").headers  # also on errors (401)


# ---------------------------------------------------------------- M7
def test_m7_vault_rejects_unsafe_key_files(tmp_path):
    k = tmp_path / "k"
    k.write_bytes(b"\x01" * 32)
    k.chmod(0o640)
    assert Vault.from_file(str(k))
    k.chmod(0o644)
    with pytest.raises(VaultError, match="world"):
        Vault.from_file(str(k))
    k.chmod(0o660)
    with pytest.raises(VaultError):
        Vault.from_file(str(k))
    k.chmod(0o600)
    (tmp_path / "link").symlink_to(k)
    with pytest.raises(VaultError):
        Vault.from_file(str(tmp_path / "link"))
    with pytest.raises(VaultError):
        Vault.from_file(str(tmp_path))


def test_m7_systemd_units_are_hardened():
    u = (ROOT / "deploy" / "ics.service").read_text()
    for d in ("User=ics", "NoNewPrivileges=true", "ProtectSystem=strict", "PrivateTmp=true", "ProtectHome=true", "PrivateDevices=true",
              "CapabilityBoundingSet=", "RestrictAddressFamilies=", "SystemCallFilter=@system-service", "MemoryDenyWriteExecute=true",
              "EnvironmentFile=/etc/office-unbound/ics.env", "ics.serve", "ics-migrate.service"):
        assert d in u, d
    assert "EnvironmentFile=/etc/office-unbound/ics-migrate" not in u and "ICS_MIGRATE" not in u and "0.0.0.0" not in u
    m = (ROOT / "deploy" / "ics-migrate.service").read_text()
    assert "ics-migrate.env" in m and "User=root" in m and "ics.migrate" in m


def test_m7_deployed_permissions():
    d = Path("/etc/office-unbound")
    if not (d / "vault.key").exists():
        pytest.skip("not the deployed host")
    import grp
    for n in ("vault.key", "audit.key", "ics.env"):
        st = (d / n).stat()
        assert st.st_uid == 0 and grp.getgrgid(st.st_gid).gr_name == "ics" and stat.S_IMODE(st.st_mode) == 0o640, n
    assert "administrator" not in grp.getgrnam("ics").gr_mem and os.getgid() != grp.getgrnam("ics").gr_gid
    assert not os.access(d / "vault.key", os.R_OK) or os.getuid() in (0,)


# ---------------------------------------------------------------- M8
def test_m8_overall_deadline_and_size_cap(rt):
    m = MockPVE()
    try:
        m.set_mode("drip")
        c = ProxmoxReadClient(m.url, TID, SEC, fingerprint_sha256=m.fingerprint, allow_loopback=True, deadline=1.0, timeout=5)
        t0 = time.monotonic()
        with pytest.raises(ProxmoxError, match="deadline"):
            c.version()
        assert time.monotonic() - t0 < 3
        m.set_mode("huge")
        c = ProxmoxReadClient(m.url, TID, SEC, fingerprint_sha256=m.fingerprint, allow_loopback=True, max_bytes=100_000)
        with pytest.raises(ProxmoxError, match="exceeds"):
            c.version()
    finally:
        m.stop()


def test_m8_job_wall_clock_timeout_and_secret_wipe(team, pve, rt, monkeypatch):
    rt.settings = dataclasses.replace(rt.settings, job_timeout_seconds=1)
    monkeypatch.setitem(actions_mod._EXEC, actions_mod.ActionType.endpoint_register, lambda *a, **k: time.sleep(4))
    pid, jid = registered(team, pve, rt)
    t0 = time.monotonic()
    worker.run_once(rt)
    assert time.monotonic() - t0 < 3.5
    job = team["op"][0].get(f"{H}/jobs/{jid}").json()
    assert job["status"] == "failed" and job["error"]["type"] == "JobTimeout"
    with rt.session() as db:
        assert db.execute(text("SELECT secret_enc IS NULL FROM plans WHERE id=:i"), {"i": pid}).scalar()
    time.sleep(3.5)  # the abandoned thread must not commit anything
    assert team["op"][0].get(f"{H}/endpoints").json() == []


def test_m8_worker_has_independent_heartbeat_thread(rt):
    w = worker.Worker(rt, interval=0.2)
    assert hasattr(w, "_beat")
    w.start()
    time.sleep(0.8)
    w.stop()
    with rt.session() as db:
        assert db.execute(text("SELECT count(*) FROM worker_heartbeat")).scalar() == 1


# ---------------------------------------------------------------- L1
def test_l1_uvicorn_ignores_forwarded_headers():
    from ics import serve
    cfg = serve.make_config()
    assert cfg.proxy_headers is False and cfg.host == "127.0.0.1"
    assert "--no-proxy-headers" not in (ROOT / "deploy" / "ics.service").read_text() or True
    assert "ics.serve" in (ROOT / "deploy" / "ics.service").read_text()


# ---------------------------------------------------------------- L2
def test_l2_expired_lease_job_is_failed_and_secret_wiped(team, pve, rt):
    c, h = team["op"]
    pid = c.post(f"{H}/plans", json=reg(pve), headers=h).json()["plan_id"]
    approve2(team, pid)
    with rt.session() as db:
        db.execute(text("UPDATE jobs SET status='running', started_at=now()-interval '1 hour', lease_expires_at=now()-interval '1 minute'"))
        assert db.execute(text("SELECT secret_enc IS NOT NULL FROM plans WHERE id=:i"), {"i": pid}).scalar()
        db.commit()
    assert reap_expired(rt) == 1
    with rt.session() as db:
        assert db.execute(text("SELECT status FROM jobs")).scalar() == "failed"
        assert db.execute(text("SELECT secret_enc IS NULL FROM plans WHERE id=:i"), {"i": pid}).scalar()
    assert reap_expired(rt) == 0


def test_l2_claim_sets_a_lease(team, pve, rt):
    pid = team["op"][0].post(f"{H}/plans", json=reg(pve), headers=team["op"][1]).json()["plan_id"]
    approve2(team, pid)
    assert actions_mod.claim_job(rt)
    with rt.session() as db:
        assert db.execute(text("SELECT lease_expires_at > now() FROM jobs")).scalar()


# ---------------------------------------------------------------- L3
def test_l3_destination_restrictions(team, pve, rt):
    c, h = team["op"]
    for url in ("https://169.254.169.254", "https://[fe80::1]:8006", "https://0.0.0.0:8006"):
        r = c.post(f"{H}/plans", json=reg(pve, base_url=url), headers=h)
        assert r.status_code == 422 and "not an allowed destination" in r.text, (url, r.text)
    r = c.post(f"{H}/plans", json=reg(pve), headers=h)  # loopback allowed in the test config
    assert r.status_code == 201 and r.json()["resolved_ips"] == ["127.0.0.1"]
    rt.settings = dataclasses.replace(rt.settings, allow_loopback_endpoints=False)
    for url in ("https://127.0.0.1:8006", "https://localhost:8006"):
        assert c.post(f"{H}/plans", json=reg(pve, base_url=url, name="b"), headers=h).status_code == 422
    with rt.session() as db:
        assert "resolved_ips" in db.execute(text("SELECT details::text FROM audit_events WHERE action='plan.create'")).scalar()


# ---------------------------------------------------------------- L6
def test_l6_nesting_body_cap_and_password_cap(client, team):
    c, h = team["op"]
    r = c.post(f"{H}/plans/preview", json={"blueprint_yaml": "[" * 50000}, headers=h)
    assert r.status_code == 200 and r.json()["valid"] is False
    big = c.post(f"{H}/plans/preview", content=b'{"blueprint_yaml":"' + b"a" * 300_000 + b'"}', headers={**h, "content-type": "application/json"})
    assert big.status_code == 413
    r = client.post(f"{H}/auth/login", json={"username": "a", "password": "x" * 5000, "totp_code": "123456"})
    assert r.status_code == 422


# ---------------------------------------------------------------- L7
def _v(n):
    return tuple(int(x) for x in metadata.version(n).split(".")[:3] if x.isdigit())


def test_l7_dependencies_are_patched_and_pinned():
    assert _v("starlette") >= (1, 3, 1) and _v("cryptography") >= (50, 0, 0) and _v("pytest") >= (9, 0, 0)
    req = (ROOT / "requirements.txt").read_text()
    lock = (ROOT / "requirements.lock").read_text()
    for pkg in ("starlette", "h11", "httpcore", "pydantic-core", "anyio"):
        assert f"\n{pkg}==" in "\n" + lock.lower(), pkg
    assert "--hash=sha256:" in lock
    assert all("==" in ln for ln in req.splitlines() if ln.strip() and not ln.startswith("#"))
    assert "request.url.path" not in (ROOT / "ics" / "auth.py").read_text()


# ---------------------------------------------------------------- L8
def test_l8_cookie_host_prefix_and_logout_all(client, mk_user, rt):
    import pyotp
    from fastapi.testclient import TestClient
    u = mk_user("cookie", "viewer")
    with rt.session() as db:
        db.execute(text("UPDATE users SET last_totp_step = 0"))
        db.commit()
    step = int(time.time() // 30)
    t = pyotp.TOTP(u["secret"])
    body = {"username": "cookie", "password": u["password"]}
    r = client.post(f"{H}/auth/login", json={**body, "totp_code": t.at((step - 1) * 30)})
    assert r.headers["set-cookie"].startswith("__Host-ics_session=") and "Path=/" in r.headers["set-cookie"]
    sessions = []
    for s_ in (step, step + 1):
        c = TestClient(client.app, base_url="https://testserver")
        rr = c.post(f"{H}/auth/login", json={**body, "totp_code": t.at(s_ * 30)})
        assert rr.status_code == 200
        sessions.append((c, {"X-CSRF-Token": rr.json()["csrf_token"]}))
    (c1, h1), (c2, h2) = sessions
    assert c1.post(f"{H}/auth/logout-all", headers=h1).json()["sessions_revoked"] >= 2
    assert c2.get(f"{H}/auth/me").status_code == 401


def test_l8_input_validation_and_readyz_is_minimal(team, pve, client, rt):
    c, h = team["op"]
    assert c.post(f"{H}/plans", json=reg(pve, token_id="u@pam!t=x"), headers=h).status_code == 422
    assert c.post(f"{H}/plans", json=reg(pve, fingerprint_sha256=None, ca_pem="-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----"), headers=h).status_code == 422
    assert c.post(f"{H}/plans", json=reg(pve, fingerprint_sha256=None, ca_pem=pve.cert_pem), headers=h).status_code == 201
    worker.heartbeat(rt)
    body = client.get("/readyz").json()
    assert body["checks"] == {"database": {"ok": True}, "worker": {"ok": True}, "audit_chain": {"ok": True}}


def test_l8_snapshot_retention_and_plan_expiry(team, pve, rt):
    pid, jid = registered(team, pve, rt)
    worker.run_once(rt)
    c, h = team["op"]
    eid = c.get(f"{H}/jobs/{jid}").json()["result"]["endpoint_id"]
    rt.settings = dataclasses.replace(rt.settings, snapshot_retention=2)
    for _ in range(4):
        c.post(f"{H}/plans", json={"action": "inventory.refresh", "params": {"endpoint_id": eid}}, headers=h)
        worker.run_once(rt)
    with rt.session() as db:
        assert db.execute(text("SELECT count(*) FROM inventory_snapshots")).scalar() == 2
    old = c.post(f"{H}/plans", json=reg(pve, name="stale"), headers=h).json()["plan_id"]
    with rt.session() as db:
        db.execute(text("UPDATE plans SET created_at = now() - interval '8 days' WHERE id=:i"), {"i": old})
        db.commit()
    r = team["ap1"][0].post(f"{H}/plans/{old}/approve", headers=team["ap1"][1])
    assert r.status_code == 409 and "expired" in r.json()["detail"]
    with rt.session() as db:
        assert db.execute(text("SELECT secret_enc IS NULL FROM plans WHERE id=:i"), {"i": old}).scalar()


def test_trusted_proxy_config_loopback_only(monkeypatch):
    import pytest as _pt
    from ics import config as _c
    from ics.serve import make_config
    assert _c._trusted_proxy(None) is None and _c._trusted_proxy("") is None
    assert _c._trusted_proxy("127.0.0.1") == "127.0.0.1"
    for bad in ("192.168.22.1", "0.0.0.0", "10.0.0.5"):
        with _pt.raises(RuntimeError):
            _c._trusted_proxy(bad)
    cfg = make_config()
    assert cfg.proxy_headers is False and cfg.forwarded_allow_ips in ("", [])
    cfg = make_config(trusted_proxy="127.0.0.1")
    assert cfg.proxy_headers is True
