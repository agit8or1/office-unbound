"""Monitoring engine: plans -> checks -> state machine -> incidents -> alerts -> remediation (real agent over HTTPS, signed requests)."""
import json
import time

import pytest
from sqlalchemy import text

from ics import agentclient, alerts, audit, checks, monitor, worker
from .lab_mock import HttpsMock, ImapMock, SmtpMock

H = "/api/v1"


class Env:
    def __init__(self, rt, op, ap1, ap2):
        self.rt, self.op, self.ap1, self.ap2 = rt, op, ap1, ap2

    def run_jobs(self):
        while worker.run_once(self.rt):
            pass

    def submit(self, action, params, high=False):
        """Create a plan as the operator (approving with two approvers if high risk), run the worker, return the finished job."""
        c, h = self.op
        r = c.post(f"{H}/plans", json={"action": action, "params": params}, headers=h)
        assert r.status_code == 201, r.text
        body = r.json()
        if body["status"] == "pending_approval":
            assert high, f"{action} unexpectedly needs approval"
            for a, ah in (self.ap1, self.ap2):
                rr = a.post(f"{H}/plans/{body['plan_id']}/approve", headers=ah)
                assert rr.status_code == 200, rr.text
                body = rr.json()
        else:
            assert not high
        self.run_jobs()
        job = c.get(f"{H}/jobs/{body['job_id']}").json()
        return job

    def ok(self, action, params, high=False):
        job = self.submit(action, params, high)
        assert job["status"] == "succeeded", job
        return job["result"]

    def due(self):
        with self.rt.session() as db:
            db.execute(text("UPDATE checks SET next_run_at = now() - interval '1 second'"))
            db.commit()

    def tick(self):
        self.due()
        return monitor.tick(self.rt)

    def q(self, sql, **p):
        with self.rt.session() as db:
            return db.execute(text(sql), p).all()


@pytest.fixture()
def env(rt, client, mk_user, login):
    return Env(rt, login(mk_user("op", "operator")), login(mk_user("ap1", "approver")), login(mk_user("ap2", "approver")))


@pytest.fixture()
def smtp():
    s = SmtpMock()
    yield s
    s.stop()


def email_channel(env, smtp, name="mail"):
    return env.ok("alert_channel.create", {"name": name, "kind": "email", "config": {
        "host": "127.0.0.1", "port": smtp.port, "tls": "none", "allow_plaintext": True, "from_addr": "ics@gw1.example",
        "to_addrs": ["ops@gw1.example"]}}, high=True)["channel_id"]


def smtp_check(env, port, name="smtp1", **over):
    p = {"name": name, "kind": "smtp_banner", "config": {"host": "127.0.0.1", "port": port, "timeout_seconds": 2}, "interval_seconds": 5,
         "fail_threshold": 3, "recover_threshold": 2}
    p.update(over)
    return env.ok("check.create", p)["check_id"]


def outcome(status, msg="m"):
    return checks.Outcome(status, msg, 5, {})


def feed(env, cid, *statuses, remediate=False):
    states = []
    for s in statuses:
        with env.rt.session() as db:
            states.append(monitor.apply_result(db, env.rt, cid, outcome(s), remediate=remediate))
    return states


# ---- checks via plans ----------------------------------------------------------------------------------------

def test_check_create_is_a_low_risk_plan_and_password_lives_only_in_the_vault(env, rt):
    s = ImapMock(password="Pw-ForVault-9")
    try:
        r = env.op[0].post(f"{H}/plans", json={"action": "check.create", "params": {
            "name": "imap1", "kind": "imap_login", "config": {"host": "127.0.0.1", "port": s.port, "username": "mon", "fingerprint_sha256": s.fp},
            "password": "Pw-ForVault-9"}}, headers=env.op[1]).json()
        assert r["status"] == "approved" and r["risk"] == "low" and r["job_id"]
        env.run_jobs()
        c = env.op[0].get(f"{H}/checks").json()[0]
        assert c["has_secret"] is True and c["state"] == "unknown" and "password" not in json.dumps(c)
        dump = json.dumps([[str(x) for x in r] for r in env.q("SELECT details FROM audit_events")]) + json.dumps(env.op[0].get(f"{H}/plans").json())
        dump += json.dumps(env.op[0].get(f"{H}/jobs").json())
        assert "Pw-ForVault-9" not in dump
        enc = bytes(env.q("SELECT secret_enc FROM checks")[0][0])
        assert b"Pw-ForVault-9" not in enc
        assert env.q("SELECT count(*) FROM plans WHERE secret_enc IS NOT NULL")[0][0] == 0  # wiped after the job
        env.tick()
        assert env.op[0].get(f"{H}/checks").json()[0]["state"] == "ok"
        # moving the stored secret to a check with different config (attacker with SQL write) makes it undecryptable
        with rt.session() as db:
            db.execute(text("UPDATE checks SET config = jsonb_set(config, '{host}', '\"attacker.example\"')"))
            db.commit()
        env.tick()
        assert "cannot be decrypted" in env.op[0].get(f"{H}/checks").json()[0]["last_message"]
    finally:
        s.stop()


def test_check_plan_validation(env):
    c, h = env.op
    bad = [
        {"name": "x1", "kind": "imap_login", "config": {"host": "127.0.0.1", "username": "u", "fingerprint_sha256": "a" * 64}},      # no password
        {"name": "x2", "kind": "smtp_banner", "config": {"host": "127.0.0.1"}, "password": "nope-nope"},                           # password not allowed
        {"name": "x3", "kind": "http", "config": {"url": "https://127.0.0.1/"}},                                                   # no trust
        {"name": "x4", "kind": "shell", "config": {}},
        {"name": "x5", "kind": "smtp_banner", "config": {"host": "127.0.0.1"}, "interval_seconds": 1},
    ]
    for p in bad:
        assert c.post(f"{H}/plans", json={"action": "check.create", "params": p}, headers=h).status_code == 422, p
    # destination guard (loopback allowed in tests, link-local metadata never)
    r = c.post(f"{H}/plans", json={"action": "check.create", "params": {"name": "meta", "kind": "smtp_banner", "config": {"host": "169.254.169.254"}}}, headers=h)
    assert r.status_code == 422 and "not an allowed destination" in r.text
    v, vh = env.ap1
    assert v.post(f"{H}/plans", json={"action": "check.create", "params": {"name": "q", "kind": "smtp_banner", "config": {"host": "127.0.0.1"}}},
                  headers=vh).status_code == 201  # approvers are >= operator


# ---- state machine, incidents, ack, maintenance -------------------------------------------------------------

def test_flap_damping_and_incident_lifecycle(env, smtp):
    email_channel(env, smtp)
    cid = smtp_check(env, 1)
    assert feed(env, cid, "ok") == ["ok"]                                    # first result leaves unknown at once
    assert feed(env, cid, "critical", "critical") == ["ok", "ok"]            # below threshold: no state change, no incident
    assert env.q("SELECT count(*) FROM incidents")[0][0] == 0
    assert feed(env, cid, "ok") == ["ok"]                                    # a success resets the failure streak
    assert feed(env, cid, "critical", "critical") == ["ok", "ok"]
    assert feed(env, cid, "critical") == ["critical"]                        # third consecutive failure
    inc = env.q("SELECT id, status, severity FROM incidents")
    assert len(inc) == 1 and inc[0].status == "open" and inc[0].severity == "critical"
    assert feed(env, cid, "critical", "critical", "critical") == ["critical"] * 3
    assert env.q("SELECT count(*) FROM incidents")[0][0] == 1               # deduplicated
    assert env.q("SELECT count(*) FROM notifications WHERE event = 'opened'")[0][0] == 1
    assert feed(env, cid, "ok") == ["critical"]                              # recovery is damped too
    assert feed(env, cid, "ok") == ["ok"]
    r = env.q("SELECT status, recovered_at FROM incidents")[0]
    assert r.status == "recovered" and r.recovered_at
    assert env.q("SELECT count(*) FROM notifications WHERE event = 'recovered'")[0][0] == 1
    env.tick()  # delivers (the smtp check itself fails against port 1, which is irrelevant to the outbox)
    subjects = [m for m in smtp.messages]
    assert len(subjects) == 2 and "CRITICAL: smtp1 opened" in subjects[0] and "OK: smtp1 RECOVERED" in subjects[1]
    # a new failure streak opens a NEW incident
    feed(env, cid, "critical", "critical", "critical")
    assert env.q("SELECT count(*) FROM incidents")[0][0] == 2


def test_warning_then_critical_changes_severity_and_notifies(env, smtp):
    email_channel(env, smtp)
    cid = smtp_check(env, 1, fail_threshold=2)
    feed(env, cid, "ok")
    assert feed(env, cid, "warning", "warning") == ["ok", "warning"]
    assert feed(env, cid, "critical") == ["warning"]                         # a different raw status restarts the streak
    assert feed(env, cid, "critical") == ["critical"]
    assert env.q("SELECT severity FROM incidents")[0][0] == "critical" and env.q("SELECT count(*) FROM incidents")[0][0] == 1
    assert [r[0] for r in env.q("SELECT event FROM notifications ORDER BY id")] == ["opened", "severity_changed"]


def test_ack_is_a_typed_plan_and_recovery_after_ack(env, smtp):
    email_channel(env, smtp)
    cid = smtp_check(env, 1, fail_threshold=1)
    feed(env, cid, "critical")
    iid = env.q("SELECT id FROM incidents")[0][0]
    res = env.ok("incident.ack", {"incident_id": str(iid), "note": "looking"})
    assert res["status"] == "acked"
    i = env.op[0].get(f"{H}/incidents/{iid}").json()
    assert i["status"] == "acked" and i["acked_at"]
    assert env.q("SELECT status, ack_note FROM incidents")[0] == ("acked", "looking")
    assert env.submit("incident.ack", {"incident_id": str(iid)})["status"] == "failed"   # only open incidents can be acked
    feed(env, cid, "ok")            # unknown -> first ok... state is critical: needs 2
    feed(env, cid, "ok")
    assert env.q("SELECT status FROM incidents")[0][0] == "recovered"
    assert len(env.op[0].get(f"{H}/incidents?status=recovered").json()) == 1
    assert len(env.op[0].get(f"{H}/incidents?status=active").json()) == 0


def test_maintenance_suppresses_notifications_and_remediation(env, smtp):
    email_channel(env, smtp)
    cid = smtp_check(env, 1, fail_threshold=1)
    env.ok("maintenance.create", {"name": "patching", "check_id": cid, "duration_minutes": 30, "reason": "kernel update"})
    assert env.op[0].get(f"{H}/maintenance").json()[0]["active"] is True
    feed(env, cid, "critical")
    n = env.q("SELECT status, detail FROM notifications WHERE incident_id IS NOT NULL")
    assert [(r.status, r.detail) for r in n] == [("suppressed", "maintenance window")]
    env.tick()
    assert len(smtp.messages) == 1 and "MAINTENANCE STARTED" in smtp.messages[0]   # only the non-suppressible start notice (review M4)
    # a window for one check does not cover another
    other = smtp_check(env, 1, name="other", fail_threshold=1)
    feed(env, other, "critical")
    assert env.q("SELECT status FROM notifications WHERE incident_id IS NOT NULL ORDER BY id")[-1][0] == "pending"
    # maintenance validation
    c, h = env.op
    assert c.post(f"{H}/plans", json={"action": "maintenance.create", "params": {"name": "x", "duration_minutes": 9999}}, headers=h).status_code == 422


# ---- alert channels -----------------------------------------------------------------------------------------------------

def test_email_channel_test_notification_and_retry_then_fail(env, smtp):
    cid_ch = email_channel(env, smtp)
    env.ok("alert_channel.test", {"channel_id": cid_ch})
    monitor.dispatch_notifications(env.rt)
    assert len(smtp.messages) == 1 and "test notification" in smtp.messages[0]
    smtp.reject = True
    env.ok("alert_channel.test", {"channel_id": cid_ch})
    for _ in range(3):
        monitor.dispatch_notifications(env.rt)
        with env.rt.session() as db:
            db.execute(text("UPDATE notifications SET next_attempt_at = now() WHERE status = 'pending'"))
            db.commit()
    n = env.q("SELECT status, attempts, last_error FROM notifications ORDER BY id")
    assert n[0].status == "sent" and n[1].status == "failed" and n[1].attempts == 2 and "smtp failed" in n[1].last_error   # notify_max_attempts=2 in tests
    assert env.q("SELECT count(*) FROM audit_events WHERE action = 'notification.failed'")[0][0] == 1


def test_email_config_requires_tls_or_explicit_plaintext():
    with pytest.raises(Exception, match="allow_plaintext"):
        alerts.validate_config("email", {"host": "h.example", "tls": "none", "from_addr": "a@b.c", "to_addrs": ["x@y.z"]})
    with pytest.raises(Exception, match="exactly one of ca_pem"):
        alerts.validate_config("email", {"host": "h.example", "tls": "starttls", "from_addr": "a@b.c", "to_addrs": ["x@y.z"]})
    with pytest.raises(Exception, match="credentials"):
        alerts.validate_config("email", {"host": "h.example", "tls": "none", "allow_plaintext": True, "username": "u", "from_addr": "a@b.c",
                                         "to_addrs": ["x@y.z"]})
    with pytest.raises(Exception):  # header injection in recipients
        alerts.validate_config("email", {"host": "h.example", "tls": "none", "allow_plaintext": True, "from_addr": "a@b.c",
                                         "to_addrs": ["x@y.z\nBcc: evil@x.z"]})


def test_webhook_channel_is_hmac_signed(env):
    key = "webhook-signing-key-123456"
    got = []
    s = HttpsMock({("POST", "/hook"): lambda h, b: (got.append((dict(h.headers), b)) or (200, b"ok"))})
    try:
        ch = env.ok("alert_channel.create", {"name": "hook", "kind": "webhook", "config": {"url": s.base + "/hook", "fingerprint_sha256": s.fp},
                                             "secret": key}, high=True)["channel_id"]
        env.ok("alert_channel.test", {"channel_id": ch})
        monitor.dispatch_notifications(env.rt)
        assert len(got) == 1
        hdr, body = got[0]
        assert alerts.verify_webhook(key, hdr["X-OU-Timestamp"], body, hdr["X-OU-Signature"])
        assert not alerts.verify_webhook("another-key-another-key", hdr["X-OU-Timestamp"], body, hdr["X-OU-Signature"])
        assert not alerts.verify_webhook(key, hdr["X-OU-Timestamp"], body + b" ", hdr["X-OU-Signature"])
        assert not alerts.verify_webhook(key, hdr["X-OU-Timestamp"], body, hdr["X-OU-Signature"], now=time.time() + 4000)   # stale timestamp
        assert json.loads(body)["event"] == "test"
        assert key not in json.dumps(env.op[0].get(f"{H}/alert-channels").json())
        # wrong secret on the receiving side is detectable; a too short key is refused at plan time
        r = env.op[0].post(f"{H}/plans", json={"action": "alert_channel.create", "params": {
            "name": "weak", "kind": "webhook", "config": {"url": s.base + "/hook", "fingerprint_sha256": s.fp}, "secret": "short"}}, headers=env.op[1])
        assert r.status_code == 422
    finally:
        s.stop()


def test_paid_channels_are_disabled_by_design(env):
    c, h = env.op
    for kind, cfg in (("pushover", {"user_key": "u" * 30}), ("sms", {"to_number": "+15551234567", "gateway_url": "https://sms.example/send"})):
        r = c.post(f"{H}/plans", json={"action": "alert_channel.create", "params": {"name": kind, "kind": kind, "config": cfg, "secret": "tok" * 10,
                                                                                    "enabled": True}}, headers=h)
        assert r.status_code == 422 and "ADR-0007" in r.text
        res = env.ok("alert_channel.create", {"name": kind, "kind": kind, "config": cfg, "secret": "tok" * 10}, high=True)
        assert res["enabled"] is False
    listing = c.get(f"{H}/alert-channels").json()
    assert {x["kind"]: (x["enabled"], x["delivery_available"]) for x in listing} == {"pushover": (False, False), "sms": (False, False)}
    with pytest.raises(alerts.ChannelDisabled):
        alerts.send("pushover", {"user_key": "u" * 30}, "t", alerts.Message("test", "s", "t", {}))
    with pytest.raises(alerts.ChannelDisabled):
        alerts.send("sms", {}, "t", alerts.Message("test", "s", "t", {}))
    # even a test action cannot be queued for a disabled channel
    ch = listing[0]["id"]
    assert env.submit("alert_channel.test", {"channel_id": ch})["status"] == "failed"


def test_alert_channel_create_is_high_risk(env):
    r = env.op[0].post(f"{H}/plans", json={"action": "alert_channel.create", "params": {
        "name": "m", "kind": "email", "config": {"host": "127.0.0.1", "tls": "none", "allow_plaintext": True, "from_addr": "a@b.c", "to_addrs": ["x@y.z"]}}},
        headers=env.op[1]).json()
    assert r["risk"] == "high" and r["status"] == "pending_approval" and r["job_id"] is None


# ---- node enrollment + remediation against the real agent ------------------------------------------------------------------

def enroll(env, fa, name="gw1"):
    res = env.ok("node.enroll", {"name": name, "address": "127.0.0.1", "port": fa.port, "tls_fingerprint_sha256": fa.tls_fp,
                                 "agent_key_fingerprint_sha256": fa.key_fp, "enrollment_token": fa.token}, high=True)
    return res["node_id"], res["capabilities"]


def test_node_enrollment_flow_and_safety(env, fake_agent):
    c, h = env.op
    bad = {"name": "gw1", "address": "127.0.0.1", "port": fake_agent.port, "tls_fingerprint_sha256": fake_agent.tls_fp,
           "agent_key_fingerprint_sha256": "00" * 32, "enrollment_token": fake_agent.token}
    job = env.submit("node.enroll", bad, high=True)          # operator supplied the wrong agent key fingerprint (MITM / wrong box)
    assert job["status"] == "failed" and "does not match" in job["error"]["message"]
    assert fake_agent.token not in json.dumps(job)
    assert not env.q("SELECT 1 FROM nodes")
    assert fake_agent.agent.trust() is None                  # the token was not even sent
    nid, caps = enroll(env, fake_agent)
    assert caps["service.restart"]["units"] == ["gromox-imap", "mariadb", "nginx"]
    node = env.op[0].get(f"{H}/nodes").json()[0]
    assert node["id"] == nid and node["agent_key_fp"] == fake_agent.key_fp and "agent_pubkey" not in node
    assert fake_agent.agent.trust()["node_id"] == nid
    assert fake_agent.token not in json.dumps([[str(x) for x in r] for r in env.q("SELECT details FROM audit_events")])


def test_runbook_plans_validate_against_node_capabilities_and_risk(env, fake_agent):
    nid, _ = enroll(env, fake_agent)
    c, h = env.op
    r = c.post(f"{H}/plans", json={"action": "runbook.execute", "params": {"node_id": nid, "runbook": "service.restart", "unit": "sshd"}}, headers=h)
    assert r.status_code == 422 and "allowlist" in r.text
    r = c.post(f"{H}/plans", json={"action": "runbook.execute", "params": {"node_id": nid, "runbook": "service.restart", "unit": "nginx;id"}}, headers=h)
    assert r.status_code == 422
    low = c.post(f"{H}/plans", json={"action": "runbook.execute", "params": {"node_id": nid, "runbook": "service.restart", "unit": "nginx"}}, headers=h).json()
    assert low["risk"] == "low" and low["job_id"]
    hi = c.post(f"{H}/plans", json={"action": "runbook.execute", "params": {"node_id": nid, "runbook": "service.restart", "unit": "mariadb"}}, headers=h).json()
    assert hi["risk"] == "high" and hi["status"] == "pending_approval" and hi["job_id"] is None
    env.run_jobs()
    assert fake_agent.calls() == ["--no-ask-password restart nginx.service", "--no-ask-password show --property=ActiveState,SubState,UnitFileState,MainPID,NRestarts nginx.service"]
    row = env.q("SELECT status, response_code, action FROM agent_requests")
    assert [tuple(r) for r in row] == [("done", "ok", "service.restart")]


def test_agent_rejection_is_a_failed_job_with_evidence(env, fake_agent):
    nid, _ = enroll(env, fake_agent)
    with env.rt.session() as db:   # ICS-side capability record drifts from the agent's real allowlist (or is tampered with)
        db.execute(text("UPDATE nodes SET capabilities = jsonb_set(capabilities, '{service.restart,units}', '[\"nginx\",\"sshd\"]')"))
        db.commit()
    job = env.submit("runbook.execute", {"node_id": nid, "runbook": "service.restart", "unit": "sshd"})
    assert job["status"] == "failed" and "not_allowed" in job["error"]["message"]
    assert fake_agent.calls() == []                          # the agent, not ICS, is the authority
    assert env.q("SELECT status, response_code FROM agent_requests")[0] == ("failed", "not_allowed")


def test_signing_key_is_required_and_file_modes_are_checked(env, fake_agent, rt, tmp_path):
    bad = tmp_path / "k"
    bad.write_bytes(b"\x01" * 32)
    bad.chmod(0o644)
    with pytest.raises(agentclient.AgentError, match="world-accessible"):
        agentclient.load_signing_key(str(bad))
    with pytest.raises(agentclient.AgentError, match="not configured"):
        agentclient.load_signing_key(None)
    bad.chmod(0o600)
    bad.write_bytes(b"short")
    with pytest.raises(agentclient.AgentError, match="32"):
        agentclient.load_signing_key(str(bad))


def imap_setup(env, fa, imap, *, fail_threshold=2, remediation=None, name="imap-gw1"):
    cfg = {"host": "127.0.0.1", "port": imap.port, "username": "mon", "fingerprint_sha256": imap.fp, "timeout_seconds": 3}
    p = {"name": name, "kind": "imap_login", "config": cfg, "password": imap.password, "interval_seconds": 5, "fail_threshold": fail_threshold,
         "recover_threshold": 2}
    if remediation:
        p["remediation"] = remediation
    return env.ok("check.create", p)["check_id"]


def test_end_to_end_detect_alert_auto_restart_verify_recover(env, fake_agent, smtp, monkeypatch):
    email_channel(env, smtp)
    nid, _ = enroll(env, fake_agent)
    imap = ImapMock(password="good-password-1")
    try:
        rem = {"node_id": nid, "runbook": "service.restart", "unit": "gromox-imap", "mode": "auto", "max_attempts": 3, "window_seconds": 600,
               "backoff_seconds": 1, "verify_timeout_seconds": 20}
        cid = imap_setup(env, fake_agent, imap, remediation=rem)
        env.tick()
        assert env.op[0].get(f"{H}/checks").json()[0]["state"] == "ok"
        # simulated failure: the IMAP service rejects logins until "restarted"
        real = fake_agent.runbooks.execute

        def exec_and_heal(action, params):
            res = real(action, params)
            if action == "service.restart" and params["unit"] == "gromox-imap":
                imap.down = False   # the restart "fixes" the service
            return res
        monkeypatch.setattr(fake_agent.runbooks, "execute", exec_and_heal)
        imap.down = True    # a real outage (a rejected login is an auth failure and must NOT restart anything: review M1)
        env.tick()
        assert env.op[0].get(f"{H}/checks").json()[0]["state"] == "ok"          # 1 failure < threshold 2 (flap damping)
        env.tick()                                                              # 2nd failure -> critical -> incident -> remediation queued
        c = env.op[0].get(f"{H}/checks").json()[0]
        assert c["state"] == "critical" and c["active_incident_id"]
        att = env.q("SELECT status, runbook, attempt_no, job_id FROM remediation_attempts")
        assert len(att) == 1 and att[0].status == "queued" and att[0].job_id
        env.run_jobs()                                                          # job: signed request -> agent -> restart -> re-run check until ok
        job = env.op[0].get(f"{H}/jobs?limit=1").json()[0]
        assert job["status"] == "succeeded" and job["result"]["verified"] is True and "recovered" in job["result"]["verification"], job
        assert fake_agent.calls()[0] == "--no-ask-password restart gromox-imap.service"
        env.tick()                                                              # sync attempts, deliver notifications
        a = env.op[0].get(f"{H}/checks/{cid}/remediation").json()
        assert a[0]["status"] == "verified" and a[0]["verified"] is True
        inc = env.op[0].get(f"{H}/incidents").json()[0]
        assert inc["status"] == "recovered" and inc["escalated_at"] is None
        detail = env.op[0].get(f"{H}/incidents/{inc['id']}").json()
        assert [n["event"] for n in detail["notifications"]] == ["opened", "recovered"] and all(n["status"] == "sent" for n in detail["notifications"])
        assert len(detail["remediation"]) == 1
        assert len(smtp.messages) == 2 and "RECOVERED" in smtp.messages[1] and "imap-gw1" in smtp.messages[1]
        assert "good-password-1" not in "".join(smtp.messages)
        acts = [r[0] for r in env.q("SELECT action FROM audit_events ORDER BY seq")]
        for needed in ("check.state_changed", "incident.opened", "remediation.attempt", "job.queued", "runbook.executed", "incident.recovered",
                       "notification.sent"):
            assert needed in acts, needed
        assert acts.index("incident.opened") < acts.index("remediation.attempt") < acts.index("runbook.executed") < acts.index("incident.recovered")
        assert env.ap1[0].get(f"{H}/audit/verify").json()["ok"] is True
        # the request the ICS sent is recorded (single-use job id + nonce) and cannot be replayed
        ar = env.q("SELECT job_id, nonce, status FROM agent_requests")[0]
        assert ar.status == "done"
    finally:
        imap.stop()


def test_policy_stops_after_max_attempts_and_escalates_without_looping(env, fake_agent, smtp):
    email_channel(env, smtp)
    nid, _ = enroll(env, fake_agent)
    # a check against a deliberately wrong port: a restart would never fix it, and we must not touch services -> harmless status runbook
    rem = {"node_id": nid, "runbook": "service.status", "unit": "nginx", "mode": "auto", "max_attempts": 2, "window_seconds": 600,
           "backoff_seconds": 0, "verify_timeout_seconds": 0}
    cid = env.ok("check.create", {"name": "wrong-port", "kind": "http", "config": {"url": "https://127.0.0.1:9/health", "fingerprint_sha256": "a" * 64,
                                                                                "timeout_seconds": 2},
                                  "interval_seconds": 5, "fail_threshold": 1, "remediation": rem})["check_id"]
    for _ in range(8):
        env.tick()
        env.run_jobs()
    att = env.q("SELECT attempt_no, status, verified FROM remediation_attempts ORDER BY attempt_no")
    assert [(a.attempt_no, a.status, a.verified) for a in att] == [(1, "failed", False), (2, "failed", False)]    # exactly max_attempts, never more
    inc = env.op[0].get(f"{H}/incidents").json()[0]
    assert inc["escalated_at"] and inc["status"] == "open"
    assert env.q("SELECT count(*) FROM audit_events WHERE action = 'remediation.escalated'")[0][0] == 1       # once
    assert [r[0] for r in env.q("SELECT event FROM notifications ORDER BY id")] == ["opened", "escalated"]
    assert len(smtp.messages) == 2 and "ESCALATED" in smtp.messages[1] and "exhausted" in smtp.messages[1]
    assert env.q("SELECT count(*) FROM jobs WHERE action = 'runbook.execute'")[0][0] == 2
    assert all("restart" not in c for c in fake_agent.calls())                                               # nothing was restarted


def test_backoff_and_single_flight(env, fake_agent):
    nid, _ = enroll(env, fake_agent)
    rem = {"node_id": nid, "runbook": "service.status", "unit": "nginx", "mode": "auto", "max_attempts": 5, "window_seconds": 600,
           "backoff_seconds": 3600, "verify_timeout_seconds": 0}
    cid = smtp_check(env, 9, fail_threshold=1, remediation=rem)
    feed(env, cid, "critical", remediate=True)
    assert env.q("SELECT count(*) FROM remediation_attempts")[0][0] == 1
    feed(env, cid, "critical", "critical", remediate=True)      # attempt is in flight (queued): no second one
    assert env.q("SELECT count(*) FROM remediation_attempts")[0][0] == 1
    env.run_jobs()
    monitor.tick(env.rt)
    feed(env, cid, "critical", remediate=True)                  # attempt 1 finished (failed verification) but backoff is 1 h
    assert env.q("SELECT count(*) FROM remediation_attempts")[0][0] == 1
    with env.rt.session() as db:                                # the attempt ages out of the 600 s window: the budget resets
        db.execute(text("UPDATE remediation_attempts SET at = now() - interval '2 hours', finished_at = now() - interval '2 hours'"))
        db.commit()
    feed(env, cid, "critical", remediate=True)
    assert [r[0] for r in env.q("SELECT attempt_no FROM remediation_attempts ORDER BY id")] == [1, 1]


def test_high_risk_runbook_requires_approval_never_auto(env, fake_agent):
    nid, _ = enroll(env, fake_agent)
    c, h = env.op
    auto = {"node_id": nid, "runbook": "service.restart", "unit": "mariadb", "mode": "auto"}
    r = c.post(f"{H}/plans", json={"action": "check.create", "params": {"name": "db", "kind": "smtp_banner", "config": {"host": "127.0.0.1", "port": 9},
                                                                       "remediation": auto}}, headers=h)
    assert r.status_code == 422 and "high-risk" in r.text
    rem = {**auto, "mode": "approval", "max_attempts": 2, "backoff_seconds": 0, "verify_timeout_seconds": 0}
    cid = smtp_check(env, 9, name="db", fail_threshold=1, remediation=rem)
    feed(env, cid, "critical", remediate=True)
    att = env.q("SELECT status, plan_id, job_id FROM remediation_attempts")[0]
    assert att.status == "pending_approval" and att.plan_id and att.job_id is None
    env.run_jobs()
    assert fake_agent.calls() == []                                    # nothing ran without approval
    plan = env.q("SELECT risk, status, requested_by FROM plans WHERE id = :p", p=att.plan_id)[0]
    assert plan.risk == "high" and plan.status == "pending_approval"
    monitor.tick(env.rt)
    assert env.q("SELECT count(*) FROM remediation_attempts")[0][0] == 1  # still waiting: no second pending plan piles up
    for a, ah in (env.ap1, env.ap2):
        assert a.post(f"{H}/plans/{att.plan_id}/approve", headers=ah).status_code == 200
    env.run_jobs()
    assert "restart mariadb.service" in fake_agent.calls()[0]


def test_remediation_runs_nothing_for_disabled_checks_or_in_maintenance(env, fake_agent):
    nid, _ = enroll(env, fake_agent)
    rem = {"node_id": nid, "runbook": "service.status", "unit": "nginx", "mode": "auto", "backoff_seconds": 0, "verify_timeout_seconds": 0}
    cid = smtp_check(env, 9, fail_threshold=1, remediation=rem)
    env.ok("maintenance.create", {"name": "m", "check_id": cid, "duration_minutes": 10})
    feed(env, cid, "critical", remediate=True)
    assert env.q("SELECT count(*) FROM remediation_attempts")[0][0] == 0
    c, h = env.op
    pid = c.post(f"{H}/plans", json={"action": "check.set_enabled", "params": {"check_id": cid, "enabled": False}}, headers=h).json()["plan_id"]
    assert env.ap1[0].post(f"{H}/plans/{pid}/approve", headers=env.ap1[1]).status_code == 200   # disabling needs a second person (review M4)
    env.run_jobs()
    assert env.q("SELECT enabled FROM checks")[0][0] is False
    env.due()
    assert monitor.run_due_checks(env.rt) == 0


def test_bind_and_unbind_remediation_plan(env, fake_agent):
    nid, _ = enroll(env, fake_agent)
    cid = smtp_check(env, 9)
    rem = {"node_id": nid, "runbook": "service.restart", "unit": "nginx"}
    env.ok("check.bind_remediation", {"check_id": cid, "remediation": rem})
    assert env.op[0].get(f"{H}/checks").json()[0]["remediation"]["unit"] == "nginx"
    r = env.op[0].post(f"{H}/plans", json={"action": "check.bind_remediation", "params": {"check_id": cid, "remediation": {**rem, "unit": "sshd"}}},
                       headers=env.op[1])
    assert r.status_code == 422
    env.ok("check.bind_remediation", {"check_id": cid, "remediation": None})
    assert env.op[0].get(f"{H}/checks").json()[0]["remediation"] is None


def test_results_time_series_listing_and_retention(env):
    cid = smtp_check(env, 9)
    feed(env, cid, "ok", "ok", "warning")
    res = env.op[0].get(f"{H}/checks/{cid}/results?limit=2").json()
    assert len(res) == 2 and res[0]["status"] == "warning" and res[0]["id"] > res[1]["id"]
    older = env.op[0].get(f"{H}/checks/{cid}/results?before_id={res[-1]['id']}").json()
    assert len(older) == 1
    with env.rt.session() as db:
        db.execute(text("UPDATE check_results SET at = now() - interval '30 days' WHERE id = :i"), {"i": older[0]["id"]})
        db.commit()
    monitor._last_retention = None
    assert monitor.retention(env.rt) == 1
    assert len(env.op[0].get(f"{H}/checks/{cid}/results").json()) == 2


def test_scheduler_runs_due_checks_and_records(env, smtp):
    cid = smtp_check(env, smtp.port)
    c = env.op[0].get(f"{H}/checks").json()[0]
    assert c["state"] in ("unknown", "ok")
    env.tick()
    c = env.op[0].get(f"{H}/checks").json()[0]
    assert c["state"] == "ok" and c["last_run_at"] and c["last_latency_ms"] is not None and "SMTP" in c["last_message"]


def test_viewer_can_read_but_not_mutate(env, mk_user, login):
    v, vh = login(mk_user("view", "viewer"))
    for p in ("nodes", "checks", "incidents", "alert-channels", "maintenance"):
        assert v.get(f"{H}/{p}").status_code == 200
    assert v.post(f"{H}/plans", json={"action": "incident.ack", "params": {"incident_id": "00000000-0000-0000-0000-000000000000"}},
                  headers=vh).status_code == 403


def test_approval_mode_waits_for_a_human_even_for_low_risk_units(env, fake_agent):
    """Review H2: mode=approval on a low-risk unit must NOT auto-execute; one approver other than the requester."""
    nid, _ = enroll(env, fake_agent)
    rem = {"node_id": nid, "runbook": "service.restart", "unit": "gromox-imap", "mode": "approval", "max_attempts": 2,
           "backoff_seconds": 0, "verify_timeout_seconds": 0}
    cid = smtp_check(env, 9, name="imap-approval", fail_threshold=1, remediation=rem)
    feed(env, cid, "critical", remediate=True)
    att = env.q("SELECT status, plan_id, job_id FROM remediation_attempts")[0]
    assert att.status == "pending_approval" and att.plan_id and att.job_id is None
    env.run_jobs()
    assert fake_agent.calls() == []                                    # nothing ran unattended
    plan = env.q("SELECT risk, status FROM plans WHERE id = :p", p=att.plan_id)[0]
    assert plan.risk == "normal" and plan.status == "pending_approval"
    a, ah = env.ap1
    assert a.post(f"{H}/plans/{att.plan_id}/approve", headers=ah).status_code == 200
    env.run_jobs()
    assert "restart gromox-imap.service" in fake_agent.calls()[0]


def test_auto_mode_low_risk_still_auto_executes(env, fake_agent):
    nid, _ = enroll(env, fake_agent)
    rem = {"node_id": nid, "runbook": "service.restart", "unit": "gromox-imap", "mode": "auto", "max_attempts": 2,
           "backoff_seconds": 0, "verify_timeout_seconds": 0}
    cid = smtp_check(env, 9, name="imap-auto", fail_threshold=1, remediation=rem)
    feed(env, cid, "critical", remediate=True)
    env.run_jobs()
    assert "restart gromox-imap.service" in fake_agent.calls()[0]


def test_retention_runs_on_a_freshly_booted_host(env, monkeypatch):
    """Regression (found by GitHub CI, 2026-11-15): time.monotonic() counts from host boot; with "never run" encoded as 0.0
    retention silently did nothing for the first 10 minutes after boot. "Never run" must always run."""
    cid = smtp_check(env, 9)
    feed(env, cid, "ok")
    with env.rt.session() as db:
        db.execute(text("UPDATE check_results SET at = now() - interval '30 days'")); db.commit()
    monitor._last_retention = None
    monkeypatch.setattr(monitor.time, "monotonic", lambda: 5.0)     # 5 s after boot
    assert monitor.retention(env.rt) >= 1
    assert monitor.retention(env.rt) == 0                            # throttled on the immediate second call
