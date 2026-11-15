"""Regression tests for the monitoring security review (docs/status/security-review-ics-monitoring-2026-11-15.md): M1-M4, L1-L6."""
import dataclasses
import http.server
import json
import socket
import socketserver
import ssl
import threading
import time

import pytest
from sqlalchemy import text

from ics import actions, checks, monitor, worker
from ics.actions import CheckCreate, RunbookExecute
from .lab_mock import HttpsMock, ImapMock, SmtpMock, server_ctx
from .test_monitor import (H, Env, email_channel, enroll, env, feed, imap_setup, smtp, smtp_check)  # noqa: F401  (fixtures)


def settings(rt, monkeypatch, **kw):
    monkeypatch.setattr(rt, "settings", dataclasses.replace(rt.settings, **kw))


def rem(nid, unit="nginx", runbook="service.restart", **kw):
    return {"node_id": nid, "runbook": runbook, "unit": unit, "mode": "auto", "max_attempts": 3, "window_seconds": 600,
            "backoff_seconds": 0, "verify_timeout_seconds": 0, **kw}


def tick_only(env):
    return monitor.tick(env.rt)


# ======================================= M1: restart storms ============================================

def test_m1_restart_budget_is_global_per_node_and_unit_across_checks(env, fake_agent):
    nid, _ = enroll(env, fake_agent)
    cids = [smtp_check(env, 9, name=f"c{i}", fail_threshold=1, remediation=rem(nid)) for i in range(4)]
    for c in cids:
        feed(env, c, "critical", remediate=True)
    assert env.q("SELECT count(*) FROM remediation_attempts")[0][0] == 3          # default budget: 3 restarts/hour of nginx on that node
    blocked = env.q("SELECT escalated_at FROM incidents WHERE check_id = :c", c=cids[3])[0][0]
    assert blocked is not None                                                    # the 4th was escalated to a human, not retried
    assert env.q("SELECT count(*) FROM audit_events WHERE action = 'remediation.escalated'")[0][0] == 1
    # the budget does not refill by itself inside the window
    feed(env, cids[3], "critical", remediate=True)
    assert env.q("SELECT count(*) FROM remediation_attempts")[0][0] == 3


def test_m1_escalation_is_terminal_until_a_human_acknowledges(env, fake_agent):
    nid, _ = enroll(env, fake_agent)
    cid = smtp_check(env, 9, fail_threshold=1, remediation=rem(nid, runbook="service.status", max_attempts=1))
    feed(env, cid, "critical", remediate=True)
    env.run_jobs()
    tick_only(env)
    inc = env.q("SELECT id, escalated_at FROM incidents")[0]
    assert inc.escalated_at is not None
    with env.rt.session() as db:   # the window slides past the attempt: the old code silently refilled the budget here
        db.execute(text("UPDATE remediation_attempts SET at = now() - interval '2 hours', finished_at = now() - interval '2 hours'"))
        db.commit()
    feed(env, cid, "critical", "critical", remediate=True)
    tick_only(env)
    assert env.q("SELECT count(*) FROM remediation_attempts")[0][0] == 1
    env.ok("incident.ack", {"incident_id": str(inc.id)})                           # a human is on it: re-armed
    assert env.q("SELECT escalated_at FROM incidents")[0][0] is None
    feed(env, cid, "critical", remediate=True)
    assert env.q("SELECT count(*) FROM remediation_attempts")[0][0] == 2


def test_m1_auth_failure_is_not_a_service_outage_but_a_real_outage_is(env, fake_agent):
    nid, _ = enroll(env, fake_agent)
    imap = ImapMock(password="good-password-1")
    try:
        cid = imap_setup(env, fake_agent, imap, remediation=rem(nid, unit="gromox-imap"))
        imap.password = "changed-by-someone"                    # login is now rejected: restarting IMAP cannot fix that
        env.tick()
        env.tick()
        c = env.op[0].get(f"{H}/checks").json()[0]
        assert c["state"] == "critical"
        assert env.q("SELECT details->>'cause' FROM check_results ORDER BY id DESC LIMIT 1")[0][0] == "auth"
        assert env.q("SELECT count(*) FROM remediation_attempts")[0][0] == 0 and fake_agent.calls() == []
        assert env.q("SELECT remediation_skipped_at IS NOT NULL FROM incidents")[0][0] is True
        assert env.q("SELECT count(*) FROM audit_events WHERE action = 'remediation.skipped'")[0][0] == 1
        env.tick()
        assert env.q("SELECT count(*) FROM audit_events WHERE action = 'remediation.skipped'")[0][0] == 1   # once per incident
        imap.stop()                                             # now the service really is down (connection refused: no cause)
        env.tick()
        assert env.q("SELECT count(*) FROM remediation_attempts")[0][0] == 1
        env.run_jobs()
        assert "restart gromox-imap.service" in fake_agent.calls()[0]
    finally:
        imap.stop()


def test_m1_runner_tags_auth_and_config_causes():
    s = ImapMock(password="pw-right-1")
    try:
        cfg = {"host": "127.0.0.1", "port": s.port, "username": "mon", "fingerprint_sha256": s.fp, "timeout_seconds": 3}
        o = checks.run_check("imap_login", cfg, "pw-wrong-1", True)
        assert o.status == "critical" and o.details["cause"] == "auth" and "pw-wrong-1" not in o.message
        s.mailbox_ok = False
        s.password = "pw-right-1"
        assert checks.run_check("imap_login", cfg, "pw-right-1", True).details["cause"] == "config"
    finally:
        s.stop()
    assert checks.run_check("imap_login", {"host": "127.0.0.1", "port": 9, "username": "u", "fingerprint_sha256": "a" * 64}, None, True).details["cause"] == "config"


def test_m1_policy_floors_apply_with_production_settings(env, fake_agent, rt, monkeypatch):
    nid, _ = enroll(env, fake_agent)
    settings(rt, monkeypatch, remediation_min_backoff_seconds=30, remediation_min_window_seconds=300)
    c, h = env.op
    for bad in ({"backoff_seconds": 0}, {"window_seconds": 60}):
        r = c.post(f"{H}/plans", json={"action": "check.create", "params": {
            "name": "x", "kind": "smtp_banner", "config": {"host": "127.0.0.1", "port": 9}, "interval_seconds": 60,
            "remediation": rem(nid, **bad)}}, headers=h)
        assert r.status_code == 422 and "backoff_seconds >= 30" in r.text, r.text
    ok = c.post(f"{H}/plans", json={"action": "check.create", "params": {
        "name": "x", "kind": "smtp_banner", "config": {"host": "127.0.0.1", "port": 9}, "interval_seconds": 60,
        "remediation": rem(nid, backoff_seconds=30, window_seconds=300)}}, headers=h)
    assert ok.status_code == 201


def test_l6_a_demoted_check_owner_no_longer_requests_restarts(env, fake_agent):
    nid, _ = enroll(env, fake_agent)
    cid = smtp_check(env, 9, fail_threshold=1, remediation=rem(nid))
    env.q("SELECT 1")
    with env.rt.session() as db:
        db.execute(text("UPDATE users SET role = 'viewer' WHERE username = 'op'"))
        db.commit()
    feed(env, cid, "critical", remediate=True)
    assert env.q("SELECT count(*) FROM remediation_attempts")[0][0] == 0


# ======================================= M2: deadlines and isolation ===================================

class Trickle:
    """TLS server that answers (HTTP) or greets (IMAP) one byte at a time, forever: every per-read timeout is satisfied."""

    def __init__(self, http_mode=True, gap=0.3):
        ctx, self.pem, self.fp = server_ctx()
        self.http_mode, self.gap, self.stop_evt = http_mode, gap, threading.Event()
        outer = self

        class Hd(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    if outer.http_mode:
                        self.request.settimeout(2)
                        self.request.recv(4096)
                        self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n")
                    while not outer.stop_evt.is_set():
                        self.request.sendall(b"x" if outer.http_mode else b"*")
                        time.sleep(outer.gap)
                except (OSError, ssl.SSLError):
                    pass

        class S(socketserver.ThreadingTCPServer):
            daemon_threads = True
            allow_reuse_address = True

        self.srv = S(("127.0.0.1", 0), Hd)
        self.srv.socket = ctx.wrap_socket(self.srv.socket, server_side=True)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def stop(self):
        self.stop_evt.set()
        self.srv.shutdown()
        self.srv.server_close()


@pytest.mark.parametrize("kind", ["http", "imap_login"])
def test_m2_trickling_target_is_cut_at_the_overall_deadline(kind):
    t = Trickle(http_mode=(kind == "http"))
    try:
        cfg = ({"url": f"https://127.0.0.1:{t.port}/", "fingerprint_sha256": t.fp, "timeout_seconds": 2} if kind == "http" else
               {"host": "127.0.0.1", "port": t.port, "username": "mon", "fingerprint_sha256": t.fp, "timeout_seconds": 2})
        t0 = time.monotonic()
        o = checks.run_check(kind, cfg, "pw-trickle-1" if kind == "imap_login" else None, True)
        took = time.monotonic() - t0
        assert o.status == "critical" and "deadline" in o.message and o.details["cause"] == "timeout"
        assert took < 3.5, took          # old behaviour: ~18 s and unbounded (every single read succeeded in time)
    finally:
        t.stop()


def test_m2_stuck_check_threads_are_capped(monkeypatch):
    monkeypatch.setattr(checks, "MAX_STUCK_CHECKS", 0)
    o = checks.run_check("smtp_banner", {"host": "127.0.0.1", "port": 9}, None, True)
    assert o.status == "critical" and "stuck" in o.message


def test_m2_a_stalled_monitor_does_not_block_jobs_and_turns_the_heartbeat_stale(env, rt, monkeypatch):
    gate = threading.Event()
    monkeypatch.setattr(monitor, "tick", lambda r: gate.wait(30))
    monkeypatch.setattr(worker.identity, "reconcile_due", lambda r: None)
    settings(rt, monkeypatch, monitor_stall_seconds=1)
    c, h = env.op
    pid = c.post(f"{H}/plans", json={"action": "check.create", "params": {"name": "j1", "kind": "smtp_banner",
                                                                           "config": {"host": "127.0.0.1", "port": 9}, "interval_seconds": 60}}, headers=h).json()
    w = worker.Worker(rt, interval=0.05)
    w.beat_interval = 0.2
    w.start()
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and c.get(f"{H}/jobs/{pid['job_id']}").json()["status"] != "succeeded":
            time.sleep(0.1)
        assert c.get(f"{H}/jobs/{pid['job_id']}").json()["status"] == "succeeded"       # the job ran although tick() is blocked
        time.sleep(3.0)                                                                  # > monitor_stall_seconds + a heartbeat period
        age = env.q("SELECT EXTRACT(EPOCH FROM now() - max(at)) FROM worker_heartbeat")[0][0]
        assert age is not None and age > 1.8, age                                        # no longer fresh: /readyz would be red
        assert not w.healthy()
    finally:
        gate.set()
        w.stop()


def test_m2_heartbeat_stays_fresh_while_both_loops_progress(env, rt):
    w = worker.Worker(rt, interval=0.05)
    w.beat_interval = 0.2
    w.start()
    try:
        time.sleep(1.5)
        age = env.q("SELECT EXTRACT(EPOCH FROM now() - max(at)) FROM worker_heartbeat")[0][0]
        assert age is not None and age < 1.0 and w.healthy()
    finally:
        w.stop()


# ======================================= M3: stale remediation plans ===================================

def _mariadb_pending(env, fake_agent):
    nid, _ = enroll(env, fake_agent)
    cid = smtp_check(env, 9, name="db", fail_threshold=1, remediation=rem(nid, unit="mariadb", mode="approval", max_attempts=2))
    feed(env, cid, "critical", remediate=True)
    att = env.q("SELECT id, status, plan_id FROM remediation_attempts")[0]
    assert att.status == "pending_approval"
    return cid, att


def test_m3_pending_approval_blocks_new_attempts_even_after_the_window(env, fake_agent):
    cid, att = _mariadb_pending(env, fake_agent)
    with env.rt.session() as db:
        db.execute(text("UPDATE remediation_attempts SET at = now() - interval '3 hours'"))
        db.commit()
    feed(env, cid, "critical", "critical", remediate=True)
    assert env.q("SELECT count(*) FROM remediation_attempts")[0][0] == 1       # old code: a second pending high-risk plan per window


def test_m3_recovery_supersedes_the_plan_and_approving_it_executes_nothing(env, fake_agent):
    cid, att = _mariadb_pending(env, fake_agent)
    feed(env, cid, "ok", "ok")                                                  # recovered
    a = env.q("SELECT status, message FROM remediation_attempts")[0]
    assert a.status == "superseded" and "recovered" in a.message
    assert env.q("SELECT status FROM plans WHERE id = :p", p=att.plan_id)[0][0] == "rejected"
    assert env.q("SELECT count(*) FROM audit_events WHERE action = 'plan.superseded'")[0][0] == 1
    for ap, ah in (env.ap1, env.ap2):
        assert ap.post(f"{H}/plans/{att.plan_id}/approve", headers=ah).status_code == 409
    env.run_jobs()
    assert fake_agent.calls() == []


def test_m3_approval_of_a_plan_whose_check_recovered_is_refused_even_if_it_was_not_superseded(env, fake_agent):
    cid, att = _mariadb_pending(env, fake_agent)
    with env.rt.session() as db:   # simulate the monitor never having run (race): check ok, plan still pending
        db.execute(text("UPDATE checks SET state = 'ok'"))
        db.commit()
    r = env.ap1[0].post(f"{H}/plans/{att.plan_id}/approve", headers=env.ap1[1])
    assert r.status_code == 409 and "stale" in r.text
    assert env.q("SELECT status FROM plans WHERE id = :p", p=att.plan_id)[0][0] == "rejected"
    env.run_jobs()
    assert fake_agent.calls() == []


def test_m3_executor_refuses_a_queued_remediation_whose_check_is_no_longer_critical(env, fake_agent):
    nid, _ = enroll(env, fake_agent)
    cid = smtp_check(env, 9, fail_threshold=1, remediation=rem(nid))
    feed(env, cid, "critical", remediate=True)
    assert env.q("SELECT status FROM remediation_attempts")[0][0] == "queued"
    with env.rt.session() as db:
        db.execute(text("UPDATE checks SET state = 'ok'"))
        db.commit()
    env.run_jobs()
    job = env.q("SELECT status, error FROM jobs WHERE action = 'runbook.execute'")[0]
    assert job.status == "failed" and "stale" in job.error["message"]
    assert fake_agent.calls() == []


def test_m3_pending_plans_expire_after_their_ttl(env, fake_agent, rt, monkeypatch):
    cid, att = _mariadb_pending(env, fake_agent)
    settings(rt, monkeypatch, remediation_plan_ttl_seconds=60)
    with env.rt.session() as db:
        db.execute(text("UPDATE remediation_attempts SET at = now() - interval '5 minutes'"))
        db.commit()
    tick_only(env)
    assert env.q("SELECT status FROM remediation_attempts ORDER BY id")[0][0] == "superseded"
    assert env.q("SELECT status FROM plans WHERE id = :p", p=att.plan_id)[0][0] == "rejected"


# ======================================= M4: silencing alerting alone ==================================

def plan_risk(env, action, params):
    c, h = env.op
    r = c.post(f"{H}/plans", json={"action": action, "params": params}, headers=h)
    assert r.status_code == 201, r.text
    return r.json()


def test_m4_global_or_long_maintenance_and_disabling_need_approval(env):
    cid = smtp_check(env, 9)
    assert plan_risk(env, "maintenance.create", {"name": "a", "check_id": cid, "duration_minutes": 30})["risk"] == "low"
    g = plan_risk(env, "maintenance.create", {"name": "b", "duration_minutes": 5})
    assert g["risk"] == "high" and g["status"] == "pending_approval" and g["job_id"] is None
    assert plan_risk(env, "maintenance.create", {"name": "c", "check_id": cid, "duration_minutes": 120})["risk"] == "high"
    d = plan_risk(env, "check.set_enabled", {"check_id": cid, "enabled": False})
    assert d["risk"] == "normal" and d["status"] == "pending_approval"
    assert plan_risk(env, "check.set_enabled", {"check_id": cid, "enabled": True})["risk"] == "low"
    env.run_jobs()
    assert env.q("SELECT enabled FROM checks")[0][0] is True and env.q("SELECT count(*) FROM maintenance_windows")[0][0] == 1


def test_m4_ack_bursts_need_a_second_person(env, rt, monkeypatch):
    settings(rt, monkeypatch, ack_burst_limit=2)
    cids = [smtp_check(env, 9, name=f"a{i}", fail_threshold=1) for i in range(3)]
    for c in cids:
        feed(env, c, "critical")
    iids = [r[0] for r in env.q("SELECT id FROM incidents ORDER BY opened_at")]
    risks = [plan_risk(env, "incident.ack", {"incident_id": str(i)})["risk"] for i in iids]
    assert risks == ["low", "low", "normal"]


def test_m4_window_start_and_end_are_announced_and_suppressed_alerts_summarised(env, smtp):
    email_channel(env, smtp)
    cid = smtp_check(env, 9, fail_threshold=1)
    env.ok("maintenance.create", {"name": "big-window", "duration_minutes": 30}, high=True)   # global: approved by two people
    tick_only(env)
    assert len(smtp.messages) == 1 and "MAINTENANCE STARTED" in smtp.messages[0] and "ALL checks" in smtp.messages[0]
    feed(env, cid, "critical")                                                                # suppressed by the window
    tick_only(env)
    assert len(smtp.messages) == 1
    with env.rt.session() as db:      # the window ends
        db.execute(text("UPDATE maintenance_windows SET starts_at = now() - interval '1 hour', ends_at = now() - interval '1 minute'"))
        db.execute(text("UPDATE notifications SET created_at = now() - interval '30 minutes' WHERE status = 'suppressed'"))
        db.commit()
    tick_only(env)
    tick_only(env)
    body = "\n".join(smtp.messages)
    assert "MAINTENANCE ENDED" in body and "1 alert(s) were suppressed" in body and "still open: smtp1" in body
    assert "still open" in body.lower() and any("smtp1" in m and "OU-ICS" in m for m in smtp.messages)
    assert len(smtp.messages) == 3                                                            # started, ended, reminder for the open incident
    tick_only(env)
    assert len(smtp.messages) == 3                                                            # summarised exactly once


def test_m4_disabling_a_check_with_an_open_incident_notifies_the_channels(env, smtp):
    email_channel(env, smtp)
    cid = smtp_check(env, 9, fail_threshold=1)
    feed(env, cid, "critical")
    tick_only(env)
    n0 = len(smtp.messages)
    c, h = env.op
    pid = c.post(f"{H}/plans", json={"action": "check.set_enabled", "params": {"check_id": cid, "enabled": False}}, headers=h).json()["plan_id"]
    assert env.ap1[0].post(f"{H}/plans/{pid}/approve", headers=env.ap1[1]).status_code == 200
    env.run_jobs()
    tick_only(env)
    assert len(smtp.messages) == n0 + 1 and "DISABLED while the incident is open" in smtp.messages[-1] and "disabled by op" in smtp.messages[-1]


# ======================================= L3-L5 =========================================================

def test_l3_one_verify_limit_and_a_job_budget_that_covers_the_agent_deadline(rt):
    assert monitor.MAX_VERIFY_TIMEOUT == 45
    with pytest.raises(Exception):
        monitor.Remediation.model_validate({"node_id": "00000000-0000-0000-0000-000000000000", "runbook": "service.status", "unit": "x",
                                            "verify_timeout_seconds": 46})
    with pytest.raises(Exception):
        RunbookExecute.model_validate({"node_id": "00000000-0000-0000-0000-000000000000", "runbook": "service.status", "unit": "x",
                                       "verify_timeout_seconds": 46})
    s = type(rt.settings)  # production defaults, not the test overrides
    assert s.__dataclass_fields__["job_timeout_seconds"].default >= (s.__dataclass_fields__["agent_deadline_seconds"].default
                                                                     + monitor.MAX_VERIFY_TIMEOUT + checks.MAX_TIMEOUT_SECONDS)


@pytest.fixture()
def rebind(monkeypatch):
    """A name that resolves to 127.0.0.1 exactly once; any further lookup would fail (or, in real life, return an internal address)."""
    calls = []
    real = socket.getaddrinfo

    def fake(host, *a, **k):
        if host == "rebind.example.test":
            calls.append(host)
            if len(calls) > 1:
                raise OSError("second lookup: attacker flipped the record")
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]
        return real(host, *a, **k)
    monkeypatch.setattr(socket, "getaddrinfo", fake)
    return calls


def test_l4_checks_connect_to_the_validated_address_not_a_second_lookup(rebind):
    web = HttpsMock({("GET", "/health"): (200, b"ok")})
    try:
        o = checks.run_check("http", {"url": f"https://rebind.example.test:{web.base.rsplit(':', 1)[1]}/health", "fingerprint_sha256": web.fp,
                                      "timeout_seconds": 3}, None, True)
        assert o.status == "ok", o.message
        assert web.seen[0][2].get("Host", "").startswith("rebind.example.test")          # name preserved for virtual hosting
        rebind.clear()
        o = checks.run_check("tcp_tls", {"host": "rebind.example.test", "port": int(web.base.rsplit(":", 1)[1]), "fingerprint_sha256": web.fp,
                                         "timeout_seconds": 3}, None, True)
        assert o.status == "ok", o.message
    finally:
        web.stop()
    imap = ImapMock(password="pw-pin-1")
    try:
        rebind.clear()
        o = checks.run_check("imap_login", {"host": "rebind.example.test", "port": imap.port, "username": "mon", "fingerprint_sha256": imap.fp,
                                            "timeout_seconds": 3}, "pw-pin-1", True)
        assert o.status == "ok", o.message
    finally:
        imap.stop()
    sm = SmtpMock()
    try:
        rebind.clear()
        o = checks.run_check("smtp_banner", {"host": "rebind.example.test", "port": sm.port, "timeout_seconds": 3}, None, True)
        assert o.status == "ok", o.message
    finally:
        sm.stop()


def test_l5_check_count_and_interval_quotas(env, rt, monkeypatch):
    settings(rt, monkeypatch, check_min_interval_seconds=15, check_min_interval_credentialed_seconds=30, max_checks=2)
    c, h = env.op

    def create(name, **kw):
        p = {"name": name, "kind": "smtp_banner", "config": {"host": "127.0.0.1", "port": 9}, "interval_seconds": 60}
        p.update(kw)
        return c.post(f"{H}/plans", json={"action": "check.create", "params": p}, headers=h)
    assert create("fast", interval_seconds=5).status_code == 422
    r = create("imap-fast", kind="imap_login", config={"host": "127.0.0.1", "username": "u", "fingerprint_sha256": "a" * 64}, password="pw-x-12345",
               interval_seconds=20)
    assert r.status_code == 422 and ">= 30" in r.text
    assert create("one", interval_seconds=15).status_code == 201
    env.run_jobs()
    assert create("two").status_code == 201
    env.run_jobs()
    r = create("three")
    assert r.status_code == 409 and "limit" in r.text


def test_l5_check_results_are_capped_per_check(env, rt, monkeypatch):
    settings(rt, monkeypatch, check_results_max_per_check=3)
    cid = smtp_check(env, 9)
    feed(env, cid, *["ok"] * 8)
    monitor._last_retention = None
    assert monitor.retention(env.rt) >= 5
    assert env.q("SELECT count(*) FROM check_results WHERE check_id = :c", c=cid)[0][0] == 3
