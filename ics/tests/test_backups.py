"""Backup product (ADR-0010): policy validation, retention math, runbook parameter validation (ICS + agent), secret non-leakage,
verification state machine, the four states, the executors through a REAL agent (stub systemctl + canned runner result), scheduler, monitoring."""
import json
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError
from sqlalchemy import text

from ics import actions, agentclient, auth, worker
from ics.actions import ActionType
from ics.backups import ops, policy as pol

from .conftest import FakeAgent
from .test_identity import enrolled_node

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))
UTC = timezone.utc
CA = "ab" * 32


def good(**kw):
    d = {"name": "files-lab", "tier": "files", "deployment": "lab stack", "runner_node_id": str(uuid.uuid4()), "schedule": {"every_hours": 24},
         "rpo_seconds": 86400, "rto_seconds": 1800, "repo": {"url": "https://192.168.186.85:8000/files", "ca_sha256": CA}}
    d.update(kw)
    return d


# ---- policy validation ---------------------------------------------------------------------------------------------------------------------
def test_policy_valid_defaults():
    p = pol.PolicyCreate.model_validate(good())
    assert p.retention.daily == 7 and p.copies_required == 1 and p.verify.check_read_data_percent == 10 and p.repo_password is None
    assert p.repo.host == "192.168.186.85"


@pytest.mark.parametrize("patch", [
    {"rpo_seconds": 299},                                                       # below the floor
    {"rpo_seconds": 3600, "schedule": {"every_hours": 2}},                      # schedule slower than RPO: could never be met
    {"rpo_seconds": 3600, "schedule": {"daily_at": "02:30"}},
    {"schedule": {"every_hours": 6, "daily_at": "02:30"}},                      # exactly one
    {"schedule": {}},
    {"schedule": {"daily_at": "24:00"}},
    {"schedule": {"every_hours": 0}},
    {"retention": {"last": 0, "daily": 0, "weekly": 0, "monthly": 0}},          # keeps nothing -> would delete everything
    {"retention": {"daily": -1}},
    {"retention": {"daily": 1000}},
    {"repo": {"url": "http://192.168.186.85:8000/files", "ca_sha256": CA}},     # plaintext
    {"repo": {"url": "https://user:pw@192.168.186.85:8000/files", "ca_sha256": CA}},   # credentials in the URL
    {"repo": {"url": "https://192.168.186.85:99999/files", "ca_sha256": CA}},
    {"repo": {"url": "https://h/files?x=1", "ca_sha256": CA}},
    {"repo": {"url": "https://h/../etc", "ca_sha256": CA}},
    {"repo": {"url": "https://h:8000/files", "ca_sha256": "zz"}},               # no trust anchor
    {"repo": {"url": "https://h:8000/files"}},
    {"tier": "mail"},
    {"name": "bad name"}, {"name": "../x"},
    {"runner_node_id": "not-a-uuid"},
    {"repo_password": "short"}, {"repo_password": "x" * 40 + " ;"},
    {"copies_required": 0},
    {"verify": {"check_read_data_percent": 0}}, {"verify": {"check_read_data_percent": 101}}, {"verify": {"restore_every_seconds": 10}},
    {"surprise": 1},
])
def test_policy_rejects(patch):
    with pytest.raises(ValidationError):
        pol.PolicyCreate.model_validate(good(**patch))


def test_policy_password_is_a_secret_type():
    p = pol.PolicyCreate.model_validate(good(repo_password="a" * 40))
    assert "a" * 40 not in repr(p) and "a" * 40 not in p.model_dump_json() and p.repo_password.get_secret_value() == "a" * 40


# ---- retention math -------------------------------------------------------------------------------------------------------------------------
def snaps(*specs):
    return [(f"s{i:02d}", datetime(*s, tzinfo=UTC)) for i, s in enumerate(specs)]


def test_retention_daily_keeps_newest_of_each_day():
    s = snaps((2026, 11, 10, 1), (2026, 11, 10, 13), (2026, 11, 11, 2), (2026, 11, 12, 2), (2026, 11, 12, 22), (2026, 11, 13, 5))
    k = pol.retention_keep(s, pol.Retention(last=0, daily=3, weekly=0, monthly=0))
    assert set(k) == {"s05", "s04", "s02"} and all(v == ["daily"] for v in k.values())    # newest of 13th, 12th (22:00 not 02:00), 11th
    assert pol.retention_prune_candidates(s, pol.Retention(last=0, daily=3, weekly=0, monthly=0)) == ["s00", "s01", "s03"]


def test_retention_counts_days_that_have_snapshots_not_calendar_days():
    s = snaps((2026, 11, 1, 3), (2026, 11, 5, 3), (2026, 11, 9, 3))   # gaps
    assert set(pol.retention_keep(s, pol.Retention(last=0, daily=2, weekly=0, monthly=0))) == {"s02", "s01"}


def test_retention_weekly_uses_iso_weeks_and_monthly_calendar_months():
    # 2026-11-01 is a Sunday (ISO week 44); Mon 2026-11-02 starts ISO week 45
    s = snaps((2026, 10, 30, 1), (2026, 11, 1, 1), (2026, 11, 2, 1), (2026, 11, 8, 1), (2026, 11, 9, 1))
    k = pol.retention_keep(s, pol.Retention(last=0, daily=0, weekly=3, monthly=0))
    assert set(k) == {"s04", "s03", "s01"}            # week 46: the 9th; week 45: the 8th (newest of 2nd..8th); week 44: the 1st (newest of 30th/1st)
    m = pol.retention_keep(s, pol.Retention(last=0, daily=0, weekly=0, monthly=2))
    assert set(m) == {"s04", "s00"}                    # November -> newest (the 9th); October -> the 30th


def test_retention_rules_stack_and_keep_last():
    s = snaps(*[(2026, 11, d, 4) for d in range(1, 15)])
    k = pol.retention_keep(s, pol.Retention(last=2, daily=3, weekly=2, monthly=1))
    assert set(k) >= {"s13", "s12", "s11"} and k["s13"] == ["last", "daily", "weekly", "monthly"] or k["s13"][0] == "last"
    assert len(pol.retention_prune_candidates(s, pol.Retention(last=1, daily=0, weekly=0, monthly=0))) == 13
    assert pol.retention_keep([], pol.Retention()) == {}


def test_retention_is_timezone_independent_and_order_independent():
    a = [("a", datetime(2026, 11, 10, 23, 30, tzinfo=timezone(timedelta(hours=-5)))),     # = 04:30 UTC on the 11th
         ("b", datetime(2026, 11, 11, 3, 0, tzinfo=UTC))]
    k = pol.retention_keep(a, pol.Retention(last=0, daily=1, weekly=0, monthly=0))
    assert set(k) == {"a"}                                                                # both are the 11th UTC; a is newer
    assert pol.retention_keep(a[::-1], pol.Retention(last=0, daily=1, weekly=0, monthly=0)) == k


def test_retention_horizon():
    assert pol.retention_horizon(pol.Retention(last=1, daily=7, weekly=4, monthly=6)) == timedelta(days=186)


# ---- schedule / RPO / growth --------------------------------------------------------------------------------------------------------------------
def test_schedule_due():
    now = datetime(2026, 11, 15, 12, tzinfo=UTC)
    h = pol.Schedule(every_hours=6)
    assert pol.is_due(h, None, now) and not pol.is_due(h, now - timedelta(hours=5), now) and pol.is_due(h, now - timedelta(hours=6), now)
    d = pol.Schedule(daily_at="02:30")
    assert pol.next_due(d, datetime(2026, 11, 15, 2, 31, tzinfo=UTC), now) == datetime(2026, 11, 16, 2, 30, tzinfo=UTC)
    assert pol.next_due(d, datetime(2026, 11, 15, 1, 0, tzinfo=UTC), now) == datetime(2026, 11, 15, 2, 30, tzinfo=UTC)
    assert pol.is_due(d, datetime(2026, 11, 14, 2, 31, tzinfo=UTC), now)


def test_rpo_state_and_growth():
    now = datetime(2026, 11, 15, 12, tzinfo=UTC)
    assert pol.rpo_state(None, now, 3600) == ("critical", None)
    assert pol.rpo_state(now - timedelta(minutes=59), now, 3600)[0] == "ok"
    assert pol.rpo_state(now - timedelta(minutes=80), now, 3600)[0] == "warning"
    assert pol.rpo_state(now - timedelta(minutes=91), now, 3600)[0] == "critical"
    pts = [(now - timedelta(days=3 - i), 100 + 10 * i) for i in range(4)]
    assert round(pol.growth_per_day(pts), 6) == 10.0 and pol.growth_per_day(pts[:1]) is None and pol.growth_per_day([pts[0], pts[0]]) is None
    assert pol.days_until_full(100, 10.0) == 10.0 and pol.days_until_full(100, 0.0) is None and pol.days_until_full(100, None) is None


# ---- runbook parameter validation (ICS + agent must agree) ------------------------------------------------------------------------------------
BAD = [("backup.run", {}), ("backup.run", {"tier": "mail"}), ("backup.run", {"tier": "files", "x": 1}), ("backup.run", {"tier": ["files"]}),
       ("backup.run", {"tier": "files; rm -rf /"}), ("backup.run", {"tier": "../files"}),
       ("backup.verify", {"tier": "files"}), ("backup.verify", {"tier": "files", "level": "full"}), ("backup.verify", {"tier": "files", "level": "check", "percent": 0}),
       ("backup.verify", {"tier": "files", "level": "check", "percent": 101}), ("backup.verify", {"tier": "files", "level": "check", "percent": 5.5}),
       ("backup.verify", {"tier": "files", "level": "check", "percent": True}),
       ("backup.verify", {"tier": "files", "level": "restore", "snapshot": "latest"}), ("backup.verify", {"tier": "files", "level": "restore", "snapshot": "abc"}),
       ("backup.verify", {"tier": "files", "level": "restore", "snapshot": "abcdefgh; id"}), ("backup.verify", {"tier": "files", "level": "restore", "snapshot": "A" * 8}),
       ("backup.prune", {"tier": "files"}), ("backup.prune", {"tier": "files", "last": 0, "daily": 0, "weekly": 0, "monthly": 0}),
       ("backup.prune", {"tier": "files", "last": -1, "daily": 1, "weekly": 0, "monthly": 0}), ("backup.prune", {"tier": "files", "last": 1, "daily": 1.5, "weekly": 0, "monthly": 0}),
       ("backup.prune", {"tier": "files", "last": 1, "daily": 1000, "weekly": 0, "monthly": 0}), ("backup.prune", {"tier": "files", "last": 1, "daily": 1, "weekly": 0, "monthly": 0, "x": 1}),
       ("backup.exec", {"tier": "files"}), ("backup.run", {"tier": "files", "cmd": "id"})]
OK = [("backup.run", {"tier": "files"}), ("backup.verify", {"tier": "identity", "level": "check"}),
      ("backup.verify", {"tier": "groupware", "level": "check", "percent": 100}),
      ("backup.verify", {"tier": "files", "level": "restore", "snapshot": "480b05f9"}),
      ("backup.prune", {"tier": "ics", "last": 1, "daily": 7, "weekly": 4, "monthly": 6})]


@pytest.mark.parametrize("action,params", BAD)
def test_runbook_params_refused_by_ics_and_agent(action, params):
    from ou_agent import runbooks
    from ou_agent.proto import Reject
    with pytest.raises(ValueError):
        pol.runbook_params(action, params)
    spec = {"tiers": list(runbooks.BACKUP_TIERS)}
    if action in runbooks.BACKUP_RUNBOOKS:
        with pytest.raises(Reject):
            runbooks.check_backup(action, params, spec)


@pytest.mark.parametrize("action,params", OK)
def test_runbook_params_accepted_by_both(action, params):
    from ou_agent import runbooks
    assert pol.runbook_params(action, params) == params
    assert runbooks.check_backup(action, params, {"tiers": list(runbooks.BACKUP_TIERS)}) == params


def test_agent_config_and_tier_allowlist():
    from ou_agent import runbooks
    from ou_agent.proto import Reject
    cfg = runbooks.validate_config({"listen": {"address": "0", "port": 1}, "runbooks": {"backup.run": {"tiers": ["files"]}}})
    assert runbooks.capabilities(cfg)["backup.run"] == {"tiers": ["files"]}
    assert runbooks.check_allowed(cfg, "backup.run", {"tier": "files"}) == {"tier": "files"}
    with pytest.raises(Reject) as e:
        runbooks.check_allowed(cfg, "backup.run", {"tier": "identity"})     # not enabled on THIS node
    assert e.value.code == "not_allowed"
    with pytest.raises(Reject):
        runbooks.check_allowed(cfg, "backup.verify", {"tier": "files", "level": "check"})   # runbook not enabled at all
    for bad in ({"backup.run": {"tiers": ["mail"]}}, {"backup.run": {"tiers": []}}, {"backup.run": {"enabled": True}}, {"backup.run": {"tiers": ["files"], "x": 1}},
                {"backup.shell": {"tiers": ["files"]}}):
        with pytest.raises(ValueError):
            runbooks.validate_config({"listen": {"address": "0", "port": 1}, "runbooks": bad})


def test_polkit_allows_the_backup_template_only(tmp_path):
    import subprocess
    cfg = tmp_path / "a.json"
    cfg.write_text(json.dumps({"listen": {"address": "0.0.0.0", "port": 1}, "runbooks": {"backup.run": {"tiers": ["files"]}}}))
    out = subprocess.run([sys.executable, os.path.join(os.path.dirname(__file__), "..", "agent", "deploy", "render_polkit.py"), str(cfg)],
                         capture_output=True, text=True, check=True).stdout
    assert 'var tmpl = ["ou-rb-backup"]' in out and "polkit.Result.NO" in out


# ---- verification state machine / canary / four states ------------------------------------------------------------------------------------
def test_verification_state_machine():
    assert pol.verif_transition("pending", "running") == "running"
    assert pol.verif_transition("running", "passed") == "passed"
    for cur, new in [("pending", "passed"), ("passed", "failed"), ("failed", "passed"), ("error", "running"), ("running", "pending"),
                     ("cancelled", "running"), ("passed", "passed"), ("bogus", "running"), ("running", "bogus")]:
        with pytest.raises(pol.BadTransition):
            pol.verif_transition(cur, new)
    assert pol.TERMINAL == {"passed", "failed", "error", "cancelled"}


def test_canary_judgement_never_passes_without_evidence():
    e = {"documents": {"a.docx": {"sha256": "1", "versions": ["v"]}}}
    assert pol.judge_canary(e, json.loads(json.dumps(e))) == (True, [])
    assert not pol.judge_canary(None, e)[0] and not pol.judge_canary({}, {})[0]          # nothing recorded -> not verified
    assert not pol.judge_canary(e, None)[0] and not pol.judge_canary(e, {})[0]
    ok, why = pol.judge_canary(e, {"documents": {"a.docx": {"sha256": "2", "versions": ["v"]}}})
    assert not ok and "documents" in why[0]
    assert not pol.judge_canary({"x": 1}, {"x": 1, "y": 2})[0]                           # extra observed key also differs


def states(**kw):
    now = datetime(2026, 11, 15, 12, tzinfo=UTC)
    base = dict(now=now, rpo_seconds=3600, rto_seconds=600, copies_required=1, copies_present=1, last_success=now - timedelta(minutes=10),
                last_snapshot_id="abcd1234", last_check={"finished_at": now - timedelta(hours=1), "passed": True}, recovery_key_exported=True,
                last_restore={"finished_at": now - timedelta(days=1), "passed": True, "snapshot_id": "abcd1234", "rto_seconds": 120.0},
                check_max_age=172800, restore_max_age=10 * 86400)
    base.update(kw)
    return pol.four_states(**base)


def test_four_states_are_independent():
    s = states()
    assert (s["backup_success"]["state"], s["replication"]["state"], s["recovery_readiness"]["state"], s["verified_restore"]["state"]) == ("ok", "ok", "ready", "verified")
    now = datetime(2026, 11, 15, 12, tzinfo=UTC)
    # a good backup that was never restore-tested is NOT "verified"
    s = states(last_restore=None)
    assert s["backup_success"]["state"] == "ok" and s["verified_restore"]["state"] == "never_verified"
    # backup ok but only one copy of two required: replication degraded, backup still ok
    s = states(copies_required=2)
    assert s["backup_success"]["state"] == "ok" and s["replication"]["state"] == "degraded"
    # no recovery key exported / no repository check -> not ready, backup still ok
    s = states(recovery_key_exported=False, last_check=None)
    assert s["backup_success"]["state"] == "ok" and s["recovery_readiness"]["state"] == "not_ready" and len(s["recovery_readiness"]["reasons"]) == 2
    assert states(last_check={"finished_at": now, "passed": False})["recovery_readiness"]["state"] == "not_ready"
    assert states(last_check={"finished_at": now - timedelta(days=9), "passed": True})["recovery_readiness"]["reasons"] == ["repository check is stale"]
    # stale / failed / slow restore verification
    assert states(last_restore={"finished_at": now - timedelta(days=30), "passed": True, "snapshot_id": "x", "rto_seconds": 1.0})["verified_restore"]["state"] == "stale"
    assert states(last_restore={"finished_at": now, "passed": False, "snapshot_id": "x"})["verified_restore"]["state"] == "failed"
    assert states(last_restore={"finished_at": now, "passed": True, "snapshot_id": "x", "rto_seconds": 601.0})["verified_restore"]["state"] == "verified_rto_exceeded"
    # no backup at all
    s = states(last_success=None, last_snapshot_id=None, copies_present=0)
    assert s["backup_success"]["state"] == "failed" and s["replication"]["state"] == "unprotected" and s["recovery_readiness"]["state"] == "not_ready"
    # old backup -> RPO breached
    assert states(last_success=now - timedelta(hours=3))["backup_success"]["state"] == "critical"
    assert states(last_run_failed=True)["backup_success"]["state"] == "failed"


# ---- DB-backed: actions, jobs through a REAL agent, secrets, scheduler, monitoring ---------------------------------------------------------------
@pytest.fixture()
def bk(rt, mk_user, tmp_path, monkeypatch):
    """Operator + two approvers, an enrolled node backed by a real ou_agent whose systemctl is a stub that makes the runner answer from `canned`."""
    op, a1, a2 = mk_user("bk-op", "operator"), mk_user("bk-ap1", "approver"), mk_user("bk-ap2", "approver")
    spool, results = tmp_path / "spool", tmp_path / "results"
    spool.mkdir()
    results.mkdir()
    canned: dict = {}
    fa = FakeAgent(tmp_path, extra={"backup.run": {"tiers": ["files"]}, "backup.verify": {"tiers": ["files"]}, "backup.prune": {"tiers": ["files"]}})
    rb = fa.runbooks
    monkeypatch.setattr(rb, "SPOOL_DIR", str(spool))
    monkeypatch.setattr(rb, "BACKUP_RESULT_DIR", str(results))
    orig = rb._systemctl
    calls = []

    def fake_systemctl(*args, timeout=60):
        if len(args) == 3 and args[0] == "start" and args[2].startswith("ou-rb-backup@"):
            rid = args[2].split("@")[1].removesuffix(".service")
            req = json.loads((spool / (rid + ".json")).read_text())
            calls.append(req)
            out = canned[req["action"] + ":" + req["params"].get("level", "")] if (req["action"] + ":" + req["params"].get("level", "")) in canned else canned.get(req["action"])
            (results / (rid + ".json")).write_text(json.dumps({"rid": rid, **(out() if callable(out) else out)}))
            import subprocess
            return subprocess.CompletedProcess(args, 0, "", "")
        return orig(*args, timeout=timeout)
    monkeypatch.setattr(rb, "_systemctl", fake_systemctl)
    priv = agentclient.load_signing_key(rt.settings.signing_key_file)
    _, node = enrolled_node(fa, priv=priv)
    caps = {k: {"tiers": ["files"]} for k in ("backup.run", "backup.verify", "backup.prune")}
    with rt.session() as d:
        d.execute(text("INSERT INTO nodes (id, name, address, port, tls_fingerprint_sha256, agent_pubkey, agent_key_fp, capabilities) "
                       "VALUES (:i, 'bkn', '127.0.0.1', :p, :t, :k, :f, CAST(:c AS jsonb))"),
                  {"i": node.id, "p": fa.port, "t": fa.tls_fp, "k": node.agent_pubkey, "f": fa.key_fp, "c": json.dumps(caps)})
        d.commit()

    def user(u):
        with rt.session() as d:
            return auth.User(d.execute(text("SELECT * FROM users WHERE username = :u"), {"u": u["username"]}).first())

    class H:
        pass
    h = H()
    h.node, h.canned, h.calls, h.op, h.a1, h.a2 = node.id, canned, calls, user(op), user(a1), user(a2)

    def plan(action, params, who=None, approve=0):
        with rt.session() as d:
            r = actions.create_plan(d, rt, who or h.op, ActionType(action), params, "127.0.0.1")
            for ap in (h.a1, h.a2)[:approve]:
                if r["status"] != "approved":
                    r.update({k: v for k, v in actions.decide_plan(d, rt, ap, uuid.UUID(r["plan_id"]), True, "127.0.0.1").items() if k in ("status", "job_id")})
            return r

    def run_lane():
        n = 0
        while worker.run_once(rt, beat=False, backup_lane=True):
            n += 1
        return n

    def job(r):
        with rt.session() as d:
            return d.execute(text("SELECT status, result, error FROM jobs WHERE plan_id = :p"), {"p": r["plan_id"]}).first()
    h.plan, h.run_lane, h.job, h.fa = plan, run_lane, job, fa
    yield h
    fa.stop()


def make_policy(rt, bk, **kw):
    r = bk.plan("backup.policy.create", good(runner_node_id=str(bk.node), **kw), approve=1)
    assert r["status"] == "approved" and r["risk"] == "normal"
    assert bk.run_lane() == 1
    j = bk.job(r)
    assert j.status == "succeeded", j.error
    return r


RUN_OK = {"result": {"tier": "files", "snapshot": "a" * 64, "bytes_added": 5000, "bytes_processed": 27290245, "repo_bytes": 17155441, "snapshots_total": 2,
                     "repo_confirmed": True, "canary_recorded": True, "repo_id": "r" * 64, "seconds": {"total": 6.0, "restic": 1.3}, "files_new": 0}}


def test_policy_create_secret_never_leaks(rt, bk):
    pw = "SuperSecretRepoPassw0rd-0123456789abcdef"
    r = bk.plan("backup.policy.create", good(runner_node_id=str(bk.node), repo_password=pw), approve=1)
    assert bk.run_lane() == 1 and bk.job(r).status == "succeeded"
    with rt.session() as d:
        pr = d.execute(text("SELECT * FROM backup_policies WHERE name = 'files-lab'")).first()
        dump = json.dumps([[str(c) for c in row] for t in ("audit_events", "jobs", "plans", "backup_runs", "backup_verifications", "agent_requests")
                           for row in d.execute(text(f"SELECT * FROM {t}")).all()])
        assert pw not in dump and "SuperSecret" not in dump
        # it is in the vault, bound to this policy AND this repository URL
        assert json.loads(rt.vault.decrypt(pr.repo_secret_enc, ops.repo_aad(pr.id, pr.repo["url"])))["repo_password"] == pw
        with pytest.raises(Exception):
            rt.vault.decrypt(pr.repo_secret_enc, ops.repo_aad(pr.id, "https://evil.example:8000/files"))
        with pytest.raises(Exception):
            rt.vault.decrypt(pr.repo_secret_enc, ops.repo_aad(uuid.uuid4(), pr.repo["url"]))
        assert pr.repo_secret_enc is not None and pw.encode() not in bytes(pr.repo_secret_enc)
        d.execute(text("DELETE FROM backup_policies"))
        d.commit()
    # generated password: never shown anywhere either; node_secret (break-glass) returns it once and audits the export without the value
    r = bk.plan("backup.policy.create", good(runner_node_id=str(bk.node), name="gen"), approve=1)
    assert bk.run_lane() == 1
    with rt.session() as d:
        sec = ops.node_secret(rt, d, "gen")
        assert len(sec["repo_password"]) >= 40
        dump = json.dumps([[str(c) for c in row] for t in ("audit_events", "jobs", "plans") for row in d.execute(text(f"SELECT * FROM {t}")).all()])
        assert sec["repo_password"] not in dump
        assert d.execute(text("SELECT count(*) FROM audit_events WHERE action = 'backup.key.exported'")).scalar() == 1


def test_policy_api_views_have_no_secret_and_need_login(rt, bk, client, mk_user, login):
    make_policy(rt, bk)
    assert client.get("/api/v1/backups/policies").status_code in (401, 403)
    c, _ = login(mk_user("bk-viewer", "viewer"))
    for path in ("policies", "runs", "verifications"):
        r = c.get(f"/api/v1/backups/{path}")
        assert r.status_code == 200 and "repo_secret" not in r.text and "password" not in r.text.lower()
    p = c.get("/api/v1/backups/policies").json()[0]
    assert p["name"] == "files-lab" and set(p["states"]) == {"backup_success", "replication", "recovery_readiness", "verified_restore"}
    assert p["states"]["backup_success"]["state"] == "failed" and p["states"]["verified_restore"]["state"] == "never_verified"


def test_policy_precheck_refusals(rt, bk):
    with pytest.raises(actions.PlanError) as e:
        bk.plan("backup.policy.create", good(runner_node_id=str(uuid.uuid4())))
    assert e.value.status == 404
    with pytest.raises(actions.PlanError) as e:
        bk.plan("backup.policy.create", good(runner_node_id=str(bk.node), tier="identity"))   # the agent only allows tier files
    assert e.value.status == 422
    with pytest.raises(actions.PlanError) as e:
        bk.plan("backup.policy.create", good(runner_node_id=str(bk.node), repo={"url": "https://169.254.169.254/files", "ca_sha256": CA}))
    assert e.value.status == 422                                                      # metadata address: destination guard
    make_policy(rt, bk)
    with pytest.raises(actions.PlanError) as e:
        bk.plan("backup.policy.create", good(runner_node_id=str(bk.node)))
    assert e.value.status == 409
    with pytest.raises(actions.PlanError) as e:
        bk.plan("backup.run", {"policy": "nope"})
    assert e.value.status == 404


def test_run_executes_via_agent_and_records(rt, bk):
    make_policy(rt, bk)
    bk.canned["backup.run"] = RUN_OK
    r = bk.plan("backup.run", {"policy": "files-lab"})
    assert r["risk"] == "low" and r["status"] == "approved"
    assert bk.run_lane() == 1
    j = bk.job(r)
    assert j.status == "succeeded", j.error
    assert bk.calls[-1] == {"action": "backup.run", "params": {"tier": "files"}}            # exactly the typed runbook, nothing else crossed
    with rt.session() as d:
        run = d.execute(text("SELECT * FROM backup_runs")).first()
        assert run.status == "succeeded" and run.snapshot_id == "a" * 64 and run.bytes_added == 5000 and run.repo_bytes == 17155441 and run.repo_confirmed
        assert run.detail["seconds"]["total"] == 6.0
        pr = d.execute(text("SELECT repo_id FROM backup_policies")).first()
        assert pr.repo_id == "r" * 64                                                       # first contact pins the repository identity
        assert d.execute(text("SELECT response_code FROM agent_requests WHERE action = 'backup.run'")).scalar() == "ok"
        assert d.execute(text("SELECT count(*) FROM audit_events WHERE action = 'backup.runbook'")).scalar() == 1
        assert ops.list_policies(d)[0]["states"]["backup_success"]["state"] == "ok"
    # a repository swap is refused and recorded as a failed run
    bk.canned["backup.run"] = {"result": {**RUN_OK["result"], "repo_id": "x" * 64}}
    r = bk.plan("backup.run", {"policy": "files-lab"})
    bk.run_lane()
    assert bk.job(r).status == "failed" and "repository id changed" in bk.job(r).error["message"]
    with rt.session() as d:
        assert d.execute(text("SELECT status FROM backup_runs ORDER BY started_at DESC LIMIT 1")).scalar() == "failed"
        assert ops.list_policies(d)[0]["states"]["backup_success"]["state"] == "failed"      # last run failed -> not "ok"


def test_run_failures_are_recorded_and_unconfirmed_snapshot_is_not_success(rt, bk):
    make_policy(rt, bk)
    bk.canned["backup.run"] = {"error": "files-backup.sh failed (rc=1): boom"}
    r = bk.plan("backup.run", {"policy": "files-lab"})
    bk.run_lane()
    assert bk.job(r).status == "failed"
    bk.canned["backup.run"] = {"result": {**RUN_OK["result"], "repo_confirmed": False}}
    r = bk.plan("backup.run", {"policy": "files-lab"})
    bk.run_lane()
    assert bk.job(r).status == "failed"
    with rt.session() as d:
        rows = d.execute(text("SELECT status, error FROM backup_runs ORDER BY started_at")).all()
        assert [x.status for x in rows] == ["failed", "failed"] and "boom" in rows[0].error and "not confirmed" in rows[1].error


def test_verification_check_and_restore_states(rt, bk):
    make_policy(rt, bk)
    bk.canned["backup.run"] = RUN_OK
    bk.plan("backup.run", {"policy": "files-lab"})
    bk.run_lane()
    bk.canned["backup.verify:check"] = {"result": {"passed": True, "level": "check", "read_data_percent": 10, "seconds": 1.1, "repo_id": "r" * 64}}
    r = bk.plan("backup.verify", {"policy": "files-lab", "level": "check"})
    bk.run_lane()
    assert bk.job(r).status == "succeeded"
    assert bk.calls[-1] == {"action": "backup.verify", "params": {"tier": "files", "level": "check", "percent": 10}}
    # a restore whose canary did not match: state failed, job failed, never "verified"
    bk.canned["backup.verify:restore"] = {"result": {"match": False, "problems": ["canary documents differs"], "snapshot": "a" * 64, "rto_seconds": 10.2}}
    r = bk.plan("backup.verify", {"policy": "files-lab", "level": "restore"})
    bk.run_lane()
    assert bk.job(r).status == "failed"
    with rt.session() as d:
        v = ops.list_verifications(d)
        assert {(x["level"], x["state"]) for x in v} == {("check", "passed"), ("restore", "failed")}
        st = ops.list_policies(d)[0]["states"]
        assert st["verified_restore"]["state"] == "failed" and st["recovery_readiness"]["state"] == "not_ready"
    bk.canned["backup.verify:restore"] = {"result": {"match": True, "problems": [], "snapshot": "a" * 64, "rto_seconds": 10.2, "seconds": {"restic_restore": 1.1}}}
    r = bk.plan("backup.verify", {"policy": "files-lab", "level": "restore", "snapshot": "a" * 16})
    bk.run_lane()
    assert bk.job(r).status == "succeeded"
    assert bk.calls[-1]["params"] == {"tier": "files", "level": "restore", "snapshot": "a" * 16}
    with rt.session() as d:
        st = ops.list_policies(d)[0]["states"]
        assert st["verified_restore"]["state"] == "verified" and st["verified_restore"]["rto_seconds"] == 10.2
        vs = ops.list_verifications(d, level="restore")
        assert vs[0]["rto_within_target"] is True and vs[0]["state"] == "passed"
    # the runner could not run at all -> state 'error' (distinct from 'failed')
    bk.canned["backup.verify:restore"] = {"error": "scratch machine ou-files-r1 did not come up"}
    r = bk.plan("backup.verify", {"policy": "files-lab", "level": "restore"})
    bk.run_lane()
    with rt.session() as d:
        assert ops.list_verifications(d, level="restore")[0]["state"] == "error"


def test_prune_uses_the_policy_retention_not_the_callers(rt, bk):
    make_policy(rt, bk, retention={"last": 1, "daily": 3, "weekly": 2, "monthly": 1})
    bk.canned["backup.prune"] = {"result": {"kept": 5, "removed": 2, "repo_bytes": 1000}}
    with pytest.raises(Exception):
        bk.plan("backup.prune", {"policy": "files-lab", "daily": 0})                      # no retention parameters exist on the action
    r = bk.plan("backup.prune", {"policy": "files-lab"})
    bk.run_lane()
    assert bk.job(r).status == "succeeded"
    assert bk.calls[-1] == {"action": "backup.prune", "params": {"tier": "files", "last": 1, "daily": 3, "weekly": 2, "monthly": 1}}


def test_policy_update_risk_and_coherence(rt, bk):
    make_policy(rt, bk, retention={"last": 1, "daily": 7, "weekly": 4, "monthly": 6})
    assert bk.plan("backup.policy.update", {"policy": "files-lab", "retention": {"last": 1, "daily": 14, "weekly": 4, "monthly": 6}})["risk"] == "normal"
    shrink = bk.plan("backup.policy.update", {"policy": "files-lab", "retention": {"last": 1, "daily": 3, "weekly": 4, "monthly": 6}})
    assert shrink["risk"] == "high" and shrink["status"] == "pending_approval" and shrink["approvals_required"] == 2     # irreversible: two people
    assert bk.plan("backup.policy.update", {"policy": "files-lab", "enabled": False})["risk"] == "normal"
    with pytest.raises(Exception):
        bk.plan("backup.policy.update", {"policy": "files-lab"})                          # nothing to change
    r = bk.plan("backup.policy.update", {"policy": "files-lab", "rpo_seconds": 3600}, approve=1)    # 24 h schedule vs 1 h RPO
    bk.run_lane()
    assert bk.job(r).status == "failed"
    r = bk.plan("backup.policy.update", {"policy": "files-lab", "enabled": False}, approve=1)
    bk.run_lane()
    assert bk.job(r).status == "succeeded"
    with pytest.raises(actions.PlanError) as e:
        bk.plan("backup.run", {"policy": "files-lab"})                                    # disabled policy refuses runs
    assert e.value.status == 409


def test_scheduler_creates_one_plan_per_policy_and_never_piles_up(rt, bk):
    make_policy(rt, bk, schedule={"every_hours": 24}, verify={"check_every_seconds": 3600, "restore_every_seconds": 7200, "check_read_data_percent": 5})
    now = datetime.now(UTC)
    assert ops.tick(rt, now) == ["backup.run:files-lab"]                                  # never ran: due at once
    assert ops.tick(rt, now) == []                                                        # already in flight: no duplicate plan
    bk.canned["backup.run"] = RUN_OK
    assert bk.run_lane() == 1
    with rt.session() as d:
        assert d.execute(text("SELECT trigger FROM backup_runs")).scalar() == "schedule"
    # the first thing after a good backup is the repository check, then the restore verification, then prune
    assert ops.tick(rt, now + timedelta(minutes=1)) == ["backup.verify:files-lab"]
    bk.canned["backup.verify:check"] = {"result": {"passed": True, "repo_id": "r" * 64}}
    bk.run_lane()
    assert ops.tick(rt, now + timedelta(minutes=2)) == ["backup.verify:files-lab"]       # restore (check ran 2 min ago, not yet due again)
    bk.canned["backup.verify:restore"] = {"result": {"match": True, "snapshot": "a" * 64, "rto_seconds": 5.0}}
    bk.run_lane()
    assert ops.tick(rt, now + timedelta(minutes=3)) == ["backup.prune:files-lab"]
    bk.canned["backup.prune"] = {"result": {"kept": 1, "removed": 0}}
    bk.run_lane()
    assert ops.tick(rt, now + timedelta(minutes=4)) == []                                 # everything done and not due
    assert ops.tick(rt, now + timedelta(hours=2)) == ["backup.verify:files-lab"]          # hourly check due again
    with rt.session() as d:
        assert ops.list_policies(d)[0]["states"]["verified_restore"]["state"] == "verified"


def test_scheduler_retries_failed_backup_only_after_the_backoff(rt, bk):
    make_policy(rt, bk)
    now = datetime.now(UTC)
    assert ops.tick(rt, now)
    bk.canned["backup.run"] = {"error": "runner down"}
    bk.run_lane()
    assert ops.tick(rt, now + timedelta(minutes=5)) == []                                 # backoff (15 min): a down runner is not hammered
    assert ops.tick(rt, now + timedelta(hours=25)) == ["backup.run:files-lab"]


def test_main_lane_never_runs_backup_jobs_and_backup_lane_never_runs_others(rt, bk):
    make_policy(rt, bk)   # consumed through the backup lane
    bk.canned["backup.run"] = RUN_OK
    r = bk.plan("backup.run", {"policy": "files-lab"})
    assert worker.run_once(rt, beat=False) is False                                       # main lane: nothing to do
    assert bk.job(r).status == "queued"
    assert bk.run_lane() == 1 and bk.job(r).status == "succeeded"


def test_backup_checks_age_repo_restore_growth(rt, bk):
    make_policy(rt, bk, rpo_seconds=3600, schedule={"every_hours": 1})
    ev = lambda **c: ops.evaluate(rt, {"policy": "files-lab", **c})                       # noqa: E731
    assert ev(aspect="age").status == "critical" and "no successful backup" in ev(aspect="age").message
    assert ev(aspect="repo_check").status == "warning" or ev(aspect="repo_check").status == "critical"
    assert ev(aspect="restore").status == "warning"                                      # never verified is a warning, not silence
    bk.canned["backup.run"] = RUN_OK
    bk.plan("backup.run", {"policy": "files-lab"})
    bk.run_lane()
    assert ev(aspect="age").status == "ok"
    now = datetime.now(UTC)
    assert ops.evaluate(rt, {"policy": "files-lab", "aspect": "age"}, now + timedelta(minutes=70)).status == "warning"
    assert ops.evaluate(rt, {"policy": "files-lab", "aspect": "age"}, now + timedelta(hours=3)).status == "critical"
    assert ev(aspect="growth", max_repo_bytes=10**9).status == "ok"
    assert ev(aspect="growth", max_repo_bytes=18_000_000).status == "warning"            # >= 80 % of the ceiling
    assert ev(aspect="growth", max_repo_bytes=17_000_000).status == "critical"
    assert ops.evaluate(rt, {"policy": "ghost", "aspect": "age"}).status == "critical"
    assert ops.evaluate(rt, {"policy": "files-lab", "aspect": "growth"}).status == "critical"   # config error never reads as healthy
    bk.canned["backup.verify:check"] = {"result": {"passed": False, "repo_id": "r" * 64}}
    bk.plan("backup.verify", {"policy": "files-lab", "level": "check"})
    bk.run_lane()
    assert ev(aspect="repo_check").status == "critical"


def test_backup_check_kind_goes_through_check_create(rt, bk):
    make_policy(rt, bk)
    r = bk.plan("check.create", {"name": "bk-age", "kind": "backup", "config": {"policy": "files-lab", "aspect": "age"}, "interval_seconds": 60})
    assert r["status"] == "approved"
    worker.run_once(rt, beat=False)
    with rt.session() as d:
        c = d.execute(text("SELECT kind, config FROM checks WHERE name = 'bk-age'")).first()
        assert c.kind == "backup" and c.config == {"policy": "files-lab", "aspect": "age", "timeout_seconds": 10}
    with pytest.raises(actions.PlanError):
        bk.plan("check.create", {"name": "bk-x", "kind": "backup", "config": {"policy": "ghost", "aspect": "age"}, "interval_seconds": 60})


def test_recovery_ack_records_fingerprint_only(rt, bk):
    make_policy(rt, bk)
    with rt.session() as d:
        with pytest.raises(ops.BackupError):
            ops.recovery_ack(d, "files-lab", "not-hex")
        ops.recovery_ack(d, "files-lab", pol.key_fingerprint("whatever-recovery-key"))
        v = ops.list_policies(d)[0]
        assert v["recovery_key"]["exported"] and len(v["recovery_key"]["fingerprint"]) == 16
        assert "whatever-recovery-key" not in json.dumps(v)
    assert pol.key_fingerprint("a") != pol.key_fingerprint("b") and "a" not in pol.key_fingerprint("a")[:0] + "x"
