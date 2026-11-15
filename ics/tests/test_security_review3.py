"""Regression tests for docs/status/security-review-3-2026-11-15.md (H1, M1-M5, L1-L9). Each test fails on the code before the fixes."""
import dataclasses
import json
import sys
import threading
import time
import os
import uuid

import pytest
from sqlalchemy import text

from ics import actions, auth, worker
from ics.deploy import executor, ops
from ics.deploy.lease import Lease
from ics.deploy.ports import DeployError, Fenced

from .test_deploy_exec import (H, FakeAgent, FakeChecks, FakeProvider, actors, cprev, create, env, job, preview, seed_inventory,  # noqa: F401
                               spec_body, steps, submit, _active)

AGENT_DIR = os.path.join(os.path.dirname(__file__), "..", "agent")
sys.path.insert(0, AGENT_DIR)


def _wait(cond, timeout=10.0):
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        if cond():
            return True
        time.sleep(0.05)
    return False


# ---------------------------------------------------------------- H1
def test_h1_step_deadline_stops_executor_and_no_calls_after_failure(client, actors, rt, env, monkeypatch):
    """The reviewer's probe: a slow step used to leave an orphan thread cloning/configuring behind a 'failed' job."""
    rt.settings = dataclasses.replace(rt.settings, deployment_step_deadline_seconds=1)
    seed_inventory(rt)
    p = preview(actors[0])

    def slow_enroll(vm, timeout_s):
        time.sleep(1.5)
        return f"node-{vm}"
    monkeypatch.setattr(env.agent, "wait_enrollment", slow_enroll)
    _, jid = submit(actors, rt, "deployment.create", {"spec": spec_body(), "plan_hash": p["plan_hash"]})
    j = job(actors[0], jid)
    assert j["status"] == "failed" and "deadline" in j["error"]["message"], j
    n = len(env.provider.calls) + len(env.agent.runbooks)
    time.sleep(4)
    assert len(env.provider.calls) + len(env.agent.runbooks) == n          # nothing is issued after the job was reported failed
    with rt.session() as db:
        assert db.execute(text("SELECT count(*) FROM deployment_locks")).scalar() == 0   # lock released


def test_h1_abandoned_executor_is_fenced_and_resubmit_cannot_double_clone(client, actors, rt, env):
    seed_inventory(rt)
    p = preview(actors[0])
    prov = env.provider
    gate, entered = threading.Event(), threading.Event()
    orig = prov.clone_vm

    def blocking_clone(spec):
        t = orig(spec)                      # the provider created the VM ...
        if not entered.is_set():
            entered.set()
            gate.wait(30)                   # ... but this executor thread hangs before it can record it
        return t
    prov.clone_vm = blocking_clone
    (o, oh), a1, a2 = actors
    pid = o.post("/api/v1/plans", json={"action": "deployment.create", "params": {"spec": spec_body(), "plan_hash": p["plan_hash"]}}, headers=oh).json()["plan_id"]
    for c, h in (a1, a2):
        jidA = c.post(f"/api/v1/plans/{pid}/approve", headers=h).json()["job_id"]
    th = threading.Thread(target=lambda: worker.run_once(rt), daemon=True)
    th.start()
    assert entered.wait(10)
    # while the executor lives, nobody else can start one (precheck + lock)
    r = o.post("/api/v1/plans", json={"action": "deployment.create", "params": {"spec": spec_body(), "plan_hash": p["plan_hash"]}}, headers=oh)
    assert r.status_code == 409 and "executor" in r.text
    # the lease runs out (hung thread cannot renew): the reaper fails the job and fences the thread
    with rt.session() as db:
        db.execute(text("UPDATE jobs SET lease_expires_at = now() - interval '1 second' WHERE status = 'running'"))
        db.execute(text("UPDATE deployment_locks SET lease_expires_at = now() - interval '1 second'"))
        db.commit()
    assert actions.reap_expired(rt) == 1
    th.join(10)
    assert not th.is_alive()
    assert job(actors[0], jidA)["status"] == "failed"
    # operator re-submits: a second executor takes over and must not clone again
    _, jidB = submit(actors, rt, "deployment.create", {"spec": spec_body(), "plan_hash": p["plan_hash"]})
    assert job(actors[0], jidB)["status"] == "succeeded", job(actors[0], jidB)
    assert sorted(prov.names("clone")) == sorted(set(prov.names("clone")))     # one clone per VM name
    snapshot = list(prov.calls)
    stepsA = steps(actors[0], jidA)
    gate.set()                              # the orphan wakes up ...
    time.sleep(1.5)
    assert prov.calls == snapshot           # ... and issues no further provider call
    assert steps(actors[0], jidA) == stepsA  # nor writes step rows


def test_h1_execution_lock_is_exclusive_and_fenced(rt, env, mk_user):
    seed_inventory(rt)
    uid = mk_user('lockuser', 'operator')['id']
    with rt.session() as db:
        ep = db.execute(text("SELECT id FROM endpoints LIMIT 1")).scalar()
        dep = str(db.execute(text("INSERT INTO deployments (slug, customer_id, profile, profile_version, endpoint_id, status, desired_spec) "
                                  "VALUES ('lk', 'c', 'small', '1', :e, 'planned', '{}') RETURNING id"), {"e": ep}).scalar())
        pl = [str(db.execute(text("INSERT INTO plans (action, params, risk, status, requested_by, params_hash) VALUES "
                                  "('deployment.create', '{}', 'high', 'approved', :u, 'h') RETURNING id"), {"u": uid}).scalar()) for _ in range(2)]
        j1, j2 = [str(db.execute(text("INSERT INTO jobs (plan_id, action, status) VALUES (:p, 'deployment.create', 'running') RETURNING id"),
                                 {"p": p}).scalar()) for p in pl]
        db.commit()
    a, b = Lease(rt, dep, j1), Lease(rt, dep, j2)
    a.acquire()
    with pytest.raises(DeployError, match="another executor"):
        b.acquire()
    a.check()                                                   # holder is fine
    with rt.session() as db:
        db.execute(text("UPDATE deployment_locks SET lease_expires_at = now() - interval '1 second'"))
        db.commit()
    b.acquire()                                                 # expired lease can be taken over, token increases
    assert b.token == a.token + 1
    with pytest.raises(Fenced):
        a.check()
    b.check()
    a.release()                                                 # a stale holder's release must not drop b's lock
    b.check()
    b.release()


def test_h1_job_wall_clock_does_not_apply_to_deployments(client, actors, rt, env, monkeypatch):
    rt.settings = dataclasses.replace(rt.settings, job_timeout_seconds=1)
    seed_inventory(rt)
    p = preview(actors[0])
    orig = env.agent.wait_enrollment

    def slow(vm, t):
        time.sleep(1.2)
        return orig(vm, t)
    monkeypatch.setattr(env.agent, "wait_enrollment", slow)
    _, jid = submit(actors, rt, "deployment.create", {"spec": spec_body(), "plan_hash": p["plan_hash"]})
    assert job(actors[0], jid)["status"] == "succeeded"          # far beyond job_timeout_seconds: lease based, per-step deadline only


# ---------------------------------------------------------------- M1
def test_m1_last_admin_cannot_be_removed_with_two_approved_plans(client, rt, mk_user, login):
    adm1, adm2 = login(mk_user("adm1", "admin")), login(mk_user("adm2", "admin"))
    ap1, ap2 = login(mk_user("ap1", "approver")), login(mk_user("ap2", "approver"))
    p1 = adm2[0].post("/api/v1/plans", json={"action": "user.disable", "params": {"username": "adm1", "reason": "x"}}, headers=adm2[1]).json()["plan_id"]
    p2 = adm1[0].post("/api/v1/plans", json={"action": "user.set_role", "params": {"username": "adm2", "role": "viewer", "justification": "x"}},
                      headers=adm1[1]).json()["plan_id"]
    for pid in (p1, p2):
        for c, h in (ap1, ap2):
            assert c.post(f"/api/v1/plans/{pid}/approve", headers=h).status_code == 200
    worker.run_once(rt)
    worker.run_once(rt)
    with rt.session() as db:
        assert db.execute(text("SELECT count(*) FROM users WHERE role = 'admin' AND enrolled AND NOT disabled")).scalar() == 1
        st = sorted(r[0] for r in db.execute(text("SELECT status FROM jobs")))
    assert st == ["failed", "succeeded"]


# ---------------------------------------------------------------- M2
def test_m2_destroy_uses_applied_revision_not_a_proposed_change(client, actors, rt, env):
    _active(actors, rt)
    prov = env.provider
    with rt.session() as db:   # a later change that drops one VM was only PROPOSED (never applied)
        dep = db.execute(text("SELECT id FROM deployments WHERE slug = 'prod'")).scalar()
        plan = db.execute(text("SELECT plan FROM deployment_revisions WHERE deployment_id = :d AND kind = 'create'"), {"d": dep}).scalar()
        plan = {**plan, "vms": plan["vms"][:-1], "plan_hash": "x"}
        h = ops.plan_hash(plan)
        db.execute(text("INSERT INTO deployment_revisions (deployment_id, revision, kind, plan_hash, spec_hash, spec, plan, diff, risk, status) "
                        "SELECT :d, 2, 'change', :h, spec_hash, spec, CAST(:p AS jsonb), '{}'::jsonb, 'normal', 'proposed' "
                        "FROM deployment_revisions WHERE deployment_id = :d AND kind = 'create'"), {"d": dep, "h": h, "p": json.dumps({**plan, "plan_hash": h})})
        db.commit()
    (o, oh) = actors[0]
    pv = o.post("/api/v1/deployments/prod/destroy/preview", headers=oh).json()
    assert len(pv["vms"]) == 3                                                  # all applied VMs
    r, jid = submit(actors, rt, "deployment.destroy", {"deployment_id": "prod", "confirm": "prod", "plan_hash": pv["plan_hash"]})
    assert job(actors[0], jid)["status"] == "succeeded", job(actors[0], jid)
    assert prov.vms == {}                                                       # nothing left running
    assert o.get("/api/v1/deployments/prod").json()["status"] == "destroyed"


def test_m2_destroy_requires_matching_plan_hash_and_is_not_marked_destroyed_if_vm_remains(client, actors, rt, env):
    _active(actors, rt)
    prov = env.provider
    (o, oh) = actors[0]
    assert o.post("/api/v1/plans", json={"action": "deployment.destroy", "params": {"deployment_id": "prod", "confirm": "prod"}}, headers=oh).status_code == 422
    submit(actors, rt, "deployment.destroy", {"deployment_id": "prod", "confirm": "prod", "plan_hash": "f" * 64}, expect=409)
    pv = o.post("/api/v1/deployments/prod/destroy/preview", headers=oh).json()
    stubborn = next(v for v in prov.vms.values() if v["name"].endswith("-office") or v["name"].endswith("-files"))
    orig = prov.destroy_vm

    def fake_destroy(ref):                                   # the provider reports success but the guest is still there
        if ref.vmid == stubborn["vmid"]:
            return prov._task("destroy", ref.vmid, ref.node)
        return orig(ref)
    prov.destroy_vm = fake_destroy
    _, jid = submit(actors, rt, "deployment.destroy", {"deployment_id": "prod", "confirm": "prod", "plan_hash": pv["plan_hash"]})
    j = job(actors[0], jid)
    assert j["status"] == "failed" and "still exist" in j["error"]["message"]
    assert o.get("/api/v1/deployments/prod").json()["status"] == "failed"
    with rt.session() as db:                                 # the surviving VM is still tracked, not 'removed'
        assert db.execute(text("SELECT state FROM deployment_resources WHERE logical_name = :n AND kind = 'vm'"), {"n": stubborn["name"]}).scalar() != "removed"


# ---------------------------------------------------------------- M3
def test_m3_different_create_plan_never_reuses_steps_of_another_plan(client, actors, rt, env):
    seed_inventory(rt)
    env.checks.bad = {"keycloak"}
    p1, _, jid1 = create(actors, rt, users=40)
    assert job(actors[0], jid1)["status"] == "failed"
    done1 = [s for s in steps(actors[0], jid1) if s["status"] == "succeeded"]
    assert done1
    env.checks.bad = set()
    p2 = preview(actors[0], users=50)
    assert p2["plan_hash"] != p1["plan_hash"]
    _, jid2 = submit(actors, rt, "deployment.create", {"spec": spec_body(users=50), "plan_hash": p2["plan_hash"]})
    assert job(actors[0], jid2)["status"] == "succeeded", job(actors[0], jid2)
    assert all(s["carried_from_job"] is None for s in steps(actors[0], jid2))   # every step of the NEW plan really ran
    cfg = [c for c in env.provider.calls if c[0] == "configure"]
    assert len(cfg) >= 2 * len(p2["vms"])                                      # configured by plan 1 and again by plan 2


# ---------------------------------------------------------------- M5 / L2
def _window(rt, independent):
    with rt.session() as db:
        wid = str(db.execute(text("INSERT INTO maintenance_windows (name, starts_at, ends_at, independently_approved) VALUES "
                                  "('mw', now() - interval '1 minute', now() + interval '1 hour', :i) RETURNING id"), {"i": independent}).scalar())
        db.commit()
    return wid


def test_m5_stale_change_plan_is_refused_after_another_change_was_applied(client, actors, rt, env):
    _active(actors, rt, users=30)
    wid = _window(rt, True)
    pa, pb = cprev(actors[0], {"users": 40}), cprev(actors[0], {"users": 50})
    ja = submit(actors, rt, "deployment.change", {"deployment_id": "prod", "changes": {"users": 40}, "plan_hash": pa["plan"]["plan_hash"],
                                                    "maintenance": "window", "maintenance_window_id": wid}, approvals=1, run=False)[1]
    jb = submit(actors, rt, "deployment.change", {"deployment_id": "prod", "changes": {"users": 50}, "plan_hash": pb["plan"]["plan_hash"],
                                                    "maintenance": "window", "maintenance_window_id": wid}, approvals=1, run=False)[1]
    worker.run_once(rt)
    worker.run_once(rt)
    ok, stale = job(actors[0], ja), job(actors[0], jb)
    assert ok["status"] == "succeeded"
    assert stale["status"] == "failed" and "preview the change again" in stale["error"]["message"]
    d = actors[0][0].get("/api/v1/deployments/prod").json()
    assert d["desired_spec"]["users"] == 40 and d["current_revision"] == 2


def test_l2_self_minted_maintenance_window_cannot_lower_the_change_tier(client, actors, rt, env):
    _active(actors, rt, users=30)
    (o, oh) = actors[0]
    with rt.session() as db:
        db.execute(text("INSERT INTO checks (name, kind, config, interval_seconds, created_by) VALUES ('c1', 'tcp_tls', '{}'::jsonb, 60, (SELECT id FROM users LIMIT 1))"))
        cid = str(db.execute(text("SELECT id FROM checks WHERE name = 'c1'")).scalar())
        db.commit()
    r = o.post("/api/v1/plans", json={"action": "maintenance.create", "params": {"name": "mine", "check_id": cid, "duration_minutes": 30}}, headers=oh).json()
    assert r["status"] == "approved"                       # low risk: auto-approved for the requester alone
    worker.run_once(rt)
    with rt.session() as db:
        wid, ind = db.execute(text("SELECT id, independently_approved FROM maintenance_windows WHERE name = 'mine'")).first()
    assert ind is False
    pv = cprev(actors[0], {"users": 40})
    params = {"deployment_id": "prod", "changes": {"users": 40}, "plan_hash": pv["plan"]["plan_hash"], "maintenance": "window", "maintenance_window_id": str(wid)}
    r = submit(actors, rt, "deployment.change", params, expect=409)
    assert "approved by anyone other than" in r.text
    # a window two other people approved is accepted (and the executor re-checks it)
    r = o.post("/api/v1/plans", json={"action": "maintenance.create", "params": {"name": "long", "check_id": cid, "duration_minutes": 120}}, headers=oh).json()
    assert r["risk"] == "high"
    for c, h in actors[1:]:
        assert c.post(f"/api/v1/plans/{r['plan_id']}/approve", headers=h).status_code == 200
    worker.run_once(rt)
    with rt.session() as db:
        assert db.execute(text("SELECT independently_approved FROM maintenance_windows WHERE name = 'long'")).scalar() is True


# ---------------------------------------------------------------- L3 / L4
def test_l3_destroy_and_power_check_vmid_and_tags_not_the_name(client, actors, rt, env):
    _active(actors, rt)
    prov = env.provider
    (o, oh) = actors[0]
    pv = o.post("/api/v1/deployments/prod/destroy/preview", headers=oh).json()
    victim = next(v for v in prov.vms.values() if v["name"].endswith("-groupware"))
    vmid = victim["vmid"]
    prov.vms[vmid] = {**victim, "name": "someone-elses-db", "tags": ["customer-db"]}      # the recorded vmid was recycled by a foreign guest
    twin = {**victim, "vmid": 999, "node": victim["node"]}                                # same-name tagged twin elsewhere
    prov.vms[999] = twin
    _, jid = submit(actors, rt, "deployment.destroy", {"deployment_id": "prod", "confirm": "prod", "plan_hash": pv["plan_hash"]})
    assert vmid in prov.vms and prov.vms[vmid]["name"] == "someone-elses-db"              # foreign guest untouched
    assert 999 in prov.vms                                                                # by-name twin untouched too


def test_l4_deployment_never_adopts_a_foreign_check_by_name(client, actors, rt, env):
    seed_inventory(rt)
    p = preview(actors[0])
    name = p["checks"][0]["name"] if p.get("checks") else None
    assert name, "plan has checks"
    with rt.session() as db:
        db.execute(text("INSERT INTO checks (name, kind, config, interval_seconds, created_by) VALUES (:n, 'tcp_tls', '{}'::jsonb, 60, (SELECT id FROM users LIMIT 1))"), {"n": name})
        db.commit()
    _, jid = submit(actors, rt, "deployment.create", {"spec": spec_body(), "plan_hash": p["plan_hash"]})
    j = job(actors[0], jid)
    assert j["status"] == "failed" and "does not belong to this deployment" in j["error"]["message"]
    with rt.session() as db:
        assert db.execute(text("SELECT deployment_id FROM checks WHERE name = :n"), {"n": name}).scalar() is None   # untouched


# ---------------------------------------------------------------- L5 / L8
def test_l5_revoke_invite_of_privileged_account_is_high_risk(client, rt, mk_user, login):
    adm = login(mk_user("adm", "admin"))
    with rt.session() as db:
        auth.create_invite(db, rt, "invadmin", "admin", created_by=None, actor="t")
        auth.create_invite(db, rt, "invview", "viewer", created_by=None, actor="t")
    r = adm[0].post("/api/v1/plans", json={"action": "user.revoke_invite", "params": {"username": "invadmin"}}, headers=adm[1]).json()
    assert r["risk"] == "high" and r["status"] == "pending_approval"
    r = adm[0].post("/api/v1/plans", json={"action": "user.revoke_invite", "params": {"username": "invview"}}, headers=adm[1]).json()
    assert r["risk"] == "low"


def test_l8_viewers_do_not_see_lockout_mfa_or_sessions(client, rt, mk_user, login):
    mk_user("target", "operator")
    adm, vw = login(mk_user("adm", "admin")), login(mk_user("vw", "viewer"))
    with rt.session() as db:
        for _ in range(8):
            db.execute(text("INSERT INTO login_attempts (username, ip, success) VALUES ('target', '10.1.1.1', false)"))
        db.commit()
    a = next(u for u in adm[0].get("/api/v1/users").json() if u["username"] == "target")
    v = next(u for u in vw[0].get("/api/v1/users").json() if u["username"] == "target")
    assert a["status"] == "locked" and a["mfa_enrolled"] is True and a["active_sessions"] == 0
    assert v["status"] == "active" and v["mfa_enrolled"] is None and v["active_sessions"] is None and v["last_login_at"] is None
    d = vw[0].get(f"/api/v1/users/{v['id']}").json()
    assert all(h["justification"] is None for h in d["role_history"])


# ---------------------------------------------------------------- M4 / L1 / L9
def test_m4_ou_repo_components_are_strict_tokens():
    from ics.guest import cloudinit as ci
    base = dict(url="https://repo.example/apt", suite="noble", key_armored="-----BEGIN PGP PUBLIC KEY BLOCK-----\nxx\n-----END PGP PUBLIC KEY BLOCK-----",
                key_fingerprint="A" * 40)
    ci.OuRepo(**base)
    for bad in (["main\ndeb [trusted=yes] http://evil.invalid/ubuntu noble main"], ["main contrib"], ["[trusted=yes]"], ["main\n"], [], ["Main"]):
        with pytest.raises(ValueError):
            ci.OuRepo(**{**base, "components": bad})
    for bad in ({"suite": "noble main"}, {"suite": "noble\n"}, {"url": "https://repo.example/apt [trusted=yes]"}, {"url": "https://repo.example/a\n"}):
        with pytest.raises(ValueError):
            ci.OuRepo(**{**base, **bad})


def test_m4_helper_refuses_unsigned_or_option_sources(tmp_path, monkeypatch):
    from ou_agent import guesthelper as gh
    from ou_agent.proto import Reject
    monkeypatch.setattr(gh, "APT_DIR", str(tmp_path))
    ok = "# generated\ndeb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] http://archive.ubuntu.com/ubuntu noble main universe\n"
    (tmp_path / "sources.list").write_text(ok)
    gh._check_sources()
    for bad in ("deb [trusted=yes] http://evil.invalid/ubuntu noble main\n", ok + "deb [signed-by=/x trusted=yes] http://e/x noble main\n",
                ok + "deb http://e/x noble main\n"):
        (tmp_path / "sources.list").write_text(bad)
        with pytest.raises(Reject):
            gh._check_sources()


def test_l1_trailing_newline_is_rejected_everywhere():
    from ics.guest import cloudinit as ci
    from ou_agent import guestspec as gs
    from ou_agent.proto import Reject
    from .test_guest_bootstrap import CFG, GOOD, spec
    for bad in ({"volumes": [{"name": "data", "path": "/etc\n", "read_only": True}]}, {"component": "mail\n"}, {"name": "web\n"},
                {"env": {"A": "b\n"}}, {"image": GOOD["image"] + "\n"}):
        with pytest.raises(Reject):
            gs.check_deploy({**GOOD, **bad}, CFG)
    with pytest.raises(ValueError):
        spec(hostname="gw-app1\n")
    with pytest.raises(ValueError):
        spec(domain="cust1.example.com\n")
    assert not ci.LABEL_RE.fullmatch("gw\n") and not ci.HEX64.fullmatch("a" * 64 + "\n")


def test_l9_quadlet_never_repulls_outside_the_verified_pull():
    from ou_agent import guestspec as gs
    from .test_guest_bootstrap import CFG, GOOD
    c = gs.render(gs.check_deploy(GOOD, CFG))["ou-web-whoami.container"]
    assert "\nPull=never\n" in c
