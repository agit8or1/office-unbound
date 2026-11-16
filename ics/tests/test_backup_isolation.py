"""Per-customer backup boundaries (agent AU, closes the T20 backup FAIL): customer-bound policies, vault AAD, operator scoping on plans and on
the read API, runner profiles (agent allowlist + root helper config isolation), ICS-tier policy. The storage-level proof (separate restic
repositories, rest-server --private-repos, A's keys cannot open B's repository) is in blueprints/lab/tests/t20_tenant_isolation.py (lab)."""
import importlib.machinery
import importlib.util
import json
import os
import subprocess
import sys
import uuid

import pytest
from pydantic import ValidationError
from sqlalchemy import text

from ics import actions, agentclient, auth, worker
from ics.actions import ActionType
from ics.backups import ops, policy as pol

from .conftest import FakeAgent
from .test_backups import CA
from .test_identity import enrolled_node
from .test_vault_m import mk_customer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))
H = "/api/v1"
HELPER = os.path.join(os.path.dirname(__file__), "..", "agent", "deploy", "runbooks", "ou-backup")


def load_helper():
    loader = importlib.machinery.SourceFileLoader("ou_backup_helper", HELPER)
    spec = importlib.util.spec_from_loader("ou_backup_helper", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


def pdoc(cid, tier="files", name=None, **kw):
    prof = pol.customer_profile(cid)
    d = {"name": name or f"{tier}-{prof[2:8]}", "tier": tier, "deployment": "cust stack", "customer_id": cid, "schedule": {"every_hours": 24},
         "rpo_seconds": 86400, "rto_seconds": 1800, "repo": {"url": f"https://192.168.186.85:8010/{prof}/{tier}", "ca_sha256": CA}}
    d.update(kw)
    return d


@pytest.fixture()
def iso(rt, mk_user, login, tmp_path, monkeypatch):
    ca, cb = mk_customer(rt, "iso-a", msp_owned=True, mode="auto"), mk_customer(rt, "iso-b", msp_owned=True, mode="auto")
    pa, pb = pol.customer_profile(ca), pol.customer_profile(cb)
    spool, results = tmp_path / "spool", tmp_path / "results"
    spool.mkdir()
    results.mkdir()
    fa = FakeAgent(tmp_path, extra={k: {"tiers": ["files", "ics"], "customers": [pa, pb]} for k in ("backup.run", "backup.verify", "backup.prune")})
    rb = fa.runbooks
    monkeypatch.setattr(rb, "SPOOL_DIR", str(spool))
    monkeypatch.setattr(rb, "BACKUP_RESULT_DIR", str(results))
    calls = []
    orig = rb._systemctl

    def fake(*args, timeout=60):
        if len(args) == 3 and args[0] == "start" and args[2].startswith("ou-rb-backup@"):
            rid = args[2].split("@")[1].removesuffix(".service")
            calls.append(json.loads((spool / (rid + ".json")).read_text()))
            (results / (rid + ".json")).write_text(json.dumps({"rid": rid, "result": {"tier": "files", "snapshot": "a" * 64, "repo_confirmed": True, "repo_id": "r" * 64,
                                                                             "canary_recorded": True, "repo_bytes": 10, "snapshots_total": 1, "passed": True}}))
            return subprocess.CompletedProcess(args, 0, "", "")
        return orig(*args, timeout=timeout)
    monkeypatch.setattr(rb, "_systemctl", fake)
    priv = agentclient.load_signing_key(rt.settings.signing_key_file)
    _, node = enrolled_node(fa, priv=priv)
    caps = {k: {"tiers": ["files", "ics"], "customers": [pa, pb]} for k in ("backup.run", "backup.verify", "backup.prune")}
    with rt.session() as d:
        d.execute(text("INSERT INTO nodes (id, name, address, port, tls_fingerprint_sha256, agent_pubkey, agent_key_fp, capabilities) "
                       "VALUES (:i, 'isn', '127.0.0.1', :p, :t, :k, :f, CAST(:c AS jsonb))"),
                  {"i": node.id, "p": fa.port, "t": fa.tls_fp, "k": node.agent_pubkey, "f": fa.key_fp, "c": json.dumps(caps)})
        d.commit()
    users = {n: mk_user(n, r) for n, r in (("iso-adm", "operator"), ("iso-opa", "operator"), ("iso-opb", "operator"), ("iso-ap1", "approver"), ("iso-ap2", "approver"))}
    with rt.session() as d:
        for n, c in (("iso-opa", ca), ("iso-opb", cb)):
            d.execute(text("UPDATE users SET all_customers = false WHERE username = :u"), {"u": n})
            d.execute(text("INSERT INTO operator_customers (user_id, customer_id) VALUES (:u, :c)"), {"u": users[n]["id"], "c": c})
        d.commit()

    def U(n):
        with rt.session() as d:
            row = d.execute(text("SELECT * FROM users WHERE username = :u"), {"u": n}).first()
            u = auth.User(row)
            from ics.tenancy import scope
            u.customer_ids = scope.load(d, row.id, row.all_customers)
            return u

    class Hh:
        pass
    h = Hh()
    h.ca, h.cb, h.pa, h.pb, h.node, h.calls, h.fa, h.users, h.U = ca, cb, pa, pb, node.id, calls, fa, users, U

    def plan(action, params, who, approve=0):
        with rt.session() as d:
            r = actions.create_plan(d, rt, U(who), ActionType(action), params, "127.0.0.1")
            for ap in ("iso-ap1", "iso-ap2")[:approve]:
                if r["status"] != "approved":
                    r.update({k: v for k, v in actions.decide_plan(d, rt, U(ap), uuid.UUID(r["plan_id"]), True, "127.0.0.1").items() if k in ("status", "job_id")})
            return r

    def lane():
        n = 0
        while worker.run_once(rt, beat=False, backup_lane=True):
            n += 1
        return n
    h.plan, h.lane = plan, lane
    h.login = login
    yield h
    fa.stop()


def mk(rt, iso, cid, who="iso-adm", **kw):
    r = iso.plan("backup.policy.create", pdoc(cid, runner_node_id=str(iso.node), **kw), who, approve=1)
    assert iso.lane() >= 1
    with rt.session() as d:
        assert d.execute(text("SELECT status FROM jobs WHERE plan_id = :p"), {"p": r["plan_id"]}).scalar() == "succeeded"
    return r


# ---- model ---------------------------------------------------------------------------------------------------------------------------------
def test_customer_policy_repository_must_live_in_the_customers_namespace():
    a, b = str(uuid.uuid4()), str(uuid.uuid4())
    pol.PolicyCreate.model_validate(pdoc(a, runner_node_id=str(uuid.uuid4())))
    for url in (f"https://h:8010/{pol.customer_profile(b)}/files",       # another customer's namespace
                "https://h:8010/files", "https://h:8010/shared/c-" + a.replace("-", "")):
        with pytest.raises(ValidationError):
            pol.PolicyCreate.model_validate(pdoc(a, runner_node_id=str(uuid.uuid4()), repo={"url": url, "ca_sha256": CA}))


def test_runbook_params_carry_only_a_well_formed_profile():
    p = pol.customer_profile(uuid.uuid4())
    assert pol.runbook_params("backup.run", {"tier": "files", "customer": p}) == {"tier": "files", "customer": p}
    for bad in ("c-x", "../c-" + "a" * 32, "C-" + "A" * 32, "c-" + "a" * 31, 7, "c-" + "a" * 32 + "/../x"):
        with pytest.raises(ValueError):
            pol.runbook_params("backup.run", {"tier": "files", "customer": bad})


# ---- agent allowlist ------------------------------------------------------------------------------------------------------------------------
def test_agent_refuses_a_customer_profile_that_is_not_allowlisted_on_this_node(iso):
    other = pol.customer_profile(uuid.uuid4())
    spec = {"tiers": ["files"], "customers": [iso.pa]}
    from ou_agent import runbooks as rb
    assert rb.check_backup("backup.run", {"tier": "files", "customer": iso.pa}, spec)["customer"] == iso.pa
    for bad in ({"tier": "files", "customer": other}, {"tier": "files", "customer": "c-zz"}, {"tier": "files", "customer": iso.pa, "x": 1}):
        with pytest.raises(rb.Reject):
            rb.check_backup("backup.run", bad, spec)
    with pytest.raises(rb.Reject):   # a node without a customers allowlist serves no customer profile at all
        rb.check_backup("backup.run", {"tier": "files", "customer": iso.pa}, {"tiers": ["files"]})
    rb.validate_config({"listen": {"address": "127.0.0.1", "port": 1}, "runbooks": {"backup.run": {"tiers": ["files"], "customers": [iso.pa]}}})
    with pytest.raises(ValueError):
        rb.validate_config({"listen": {"address": "127.0.0.1", "port": 1}, "runbooks": {"backup.run": {"tiers": ["files"], "customers": ["../x"]}}})


# ---- ICS: policy binding, vault AAD, plan scoping, read scoping -------------------------------------------------------------------------------
def test_policy_is_bound_to_the_customer_in_the_vault(rt, iso):
    mk(rt, iso, iso.ca)
    with rt.session() as d:
        r = d.execute(text("SELECT * FROM backup_policies")).first()
        assert str(r.customer_id) == iso.ca
        ok = ops.repo_aad(r.id, r.repo["url"], iso.ca)
        assert json.loads(rt.vault.decrypt(r.repo_secret_enc, ok))["repo_password"]
        for bad in (ops.repo_aad(r.id, r.repo["url"], iso.cb), ops.repo_aad(r.id, r.repo["url"])):   # relabelled to customer B / customer binding dropped
            with pytest.raises(Exception):
                rt.vault.decrypt(r.repo_secret_enc, bad)
        assert len(ops.node_secret(rt, d, r.name)["repo_password"]) >= 40


def test_node_must_allow_the_customer_and_repo_urls_are_unique(rt, iso):
    c = mk_customer(rt, "iso-c", msp_owned=True, mode="auto")        # profile not in the node's allowlist
    with pytest.raises(actions.PlanError) as e:
        iso.plan("backup.policy.create", pdoc(c, runner_node_id=str(iso.node)), "iso-adm")
    assert e.value.args[0] == 422 or "customer" in str(e.value)
    mk(rt, iso, iso.ca, name="first")
    with pytest.raises(actions.PlanError) as e:      # a second policy on the same repository (another name) is refused
        iso.plan("backup.policy.create", pdoc(iso.ca, runner_node_id=str(iso.node), name="second"), "iso-adm")
    assert e.value.args[0] == 409


def test_scoped_operator_cannot_plan_anything_on_another_customers_backups(rt, iso):
    mk(rt, iso, iso.ca, name="pol-a")
    mk(rt, iso, iso.cb, name="pol-b")
    # operator A on its own policy works for every action; on B's policy every action is a 404 identical to a missing policy
    for action, extra in (("backup.run", {}), ("backup.verify", {"level": "check"}), ("backup.verify", {"level": "restore"}), ("backup.prune", {}),
                          ("backup.policy.update", {"enabled": False})):
        with pytest.raises(actions.PlanError) as foreign:
            iso.plan(action, {"policy": "pol-b", **extra}, "iso-opa")
        with pytest.raises(actions.PlanError) as missing:
            iso.plan(action, {"policy": "does-not-exist", **extra}, "iso-opa")
        assert foreign.value.args == missing.value.args and foreign.value.args[0] == 404, (action, foreign.value.args)
    r = iso.plan("backup.run", {"policy": "pol-a"}, "iso-opa")
    assert r["status"] in ("approved", "pending_approval")
    with pytest.raises(actions.PlanError) as e:       # creating a policy for another customer, or without a customer, is also a 404
        iso.plan("backup.policy.create", pdoc(iso.cb, runner_node_id=str(iso.node), name="sneaky"), "iso-opa")
    assert e.value.args[0] == 404
    legacy = pdoc(iso.ca, runner_node_id=str(iso.node), name="legacy")
    legacy.pop("customer_id")
    legacy["repo"] = {"url": "https://h:8010/legacy", "ca_sha256": CA}
    with pytest.raises(actions.PlanError) as e:
        iso.plan("backup.policy.create", legacy, "iso-opa")
    assert e.value.args[0] == 404


def test_run_reaches_the_node_with_the_customers_own_profile(rt, iso):
    mk(rt, iso, iso.ca, name="pol-a")
    mk(rt, iso, iso.cb, name="pol-b")
    iso.calls.clear()
    for who, pn in (("iso-opa", "pol-a"), ("iso-adm", "pol-b")):
        r = iso.plan("backup.run", {"policy": pn}, who, approve=2)
        assert iso.lane() == 1
    assert [c["params"] for c in iso.calls] == [{"tier": "files", "customer": iso.pa}, {"tier": "files", "customer": iso.pb}]
    with rt.session() as d:   # the plan of A's run carries customer A (scheduler plans too: they are made by create_plan)
        assert sorted(str(x) for x in d.execute(text("SELECT customer_id FROM plans WHERE action = 'backup.run'")).scalars()) == sorted([iso.ca, iso.cb])


def test_job_refuses_a_policy_that_belongs_to_another_customer_than_its_plan(rt, iso):
    mk(rt, iso, iso.ca, name="pol-a")
    mk(rt, iso, iso.cb, name="pol-b")
    r = iso.plan("backup.run", {"policy": "pol-a"}, "iso-adm", approve=2)
    with rt.session() as d:   # after approval someone re-points the policy row at customer B (or the plan was made for another customer)
        d.execute(text("UPDATE backup_policies SET customer_id = :c WHERE name = 'pol-a'"), {"c": iso.cb})
        d.commit()
    iso.calls.clear()
    assert iso.lane() == 1
    with rt.session() as d:
        st, err = d.execute(text("SELECT status, error FROM jobs WHERE plan_id = :p"), {"p": r["plan_id"]}).first()
    assert st == "failed" and not iso.calls and "different customers" in json.dumps(err)


def test_read_api_is_scoped_to_the_operators_customers(rt, iso):
    mk(rt, iso, iso.ca, name="pol-a")
    mk(rt, iso, iso.cb, name="pol-b")
    for n in ("pol-a", "pol-b"):
        r = iso.plan("backup.run", {"policy": n}, "iso-adm", approve=2)
        assert iso.lane() == 1
    with rt.session() as d:
        d.execute(text("INSERT INTO backup_verifications (policy_id, level, state, finished_at) SELECT id, 'check', 'passed', now() FROM backup_policies"))
        d.commit()
    for who in ("iso-opa", "iso-opb"):
        c, _ = iso.login(iso.users[who])
        mine = "pol-a" if who == "iso-opa" else "pol-b"
        assert [p["name"] for p in c.get(f"{H}/backups/policies").json()] == [mine]
        assert {r["policy"] for r in c.get(f"{H}/backups/runs").json()} == {mine}
        assert {r["policy"] for r in c.get(f"{H}/backups/verifications").json()} == {mine}
        other = "pol-b" if mine == "pol-a" else "pol-a"
        assert c.get(f"{H}/backups/runs?policy={other}").json() == []
        assert c.get(f"{H}/backups/verifications?policy={other}").json() == []
    c, _ = iso.login(iso.users["iso-adm"])
    assert sorted(p["name"] for p in c.get(f"{H}/backups/policies").json()) == ["pol-a", "pol-b"]


def test_ics_controller_tier_policy_and_scheduler_includes_restore_verification(rt, iso):
    r = iso.plan("backup.policy.create", pdoc(iso.ca, tier="ics", name="ics-dev", runner_node_id=str(iso.node)), "iso-adm", approve=1)
    assert iso.lane() == 1
    with rt.session() as d:
        pid = d.execute(text("SELECT id FROM backup_policies WHERE name = 'ics-dev'")).scalar()
        d.execute(text("INSERT INTO backup_runs (policy_id, kind, status, started_at, finished_at, snapshot_id, repo_confirmed) "
                       "VALUES (:p, 'backup', 'succeeded', now(), now(), :s, true)"), {"p": str(pid), "s": "b" * 64})
        d.execute(text("INSERT INTO backup_verifications (policy_id, level, state, started_at, finished_at) VALUES (:p, 'check', 'passed', now(), now())"), {"p": str(pid)})
        d.commit()
    made = ops.tick(rt)
    assert "backup.verify:ics-dev" in made          # an ICS controller policy gets its scheduled restore verification (scratch machine, passive restore)


# ---- root helper: profile isolation ---------------------------------------------------------------------------------------------------------
@pytest.fixture()
def helper(tmp_path, monkeypatch):
    m = load_helper()
    monkeypatch.setattr(m, "CONFIG_DIR", str(tmp_path / "ou-backup"))
    monkeypatch.setattr(m, "ROOT_UID", os.getuid())
    (tmp_path / "ou-backup").mkdir()
    return m, tmp_path / "ou-backup"


def write_profile(base, prof, tier="identity", **over):
    d = base / prof
    (d / "creds" / tier).mkdir(parents=True, exist_ok=True)
    cfg = {"tier": tier, "customer": prof, "machine": f"src-{prof[2:6]}", "scratch": f"scr-{prof[2:6]}", "repo_url": f"https://bkp:8010/{prof}/{tier}",
           "maint_repo_url": f"https://bkp:8011/{prof}/{tier}", "cacert": "/x", "creds_dir": str(d / "creds" / tier), "scripts_dir": "/x",
           "stage_dir": f"/var/lib/ou-backup/stage/{prof}", "restic": "/x", "restic_sha256": "0" * 64}
    cfg.update(over)
    (d / f"{tier}.json").write_text(json.dumps(cfg))
    os.chmod(d / f"{tier}.json", 0o644)
    for n, v in (("rest-user", prof), ("rest-password", "x" * 20), ("repo-password", "y" * 40)):
        fp = d / "creds" / tier / n
        fp.write_text(v + "\n")
        os.chmod(fp, 0o600)
    return cfg


def test_helper_profile_config_is_self_contained(helper):
    m, base = helper
    pa, pb = pol.customer_profile(uuid.uuid4()), pol.customer_profile(uuid.uuid4())
    write_profile(base, pa)
    write_profile(base, pb)
    assert m.load_cfg("identity", pa)["customer"] == pa and m.load_cfg("identity", pb)["customer"] == pb
    with pytest.raises(m.Fail):   # a profile that does not exist is not "the legacy config"
        m.load_cfg("identity", pol.customer_profile(uuid.uuid4()))
    with pytest.raises(m.Fail):
        m.load_cfg("identity", "../etc")
    # config of A that points into B's repository namespace / credentials / staging / machines / REST user
    for over, why in (({"repo_url": f"https://bkp:8010/{pb}/identity"}, "repo_url"), ({"maint_repo_url": f"https://bkp:8011/{pb}/identity"}, "maint_repo_url"),
                      ({"creds_dir": str(base / pb / "creds" / "identity")}, "creds_dir"), ({"stage_dir": f"/var/lib/ou-backup/stage/{pb}"}, "stage_dir"),
                      ({"customer": pb}, "profile"), ({"scratch": f"scr-{pb[2:6]}"}, "scratch shared with B"), ({"machine": f"src-{pb[2:6]}"}, "source shared with B"),
                      ({"scratch": f"src-{pb[2:6]}"}, "scratch is B's source")):
        write_profile(base, pa, **over)
        with pytest.raises(m.Fail):
            m.load_cfg("identity", pa)
    write_profile(base, pa)
    (base / pa / "creds" / "identity" / "rest-user").write_text(pb + "\n")        # A's runner holds B's REST user name -> refuse
    with pytest.raises(m.Fail):
        m.load_cfg("identity", pa)


def test_helper_legacy_machine_cannot_be_claimed_by_a_customer_profile(helper):
    m, base = helper
    pa = pol.customer_profile(uuid.uuid4())
    (base / "identity.json").write_text(json.dumps({"machine": "ou-id1", "scratch": "ou-id-r1"}))
    write_profile(base, pa, scratch="ou-id-r1")
    with pytest.raises(m.Fail):
        m.load_cfg("identity", pa)
    write_profile(base, pa)
    assert m.load_cfg("identity", pa)["machine"].startswith("src-")


def test_helper_validates_customer_in_spool_requests(helper):
    m, _ = helper
    p = pol.customer_profile(uuid.uuid4())
    assert m.validate("backup.run", {"tier": "files", "customer": p})["customer"] == p
    for bad in ({"tier": "files", "customer": "../x"}, {"tier": "files", "customer": 1}, {"tier": "files", "cust": p}):
        with pytest.raises(m.Fail):
            m.validate("backup.run", bad)
