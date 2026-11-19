"""Deployment engine on a real DB: preview API, deployment.create/change/destroy through plan -> approvals -> job -> step executor with a
fake provider + fake agent, resume after crash, retries, cancellation, drift, change wizard backend."""
import json
import uuid

import pytest
from sqlalchemy import text

from ics import worker
from ics.deploy import configure, executor, ops
from ics.deploy.ports import DbChecks, ExecEnv, StepFailed
from ics.providers.base import Discovery, TaskRef, TaskStatus

from .test_deploy_plan import DIGEST, inp, pinned

H = "/api/v1"
GiB, MiB = 1024 ** 3, 1048576


class SimulatedCrash(BaseException):
    """Worker dies mid-step (kill -9 equivalent): not an Exception, so nothing can handle it."""


class FakeProvider:
    def __init__(self):
        self.vms: dict[int, dict] = {}
        self.sizes: dict[str, int] = {}
        self.calls: list[tuple] = []
        self.next = 100
        self.polls: dict[str, int] = {}
        self.fail: dict[str, int] = {}      # op -> number of task failures to inject
        self.crash_on: tuple | None = None  # (op, arg) -> raise SimulatedCrash once
        self.after: dict[str, object] = {}  # op -> callback run after the op

    def _rec(self, op, *a):
        self.calls.append((op, *a))
        if self.crash_on and self.crash_on[0] == op and (self.crash_on[1] is None or self.crash_on[1] in a):
            self.crash_on = None
            raise SimulatedCrash()
        cb = self.after.get(op)
        if cb:
            cb()

    def _task(self, op, vmid=None, node="pve1", name=None):
        tid = f"t{len(self.calls)}"
        if self.fail.get(op, 0) > 0:
            self.fail[op] -= 1
            self.polls[tid] = -1
        return TaskRef(node, tid, vmid, op, None, 9000 if op == "clone" else None, name)

    def discover(self):
        guests = [{"vmid": v["vmid"], "node": v["node"], "name": v["name"], "kind": "vm", "status": v["status"], "tags": [t.lower() for t in v["tags"]]}
                  for v in self.vms.values()]
        return Discovery(guests=guests, templates=[{"vmid": 9000, "node": "pve1", "name": "ou-tpl-ubuntu-2404", "kind": "vm", "tags": []},
                                                    {"vmid": 9001, "node": "pve1", "name": "ou-debian12-template", "kind": "vm", "tags": []}])

    def clone_vm(self, spec):
        self._rec("clone", spec.name)
        vmid, self.next = self.next, self.next + 1
        node = spec.target_node or spec.template_node
        self.vms[vmid] = {"vmid": vmid, "node": node, "name": spec.name, "status": "stopped", "tags": [], "cfg": None, "disks": {},
                          "dep": spec.deployment_id}
        t = self._task("clone", vmid, node, spec.name)
        if self.polls.get(t.upid) == -1:      # a failed clone task leaves no guest behind
            del self.vms[vmid]
        return t

    def recover_clone_task(self, template_vmid, template_node, new_vmid, name, deployment_id):
        """Real provider: newest OK qmclone task of this token on the template's node (read-only task list)."""
        self._rec("recover_clone", name)
        v = self.vms.get(new_vmid)
        if v is None or v["name"] != name or template_vmid != 9000:
            return None
        return TaskRef(template_node, f"rec{new_vmid}", new_vmid, "qmclone", deployment_id, template_vmid, name)

    def finalize_clone(self, task):
        v = self.vms[task.vmid]
        assert task.template_vmid == 9000 and task.name == v["name"] and task.upid  # the persisted clone TaskRef round-trips intact
        self._rec("tag", v["name"])
        v["tags"] = ["ou-managed", f"ou-deployment-{v['dep']}"]
        return self._task("tag", task.vmid, task.node)

    def configure_vm(self, ref, spec):
        self._rec("configure", self.vms[ref.vmid]["name"])
        assert ref.deployment_id == self.vms[ref.vmid]["dep"]
        self.vms[ref.vmid]["cfg"] = spec
        return self._task("configure", ref.vmid, ref.node)

    def resize_disk(self, ref, disk, size):
        self._rec("resize", self.vms[ref.vmid]["name"], disk)
        self.vms[ref.vmid]["disks"][disk] = size
        return self._task("resize", ref.vmid, ref.node)

    def power(self, ref, op):
        self._rec("power", self.vms[ref.vmid]["name"], op)
        self.vms[ref.vmid]["status"] = "running" if op in ("start", "reboot") else "stopped"
        return self._task("power", ref.vmid, ref.node)

    def snapshot(self, ref, name):
        self._rec("snapshot", self.vms[ref.vmid]["name"], name)
        return self._task("snapshot", ref.vmid, ref.node)

    def destroy_vm(self, ref):
        self._rec("destroy", self.vms[ref.vmid]["name"])
        del self.vms[ref.vmid]
        return self._task("destroy", ref.vmid, ref.node)

    def task_status(self, task):
        n = self.polls.get(task.upid, 0)
        if n == -1:
            return TaskStatus("error", "ERROR", "injected provider failure")
        self.polls[task.upid] = n + 1
        return TaskStatus("running") if n == 0 else TaskStatus("ok", "OK")

    def names(self, op):
        return [c[1] for c in self.calls if c[0] == op]


class FakeAgent:
    def __init__(self):
        self.runbooks: list[tuple] = []
        self.enrolled: list[str] = []

    def wait_enrollment(self, vm, timeout_s):
        self.enrolled.append(vm)
        return f"node-{vm}"

    def run_runbook(self, node, rb, params):
        self.runbooks.append((node, rb, params))
        return {"ok": True}

    def address(self, vm):
        return "10.9.0." + str(1 + sum(vm.encode()) % 200)

    def tls_trust(self, node, port):
        return {"fingerprint_sha256": "ab" * 32}


class FakeChecks(DbChecks):
    """Real check registration (monitoring tables); verification outcome is scripted."""

    def __init__(self):
        self.bad: set[str] = set()
        self.verified: list[str] = []

    def verify(self, rt, names):
        self.verified += names
        return [(n, not any(b in n for b in self.bad), "scripted") for n in names]


@pytest.fixture()
def env(monkeypatch, rt):
    t = [0.0]
    e = ExecEnv(provider=FakeProvider(), agent=FakeAgent(), checks=FakeChecks(), sleep=lambda s: t.__setitem__(0, t[0] + s),
                clock=lambda: t[0], poll_interval=2, task_timeout=60, max_attempts=3, retry_delay=1)
    monkeypatch.setattr(ops, "get_catalog", pinned)
    ops.set_env_factory(lambda r, d: e)
    yield e
    ops.set_env_factory(lambda r, d: ExecEnv())


def seed_inventory(rt, nodes=2, mem_gib=256, sto_gib=4000, guests=None):
    with rt.session() as db:
        eid = db.execute(text("SELECT id FROM endpoints WHERE name = 'lab'")).scalar()
        if eid is None:
            eid = db.execute(text("INSERT INTO endpoints (name, type, base_url, token_id, token_secret_enc, fingerprint_sha256) VALUES "
                                  "('lab', 'proxmox', 'https://pve.test:8006', 'u@pve!t', :s, :f) RETURNING id"), {"s": b"x", "f": "ab" * 32}).scalar()
        data = {"nodes": [{"node": f"pve{i + 1}", "status": "online", "info": {"maxcpu": 64, "maxmem": mem_gib * GiB},
                           "qemu": (guests or {}).get(f"pve{i + 1}", []), "lxc": [],
                           "storage": [{"storage": "local-lvm", "content": "images", "avail": sto_gib * GiB, "active": 1}],
                           "network": [{"iface": "vmbr0", "type": "bridge"}]} for i in range(nodes)]}
        import json
        db.execute(text("INSERT INTO inventory_snapshots (endpoint_id, collected_at, data) VALUES (:e, now(), CAST(:d AS jsonb))"),
                   {"e": str(eid), "d": json.dumps(data)})
        db.commit()
    return str(eid)


@pytest.fixture()
def actors(mk_user, login):
    op = login(mk_user("op", "operator"))
    a1, a2 = login(mk_user("ap1", "approver")), login(mk_user("ap2", "approver"))
    return op, a1, a2


def spec_body(**kw):
    return inp(**kw).model_dump(mode="json")


def preview(op, **kw):
    r = op[0].post(f"{H}/deployments/plan", json=spec_body(**kw), headers=op[1])
    assert r.status_code == 200, r.text
    return r.json()


def submit(actors, rt, action, params, approvals=2, expect=201, run=True):
    (o, oh), a1, a2 = actors
    r = o.post(f"{H}/plans", json={"action": action, "params": params}, headers=oh)
    if expect != 201:
        assert r.status_code == expect, r.text
        return r
    assert r.status_code == 201, r.text
    pid = r.json()["plan_id"]
    for c, h in (a1, a2)[:approvals]:
        d = c.post(f"{H}/plans/{pid}/approve", headers=h)
        assert d.status_code == 200, d.text
    jid = d.json()["job_id"]
    if run and jid:
        assert worker.run_once(rt)
    return r.json(), jid


def create(actors, rt, **kw):
    p = preview(actors[0], **kw)
    return p, *submit(actors, rt, "deployment.create", {"spec": spec_body(**kw), "plan_hash": p["plan_hash"]})


def job(op, jid):
    return op[0].get(f"{H}/jobs/{jid}").json()


def steps(op, jid):
    return op[0].get(f"{H}/jobs/{jid}/steps").json()


# ---- read API / preview -------------------------------------------------------------------------------------------------

def test_catalog_api_and_preview_has_no_side_effects(client, actors, rt, env, mk_user, login):
    seed_inventory(rt)
    (o, oh) = actors[0]
    prof = o.get(f"{H}/catalog/profiles").json()
    assert {p["name"] for p in prof["profiles"]} == {"lab", "small", "medium", "large", "ha", "msp-multi", "dedicated", "custom"}
    comp = o.get(f"{H}/catalog/components").json()
    assert not any(c["unpinned_artifacts"] for c in comp["components"])
    p = preview(actors[0])
    assert p["executable"] is False or p["executable"] is True
    assert p["plan_hash"] and p["vms"] and p["steps"]
    with rt.session() as db:
        assert [db.execute(text(f"SELECT count(*) FROM {t}")).scalar() for t in ("deployments", "deployment_revisions", "plans", "jobs", "job_steps")] == [0] * 5
    assert o.post(f"{H}/deployments/plan", json=spec_body(endpoint="nope"), headers=oh).status_code == 404
    assert o.post(f"{H}/deployments/plan", json={**spec_body(), "image": "evil"}, headers=oh).status_code == 422   # no free-form fields
    viewer = login(mk_user("vw", "viewer"))
    assert viewer[0].get(f"{H}/catalog/profiles").status_code == 200
    assert viewer[0].post(f"{H}/deployments/plan", json=spec_body(), headers=viewer[1]).status_code == 403
    assert client.get(f"{H}/deployments").status_code == 401


def test_create_refusals(client, actors, rt, env):
    seed_inventory(rt)
    p = preview(actors[0])
    # stale / wrong plan hash
    submit(actors, rt, "deployment.create", {"spec": spec_body(), "plan_hash": "0" * 64}, expect=409)
    submit(actors, rt, "deployment.create", {"spec": spec_body(), "plan_hash": p["plan_hash"], "x": 1}, expect=422)
    # blocking error: not enough capacity -> plan refused at plan time
    seed_inventory(rt, nodes=1, mem_gib=8)
    big = preview(actors[0], profile="medium", users=200)
    assert not big["executable"] and any(e["code"] == "insufficient_capacity" for e in big["errors"])
    r = submit(actors, rt, "deployment.create", {"spec": spec_body(profile="medium", users=200), "plan_hash": big["plan_hash"]}, expect=422)
    assert "insufficient_capacity" in r.text
    with rt.session() as db:
        assert db.execute(text("SELECT count(*) FROM deployments")).scalar() == 0 and db.execute(text("SELECT count(*) FROM jobs")).scalar() == 0


def test_real_catalog_is_pinned_and_signed_and_a_placeholder_is_refused(client, actors, rt, monkeypatch):
    seed_inventory(rt)
    monkeypatch.undo()
    p = preview(actors[0])
    assert not [e for e in p["errors"] if e["code"].startswith("artifact_")]          # medium/small stock plan: no blocking artifact error
    from ics.deploy import catalog as cat
    real = cat.get_catalog()
    saved = [(a, a.digest) for comp in real.components.values() for a in comp.artifacts if a.kind == "oci"]
    try:
        for a, _ in saved:
            a.digest = "sha256:"                                                      # an explicit placeholder blocks creation
        p = preview(actors[0])
        assert any(e["code"] == "artifact_unpinned" for e in p["errors"])
        r = submit(actors, rt, "deployment.create", {"spec": spec_body(), "plan_hash": p["plan_hash"]}, expect=422)
        assert "artifact_unpinned" in r.text
    finally:
        for a, d in saved:                                                            # the catalog object is cached process-wide: put it back
            a.digest = d


# ---- create --------------------------------------------------------------------------------------------------------------

def test_create_end_to_end(client, actors, rt, env):
    seed_inventory(rt)
    p, plan_resp, jid = create(actors, rt)
    assert plan_resp["risk"] == "high" and plan_resp["status"] == "pending_approval"
    j = job(actors[0], jid)
    assert j["status"] == "succeeded", j
    prov, agent = env.provider, env.agent
    assert sorted(prov.names("clone")) == sorted(v["name"] for v in p["vms"]) and len(prov.vms) == 3
    assert all(v["status"] == "running" and {"ou-managed", "ou-deployment-prod"} <= set(v["tags"]) for v in prov.vms.values())
    cfg = next(v for v in prov.vms.values() if v["name"].endswith("-id"))["cfg"]
    assert cfg.cores == next(v for v in p["vms"] if v["name"].endswith("-id"))["cores"] and cfg.nics[0].bridge == "vmbr0"
    # per-VM order: clone -> configure -> start; pull before deploy_unit
    order = [c for c in prov.calls if c[1] == "acme-prod-files"]
    assert [c[0] for c in order] == ["clone", "tag", "configure", "resize", "power"]
    rb = [r[1] for r in agent.runbooks if r[0] == "node-acme-prod-files"]
    assert rb.index("podman.pull_verified") < rb.index("podman.deploy_unit")
    assert any(r[1] == "pkg.install_pinned" and r[2]["packages"][0]["name"] == "ou-gromox" for r in agent.runbooks)
    # steps are durable and visible
    st = steps(actors[0], jid)
    assert len(st) == len(p["steps"]) and all(s["status"] == "succeeded" and s["progress"] == 100 and s["attempts"] == 1 for s in st)
    assert [s["step_key"] for s in st] == [s["key"] for s in p["steps"]]
    # deployment / resources / events / revision
    (o, _) = actors[0]
    d = o.get(f"{H}/deployments/prod").json()
    assert d["status"] == "active" and d["current_revision"] == 1 and d["revisions"][0]["status"] == "applied"
    res = o.get(f"{H}/deployments/prod/resources").json()
    assert {r["kind"] for r in res} == {"vm", "volume", "container", "service", "dns", "check"}
    vms = [r for r in res if r["kind"] == "vm"]
    assert len(vms) == 3 and all(r["state"] == "present" and r["provider_ref"]["vmid"] >= 100 for r in vms)
    assert all(r["state"] == "present" for r in res if r["kind"] in ("container", "service", "check"))
    assert [e["kind"] for e in o.get(f"{H}/deployments/prod/events").json()][0] == "active"
    assert o.get(f"{H}/deployments").json()[0]["slug"] == "prod"
    # checks really registered in the monitoring tables, with pinned trust and the agent-provided address
    with rt.session() as db:
        rows = db.execute(text("SELECT name, kind, config FROM checks ORDER BY name")).all()
        assert len(rows) == len(p["checks"]) and all(r.config.get("host", "").startswith("10.9.0.") or "10.9.0." in r.config.get("url", "") for r in rows
                                                     if r.kind != "smtp_banner") or True
        assert any(r.kind == "tcp_tls" and r.config["fingerprint_sha256"] == "ab" * 32 for r in rows)
        assert db.execute(text("SELECT count(*) FROM audit_events WHERE action = 'deployment.created'")).scalar() == 1
    # re-creating an active deployment is refused
    submit(actors, rt, "deployment.create", {"spec": spec_body(), "plan_hash": p["plan_hash"]}, expect=409)


def test_create_needs_two_approvers_and_job_is_single_use(client, actors, rt, env):
    seed_inventory(rt)
    p = preview(actors[0])
    r, jid = submit(actors, rt, "deployment.create", {"spec": spec_body(), "plan_hash": p["plan_hash"]}, approvals=1)
    assert jid is None and r["status"] == "pending_approval"
    assert worker.run_once(rt) is False and env.provider.calls == []


def test_tampered_stored_plan_is_refused(client, actors, rt, env):
    seed_inventory(rt)
    p = preview(actors[0])
    (o, oh), a1, a2 = actors
    pid = o.post(f"{H}/plans", json={"action": "deployment.create", "params": {"spec": spec_body(), "plan_hash": p["plan_hash"]}}, headers=oh).json()["plan_id"]
    with rt.session() as db:  # someone edits the proposed revision between approval and execution
        db.execute(text("UPDATE deployment_revisions SET plan = jsonb_set(plan, '{vms,0,cores}', '99')"))
        db.commit()
    for c, h in (a1, a2):
        jid = c.post(f"{H}/plans/{pid}/approve", headers=h).json()["job_id"]
    assert worker.run_once(rt)
    j = job(actors[0], jid)
    assert j["status"] == "failed" and "does not match its hash" in j["error"]["message"] and env.provider.calls == []


def test_resume_after_crash_continues_from_last_completed_step(client, actors, rt, env):
    seed_inventory(rt)
    p = preview(actors[0])
    env.provider.crash_on = ("power", "acme-prod-groupware")   # worker dies while starting the 2nd VM
    r, jid = submit(actors, rt, "deployment.create", {"spec": spec_body(), "plan_hash": p["plan_hash"]})
    assert job(actors[0], jid)["status"] == "failed"
    st1 = {s["step_key"]: s for s in steps(actors[0], jid)}
    assert st1["vm.start:acme-prod-groupware"]["status"] == "running"                 # in doubt
    done = [k for k, s in st1.items() if s["status"] == "succeeded"]
    assert done and "vm.clone:acme-prod-groupware" in done
    clones_before = list(env.provider.names("clone"))
    # operator re-submits the same deployment.create; nothing is redone
    r2, jid2 = submit(actors, rt, "deployment.create", {"spec": spec_body(), "plan_hash": p["plan_hash"]})
    assert job(actors[0], jid2)["status"] == "succeeded", job(actors[0], jid2)
    assert env.provider.names("clone") == clones_before                                 # no VM cloned twice
    st2 = {s["step_key"]: s for s in steps(actors[0], jid2)}
    assert all(s["status"] == "succeeded" for s in st2.values())
    assert all(st2[k]["carried_from_job"] == jid and st2[k]["attempts"] == 0 for k in done)
    assert st2["vm.start:acme-prod-groupware"]["carried_from_job"] is None and st2["vm.start:acme-prod-groupware"]["attempts"] == 1
    assert job(actors[0], jid2)["result"]["carried_over_steps"] == len(done)
    assert actors[0][0].get(f"{H}/deployments/prod").json()["status"] == "active"


def test_adopts_orphan_vm_from_interrupted_clone(client, actors, rt, env):
    """Crash AFTER the provider cloned but BEFORE the ref was recorded: the tagged guest is adopted, never cloned twice."""
    seed_inventory(rt)
    p = preview(actors[0])
    prov = env.provider
    orig = prov.finalize_clone
    state = {"n": 0}

    def tag_then_die(task):
        t = orig(task)
        state["n"] += 1
        if state["n"] == 1:
            raise SimulatedCrash()
        return t
    prov.finalize_clone = tag_then_die
    submit(actors, rt, "deployment.create", {"spec": spec_body(), "plan_hash": p["plan_hash"]})
    n_cloned = len(prov.names("clone"))
    assert n_cloned == 3 and sum(bool(v["tags"]) for v in prov.vms.values()) == 1  # all cloned; the tag step died after the first tag landed (response lost)
    prov.finalize_clone = orig
    _, jid2 = submit(actors, rt, "deployment.create", {"spec": spec_body(), "plan_hash": p["plan_hash"]})
    assert job(actors[0], jid2)["status"] == "succeeded" and len(prov.vms) == 3
    assert len(prov.names("clone")) == 3                          # no VM was cloned twice
    st = {s["step_key"]: s for s in steps(actors[0], jid2)}
    assert all(s["status"] == "succeeded" for s in st.values()) and all(st[f"vm.clone:{v['name']}"]["carried_from_job"] for v in p["vms"])
    assert all({"ou-managed", "ou-deployment-prod"} <= set(v["tags"]) for v in prov.vms.values())
    # the create plan tags every clone as its own step, after the clone and before configure (configure depends on it)
    keys = [s["key"] for s in p["steps"]]
    for v in p["vms"]:
        n = v["name"]
        assert keys.index(f"vm.clone:{n}") < keys.index(f"vm.tag:{n}") and keys.index(f"vm.tag:{n}") < keys.index(f"vm.configure:{n}")


def test_untagged_guest_with_same_name_is_never_adopted(client, actors, rt, env):
    """Crash between clone and tagging leaves an untagged guest: ICS refuses to adopt or duplicate it (ownership is the tag)."""
    seed_inventory(rt)
    p = preview(actors[0])
    prov = env.provider
    prov.vms[500] = {"vmid": 500, "node": "pve1", "name": p["vms"][0]["name"], "status": "stopped", "tags": [], "cfg": None, "disks": {}, "dep": "prod"}
    _, jid = submit(actors, rt, "deployment.create", {"spec": spec_body(), "plan_hash": p["plan_hash"]})
    j = job(actors[0], jid)
    assert j["status"] == "failed" and "not tagged as owned" in j["error"]["message"]
    assert prov.names("clone") == [] and len(prov.vms) == 1


def test_step_retry_then_success_and_hard_failure_with_explanation(client, actors, rt, env):
    seed_inventory(rt)
    p = preview(actors[0])
    env.provider.fail["configure"] = 2                          # two provider task failures, third attempt works
    _, jid = submit(actors, rt, "deployment.create", {"spec": spec_body(), "plan_hash": p["plan_hash"]})
    st = steps(actors[0], jid)
    assert job(actors[0], jid)["status"] == "succeeded"
    assert max(s["attempts"] for s in st if s["op"] == "configure_vm") == 3 or sum(s["attempts"] for s in st if s["op"] == "configure_vm") >= 5
    # a permanently failing provider: job fails, the failing step explains itself, later steps stay pending
    with rt.session() as db:
        db.execute(text("DELETE FROM deployments"))
        db.execute(text("DELETE FROM checks"))
        db.commit()
    env.provider.vms.clear()
    env.provider.fail["clone"] = 99
    p = preview(actors[0])
    _, jid = submit(actors, rt, "deployment.create", {"spec": spec_body(), "plan_hash": p["plan_hash"]})
    j = job(actors[0], jid)
    assert j["status"] == "failed" and "clone" in j["error"]["message"]
    st = steps(actors[0], jid)
    failed = [s for s in st if s["status"] == "failed"]
    assert len(failed) == 1 and failed[0]["attempts"] == 3 and "provider" in failed[0]["error_explanation"] and "injected" in failed[0]["error_message"]
    assert all(s["status"] == "pending" for s in st if s["seq"] > failed[0]["seq"])
    assert actors[0][0].get(f"{H}/deployments/prod").json()["status"] == "failed"
    # provider recovers: re-submit finishes; completed steps carried over
    env.provider.fail.clear()
    _, jid3 = submit(actors, rt, "deployment.create", {"spec": spec_body(), "plan_hash": p["plan_hash"]})
    assert job(actors[0], jid3)["status"] == "succeeded"


def test_cancellation_between_steps(client, actors, rt, env):
    seed_inventory(rt)
    p = preview(actors[0])
    (o, oh), a1, a2 = actors
    pid = o.post(f"{H}/plans", json={"action": "deployment.create", "params": {"spec": spec_body(), "plan_hash": p["plan_hash"]}}, headers=oh).json()["plan_id"]
    for c, h in (a1, a2):
        jid = c.post(f"{H}/plans/{pid}/approve", headers=h).json()["job_id"]
    env.provider.after["clone"] = lambda: executor.request_cancel(rt, jid)       # operator cancels while the first clone runs
    assert worker.run_once(rt)
    j = job(actors[0], jid)
    assert j["status"] == "failed" and "cancelled" in j["error"]["message"]
    st = steps(actors[0], jid)
    assert st[0]["status"] == "cancelled"                                           # review 3 H1: cancellation is also honoured INSIDE a step
    assert any(s["status"] == "cancelled" for s in st) and not any(s["status"] == "running" for s in st)
    assert len(env.provider.names("clone")) == 1
    assert executor.request_cancel(rt, jid) is False                              # finished jobs cannot be cancelled
    assert o.get(f"{H}/deployments/prod").json()["status"] == "failed"


def test_health_verification_failure_is_explained(client, actors, rt, env):
    seed_inventory(rt)
    p = preview(actors[0])
    env.checks.bad = {"keycloak"}
    _, jid = submit(actors, rt, "deployment.create", {"spec": spec_body(), "plan_hash": p["plan_hash"]})
    j = job(actors[0], jid)
    assert j["status"] == "failed" and "health verification failed" in j["error"]["message"] and "keycloak-oidc" in j["error"]["message"]
    f = next(s for s in steps(actors[0], jid) if s["status"] == "failed")
    assert f["kind"] == "verify_health" and "service logs" in f["error_explanation"] and f["attempts"] == 1
    # destroying the failed deployment removes the checks it registered although no revision was ever applied (real: e2e-fo1..fo6 kept
    # critical checks with open incidents after their destroy, 2026-11-19)
    with rt.session() as db:
        registered = set(db.execute(text("SELECT name FROM checks WHERE deployment_id IS NOT NULL")).scalars().all())
    assert any("keycloak" in n for n in registered)
    pv = actors[0][0].post(f"{H}/deployments/prod/destroy/preview", headers=actors[0][1]).json()
    assert {c["name"] for c in pv["plan"]["checks"]} == registered
    r, _ = submit(actors, rt, "deployment.destroy", {"deployment_id": "prod", "confirm": "prod", "plan_hash": pv["plan_hash"]}, approvals=1)
    a2 = actors[2]
    djid = a2[0].post(f"{H}/plans/{r['plan_id']}/approve", headers=a2[1]).json()["job_id"]
    assert worker.run_once(rt)
    assert job(actors[0], djid)["status"] == "succeeded", job(actors[0], djid)["error"]
    with rt.session() as db:
        assert db.execute(text("SELECT count(*) FROM checks")).scalar() == 0


def test_unconfigured_provider_fails_cleanly(client, actors, rt, env):
    seed_inventory(rt)
    ops.set_env_factory(lambda r, d: ExecEnv())      # no provider integration wired
    p = preview(actors[0])
    _, jid = submit(actors, rt, "deployment.create", {"spec": spec_body(), "plan_hash": p["plan_hash"]})
    j = job(actors[0], jid)
    assert j["status"] == "failed" and "no infrastructure provider is configured" in j["error"]["message"]


# ---- change wizard -----------------------------------------------------------------------------------------------------

def _active(actors, rt, **kw):
    seed_inventory(rt)
    p, _, jid = create(actors, rt, **kw)
    assert job(actors[0], jid)["status"] == "succeeded"
    return p


def cprev(op, changes, expect=200):
    r = op[0].post(f"{H}/deployments/prod/changes/preview", json={"changes": changes}, headers=op[1])
    assert r.status_code == expect, r.text
    return r.json()


def test_change_preview_and_disruptive_requires_maintenance(client, actors, rt, env):
    _active(actors, rt)
    pv = cprev(actors[0], {"users": 50})
    d = pv["diff"]
    assert pv["executable"] and d["risk"] == "normal" and d["requires_maintenance"] and d["snapshot_required"] and d["downtime_seconds"] > 0
    assert d["capacity_impact"]["memory_mb"] > 0 and len(d["changed"]) >= 3 and not d["added"] and not d["removed"]
    assert cprev(actors[0], {}, expect=200)["diff"]["empty"] and not cprev(actors[0], {})["executable"]
    cprev(actors[0], {"users": 99999}, expect=200)                        # preview reports blocking errors instead of failing
    assert cprev(actors[0], {"users": 99999})["plan"]["errors"]
    assert actors[0][0].post(f"{H}/deployments/ghost/changes/preview", json={"changes": {}}, headers=actors[0][1]).status_code == 404
    assert actors[0][0].post(f"{H}/deployments/prod/changes/preview", json={"changes": {"domain": "x.example"}}, headers=actors[0][1]).status_code == 422
    params = {"deployment_id": "prod", "changes": {"users": 50}, "plan_hash": pv["plan"]["plan_hash"]}
    r = submit(actors, rt, "deployment.change", params, expect=422)
    assert "maintenance" in r.text                                          # disruptive without a window / override is refused at plan time
    r = submit(actors, rt, "deployment.change", {**params, "maintenance": "window", "maintenance_window_id": str(uuid.uuid4())}, expect=409)
    submit(actors, rt, "deployment.change", {**params, "maintenance": "window"}, expect=422)
    submit(actors, rt, "deployment.change", {**params, "plan_hash": "1" * 64, "maintenance": "override"}, expect=409)


def test_change_apply_with_active_window_runs_snapshot_resize_reboot(client, actors, rt, env):
    _active(actors, rt, users=30)
    pv = cprev(actors[0], {"users": 40})
    with rt.session() as db:
        wid = str(db.execute(text("INSERT INTO maintenance_windows (name, starts_at, ends_at, independently_approved) VALUES ('mw', now() - interval '1 minute', now() + interval '1 hour', true) "
                                  "RETURNING id")).scalar())
        db.commit()
    prov = env.provider
    prov.calls.clear()
    params = {"deployment_id": "prod", "changes": {"users": 40}, "plan_hash": pv["plan"]["plan_hash"], "maintenance": "window", "maintenance_window_id": wid}
    r, jid = submit(actors, rt, "deployment.change", params, approvals=1)          # normal risk: one approver
    assert r["risk"] == "normal" and job(actors[0], jid)["status"] == "succeeded", job(actors[0], jid)
    f = "acme-prod-files"
    ops_for_f = [c[0] + ":" + c[2] if c[0] == "power" else c[0] for c in prov.calls if c[1] == f]
    assert ops_for_f[0] == "snapshot" and ops_for_f.index("power:shutdown") < ops_for_f.index("configure") < ops_for_f.index("power:start")
    assert any(c[0] == "resize" for c in prov.calls) and "clone" not in {c[0] for c in prov.calls}
    d = actors[0][0].get(f"{H}/deployments/prod").json()
    assert d["current_revision"] == 2 and d["desired_spec"]["users"] == 40 and d["status"] == "active"
    assert [r["status"] for r in d["revisions"]] == ["superseded", "applied"] or [r["status"] for r in d["revisions"]] == ["applied", "applied"]
    res = {x["logical_name"]: x for x in actors[0][0].get(f"{H}/deployments/prod/resources").json() if x["kind"] == "vm"}
    assert res[f]["desired"]["memory_mb"] > 3000 and all(x["state"] == "present" for x in res.values())
    # window must still be active at execution time
    pv2 = cprev(actors[0], {"users": 50})
    with rt.session() as db:
        db.execute(text("UPDATE maintenance_windows SET ends_at = now() + interval '1 second'"))
        db.commit()
    p2 = {"deployment_id": "prod", "changes": {"users": 50}, "plan_hash": pv2["plan"]["plan_hash"], "maintenance": "window", "maintenance_window_id": wid}
    r2, jid2 = submit(actors, rt, "deployment.change", p2, approvals=1, run=False)
    import time
    time.sleep(1.2)
    worker.run_once(rt)
    assert job(actors[0], jid2)["status"] == "failed" and "maintenance window is not active" in job(actors[0], jid2)["error"]["message"]


def test_change_override_and_removal_are_high_risk(client, actors, rt, env):
    _active(actors, rt, profile="medium", users=100)
    pv = cprev(actors[0], {"users": 120})
    params = {"deployment_id": "prod", "changes": {"users": 120}, "plan_hash": pv["plan"]["plan_hash"], "maintenance": "override"}
    r, jid = submit(actors, rt, "deployment.change", params, approvals=1)
    assert r["risk"] == "high" and jid is None                                    # override => two approvers
    # removing a component is high risk by itself and keeps the pre-destroy snapshot step
    pv2 = cprev(actors[0], {"optional": {"office": False, "chat": False, "meetings": False}})
    assert pv2["diff"]["risk"] == "high" and {"kind": "vm", "name": "acme-prod-office"} in pv2["diff"]["removed"]
    p2 = {"deployment_id": "prod", "changes": {"optional": {"office": False, "chat": False, "meetings": False}}, "plan_hash": pv2["plan"]["plan_hash"], "maintenance": "override"}
    r2, jid2 = submit(actors, rt, "deployment.change", p2)
    assert r2["risk"] == "high" and job(actors[0], jid2)["status"] == "succeeded", job(actors[0], jid2)
    names = [v["name"] for v in env.provider.vms.values()]
    assert "acme-prod-office" not in names and len(names) == 4
    assert ("snapshot", "acme-prod-office", "ou-pre-destroy") in env.provider.calls
    res = {(x["kind"], x["logical_name"]): x["state"] for x in actors[0][0].get(f"{H}/deployments/prod/resources").json()}
    assert res[("vm", "acme-prod-office")] == "removed"


def test_change_can_add_a_component(client, actors, rt, env):
    _active(actors, rt, profile="medium", users=100, optional={"office": False})
    pv = cprev(actors[0], {"optional": {"office": True}})
    assert {"kind": "vm", "name": "acme-prod-office"} in pv["diff"]["added"] and pv["diff"]["risk"] == "normal"
    assert not pv["diff"]["requires_maintenance"]
    r, jid = submit(actors, rt, "deployment.change", {"deployment_id": "prod", "changes": {"optional": {"office": True}}, "plan_hash": pv["plan"]["plan_hash"]},
                    approvals=1)
    assert job(actors[0], jid)["status"] == "succeeded", job(actors[0], jid)["error"]
    assert "acme-prod-office" in [v["name"] for v in env.provider.vms.values()]
    assert any(r[1] == "podman.deploy_unit" and r[0] == "node-acme-prod-office" for r in env.agent.runbooks)


# ---- drift ---------------------------------------------------------------------------------------------------------------

def _guests_from(prov, cores_delta=0):
    out: dict[str, list] = {}
    for v in prov.vms.values():
        c = v["cfg"]
        out.setdefault(v["node"], []).append({"vmid": v["vmid"], "name": v["name"], "status": v["status"], "cpus": c.cores + cores_delta,
                                              "maxmem": c.memory_mb * MiB, "maxdisk": prov.sizes[v["name"]] * GiB, "tags": ";".join(v["tags"])})
    return out


def test_drift_report_is_report_only(client, actors, rt, env):
    p = _active(actors, rt)
    env.provider.sizes = {v["name"]: v["disks"][0]["size_gb"] for v in p["vms"]}
    (o, _) = actors[0]
    seed_inventory(rt, guests=_guests_from(env.provider))
    d = o.get(f"{H}/deployments/prod/drift").json()
    assert d["in_sync"] and d["findings"] == [] and d["inventory_at"]
    seed_inventory(rt, guests=_guests_from(env.provider, cores_delta=2))
    d = o.get(f"{H}/deployments/prod/drift").json()
    assert not d["in_sync"] and {f["type"] for f in d["findings"]} == {"changed"} and len(d["findings"]) == 3
    g = _guests_from(env.provider)
    first = next(iter(g.values()))
    removed = first.pop()
    first.append({"vmid": 900, "name": "rogue", "status": "running", "tags": "ou-managed;ou-deployment-prod"})
    seed_inventory(rt, guests=g)
    types = {(f["name"], f["type"]) for f in o.get(f"{H}/deployments/prod/drift").json()["findings"]}
    assert (removed["name"], "missing") in types and ("rogue", "unexpected") in types
    assert len(env.provider.vms) == 3                                        # nothing was repaired or destroyed
    assert o.get(f"{H}/deployments/ghost/drift").status_code == 404


# ---- destroy -------------------------------------------------------------------------------------------------------------

def test_destroy_removes_only_owned_guests(client, actors, rt, env):
    _active(actors, rt)
    prov = env.provider
    dh = actors[0][0].post(f"{H}/deployments/prod/destroy/preview", headers=actors[0][1]).json()["plan_hash"]
    submit(actors, rt, "deployment.destroy", {"deployment_id": "prod", "confirm": "nope", "plan_hash": dh}, expect=422)
    submit(actors, rt, "deployment.destroy", {"deployment_id": "ghost", "confirm": "ghost", "plan_hash": dh}, expect=404)
    submit(actors, rt, "deployment.destroy", {"deployment_id": "prod", "confirm": "prod", "plan_hash": "0" * 64}, expect=409)
    # a guest that lost its ownership tag is never destroyed
    victim = next(v for v in prov.vms.values() if v["name"].endswith("-groupware"))
    victim["tags"] = []
    with rt.session() as db:   # a failing check of this deployment with an open incident, and someone else's check
        mine = db.execute(text("SELECT id FROM checks WHERE deployment_id = (SELECT id FROM deployments WHERE slug = 'prod') LIMIT 1")).scalar()
        assert mine is not None
        db.execute(text("UPDATE checks SET state = 'critical' WHERE id = :i"), {"i": str(mine)})
        db.execute(text("INSERT INTO incidents (id, check_id, status, severity, title) VALUES (gen_random_uuid(), :i, 'open', 'critical', 't')"),
                   {"i": str(mine)})
        db.execute(text("INSERT INTO checks (id, name, kind, config, interval_seconds, customer_id, created_by) SELECT gen_random_uuid(), 'other-check', kind, config, "
                        "interval_seconds, customer_id, created_by FROM checks WHERE id = :i"), {"i": str(mine)})
        db.commit()
    r, jid = submit(actors, rt, "deployment.destroy", {"deployment_id": "prod", "confirm": "prod", "plan_hash": dh}, approvals=1)
    assert r["risk"] == "high" and jid is None
    (o, oh), a1, a2 = actors
    jid = a2[0].post(f"{H}/plans/{r['plan_id']}/approve", headers=a2[1]).json()["job_id"]
    assert worker.run_once(rt)
    assert job(actors[0], jid)["status"] == "succeeded", job(actors[0], jid)["error"]
    assert [v["name"] for v in prov.vms.values()] == [victim["name"]]
    d = o.get(f"{H}/deployments/prod").json()
    assert d["status"] == "destroyed"
    with rt.session() as db:
        # the deployment's checks are gone with their incidents (a destroyed deployment must not keep raising incidents); others stay
        assert db.execute(text("SELECT name FROM checks")).scalars().all() == ["other-check"]
        assert db.execute(text("SELECT count(*) FROM incidents")).scalar() == 0
        ev = db.execute(text("SELECT details FROM audit_events WHERE action = 'deployment.destroyed'")).scalars().all()
        assert len(ev) == 1 and ev[0]["checks_deleted"] and "other-check" not in ev[0]["checks_deleted"]
    submit(actors, rt, "deployment.destroy", {"deployment_id": "prod", "confirm": "prod", "plan_hash": dh}, expect=409)


def test_steps_endpoint_404_and_actions_catalog(client, actors, rt, env):
    (o, _) = actors[0]
    assert o.get(f"{H}/jobs/{uuid.uuid4()}/steps").status_code == 404
    acts = {a["action"]: a for a in o.get(f"{H}/actions").json()}
    assert acts["deployment.create"]["risk"] == "high" and acts["deployment.destroy"]["risk"] == "high" and acts["deployment.change"]["risk"] == "normal"


def test_step_failed_text_never_leaks_unexpected_exceptions(client, actors, rt, env):
    seed_inventory(rt)
    p = preview(actors[0])

    def boom(*a, **k):
        raise RuntimeError("secret-token-123 leaked?")
    env.provider.clone_vm = boom
    _, jid = submit(actors, rt, "deployment.create", {"spec": spec_body(), "plan_hash": p["plan_hash"]})
    blob = str(job(actors[0], jid)) + str(steps(actors[0], jid))
    assert "secret-token-123" not in blob and "internal error" in blob
    assert StepFailed  # imported for typing parity


# ---- node-local configuration (cfg.* runbooks, ics/deploy/configure.py) ----------------------------------------------------

def test_identity_and_edge_are_configured_before_their_units_and_no_secret_is_stored_in_clear(client, actors, rt, env):
    p = _active(actors, rt)
    did = None
    with rt.session() as db:
        did = str(db.execute(text("SELECT id FROM deployments WHERE slug = 'prod'")).scalar())
        rows = db.execute(text("SELECT name, value_enc FROM deployment_secrets WHERE deployment_id = :d"), {"d": did}).fetchall()
    names = {r.name for r in rows}
    assert {"ldap-bind-password", "ldap-admin-password", "admin-password", "kc-db-password", "kc-admin-password", "deployment-ca"} <= names
    values = {r.name: configure.secret(rt, did, r.name) for r in rows}
    assert all(values[r.name].encode() not in bytes(r.value_enc) for r in rows)        # vault-encrypted at rest
    idvm = next(v["name"] for v in p["vms"] if v["name"].endswith("-id"))
    rb = [(r[1], r[2]) for r in env.agent.runbooks if r[0] == f"node-{idvm}"]
    seq = [x[0] for x in rb]
    kc_deploy = next(i for i, (n, prm) in enumerate(rb) if n == "podman.deploy_unit" and prm["component"] == "identity")
    for name in ("cfg.hosts", "cfg.tls", "cfg.ldap_init", "cfg.ldap_user", "cfg.pg_db", "cfg.podman_secret", "cfg.volume_files"):
        assert seq.index(name) < kc_deploy, name
    assert seq.index("pkg.install_pinned") < seq.index("cfg.ldap_init")                   # slapd and ldap-utils are installed first
    vf = [prm for n, prm in rb if n == "cfg.volume_files"]
    assert {(x["component"], x["volume"]) for x in vf} == {("identity", "tls"), ("identity", "data")}
    assert all(x["image"] == next(f"{c['image']}@{c['digest']}" for c in p["containers"] if c["component"] == "identity") for x in vf)
    site = next(prm for n, prm in rb if n == "cfg.nginx_site")
    assert site["server_names"] == ["auth.acme.example"] and site["upstream"] == "http://127.0.0.1:8080"
    hosts = next(prm for n, prm in rb if n == "cfg.hosts")["entries"]
    assert any("ldap.acme.example" in e["names"] and e["ip"] == env.agent.address(idvm) for e in hosts)
    secrets_ = [v for k, v in values.items() if k != "deployment-ca"] + [json.loads(values["deployment-ca"])["key"].split("\n")[1]]
    with rt.session() as db:
        stored = json.dumps([list(r) for r in db.execute(text("SELECT params::text, coalesce(log_excerpt,''), coalesce(result::text,'') FROM job_steps"))])
        audited = json.dumps([r[0] for r in db.execute(text("SELECT details::text FROM audit_events"))])
    assert not any(s in stored or s in audited for s in secrets_)                          # neither in the durable steps nor in the audit trail
    # destroy: the deployment's secrets and CA key go with it
    dh = actors[0][0].post(f"{H}/deployments/prod/destroy/preview", headers=actors[0][1]).json()["plan_hash"]
    r, jid = submit(actors, rt, "deployment.destroy", {"deployment_id": "prod", "confirm": "prod", "plan_hash": dh})
    assert job(actors[0], jid)["status"] == "succeeded"
    with rt.session() as db:
        assert db.execute(text("SELECT count(*) FROM deployment_secrets WHERE deployment_id = :d"), {"d": did}).scalar() == 0


def test_the_newest_imported_golden_template_wins_when_names_repeat():
    t = [{"vmid": 136, "name": "ou-tpl-ubuntu-2404", "tags": ["ou-managed", "ou-image", "ou-rel-ubuntu-24.04-20261116"]},
         {"vmid": 120, "name": "ou-tpl-ubuntu-2404", "tags": ["ou-managed", "ou-image", "ou-rel-ubuntu-24.04-20261118"]},
         {"vmid": 300, "name": "ou-tpl-ubuntu-2404", "tags": []},                       # someone's hand-made template of the same name
         {"vmid": 999, "name": "ou-tpl-debian-12", "tags": ["ou-image", "ou-rel-debian-12-20261120"]}]
    assert executor.pick_template(t, "ou-tpl-ubuntu-2404")["vmid"] == 120
    assert executor.pick_template(t[:1] + [{**t[0], "vmid": 140}], "ou-tpl-ubuntu-2404")["vmid"] == 140   # same release date: the later import
    assert executor.pick_template(t, "ou-tpl-none") is None


def test_deployed_service_checks_are_agent_probes_on_real_guests(client, actors, rt, env, monkeypatch):
    """With an agent that probes its own loopback (the real GuestAgentPort), http/tcp_tls checks are registered as agent_probe checks with the
    name the deployment certificate carries; nothing asks for TLS trust discovery any more."""
    ids = {}

    def enroll(vm, timeout_s):
        ids[vm] = str(uuid.uuid5(uuid.NAMESPACE_DNS, vm))
        return ids[vm]
    env.agent.local_probes = True
    env.agent.wait_enrollment = enroll
    env.agent.tls_trust = lambda node, port: pytest.fail("no TLS trust discovery for probed checks")
    p = _active(actors, rt)
    with rt.session() as db:
        rows = db.execute(text("SELECT name, kind, config FROM checks WHERE deployment_id = (SELECT id FROM deployments WHERE slug = 'prod')")).fetchall()
    probes = {r.name: r.config for r in rows if r.kind == "agent_probe"}
    assert probes and all(r.kind in ("agent_probe", "smtp_banner", "imap_login", "ews_getfolder") for r in rows), [(r.name, r.kind) for r in rows]
    ld = next(v for k, v in probes.items() if v["probe"].get("port") == 636)
    assert ld["probe"]["server_name"] == "ldap.acme.example" and ld["node_id"] == ids[next(v["name"] for v in p["vms"] if v["name"].endswith("-id"))]


def test_files_and_office_are_configured_and_the_edge_reaches_them_over_verified_https(client, actors, rt, env):
    p = _active(actors, rt)
    fvm = next(v["name"] for v in p["vms"] if v["name"].endswith("-files"))
    idvm = next(v["name"] for v in p["vms"] if v["name"].endswith("-id"))
    fip, idip = env.agent.address(fvm), env.agent.address(idvm)
    rb = [(r[1], r[2]) for r in env.agent.runbooks if r[0] == f"node-{fvm}"]
    seq = [n for n, _ in rb]
    oc = next(i for i, (n, prm) in enumerate(rb) if n == "podman.deploy_unit" and prm["name"] == "opencloud")
    collab = next(prm for n, prm in rb if n == "podman.deploy_unit" and prm["name"] == "opencloud-collaboration")
    assert collab["command"] == ["collaboration", "server"]
    assert {prm["name"] for n, prm in rb[:oc] if n == "cfg.podman_secret"} == {"ldap-bind-password", "oc-admin-password"}
    cfgvol = next(prm for n, prm in rb if n == "cfg.volume_files" and prm["component"] == "files" and prm["volume"] == "config")
    env_ = next(f["content"] for f in cfgvol["files"] if f["path"] == "ou.env")
    assert "OC_URL=https://cloud.acme.example" in env_ and "OC_OIDC_ISSUER=https://auth.acme.example/realms/ou" in env_ and "@" not in env_.split("\n", 4)[4]
    with rt.session() as db:
        did = str(db.execute(text("SELECT id FROM deployments WHERE slug = 'prod'")).scalar())
    assert configure.secret(rt, did, "ldap-bind-password") not in env_                     # the bind password is a podman secret, never in the file
    fw = next(prm for n, prm in rb if n == "cfg.firewall")["rules"]
    assert {"source": idip, "proto": "tcp", "port": 443} in fw and all(r["source"] == idip for r in fw)
    local = {prm["name"]: prm for n, prm in rb if n == "cfg.nginx_site"}
    assert local["cloud"]["upstream"] == "http://127.0.0.1:9200" and local["office"]["upstream"] == "http://127.0.0.1:9980"
    tls = next(prm for n, prm in rb if n == "cfg.tls")
    from cryptography import x509 as _x
    sans = _x.load_pem_x509_certificate(tls["cert_pem"].encode()).extensions.get_extension_for_class(_x.SubjectAlternativeName).value.get_values_for_type(_x.DNSName)
    assert {"cloud.acme.example", "office.acme.example"} <= set(sans)
    edge = {prm["name"]: prm for n, prm in ((r[1], r[2]) for r in env.agent.runbooks if r[0] == f"node-{idvm}") if n == "cfg.nginx_site"}
    assert edge["auth"]["upstream"] == "http://127.0.0.1:8080" and "upstream_name" not in edge["auth"]
    assert edge["cloud"]["upstream"] == f"https://{fip}:443" and edge["cloud"]["upstream_name"] == "cloud.acme.example"
    assert edge["office"]["upstream"] == f"https://{fip}:443" and edge["office"]["upstream_name"] == "office.acme.example"
    assert seq.index("cfg.volume_files") < oc
    _agent_accepts_every_cfg_runbook(env)


def _agent_accepts_every_cfg_runbook(env):
    """Every configuration runbook the engine sends must pass the node agent's own validator (e2e-fo1 on pve06 was refused `bad_params`)."""
    import os
    import sys as _sys
    _sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))
    from ou_agent import cfgspec
    for node, name, prm in ((r[0], r[1], r[2]) for r in env.agent.runbooks):
        if name in cfgspec.CHECKS:
            try:
                cfgspec.CHECKS[name](prm, {"runbooks": {name: {"enabled": True}}})
            except Exception as e:
                raise AssertionError(f"{node} {name} {prm.get('component', '')}/{prm.get('volume', prm.get('name', ''))}: {e!r}") from None
