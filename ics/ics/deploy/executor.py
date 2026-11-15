"""Step executor (ADR-0009 section 4, Execution).

An approved plan becomes an ordered list of idempotent steps persisted in `job_steps` (status, progress, attempts, log excerpt,
error + operator explanation). The executor:
- resumes after a crash from the last completed step (a step left 'running' is in doubt and is simply re-run: every handler is
  idempotent), and carries over steps already succeeded by an earlier job of the same deployment revision (re-submitting a failed
  deployment.create continues instead of starting over);
- honours cancellation BETWEEN steps (`jobs.cancel_requested`), never mid-step;
- is the ONLY caller of providers/agents: handlers receive them through ExecEnv.

Every step uses its own short transaction, so progress is durable immediately and never blocks the audit chain."""
import json
import logging
import time
from dataclasses import dataclass, field

from sqlalchemy import text

from ..providers.base import DiskSpec, NicSpec, TaskRef, VmCloneSpec, VmConfigSpec, VmRef
from . import state
from .ports import Cancelled, DeployError, ExecEnv, StepFailed

log = logging.getLogger("ics.deploy.executor")
LOG_MAX = 2000


# ---- persistence ---------------------------------------------------------------------------------------------

def seed_steps(rt, job_id: str, deployment_id: str, revision: int, steps: list[dict]) -> None:
    """Create the job's step rows (idempotent). Steps already succeeded in an earlier job of the same revision are carried over."""
    with rt.session() as db:
        for s in steps:
            if db.execute(text("SELECT 1 FROM job_steps WHERE job_id = :j AND step_key = :k"), {"j": job_id, "k": s["key"]}).first():
                continue
            prev = db.execute(text("SELECT result, job_id FROM job_steps WHERE deployment_id = :d AND revision = :r AND step_key = :k "
                                   "AND status = 'succeeded' AND job_id <> :j ORDER BY id DESC LIMIT 1"),
                              {"d": deployment_id, "r": revision, "k": s["key"], "j": job_id}).first()
            db.execute(text(
                "INSERT INTO job_steps (job_id, deployment_id, revision, seq, step_key, kind, target, op, params, depends_on, disruptive, est_seconds, "
                "status, progress, result, carried_from_job, log_excerpt, finished_at) VALUES "
                "(:j, :d, :r, :q, :k, :kd, :t, :o, CAST(:p AS jsonb), CAST(:dp AS jsonb), :dis, :est, :st, :pg, CAST(:res AS jsonb), :cf, :lg, "
                "CASE WHEN :st = 'succeeded' THEN now() END)"),
                {"j": job_id, "d": deployment_id, "r": revision, "q": s["seq"], "k": s["key"], "kd": s["kind"], "t": s["target"], "o": s["op"],
                 "p": json.dumps(s["params"], sort_keys=True), "dp": json.dumps(s["depends_on"]), "dis": s["disruptive"], "est": s["est_seconds"],
                 "st": "succeeded" if prev else "pending", "pg": 100 if prev else 0,
                 "res": json.dumps(prev.result) if prev and prev.result is not None else None,
                 "cf": str(prev.job_id) if prev else None, "lg": "carried over from an earlier job of this revision" if prev else ""})
        db.commit()


def _update(rt, row_id: int, **f) -> None:
    sets = ", ".join(f"{k} = CAST(:{k} AS jsonb)" if k == "result" else f"{k} = :{k}" for k in f)
    with rt.session() as db:
        db.execute(text(f"UPDATE job_steps SET {sets} WHERE id = :_id"), {**f, "_id": row_id})  # noqa: S608 (column names are constants here)
        db.commit()


def request_cancel(rt, job_id: str) -> bool:
    """Ask a running deployment job to stop before its next step. (Exposed to a typed action later; no unauthenticated path calls this.)"""
    with rt.session() as db:
        n = db.execute(text("UPDATE jobs SET cancel_requested = true WHERE id = :j AND status IN ('queued','running')"), {"j": job_id}).rowcount
        db.commit()
    return n == 1


def _cancel_requested(rt, job_id: str) -> bool:
    with rt.session() as db:
        return bool(db.execute(text("SELECT cancel_requested FROM jobs WHERE id = :j"), {"j": job_id}).scalar())


# ---- step context & handlers -----------------------------------------------------------------------------------

@dataclass
class StepCtx:
    rt: object
    env: ExecEnv
    job_id: str
    deployment_id: str
    slug: str
    plan: dict
    created_by: str
    row_id: int
    step: dict
    outputs: dict
    buf: list[str] = field(default_factory=list)

    def log(self, msg: str, progress: int | None = None) -> None:
        self.buf.append(msg)
        text_ = "\n".join(self.buf)[-LOG_MAX:]
        f = {"log_excerpt": text_}
        if progress is not None:
            f["progress"] = max(0, min(99, progress))
        _update(self.rt, self.row_id, **f)

    def resource(self, kind: str, name: str, **kw) -> None:
        with self.rt.session() as db:
            state.set_resource(db, self.deployment_id, kind, name, **kw)
            db.commit()

    def vm_ref(self, vm: str) -> VmRef:
        with self.rt.session() as db:
            ref = state.provider_ref(db, self.deployment_id, vm)
        if not ref or ref.get("vmid") is None:
            raise StepFailed(f"VM {vm} has no provider reference yet", "The VM was never created; re-run the deployment.", retryable=False)
        return VmRef(ref["node"], int(ref["vmid"]))


def _poll(ctx: StepCtx, task: TaskRef, what: str) -> TaskRef:
    env = ctx.env
    t0 = env.clock()
    while True:
        st = env.provider.task_status(task)
        if st.state == "ok":
            return task
        if st.state == "failed":
            raise StepFailed(f"{what} failed: {st.message[:200]}", "The infrastructure provider reported the task as failed.", retryable=True)
        if env.clock() - t0 > env.task_timeout:
            raise StepFailed(f"{what} did not finish within {int(env.task_timeout)} s", "The provider task is still running or stuck; "
                             "check the task on the infrastructure and re-run.", retryable=True)
        ctx.log(f"{what}: {st.state} {st.progress}%", progress=st.progress)
        env.sleep(env.poll_interval)


def _find_guest(ctx: StepCtx, name: str):
    d = ctx.env.provider.discover()
    tag = f"ou-deployment-{ctx.slug}"
    return next((g for g in d.guests if g.name == name and tag in g.tags and "ou-managed" in g.tags), None)


def h_provider_task(ctx: StepCtx) -> dict:
    s, p, vm = ctx.step, ctx.step["params"], ctx.step["target"]
    prov, op = ctx.env.provider, s["op"]
    if op == "clone_vm":
        with ctx.rt.session() as db:
            ref = state.provider_ref(db, ctx.deployment_id, vm)
        if ref and ref.get("vmid") is not None:
            ctx.log(f"VM {vm} already exists (vmid {ref['vmid']}); not cloning again")
            return {"node": ref["node"], "vmid": ref["vmid"], "reused": True}
        g = _find_guest(ctx, vm)
        if g is not None:  # a previous attempt cloned but crashed before recording it: adopt (tag-verified), never clone twice
            ctx.resource("vm", vm, state="creating", provider_ref={"node": g.node, "vmid": g.vmid})
            ctx.log(f"adopted existing tagged guest vmid {g.vmid} left by an interrupted attempt")
            return {"node": g.node, "vmid": g.vmid, "adopted": True}
        spec = VmCloneSpec(name=vm, template=p["template"], node=p["node"], pool=p["pool"], storage=p["storage"], tags=list(p["tags"]))
        task = _poll(ctx, prov.clone_vm(spec), f"clone {vm}")
        vmid = task.vmid
        if vmid is None:
            g = _find_guest(ctx, vm)
            vmid = g.vmid if g else None
        if vmid is None:
            raise StepFailed(f"clone of {vm} finished but the new VM id is unknown", "The provider did not report the new VM.", retryable=True)
        ctx.resource("vm", vm, state="creating", provider_ref={"node": task.node or p["node"], "vmid": vmid})
        return {"node": task.node or p["node"], "vmid": vmid}
    ref = ctx.vm_ref(vm)
    if op == "configure_vm":
        spec = VmConfigSpec(cores=p["cores"], memory_mb=p["memory_mb"], disks=[DiskSpec(d["name"], d["size_gb"], d["storage"]) for d in p["disks"]],
                            nics=[NicSpec(n["bridge"], n.get("vlan")) for n in p["nics"]], cloud_init=dict(p.get("cloud_init", {})))
        _poll(ctx, prov.configure_vm(ref, spec), f"configure {vm}")
        return {"configured": True}
    if op == "power":
        want = p["op"]
        g = _find_guest(ctx, vm)
        if g is not None and ((want == "start" and g.status == "running") or (want in ("stop", "shutdown") and g.status == "stopped")):
            ctx.log(f"{vm} is already {g.status}")
        else:
            _poll(ctx, prov.power(ref, want), f"{want} {vm}")
        if want == "start":
            ctx.resource("vm", vm, state="present")
        return {"power": want}
    if op == "snapshot":
        _poll(ctx, prov.snapshot(ref, p["name"]), f"snapshot {vm}")
        return {"snapshot": p["name"]}
    if op == "resize_disk":
        _poll(ctx, prov.resize_disk(ref, p["disk"], p["new_size_gb"]), f"resize {vm}/{p['disk']}")
        return {"disk": p["disk"], "size_gb": p["new_size_gb"]}
    if op == "destroy_vm":
        try:
            ref = ctx.vm_ref(vm)
        except StepFailed:
            return {"destroyed": True, "note": "no provider reference; nothing to destroy"}
        if _find_guest(ctx, vm) is None:
            ctx.log("guest already gone")
        else:  # the tag check above is the ownership guard: only ou-managed + ou-deployment-<id> guests are ever destroyed
            _poll(ctx, prov.destroy_vm(ref), f"destroy {vm}")
        ctx.resource("vm", vm, state="removed")
        return {"destroyed": True}
    raise StepFailed(f"unknown provider operation {op!r}", "", retryable=False)


def h_wait_enroll(ctx: StepCtx) -> dict:
    vm = ctx.step["target"]
    node_id = ctx.env.agent.wait_enrollment(vm, int(ctx.step["params"].get("timeout_seconds", 600)))
    ctx.log(f"agent enrolled as node {node_id}")
    return {"node_id": node_id}


def _node_for(ctx: StepCtx, vm: str) -> str:
    r = ctx.outputs.get(f"agent.enroll:{vm}")
    if not r:
        with ctx.rt.session() as db:
            r = db.execute(text("SELECT result FROM job_steps WHERE deployment_id = :d AND step_key = :k AND status = 'succeeded' "
                                "ORDER BY id DESC LIMIT 1"), {"d": ctx.deployment_id, "k": f"agent.enroll:{vm}"}).scalar()
    if not r:
        raise StepFailed(f"no enrolled agent for {vm}", "The node agent has not enrolled; re-run the deployment.", retryable=False)
    return r["node_id"]


def h_agent_runbook(ctx: StepCtx) -> dict:
    vm, p = ctx.step["target"], ctx.step["params"]
    node = _node_for(ctx, vm)
    results = []
    rbs = p["runbooks"]
    for i, rb in enumerate(rbs):
        ctx.log(f"runbook {rb['runbook']}", progress=int(100 * i / max(1, len(rbs))))
        results.append({"runbook": rb["runbook"], "result": ctx.env.agent.run_runbook(node, rb["runbook"], rb["params"])})
    comp = p["component"]
    plan_c = [c for c in ctx.plan["containers"] if c["vm"] == vm and c["component"] == comp]
    plan_s = [x for x in ctx.plan["services"] if x["vm"] == vm and x["component"] == comp]
    for c in plan_c:
        ctx.resource("container", c["name"], state="present", actual={"version": c["version"], "digest": c["digest"]})
    for x in plan_s:
        ctx.resource("service", x["name"], state="present", actual={"version": x["version"], "package": x["package"]})
    return {"component": comp, "runbooks": [r["runbook"] for r in results]}


def h_register_checks(ctx: StepCtx) -> dict:
    vm, comp = ctx.step["target"], ctx.step["params"]["component"]
    node = _node_for(ctx, vm)
    host = ctx.env.agent.address(vm)
    names = []
    for c in ctx.plan["checks"]:
        if c["vm"] != vm or c["component"] != comp:
            continue
        trust = None
        if c["kind"] in ("http", "tcp_tls"):
            trust = ctx.env.agent.tls_trust(node, c["port"])
        ctx.env.checks.register(ctx.rt, c, host, trust, ctx.created_by)
        ctx.resource("check", c["name"], state="present")
        names.append(c["name"])
    ctx.log(f"registered {len(names)} check(s)")
    return {"checks": names}


def h_verify_health(ctx: StepCtx) -> dict:
    vm, p = ctx.step["target"], ctx.step["params"]
    names = [c["name"] for c in ctx.plan["checks"] if c["vm"] == vm and c["component"] == p["component"]]
    env = ctx.env
    t0 = env.clock()
    while True:
        res = env.checks.verify(ctx.rt, names)
        bad = [(n, m) for n, ok, m in res if not ok]
        if not bad:
            for n, ok, m in res:
                ctx.resource("check", n, actual={"state": "ok", "message": m})
            return {"verified": names}
        if env.clock() - t0 >= int(p.get("timeout_seconds", 300)):
            raise StepFailed("health verification failed: " + "; ".join(f"{n}: {m}" for n, m in bad)[:400],
                             "The service did not become healthy in time. Check the service logs on the VM, then re-run the deployment; "
                             "completed steps are kept.", retryable=False)
        ctx.log(f"waiting for {len(bad)} check(s): " + ", ".join(n for n, _ in bad))
        env.sleep(env.poll_interval)


HANDLERS = {"provider_task": h_provider_task, "wait_agent_enrollment": h_wait_enroll, "agent_runbook": h_agent_runbook,
            "register_checks": h_register_checks, "verify_health": h_verify_health}


# ---- the loop --------------------------------------------------------------------------------------------------

def run_steps(rt, *, job_id: str, deployment_id: str, slug: str, revision: int, plan: dict, steps: list[dict], env: ExecEnv,
              created_by: str) -> dict:
    """Run `steps` (already ordered) for a job. Raises StepFailed on the first failed step, Cancelled when cancelled between steps.
    Returns {'steps': n, 'carried': k}."""
    seed_steps(rt, job_id, deployment_id, revision, steps)
    with rt.session() as db:
        # a step left 'running' by a crashed worker is in doubt: reset it to pending (handlers are idempotent)
        db.execute(text("UPDATE job_steps SET status = 'pending', progress = 0 WHERE job_id = :j AND status = 'running'"), {"j": job_id})
        rows = db.execute(text("SELECT id, seq, step_key, kind, target, op, params, depends_on, status, result, attempts, carried_from_job "
                               "FROM job_steps WHERE job_id = :j ORDER BY seq"), {"j": job_id}).all()
        db.commit()
    outputs = {r.step_key: r.result for r in rows if r.status == "succeeded"}
    for r in rows:
        if r.status == "succeeded":
            continue
        if _cancel_requested(rt, job_id):
            with rt.session() as db:
                db.execute(text("UPDATE job_steps SET status = 'cancelled', finished_at = now() WHERE job_id = :j AND status IN ('pending','running')"),
                           {"j": job_id})
                state.add_event(db, deployment_id, "cancelled", f"job cancelled before step {r.step_key}", job_id)
                db.commit()
            raise Cancelled(f"cancelled by operator before step {r.step_key}; completed steps are kept and the deployment can be resumed")
        missing = [d for d in r.depends_on if d not in outputs]
        if missing:
            raise StepFailed(f"step {r.step_key} cannot run: unfinished dependencies {missing}", "", retryable=False)
        step = {"key": r.step_key, "kind": r.kind, "target": r.target, "op": r.op, "params": r.params}
        ctx = StepCtx(rt, env, job_id, deployment_id, slug, plan, created_by, r.id, step, outputs)
        attempts = r.attempts
        while True:
            attempts += 1
            _update(rt, r.id, status="running", attempts=attempts, started_at=_now(), error_message=None, error_explanation=None)
            try:
                res = HANDLERS[r.kind](ctx)
            except StepFailed as e:
                if e.retryable and attempts - r.attempts < env.max_attempts:
                    ctx.log(f"attempt {attempts} failed: {e.message}; retrying")
                    env.sleep(env.retry_delay * (attempts - r.attempts))
                    continue
                _fail(rt, r.id, e.message, e.explanation, deployment_id, job_id, r.step_key)
                raise
            except DeployError as e:
                _fail(rt, r.id, str(e)[:300], "", deployment_id, job_id, r.step_key)
                raise StepFailed(str(e)) from e
            except Exception as e:  # noqa: BLE001  never leak arbitrary exception text (may embed parameters)
                log.exception("step %s crashed with %s", r.step_key, type(e).__name__)
                _fail(rt, r.id, "internal error; see the server log", "An unexpected error occurred in the ICS.", deployment_id, job_id, r.step_key)
                raise StepFailed("internal error in step " + r.step_key) from None
            _update(rt, r.id, status="succeeded", progress=100, result=json.dumps(res or {}, sort_keys=True), finished_at=_now())
            outputs[r.step_key] = res or {}
            break
    return {"steps": len(rows), "carried": sum(1 for r in rows if r.carried_from_job)}


def _now():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc)


def _fail(rt, row_id, message, explanation, deployment_id, job_id, key) -> None:
    _update(rt, row_id, status="failed", error_message=message[:500], error_explanation=explanation[:500], finished_at=_now())
    with rt.session() as db:
        state.add_event(db, deployment_id, "step_failed", f"{key}: {message}", job_id)
        db.commit()


__all__ = ["run_steps", "seed_steps", "request_cancel", "StepFailed", "Cancelled", "time"]
