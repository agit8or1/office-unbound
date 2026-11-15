"""Step executor (ADR-0009 section 4, Execution).

An approved plan becomes an ordered list of idempotent steps persisted in `job_steps` (status, progress, attempts, log excerpt,
error + operator explanation). The executor:
- resumes after a crash from the last completed step (a step left 'running' is in doubt and is simply re-run: every handler is
  idempotent), and carries over steps already succeeded by an earlier job of the same deployment revision (re-submitting a failed
  deployment.create continues instead of starting over);
- honours cancellation between steps AND inside long steps (lease.check() before every provider/agent call and in every poll loop);
- is the ONLY caller of providers/agents: handlers receive them through ExecEnv.

Every step uses its own short transaction, so progress is durable immediately and never blocks the audit chain."""
import json
import logging
import time
from dataclasses import dataclass, field

from sqlalchemy import text

from ..providers.base import IpConfig, NicSpec, ProviderError, ProviderTimeout, ScopeViolation, TaskRef, VmCloneSpec, VmConfigSpec, VmRef
from . import state
from .ports import Cancelled, DeployError, ExecEnv, Fenced, StepFailed

log = logging.getLogger("ics.deploy.executor")
LOG_MAX = 2000


# ---- persistence ---------------------------------------------------------------------------------------------

def seed_steps(rt, job_id: str, deployment_id: str, revision: int, steps: list[dict], plan_hash: str = "") -> None:
    """Create the job's step rows (idempotent). Steps already succeeded in an earlier job of the same (deployment, revision, plan_hash)
    are carried over; a different approved plan never reuses another plan's steps (review 3 M3)."""
    with rt.session() as db:
        for s in steps:
            if db.execute(text("SELECT 1 FROM job_steps WHERE job_id = :j AND step_key = :k"), {"j": job_id, "k": s["key"]}).first():
                continue
            prev = db.execute(text("SELECT result, job_id FROM job_steps WHERE deployment_id = :d AND revision = :r AND step_key = :k "
                                   "AND status = 'succeeded' AND job_id <> :j AND plan_hash = :h ORDER BY id DESC LIMIT 1"),
                              {"d": deployment_id, "r": revision, "k": s["key"], "j": job_id, "h": plan_hash}).first()
            db.execute(text(
                "INSERT INTO job_steps (job_id, deployment_id, revision, seq, step_key, kind, target, op, params, depends_on, disruptive, est_seconds, "
                "status, progress, result, carried_from_job, log_excerpt, finished_at, plan_hash) VALUES "
                "(:j, :d, :r, :q, :k, :kd, :t, :o, CAST(:p AS jsonb), CAST(:dp AS jsonb), :dis, :est, :st, :pg, CAST(:res AS jsonb), :cf, :lg, "
                "CASE WHEN :st = 'succeeded' THEN now() END, :h)"),
                {"j": job_id, "d": deployment_id, "r": revision, "q": s["seq"], "k": s["key"], "kd": s["kind"], "t": s["target"], "o": s["op"],
                 "p": json.dumps(s["params"], sort_keys=True), "dp": json.dumps(s["depends_on"]), "dis": s["disruptive"], "est": s["est_seconds"],
                 "st": "succeeded" if prev else "pending", "pg": 100 if prev else 0,
                 "res": json.dumps(prev.result) if prev and prev.result is not None else None,
                 "cf": str(prev.job_id) if prev else None, "lg": "carried over from an earlier job of this plan" if prev else "", "h": plan_hash})
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
    plan_hash: str = ""
    lease: object = None

    def checkpoint(self) -> None:
        if self.lease is not None:
            self.lease.check()

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
        return VmRef(ref["node"], int(ref["vmid"]), "vm", self.slug)  # the slug is the ownership tag the provider re-checks live


def _poll(ctx: StepCtx, task: TaskRef, what: str) -> TaskRef:
    env = ctx.env
    t0 = env.clock()
    while True:
        ctx.checkpoint()
        st = env.provider.task_status(task)
        if st.state == "ok":
            return task
        if st.state == "error":
            raise StepFailed(f"{what} failed: {(st.message or st.exitstatus or 'unknown error')[:200]}",
                             "The infrastructure provider reported the task as failed.", retryable=True)
        if env.clock() - t0 > env.task_timeout:
            raise StepFailed(f"{what} did not finish within {int(env.task_timeout)} s", "The provider task is still running or stuck; "
                             "check the task on the infrastructure and re-run.", retryable=True)
        ctx.log(f"{what}: {st.state}")
        env.sleep(env.poll_interval)


_TRANSIENT = {"timeout", "unreachable", "node_unreachable", "locked"}


def provider_failure(e: ProviderError) -> StepFailed:
    """Provider errors are operator-readable and secret-free (providers.base); scope refusals and bad requests never retry."""
    if isinstance(e, ScopeViolation):
        return StepFailed(f"refused by the provider scope check: {e.message}"[:300],
                          "The action touches something outside this endpoint's approved pool/storage/network, or a guest this deployment does not own.",
                          retryable=False)
    return StepFailed(e.message[:300], "The infrastructure provider refused or could not complete the operation.",
                      retryable=isinstance(e, ProviderTimeout) or e.code in _TRANSIENT)


def _find_guest(ctx: StepCtx, name: str) -> dict | None:
    tag = f"ou-deployment-{ctx.slug}"
    return next((g for g in ctx.env.provider.discover().guests if g["name"] == name and tag in g["tags"] and "ou-managed" in g["tags"]), None)


def _disk_key(index: int) -> str:
    """Plan disks are ordered: index 0 = the template's root disk (scsi0), then scsi1.. in plan order."""
    return f"scsi{index}"


def _owned_guest(ctx: StepCtx, ref: VmRef, name: str):
    """Review 3 L3: ownership is by VMID + tags (+ name), never by name alone: a recycled vmid carrying someone else's guest is not ours."""
    d = ctx.env.provider.discover()
    tag = f"ou-deployment-{ctx.slug}"
    return next((g for g in d.guests if int(g["vmid"]) == int(ref.vmid) and g["name"] == name and tag in g["tags"] and "ou-managed" in g["tags"]), None)


def _require_owned(ctx: StepCtx, ref: VmRef, name: str):
    g = _owned_guest(ctx, ref, name)
    if g is None:
        raise StepFailed(f"VM {name} (vmid {ref.vmid}) is not a guest of this deployment (tags/name do not match)",
                         "The recorded VM id no longer belongs to this deployment; nothing was changed. Check the infrastructure.", retryable=False)
    return g


def _intent(ctx: StepCtx, vm: str) -> dict | None:
    with ctx.rt.session() as db:
        r = db.execute(text("SELECT actual FROM deployment_resources WHERE deployment_id = :d AND kind = 'vm' AND logical_name = :n"),
                       {"d": ctx.deployment_id, "n": vm}).first()
    return ((r.actual or {}).get("clone_intent")) if r else None


def _record_intent(ctx: StepCtx, vm: str, intent: dict) -> None:
    """Durable 'about to clone' marker written before the provider call; the first attempt's marker is kept on retries."""
    if _intent(ctx, vm) is None:
        ctx.resource("vm", vm, actual={"clone_intent": intent})


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
            ctx.resource("vm", vm, state="creating", provider_ref={"node": g["node"], "vmid": g["vmid"]})
            ctx.log(f"adopted existing tagged guest vmid {g['vmid']} left by an interrupted attempt")
            return {"node": g["node"], "vmid": g["vmid"], "adopted": True}
        d = prov.discover()
        tpl = next((t for t in d.templates if t["name"] == p["template"]), None)
        stray = next((x for x in d.guests if x["name"] == vm), None)
        if stray is not None:
            # crash window between the clone and the ownership tag: the clone intent (with the VM ids that existed before) was recorded
            # BEFORE the provider call, so an untagged guest of that name with a NEW vmid is our own clone. Recover its clone task from the
            # provider and tag it via finalize_clone; anything else (no intent, vmid already existed, no task) is never adopted.
            intent = _intent(ctx, vm)
            recover = getattr(prov, "recover_clone_task", None)
            task = None
            if (intent and tpl is not None and int(stray["vmid"]) not in set(intent.get("pre_vmids", [])) and recover is not None
                    and "ou-managed" not in stray["tags"] and not any(t.startswith("ou-deployment-") for t in stray["tags"])):
                task = recover(int(tpl["vmid"]), tpl["node"], int(stray["vmid"]), vm, ctx.slug)
            if task is None:
                raise StepFailed(f"a guest named {vm} (vmid {stray['vmid']}) already exists and is not tagged as owned by this deployment",
                                 "ICS never adopts or overwrites an untagged guest. If it is a leftover of an interrupted deployment, remove it in "
                                 f"Proxmox (or tag it ou-managed + ou-deployment-{ctx.slug}), then re-run.", retryable=False)
            ctx.resource("vm", vm, state="creating", provider_ref={"node": stray["node"], "vmid": stray["vmid"]})
            ctx.log(f"recovered the clone task of an interrupted attempt for vmid {stray['vmid']}; it will be tagged next")
            return {"node": stray["node"], "vmid": stray["vmid"], "recovered": True,
                    "task": {"node": task.node, "upid": task.upid, "vmid": task.vmid, "kind": task.kind,
                             "template_vmid": task.template_vmid, "name": task.name}}
        if tpl is None:
            raise StepFailed(f"template {p['template']!r} was not found in the approved pool(s)",
                             "The OS image template is not visible to the provisioning credential; add it to an allowed pool "
                             "(or list its VM id in the endpoint's allowed templates).", retryable=False)
        _record_intent(ctx, vm, {"pre_vmids": sorted(int(x["vmid"]) for x in d.guests), "template_vmid": int(tpl["vmid"])})
        spec = VmCloneSpec(template_vmid=int(tpl["vmid"]), template_node=tpl["node"], new_vmid=None, name=vm, pool=p["pool"],
                           storage=p["storage"], deployment_id=ctx.slug, target_node=p["node"])
        task = _poll(ctx, prov.clone_vm(spec), f"clone {vm}")
        ctx.resource("vm", vm, state="creating", provider_ref={"node": p["node"], "vmid": task.vmid})
        # the whole clone TaskRef is persisted in the step result so the tag step can resume after a crash
        return {"node": p["node"], "vmid": task.vmid, "task": {"node": task.node, "upid": task.upid, "vmid": task.vmid, "kind": task.kind,
                                                                 "template_vmid": task.template_vmid, "name": task.name}}
    ref = ctx.vm_ref(vm)
    if op == "finalize_clone":  # PVE cannot tag at clone time: ownership tags are applied here, from the persisted clone TaskRef
        if _find_guest(ctx, vm) is not None:
            ctx.log(f"{vm} already carries the ownership tags")
            return {"tagged": True, "already": True}
        t = (ctx.outputs.get(f"vm.clone:{vm}") or {}).get("task")
        if not t or not t.get("upid"):
            raise StepFailed(f"cannot tag {vm}: the clone task was not recorded",
                             "The guest exists but is not tagged as owned by this deployment and its clone task is unknown. Remove it in Proxmox "
                             "(or tag it ou-managed + ou-deployment-" + ctx.slug + ") and re-run.", retryable=False)
        task = TaskRef(t["node"], t["upid"], t["vmid"], t["kind"], ctx.slug, t.get("template_vmid"), t.get("name"))
        _poll(ctx, prov.finalize_clone(task), f"tag {vm}")
        return {"tagged": True}
    if op != "destroy_vm":
        if ctx.plan.get("kind") == "destroy" and op == "power" and _owned_guest(ctx, ref, vm) is None:
            ctx.log(f"{vm} (vmid {ref.vmid}) is not a guest of this deployment any more; not touching it")
            return {"power": p["op"], "skipped": "not owned"}
        _require_owned(ctx, ref, vm)
    if op == "configure_vm":
        ci = p.get("cloud_init") or {}
        new = p.get("new_disks")  # change steps list only the disks to add; create adds every non-root disk
        # first-contact material for the guest (only public data + the per-VM proof secret derived from the ICS key); fakes without it skip it
        boot = getattr(ctx.env.agent, "bootstrap_config", None)
        bc = boot(vm) if (boot and ci.get("agent_enrollment")) else {}
        spec = VmConfigSpec(cores=p["cores"], memory_mb=p["memory_mb"],
                            nics=tuple(NicSpec(i, n["bridge"], n.get("vlan")) for i, n in enumerate(p["nics"])),
                            new_disks=tuple((_disk_key(i), d["storage"], d["size_gb"]) for i, d in enumerate(p["disks"])
                                            if i > 0 and (new is None or d["name"] in new)),
                            cloudinit_storage=p["disks"][0]["storage"] if ci else None,
                            ciuser=bc.get("ciuser"), sshkeys=tuple(bc.get("sshkeys", ())), smbios_serial=bc.get("smbios_serial"), smbios_sku=bc.get("smbios_sku"), smbios_family=bc.get("smbios_family"),
                            ipconfigs=(IpConfig(0, "dhcp"),) if bc else (), ciupgrade=False if bc else None,
                            description=f"Office Unbound deployment {ctx.slug}: {ci.get('hostname', vm)}" if ci else None)
        _poll(ctx, prov.configure_vm(ref, spec), f"configure {vm}")
        return {"configured": True}
    if op == "power":
        want = p["op"]
        g = _owned_guest(ctx, ref, vm)
        if g is not None and ((want == "start" and g["status"] == "running") or (want in ("stop", "shutdown") and g["status"] == "stopped")):
            ctx.log(f"{vm} is already {g['status']}")
        else:
            _poll(ctx, prov.power(ref, want), f"{want} {vm}")
        if want == "start":
            ctx.resource("vm", vm, state="present")
        return {"power": want}
    if op == "snapshot":
        _poll(ctx, prov.snapshot(ref, p["name"]), f"snapshot {vm}")
        return {"snapshot": p["name"]}
    if op == "resize_disk":
        cur = prov.disk_size_gb(ref, _disk_key(p["disk_index"])) if hasattr(prov, "disk_size_gb") else None
        if cur is not None and cur >= p["new_size_gb"]:   # idempotent: a re-run after a crash, or a template that is already big enough
            ctx.log(f"{vm}/{p['disk']} is already {cur:g} GB (wanted {p['new_size_gb']} GB); not resizing")
            return {"disk": p["disk"], "size_gb": p["new_size_gb"], "already": True}
        _poll(ctx, prov.resize_disk(ref, _disk_key(p["disk_index"]), p["new_size_gb"]), f"resize {vm}/{p['disk']}")
        return {"disk": p["disk"], "size_gb": p["new_size_gb"]}
    if op == "destroy_vm":
        try:
            ref = ctx.vm_ref(vm)
        except StepFailed:
            return {"destroyed": True, "note": "no provider reference; nothing to destroy"}
        if _owned_guest(ctx, ref, vm) is None:
            ctx.log("guest already gone (no guest of this deployment has that VM id)")
        else:  # ownership guard: only the ou-managed + ou-deployment-<id> guest with the RECORDED vmid is ever destroyed
            _poll(ctx, prov.destroy_vm(ref), f"destroy {vm}")
        ctx.resource("vm", vm, state="removed")
        return {"destroyed": True}
    raise StepFailed(f"unknown provider operation {op!r}", "", retryable=False)


def h_await_callback(ctx: StepCtx) -> dict:
    """`guest.await_callback`: the golden image's first-boot unit reports in (HMAC-verified, single use). Fakes without it skip the step."""
    vm = ctx.step["target"]
    fn = getattr(ctx.env.agent, "await_callback", None)
    if fn is None:
        return {"skipped": "no callback bootstrap on this port"}
    res = fn(vm, int(ctx.step["params"].get("timeout_seconds", 600)))
    ctx.log(f"guest {vm}: " + ("bootstrap callback received" if res.get("reported") else str(next(iter(res), "done"))))
    return res


def h_wait_enroll(ctx: StepCtx) -> dict:
    vm = ctx.step["target"]
    node_id = ctx.env.agent.wait_enrollment(vm, int(ctx.step["params"].get("timeout_seconds", 600)))
    ctx.log(f"agent enrolled as node {node_id}")
    with ctx.rt.session() as db:   # remembered so that destroy can decommission the node
        ref = state.provider_ref(db, ctx.deployment_id, vm) or {}
    ctx.resource("vm", vm, provider_ref={**ref, "agent_node_id": node_id})
    from .catalog import get_catalog   # every_vm components (the node agent) are installed by the bootstrap itself: mark them present now
    every = {c.name for c in get_catalog().components.values() if c.placement == "every_vm"}
    for x in ctx.plan.get("services", []):
        if x["vm"] == vm and x["component"] in every:
            ctx.resource("service", x["name"], state="present", actual={"version": x["version"], "package": x["package"], "installed_by": "guest bootstrap"})
    return {"node_id": node_id}


def _node_for(ctx: StepCtx, vm: str) -> str:
    r = ctx.outputs.get(f"agent.enroll:{vm}")
    if not r:
        with ctx.rt.session() as db:
            r = db.execute(text("SELECT result FROM job_steps WHERE deployment_id = :d AND step_key = :k AND status = 'succeeded' "
                                "AND plan_hash = :h ORDER BY id DESC LIMIT 1"),
                           {"d": ctx.deployment_id, "k": f"agent.enroll:{vm}", "h": ctx.plan_hash}).scalar()
    if not r:
        raise StepFailed(f"no enrolled agent for {vm}", "The node agent has not enrolled; re-run the deployment.", retryable=False)
    return r["node_id"]


def h_agent_runbook(ctx: StepCtx) -> dict:
    vm, p = ctx.step["target"], ctx.step["params"]
    node = _node_for(ctx, vm)
    results = []
    rbs = p["runbooks"]
    for i, rb in enumerate(rbs):
        ctx.checkpoint()
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
        ctx.env.checks.register(ctx.rt, c, host, trust, ctx.created_by, ctx.deployment_id)
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
        ctx.checkpoint()
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


HANDLERS = {"provider_task": h_provider_task, "wait_guest_callback": h_await_callback, "wait_agent_enrollment": h_wait_enroll, "agent_runbook": h_agent_runbook,
            "register_checks": h_register_checks, "verify_health": h_verify_health}


# ---- the loop --------------------------------------------------------------------------------------------------

def run_steps(rt, *, job_id: str, deployment_id: str, slug: str, revision: int, plan: dict, steps: list[dict], env: ExecEnv,
              created_by: str, plan_hash: str = "", lease=None, step_deadline: float = 1800.0) -> dict:
    """Run `steps` (already ordered) for a job. Raises StepFailed on the first failed step, Cancelled when cancelled between steps.
    Returns {'steps': n, 'carried': k}."""
    seed_steps(rt, job_id, deployment_id, revision, steps, plan_hash)
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
        if lease is not None:
            lease.check()  # Fenced / Cancelled (between steps)
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
        ctx = StepCtx(rt, env, job_id, deployment_id, slug, plan, created_by, r.id, step, outputs, plan_hash=plan_hash, lease=lease)
        attempts = r.attempts
        while True:
            attempts += 1
            _update(rt, r.id, status="running", attempts=attempts, started_at=_now(), error_message=None, error_explanation=None)
            if lease is not None:
                lease.begin_step(step_deadline)
            try:
                res = HANDLERS[r.kind](ctx)
                ctx.checkpoint()   # a step that overran its deadline (or lost its lease) inside one blocking call does not count as done
            except Fenced:
                raise  # lost ownership: write NOTHING more (the job was already failed/reaped by whoever took over)
            except Cancelled:
                with rt.session() as db:
                    db.execute(text("UPDATE job_steps SET status = 'cancelled', finished_at = now() WHERE job_id = :j AND status IN ('pending','running')"),
                               {"j": job_id})
                    state.add_event(db, deployment_id, "cancelled", f"job cancelled during step {r.step_key}", job_id)
                    db.commit()
                raise
            except StepFailed as e:
                if e.retryable and attempts - r.attempts < env.max_attempts:
                    ctx.log(f"attempt {attempts} failed: {e.message}; retrying")
                    env.sleep(env.retry_delay * (attempts - r.attempts))
                    continue
                _fail(rt, r.id, e.message, e.explanation, deployment_id, job_id, r.step_key)
                raise
            except ProviderError as e:
                sf = provider_failure(e)
                if sf.retryable and attempts - r.attempts < env.max_attempts:
                    ctx.log(f"attempt {attempts} failed: {sf.message}; retrying")
                    env.sleep(env.retry_delay * (attempts - r.attempts))
                    continue
                _fail(rt, r.id, sf.message, sf.explanation, deployment_id, job_id, r.step_key)
                raise sf from None
            except DeployError as e:
                _fail(rt, r.id, str(e)[:300], "", deployment_id, job_id, r.step_key)
                raise StepFailed(str(e)) from e
            except Exception as e:  # noqa: BLE001  never leak arbitrary exception text (may embed parameters)
                log.exception("step %s crashed with %s", r.step_key, type(e).__name__)
                _fail(rt, r.id, "internal error; see the server log", "An unexpected error occurred in the ICS.", deployment_id, job_id, r.step_key)
                raise StepFailed("internal error in step " + r.step_key) from None
            if lease is not None:
                lease.end_step()
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


__all__ = ["run_steps", "seed_steps", "request_cancel", "StepFailed", "Cancelled", "Fenced", "time"]
