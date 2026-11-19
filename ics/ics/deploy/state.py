"""Desired vs actual state, drift report and change diff (ADR-0009 section 4).

Pure functions (`plan_resources`, `diff_plans`, `drift_findings`) plus thin DB helpers. Drift is REPORT-ONLY: nothing here ever
repairs or destroys anything (same rule as identity reconcile)."""
import json

from sqlalchemy import text

from .catalog import get_catalog
from .plan import ExistingVm

MiB = 1048576


# ---- resources ----------------------------------------------------------------------------------------------

def plan_resources(plan: dict) -> dict[tuple[str, str], dict]:
    """(kind, logical_name) -> desired JSON, for every resource a plan declares."""
    out: dict[tuple[str, str], dict] = {}
    for v in plan["vms"]:
        out[("vm", v["name"])] = {k: v[k] for k in ("cores", "memory_mb", "disks", "nics", "node", "os_image", "tags", "components")}
        for d in v["disks"]:
            if d["name"] != "root":
                out[("volume", f"{v['name']}:{d['name']}")] = {"vm": v["name"], **d}
    for c in plan["containers"]:
        out[("container", c["name"])] = {k: c[k] for k in ("vm", "component", "image", "digest", "version", "ports", "volumes")}
    for s in plan["services"]:
        out[("service", s["name"])] = {k: s[k] for k in ("vm", "component", "package", "version", "repo")}
    for d in plan["dns"]:
        out[("dns", f"{d['type']}:{d['name']}:{d['value']}")] = dict(d)
    for c in plan["checks"]:
        out[("check", c["name"])] = {k: c[k] for k in ("kind", "vm", "component", "port", "path", "expect_status", "interval_seconds")}
    return out


def sync_resources(db, deployment_id: str, plan: dict, removed: set[tuple[str, str]] | None = None) -> None:
    """Upsert desired specs from `plan`; new rows start as 'planned'. Rows no longer in the plan are NOT deleted here."""
    for (kind, name), desired in sorted(plan_resources(plan).items()):
        db.execute(text(
            "INSERT INTO deployment_resources (deployment_id, kind, logical_name, desired) VALUES (:d, :k, :n, CAST(:x AS jsonb)) "
            "ON CONFLICT (deployment_id, kind, logical_name) DO UPDATE SET desired = EXCLUDED.desired, updated_at = now()"),
            {"d": deployment_id, "k": kind, "n": name, "x": json.dumps(desired, sort_keys=True)})


def set_resource(db, deployment_id: str, kind: str, name: str, *, state: str | None = None, provider_ref: dict | None = None,
                 actual: dict | None = None) -> None:
    sets, p = ["updated_at = now()"], {"d": deployment_id, "k": kind, "n": name}
    if state:
        sets.append("state = :s")
        p["s"] = state
    if provider_ref is not None:
        sets.append("provider_ref = CAST(:r AS jsonb)")
        p["r"] = json.dumps(provider_ref, sort_keys=True)
    if actual is not None:
        sets.append("actual = CAST(:a AS jsonb)")
        p["a"] = json.dumps(actual, sort_keys=True)
    db.execute(text(f"UPDATE deployment_resources SET {', '.join(sets)} WHERE deployment_id = :d AND kind = :k AND logical_name = :n"), p)  # noqa: S608


def provider_ref(db, deployment_id: str, vm: str) -> dict | None:
    r = db.execute(text("SELECT provider_ref FROM deployment_resources WHERE deployment_id = :d AND kind = 'vm' AND logical_name = :n"),
                   {"d": deployment_id, "n": vm}).first()
    return r.provider_ref if r else None


def add_event(db, deployment_id: str, kind: str, message: str, job_id: str | None = None, details: dict | None = None) -> None:
    db.execute(text("INSERT INTO deployment_events (deployment_id, kind, message, job_id, details) VALUES (:d, :k, :m, :j, CAST(:x AS jsonb))"),
               {"d": deployment_id, "k": kind, "m": message[:2000], "j": job_id, "x": json.dumps(details or {}, sort_keys=True)})


def existing_from_resources(db, deployment_id: str) -> dict[str, ExistingVm]:
    """Current VM allocations (from the applied desired state) for change planning."""
    out = {}
    for r in db.execute(text("SELECT logical_name, desired, provider_ref FROM deployment_resources WHERE deployment_id = :d AND kind = 'vm' "
                             "AND state IN ('present','changing')"), {"d": deployment_id}):
        d = r.desired
        out[r.logical_name] = ExistingVm(d["node"], d["cores"], d["memory_mb"], {x["name"]: (x["size_gb"], x["storage"]) for x in d["disks"]})
    return out


# ---- change diff --------------------------------------------------------------------------------------------

def _fields(a: dict, b: dict) -> dict:
    return {k: {"from": a.get(k), "to": b.get(k)} for k in sorted(set(a) | set(b)) if a.get(k) != b.get(k)}


# changes to these VM fields need a reboot (no hot-plug assumed; conservative); disk growth is online
_REBOOT_FIELDS = {"cores", "memory_mb"}
SNAPSHOT_REQUIRED_KINDS = {"vm"}


def diff_plans(old: dict, new: dict, cat=None) -> dict:
    """Resources added/changed/removed between two plans plus capacity impact, downtime, backup requirement and risk."""
    cat = cat or get_catalog()
    a, b = plan_resources(old), plan_resources(new)
    added = [{"kind": k, "name": n} for (k, n) in sorted(b) if (k, n) not in a]
    removed = [{"kind": k, "name": n} for (k, n) in sorted(a) if (k, n) not in b]
    changed = []
    for key in sorted(set(a) & set(b)):
        f = _fields(a[key], b[key])
        if f:
            changed.append({"kind": key[0], "name": key[1], "fields": f})
    shrink = [c for c in changed if c["kind"] == "vm" and any(
        x["size_gb"] < y["size_gb"] for x in b[("vm", c["name"])]["disks"] for y in a[("vm", c["name"])]["disks"] if x["name"] == y["name"])]
    ov, nv = old["consumption"], new["consumption"]
    impact = {k: nv[k] - ov[k] for k in ("vms", "cores", "memory_mb", "disk_gb")}
    steps = change_steps(old, new, added, changed, removed, cat)
    downtime = sum(s.get("downtime_seconds", 0) for s in steps)
    disruptive = [s["key"] for s in steps if s["disruptive"]]
    stateful_touched = sorted({c["name"] for c in changed if c["kind"] == "vm"} | {r["name"] for r in removed if r["kind"] == "vm"})
    # backup/snapshot policy: any change to or removal of an existing VM that carries data needs a pre-change snapshot/backup
    snap_vms = [v for v in stateful_touched if v in {x["name"] for x in old["vms"] if x["stateful"]}]
    risk = "high" if (removed or shrink) else "normal"
    reasons = []
    if removed:
        reasons.append("resources are removed")
    if shrink:
        reasons.append("a disk shrink was requested")
    return {"added": added, "changed": changed, "removed": removed, "capacity_impact": impact, "downtime_seconds": downtime,
            "disruptive_steps": disruptive, "snapshot_required": bool(snap_vms), "snapshot_vms": snap_vms,
            "risk": risk, "risk_reasons": reasons, "requires_maintenance": bool(disruptive), "steps": steps,
            "empty": not (added or changed or removed)}


def change_steps(old: dict, new: dict, added, changed, removed, cat) -> list[dict]:
    """Ordered steps that turn the applied deployment into the new plan. Existing VMs keep their provider refs."""
    from .plan import PlanInput, _step, create_steps, order_steps  # local: avoid import cycle
    steps: list[dict] = []
    old_vms = {v["name"]: v for v in old["vms"]}
    inp = PlanInput.model_validate(new["input"])
    add_vm = [v for v in new["vms"] if v["name"] not in old_vms]
    if add_vm:
        create = create_steps(add_vm, inp, cat)
        keys = {s["key"] for s in create}
        for s in create:  # dependencies on already-existing instances are satisfied by the applied deployment
            s["depends_on"] = [d for d in s["depends_on"] if d in keys]
        steps += create
    new_vms = {v["name"]: v for v in new["vms"]}
    for c in changed:
        if c["kind"] != "vm":
            continue
        n, f = c["name"], c["fields"]
        ov, nv = old_vms[n], new_vms[n]
        old_d = {d["name"]: d for d in ov["disks"]}
        reboot = bool(_REBOOT_FIELDS & set(f))
        grown = [(i, d) for i, d in enumerate(nv["disks"]) if d["name"] in old_d and d["size_gb"] > old_d[d["name"]]["size_gb"]]
        fresh = [d for d in nv["disks"] if d["name"] not in old_d]
        need_cfg = bool({"cores", "memory_mb", "nics"} & set(f)) or bool(fresh)
        deps: list[str] = []
        if ov["stateful"]:
            steps.append(_step(f"vm.snapshot:{n}", "provider_task", n, "snapshot", {"name": "ou-pre-change"}, [], est_seconds=60))
            deps = [f"vm.snapshot:{n}"]
        if reboot:
            steps.append(_step(f"vm.stop:{n}", "provider_task", n, "power", {"op": "shutdown"}, deps, disruptive=True, est_seconds=60))
            deps = [f"vm.stop:{n}"]
        for i, d in grown:
            steps.append(_step(f"vm.resize:{n}:{d['name']}", "provider_task", n, "resize_disk",
                               {"disk": d["name"], "disk_index": i, "new_size_gb": d["size_gb"]}, deps, est_seconds=30))
        if need_cfg:
            steps.append(_step(f"vm.configure:{n}", "provider_task", n, "configure_vm",
                               {"cores": nv["cores"], "memory_mb": nv["memory_mb"], "disks": nv["disks"], "nics": nv["nics"], "cloud_init": {},
                                "new_disks": [d["name"] for d in fresh]},
                               deps, est_seconds=20))
        if reboot:
            steps.append(_step(f"vm.start:{n}", "provider_task", n, "power", {"op": "start"}, [s["key"] for s in steps if s["target"] == n],
                               disruptive=True, est_seconds=60, downtime_seconds=120))
    # component artifact changes: redeploy in place (disruptive by the component's declared upgrade downtime)
    upgraded: set[tuple[str, str]] = set()
    for c in changed:
        if c["kind"] not in ("container", "service"):
            continue
        comp, vm = new_resource_component(new, c), new_resource_vm(new, c)
        if not comp or (vm, comp) in upgraded:
            continue
        upgraded.add((vm, comp))
        dt = cat.components[comp].upgrade.downtime_seconds if cat and comp in cat.components else 60
        runbooks = next((s["params"]["runbooks"] for s in create_steps([v for v in new["vms"] if v["name"] == vm], inp, cat)
                         if s["key"] == f"comp.install:{vm}:{comp}"), [])
        key = f"comp.upgrade:{vm}:{comp}"
        steps.append(_step(key, "agent_runbook", vm, "install", {"component": comp, "runbooks": runbooks},
                           [s["key"] for s in steps if s["target"] == vm], disruptive=True, downtime_seconds=dt, est_seconds=dt + 60))
        steps.append(_step(f"health.verify:{vm}:{comp}:upgrade", "verify_health", vm, "verify", {"component": comp, "timeout_seconds": 300}, [key]))
    for r in removed:
        if r["kind"] == "vm":
            n = r["name"]
            steps.append(_step(f"vm.snapshot:{n}", "provider_task", n, "snapshot", {"name": "ou-pre-destroy"}, [], est_seconds=60))
            steps.append(_step(f"vm.stop:{n}", "provider_task", n, "power", {"op": "stop"}, [f"vm.snapshot:{n}"], disruptive=True))
            steps.append(_step(f"vm.destroy:{n}", "provider_task", n, "destroy_vm", {}, [f"vm.stop:{n}"], disruptive=True, est_seconds=60))
    keys = {s["key"] for s in steps}
    for s in steps:
        s["depends_on"] = sorted(d for d in s["depends_on"] if d in keys)
    return order_steps(steps)


def new_resource_vm(plan: dict, c: dict) -> str:
    return next((x["vm"] for x in plan["containers"] + plan["services"] if f"{x['name']}" == c["name"]), "")


def new_resource_component(plan: dict, c: dict) -> str:
    return next((x["component"] for x in plan["containers"] + plan["services"] if x["name"] == c["name"]), "")


def destroy_steps(plan: dict) -> list[dict]:
    from .plan import order_steps, _step
    steps = []
    for v in sorted(plan["vms"], key=lambda x: x["name"]):
        n = v["name"]
        steps.append(_step(f"vm.stop:{n}", "provider_task", n, "power", {"op": "stop"}, [], disruptive=True, est_seconds=60))
        steps.append(_step(f"vm.destroy:{n}", "provider_task", n, "destroy_vm", {}, [f"vm.stop:{n}"], disruptive=True, est_seconds=60))
    return order_steps(steps)


# ---- drift (report only) ------------------------------------------------------------------------------------

def drift_findings(resources: list[dict], guests: list[dict], slug: str) -> list[dict]:
    """resources: rows {kind, name, desired, actual, state, provider_ref}; guests: Proxmox qemu rows (inventory snapshot)."""
    out: list[dict] = []
    by_vmid = {int(g["vmid"]): g for g in guests if isinstance(g, dict) and "vmid" in g}
    managed = set()
    for r in resources:
        k, n, d, act = r["kind"], r["name"], r["desired"], r["actual"]
        if r["state"] == "removed":
            continue
        if r["state"] == "failed":
            out.append({"kind": k, "name": n, "type": "failed", "detail": "last operation on this resource failed"})
        if k == "vm":
            ref = r["provider_ref"] or {}
            if r["state"] == "planned" and not ref:
                continue
            g = by_vmid.get(int(ref["vmid"])) if ref.get("vmid") is not None else None
            if ref.get("vmid") is not None:
                managed.add(int(ref["vmid"]))
            if g is None:
                out.append({"kind": k, "name": n, "type": "missing", "detail": "VM is not present in the latest inventory"})
                continue
            f = {}
            if int(g.get("cpus", d["cores"])) != d["cores"]:
                f["cores"] = {"desired": d["cores"], "actual": int(g.get("cpus"))}
            if "maxmem" in g and int(g["maxmem"]) // MiB != d["memory_mb"]:
                f["memory_mb"] = {"desired": d["memory_mb"], "actual": int(g["maxmem"]) // MiB}
            if "maxdisk" in g and int(g["maxdisk"]) // (1024 ** 3) != d["disks"][0]["size_gb"]:
                f["root_disk_gb"] = {"desired": d["disks"][0]["size_gb"], "actual": int(g["maxdisk"]) // (1024 ** 3)}
            tags = set(str(g.get("tags", "")).split(";"))
            if not {"ou-managed", f"ou-deployment-{slug}"} <= tags:
                f["tags"] = {"desired": sorted(d["tags"]), "actual": sorted(t for t in tags if t)}
            if f:
                out.append({"kind": k, "name": n, "type": "changed", "fields": f})
            if g.get("status") not in (None, "running") and r["state"] == "present":
                out.append({"kind": k, "name": n, "type": "not_running", "detail": f"status is {g.get('status')}"})
        elif k in ("container", "service") and r["state"] == "present":
            if not act:
                out.append({"kind": k, "name": n, "type": "unobserved", "detail": "no agent report recorded yet"})
            elif act.get("version") not in (None, d["version"]):
                out.append({"kind": k, "name": n, "type": "changed", "fields": {"version": {"desired": d["version"], "actual": act.get("version")}}})
            elif k == "container" and act.get("digest") not in (None, d["digest"]):
                out.append({"kind": k, "name": n, "type": "changed", "fields": {"digest": {"desired": d["digest"], "actual": act.get("digest")}}})
        elif k == "check" and r["state"] == "present" and act and act.get("state") not in (None, "ok"):
            out.append({"kind": k, "name": n, "type": "unhealthy", "detail": f"check state {act.get('state')}"})
    for g in guests:
        if isinstance(g, dict) and f"ou-deployment-{slug}" in str(g.get("tags", "")).split(";") and int(g.get("vmid", -1)) not in managed:
            out.append({"kind": "vm", "name": str(g.get("name")), "type": "unexpected",
                        "detail": "guest carries this deployment's tag but is not a deployment resource (report only; not touched)"})
    return sorted(out, key=lambda x: (x["kind"], x["name"], x["type"]))
