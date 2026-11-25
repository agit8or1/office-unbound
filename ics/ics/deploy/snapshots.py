"""deployment.snapshots.prune: delete the ICS's own pre-change snapshots (`ou-pre-change-<UTC time>`) of a deployment's VMs, taken before a
cutoff. Owner request 2026-11-25: the change executor takes one per VM per change and nothing removed them.

Fences: only VMs the deployment tracks (provider refs), each re-checked live by the provider (pool, node, ownership tags, never the ICS
itself); only names the executor creates (`ou-pre-change-YYYYmmddTHHMMSS`), never a snapshot someone else took; only those strictly older
than `older_than`, which must be at least an hour in the past (a change running now keeps its own). Runs under the deployment's lock."""
from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import text

from .. import audit
from .lease import Lease, guard_env
from .ports import DeployError

ACTION = "deployment.snapshots.prune"
NAME_RE = re.compile(r"^ou-pre-change-(\d{8}T\d{6})$")
MIN_AGE = timedelta(hours=1)
SLUG = r"^[a-z][a-z0-9-]{1,30}$"


class SnapshotPrune(BaseModel):
    model_config = ConfigDict(extra="forbid")
    deployment_id: str = Field(pattern=SLUG)
    older_than: datetime = Field(description="delete the deployment's ou-pre-change snapshots taken before this time (UTC); at least 1 h ago")

    @field_validator("older_than")
    @classmethod
    def _tz(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("older_than needs a time zone (e.g. 2026-11-25T16:00:00Z)")
        return v.astimezone(UTC)


def taken_at(name: str) -> datetime | None:
    m = NAME_RE.match(name)
    return datetime.strptime(m.group(1), "%Y%m%dT%H%M%S").replace(tzinfo=UTC) if m else None


def selected(names: list[str], cutoff: datetime) -> list[str]:
    """The names this action deletes: ours, and taken strictly before the cutoff."""
    return sorted(n for n in names if (t := taken_at(n)) is not None and t < cutoff)


def _dep(db, slug: str):
    d = db.execute(text("SELECT * FROM deployments WHERE slug = :s"), {"s": slug}).first()
    if d is None:
        raise KeyError("deployment not found")
    if d.status == "destroyed":
        raise LookupError("the deployment is destroyed")
    return d


def _vms(db, did: str) -> dict[str, dict]:
    return {r.logical_name: r.provider_ref for r in db.execute(text(
        "SELECT logical_name, provider_ref FROM deployment_resources WHERE deployment_id = :d AND kind = 'vm' AND state <> 'removed'"),
        {"d": did}) if r.provider_ref and r.provider_ref.get("vmid") is not None}


def precheck(db, rt, p: SnapshotPrune) -> dict:
    d = _dep(db, p.deployment_id)
    if p.older_than > datetime.now(UTC) - MIN_AGE:
        raise ValueError("older_than must be at least an hour in the past, so a change that is running keeps its snapshot")
    vms = sorted(_vms(db, str(d.id)))
    if not vms:
        raise LookupError("the deployment has no VMs")
    return {"risk": "normal", "deployment": d.slug, "vms": vms, "older_than": p.older_than.isoformat(),
            "deletes": f"snapshots named ou-pre-change-<time> taken before {p.older_than:%Y-%m-%d %H:%M} UTC; newer ones and any "
                       "snapshot with another name are kept"}


def _wait(env, task, timeout: float = 600.0) -> None:
    t0 = env.clock()
    while True:
        st = env.provider.task_status(task)
        if st.state == "ok":
            return
        if st.state == "error":
            raise DeployError(f"the Proxmox task failed: {st.message}")
        if env.clock() - t0 > timeout:
            raise DeployError("the Proxmox task was still running after 10 minutes; check its log in Proxmox")
        env.sleep(env.poll_interval)


def exec_prune(rt, db, m: SnapshotPrune, plan_row, known) -> dict:
    from . import ops
    d = _dep(db, m.deployment_id)
    did = str(d.id)
    jid = ops._job_id(db, plan_row)
    lease = Lease(rt, did, jid, ops.STOP_EVENTS.get(jid))
    lease.acquire()
    deleted, kept, failed = [], [], []
    try:
        env = guard_env(ops._env_factory(rt, {"slug": d.slug, "id": did, "created_by": str(plan_row.requested_by), "plan": {}}), lease)
        prov = env.provider
        from ..providers.base import VmRef
        with rt.session() as d2:
            vms = _vms(d2, did)
        for vm, ref in sorted(vms.items()):
            r = VmRef(ref["node"], int(ref["vmid"]), "vm", d.slug)
            names = [s["name"] for s in prov.list_snapshots(r)]
            mine = selected(names, m.older_than)
            kept += [f"{vm}/{n}" for n in names if n not in mine]
            for n in mine:
                lease.check()
                try:
                    _wait(env, prov.delete_snapshot(r, n))
                    deleted.append(f"{vm}/{n}")
                except Exception as e:   # one stuck snapshot must not hide the others; reported and the job fails at the end
                    failed.append(f"{vm}/{n}: {str(e)[:160]}")
    finally:
        lease.release()
    audit.append(db, "deployment.snapshots.pruned", actor_name="worker", resource="deployment", resource_id=did,
                 details={"slug": d.slug, "older_than": m.older_than.isoformat(), "deleted": deleted, "failed": failed, "kept": len(kept)})
    if failed:
        raise DeployError(f"{len(failed)} snapshot(s) could not be deleted: " + "; ".join(failed)[:600])
    return {"deployment_id": d.slug, "deleted": deleted, "kept": kept}
