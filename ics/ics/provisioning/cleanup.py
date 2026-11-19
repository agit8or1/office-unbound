"""provider.cleanup: remove what Office Unbound left on a cluster, using TEMPORARY administrator credentials (owner request 2026-11-19: "enter root
credentials like the setup wizard ... it won't store the credentials").

Credentials: exactly the wizard's TempCreds (a Proxmox sign-in session incl. second factor, admin user+password such as root@pam, or an admin
token). They are plan secrets (ics/provisioning/actions.py): never in params, audit or job results, valid for TEMP_CRED_TTL, decrypted only inside
the job and wiped when it ends; a wizard sign-in session is destroyed after use (SESSION_FINAL).

What it removes, decided at plan time from the inventory and AGAIN in the job from the live cluster (nothing is removed on disagreement):
  * guests/templates chosen by VM id that `leftovers.leftover_reason` accepts (superseded golden-image templates; stopped ou-managed guests of
    destroyed deployments), inside the endpoint's pools and nodes, never protected guests;
  * optionally every uploaded golden-image file (`<storage>:import/ou-golden-*.qcow2`) on the endpoint's nodes and storages: image.import only
    stages the upload there (the template keeps its own disk copy) and never reuses a file it did not upload itself; skipped entirely while an
    image.import is queued or running.
The administrator credential can do more than this; the job never does: no other path is called."""
from __future__ import annotations

import re
import time
from urllib.parse import quote
from uuid import UUID

from pydantic import ConfigDict, Field, model_validator
from sqlalchemy import text
from sqlalchemy.orm import Session

from .. import audit
from ..proxmox import ProxmoxError
from ..runtime import Runtime
from . import leftovers
from .actions import TempCreds, _need_creds, open_admin, safe

IMPORT_FILE = re.compile(r"^import/ou-golden-[a-z0-9][a-z0-9.-]{0,60}?(-[0-9a-f]{8})?\.qcow2$")
MAX_GUESTS = 50


class ProviderCleanup(TempCreds):
    model_config = ConfigDict(extra="forbid")
    endpoint_id: UUID
    confirm_name: str = Field(max_length=63, description="the endpoint's name, typed again")
    vmids: list[int] = Field(default=[], max_length=MAX_GUESTS)
    import_files: bool = True

    @model_validator(mode="after")
    def _chk(self):
        self._shape()
        if len(set(self.vmids)) != len(self.vmids) or any(not 100 <= v <= 999_999_999 for v in self.vmids):
            raise ValueError("vmids must be distinct Proxmox VM ids")
        if not self.vmids and not self.import_files:
            raise ValueError("nothing to clean up: choose guests/templates and/or the uploaded image files")
        return self


def _import_busy(db: Session, endpoint_id: str) -> bool:
    return db.execute(text("SELECT 1 FROM jobs j JOIN plans p ON p.id = j.plan_id WHERE p.action = 'image.import' AND j.status IN ('queued','running') "
                           "AND p.params->>'endpoint_id' = :e LIMIT 1"), {"e": endpoint_id}).first() is not None


def precheck(db: Session, rt: Runtime, p: ProviderCleanup, ep) -> dict:
    from ..actions import PlanError
    if p.confirm_name != ep.name:
        raise PlanError(422, "confirm_name does not match the endpoint name")
    if not p.has_creds():
        raise PlanError(422, "temporary administrator credentials are required (they are used once by the job and never stored)")
    guests, tpls = leftovers._snapshot_rows(db, str(ep.id))
    items = []
    for v in p.vmids:
        if v in (ep.protected_vmids or ()):
            raise PlanError(403, f"guest {v} is protected")
        try:
            g, is_tpl, why = leftovers._classify(db, str(ep.id), v, guests, tpls)
        except leftovers.NotALeftover as e:
            raise PlanError(409, str(e)) from None
        items.append({"vmid": v, "name": g.get("name"), "template": is_tpl, "why": why})
    return {"cleanup": {"guests": items, "import_files": p.import_files,
                        "effect": "the listed guests/templates with all their disks, and the uploaded golden-image files, are deleted (cannot be undone)"}}


def _wait(cli, node: str, upid: str, timeout: float = 600.0) -> None:
    end = time.monotonic() + timeout
    while True:
        st = cli.get(f"/nodes/{quote(node)}/tasks/{quote(upid, safe='')}/status") or {}
        if st.get("status") == "stopped":
            if st.get("exitstatus") != "OK":
                raise ProxmoxError(f"Proxmox task {upid} ended with {st.get('exitstatus')}")
            return
        if time.monotonic() >= end:
            raise ProxmoxError(f"Proxmox task {upid} did not finish within {timeout:g}s")
        time.sleep(2.0)


def _live(cli) -> tuple[list[dict], list[dict], dict[int, dict]]:
    from ..providers.proxmox.provider import tags_of
    guests, tpls, raw = [], [], {}
    for r in cli.get("/cluster/resources?type=vm") or []:
        if r.get("type") not in ("qemu", "lxc"):
            continue
        row = {"vmid": int(r["vmid"]), "name": r.get("name"), "node": r.get("node"), "pool": r.get("pool"), "tags": tags_of(r.get("tags")),
               "status": r.get("status")}
        raw[row["vmid"]] = {**row, "type": r["type"], "template": bool(r.get("template"))}
        (tpls if r.get("template") else guests).append(row)
    return guests, tpls, raw


@safe
def exec_cleanup(rt: Runtime, db: Session, m: ProviderCleanup, plan, known: list[str]) -> dict:
    from ..providers.proxmox.provider import local_identity, tags_of
    me = local_identity()
    ep = db.execute(text("SELECT * FROM endpoints WHERE id = :i"), {"i": str(m.endpoint_id)}).first()
    if ep is None or ep.detached_at is not None:
        raise ProxmoxError("endpoint not found or removed")
    _need_creds(rt, m, plan)
    cli = open_admin(rt, m, ep.base_url, ep.ca_pem, ep.fingerprint_sha256, known)
    pools, nodes, stores = set(ep.allowed_pools or ()), set(ep.allowed_nodes or ()), set(ep.allowed_storage or ())
    removed, skipped, files = [], [], []
    guests, tpls, raw = _live(cli)
    deps, rec = leftovers._deployments(db), leftovers._recorded_vmids(db, str(ep.id))
    for v in m.vmids:
        r = raw.get(v)
        try:
            if r is None:
                raise leftovers.NotALeftover(f"guest {v} no longer exists")
            if r["pool"] not in pools or (nodes and r["node"] not in nodes) or v in (ep.protected_vmids or ()):
                raise leftovers.NotALeftover(f"guest {v} is outside this endpoint's pools/nodes or protected")
            why = leftovers.leftover_reason(r, r["template"], tpls, deps, rec)
            path = f"/nodes/{quote(r['node'])}/{'lxc' if r['type'] == 'lxc' else 'qemu'}/{v}"
            cfg = cli.get(path + "/config") or {}
            if me and me.matches(cfg):          # HARD RULE, independent of every tag: never the ICS's own VM
                raise leftovers.NotALeftover(f"guest {v} is the ICS host itself")
            if leftovers.OWNED_TAG not in tags_of(cfg.get("tags")):
                raise leftovers.NotALeftover(f"guest {v} does not carry {leftovers.OWNED_TAG} in its live configuration")
            if not r["template"] and (cli.get(path + "/status/current") or {}).get("status") != "stopped":
                raise leftovers.NotALeftover(f"guest {v} is not stopped")
        except leftovers.NotALeftover as e:
            skipped.append({"vmid": v, "reason": str(e)})
            continue
        _wait(cli, r["node"], cli.delete(path + "?purge=1&destroy-unreferenced-disks=1"))
        removed.append({"vmid": v, "name": r["name"], "template": r["template"], "why": why})
    if m.import_files:
        if _import_busy(db, str(ep.id)):
            skipped.append({"import_files": "an image import is queued or running on this endpoint; the uploaded files were left alone"})
        else:
            for n in sorted(nodes):
                for st in cli.get(f"/nodes/{quote(n)}/storage") or []:
                    sid = st.get("storage")
                    if sid not in stores or "import" not in str(st.get("content", "")).split(","):
                        continue
                    for c in cli.get(f"/nodes/{quote(n)}/storage/{quote(sid)}/content?content=import") or []:
                        volid = str(c.get("volid") or "")
                        if not volid.startswith(sid + ":") or not IMPORT_FILE.match(volid[len(sid) + 1:]):
                            continue
                        cli.delete(f"/nodes/{quote(n)}/storage/{quote(sid)}/content/{quote(volid, safe='')}")
                        files.append({"node": n, "volid": volid, "size": int(c.get("size") or 0)})
    audit.append(db, "provider.cleanup.done", actor_name="worker", resource="endpoint", resource_id=str(ep.id),
                 details={"removed": removed, "files": files, "skipped": skipped, "plan_id": str(plan.id)})
    return {"removed": removed, "files_deleted": files, "skipped": skipped,
            "credentials": "used for this job only; discarded when it ends"}
