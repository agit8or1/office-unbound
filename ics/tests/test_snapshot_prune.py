"""deployment.snapshots.prune: deletes only the executor's own ou-pre-change-<time> snapshots older than the cutoff, on the deployment's own VMs."""
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text

from ics.deploy import snapshots
from ics.providers.base import TaskRef

from .test_deploy_exec import _active, actors, env, job, submit  # noqa: F401


def _arm(prov):
    prov.snaps = {}
    def lst(ref):
        prov.calls.append(("list_snapshots", ref.vmid, ref.deployment_id))
        return [{"name": n, "snaptime": 0} for n in prov.snaps.get(ref.vmid, [])]
    def dele(ref, name):
        prov.calls.append(("delete_snapshot", ref.vmid, name))
        prov.snaps[ref.vmid].remove(name)
        return TaskRef(ref.node, f"del{len(prov.calls)}", ref.vmid, "delsnapshot", ref.deployment_id)
    prov.list_snapshots, prov.delete_snapshot = lst, dele


def test_names_and_cutoff_select_only_our_older_snapshots():
    cut = datetime(2026, 11, 25, 16, 0, tzinfo=UTC)
    names = ["ou-pre-change-20261123T223340", "ou-pre-change-20261125T161041", "ou-pre-change", "before-upgrade", "ou-pre-change-2026"]
    assert snapshots.selected(names, cut) == ["ou-pre-change-20261123T223340"]


def test_prune_deletes_old_own_snapshots_and_keeps_new_and_foreign_ones(client, actors, rt, env):  # noqa: F811
    _active(actors, rt, users=30)
    prov = env.provider
    _arm(prov)
    for vmid in prov.vms:
        prov.snaps[vmid] = ["ou-pre-change-20261123T223340", "ou-pre-change-20261124T184627", "ou-pre-change-29991231T000000", "admin-manual"]
    cut = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    r, jid = submit(actors, rt, "deployment.snapshots.prune", {"deployment_id": "prod", "older_than": cut}, approvals=1)
    j = job(actors[0], jid)
    assert r["risk"] == "normal" and j["status"] == "succeeded", j
    for vmid, left in prov.snaps.items():
        assert left == ["ou-pre-change-29991231T000000", "admin-manual"], (vmid, left)
    assert len(j["result"]["deleted"]) == 2 * len(prov.vms)
    assert all(c[2] == "prod" for c in prov.calls if c[0] == "list_snapshots")       # every VM checked as the deployment's own
    with rt.session() as db:
        a = db.execute(text("SELECT details FROM audit_events WHERE action = 'deployment.snapshots.pruned' ORDER BY id DESC LIMIT 1")).scalar()
    assert a and len(a["deleted"]) == 2 * len(prov.vms) and a["failed"] == []


def test_a_recent_cutoff_a_naive_time_and_an_unknown_deployment_are_refused(client, actors, rt, env):  # noqa: F811
    _active(actors, rt, users=30)
    submit(actors, rt, "deployment.snapshots.prune", {"deployment_id": "prod", "older_than": datetime.now(UTC).isoformat()}, expect=422)
    submit(actors, rt, "deployment.snapshots.prune", {"deployment_id": "prod", "older_than": "2026-11-20T00:00:00"}, expect=422)
    submit(actors, rt, "deployment.snapshots.prune", {"deployment_id": "ghost", "older_than": "2026-11-20T00:00:00Z"}, expect=404)


def test_the_real_provider_refuses_any_other_snapshot_name():
    from ics.providers.proxmox import provider as pp
    assert pp._OWN_SNAP.match("ou-pre-change-20261125T161041")
    for bad in ("admin-manual", "ou-pre-change", "ou-pre-change-20261125T161041x", "../x", "ou-pre-change-2026112T161041"):
        assert not pp._OWN_SNAP.match(bad), bad
