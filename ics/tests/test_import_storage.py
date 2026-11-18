"""Image import storage (golden images, image.import) authorized through the access wizard: the write token gets exactly Datastore.AllocateTemplate +
Datastore.Audit on the import storage (never AllocateSpace), the endpoint allowlist includes it, a missing `import` content type is added with the
administrator's sign-in as a disclosed plan step (existing content kept exactly, restored on failure), and image.import works afterwards. Simulator."""
import hashlib

import pytest
from sqlalchemy import text

from ics import imageimport
from ics.providers import base
from ics.providers.proxmox import provisioning as pp
from ics.provisioning.model import Policy
from .test_admin_session import run_as_admin, sign_in, w  # noqa: F401  (fixture)
from .test_image_import import BLOB
from .test_image_import_action import configure, floor  # noqa: F401  (fixture)
from .test_manage_access import _acl_by_token, _connect_policy, change
from .test_provisioning import owner, reader  # noqa: F401  (fixture)

ALL = ["pve01", "pve2", "pve3", "pve04", "pve05", "pve06"]
SCOPE = {"nodes": ["pve06"], "pools": ["office-unbound"], "storages": ["PVE06-Storage"], "networks": ["vmbr0"], "protected_vmids": [126]}
IMPORT_PRIVS = {"Datastore.AllocateTemplate", "Datastore.Audit"}


def _pol(**scope):
    return {"preset": "deploy", "scope_mode": "single_node", "scope": {**SCOPE, **scope}}


def _local(owner, content="iso,vztmpl,backup,import"):  # noqa: F811
    owner.sim.add_storage("local", type_="dir", content=content, shared=False, nodes=list(ALL))


def _preview(w, owner, pol):  # noqa: F811
    s = sign_in(w, owner)
    _, j = run_as_admin(w, "provider.provision.plan_preview", {"name": "owner", "base_url": owner.url, "fingerprint_sha256": owner.fingerprint,
                                                               "admin_session": s["id"], "policy": pol})
    assert j["status"] == "succeeded", j
    return j["result"]["plan"]


def _allowed_storage(rt, eid):
    with rt.session() as db:
        return sorted(db.execute(text("SELECT allowed_storage FROM endpoints WHERE id = :i"), {"i": eid}).scalar() or [])


def test_import_storage_on_every_node_is_granted_upload_only_and_verified(w, owner, rt):  # noqa: F811
    _local(owner)
    pv, eid = _connect_policy(w, owner, _pol(import_storages=["local"]))
    notes = [e for e in pv["plan"]["enforcement"] if e["control"] == "Image import storage local"]
    assert notes and notes[0]["enforced_by"] == "proxmox"
    assert ("The permission covers local on every node: Office Unbound can upload import files there on any node; it cannot place VM disks there"
            in notes[0]["detail"])
    acl = _acl_by_token(owner)
    imp = [r for p, r in acl["ics-prov"] if p == "/storage/local"]
    assert imp == ["OfficeUnboundImageImport"], acl["ics-prov"]
    assert not any(p == "/storage/local" for p, _ in acl["ics-inv"])                       # the read token gets nothing on it
    assert set(owner.sim.roles["OfficeUnboundImageImport"]) == IMPORT_PRIVS                   # never Datastore.AllocateSpace
    assert _allowed_storage(rt, eid) == ["PVE06-Storage", "local"]
    # post-apply verification with the write token itself: exactly the new privileges, and nothing more
    pol = Policy.model_validate(pv["plan"]["policy"])
    d = pp.design(pol, 9)
    tid = "ics-svc@pve!ics-prov"
    r = pp.verify_token(reader(owner, tid, owner.sim.tokens[tid]["secret"]), d, pol, "provision", ALL, sorted(owner.sim.storages))
    assert r["ok"], r
    assert r["expected"]["/storage/local"] == sorted(IMPORT_PRIVS)
    assert {"verb": "image_import", "ok": True, "missing": []} in r["verbs"]
    owner.sim.roles["OfficeUnboundImageImport"] = set(IMPORT_PRIVS) | {"Datastore.AllocateSpace"}      # someone widens the role in Proxmox
    r2 = pp.verify_token(reader(owner, tid, owner.sim.tokens[tid]["secret"]), d, pol, "provision", ALL, sorted(owner.sim.storages))
    assert not r2["ok"] and any(x["path"] == "/storage/local" and "Datastore.AllocateSpace" in x["privileges"] for x in r2["unexpected"]), r2


def _storage_steps(plan):
    return [[st["kind"], st["op"], st["target"], st["detail"]] for st in plan["steps"] if st["kind"] == "storage"]


def test_missing_import_content_is_added_with_the_sign_in_and_existing_content_is_kept_exactly(w, owner, rt):  # noqa: F811
    _local(owner, content="iso,vztmpl,backup,snippets")
    pv, eid = _connect_policy(w, owner, _pol(import_storages=["local"]))
    plan = pv["plan"]
    assert not plan["blocked"]
    assert _storage_steps(plan) == [["storage", "modify", "local", {"change": "content_add", "add": "import", "before": ["iso", "vztmpl", "backup", "snippets"],
                                                                     "after": ["iso", "vztmpl", "backup", "snippets", "import"], "storage_type": "dir"}]]
    assert any(c.startswith("Adds the 'import' content type to storage local on every node where it is defined; existing content is unchanged")
               for c in plan["consequences"]), plan["consequences"]
    assert owner.sim.storages["local"]["content"].split(",") == ["iso", "vztmpl", "backup", "snippets", "import"]   # nothing dropped, nothing else added
    assert _allowed_storage(rt, eid) == ["PVE06-Storage", "local"]
    assert [c for c in owner.sim.changes if c.startswith("storage~")] == ["storage~local:iso,vztmpl,backup,snippets,import"]


def test_import_content_is_not_touched_when_present(w, owner):  # noqa: F811
    _local(owner)
    pv, _ = _connect_policy(w, owner, _pol(import_storages=["local"]))
    assert _storage_steps(pv["plan"]) == [] and not any("content type" in c for c in pv["plan"]["consequences"])
    assert not any(c.startswith("storage~") for c in owner.sim.changes)
    assert owner.sim.storages["local"]["content"] == "iso,vztmpl,backup,import"


def test_a_storage_type_without_import_support_is_refused(w, owner):  # noqa: F811
    owner.sim.add_storage("zfs06", type_="zfspool", content="images,rootdir", nodes=["pve06"])
    plan = _preview(w, owner, _pol(import_storages=["zfs06"]))
    assert any("storage zfs06 is of type zfspool, which cannot hold the `import` content type" in b for b in plan["blocked"]), plan["blocked"]
    assert not _storage_steps(plan)


def _failing_verification(monkeypatch):
    from ics.provisioning import actions as pa
    bad = {"ok": False, "missing": [{"path": "/storage/local", "privileges": ["Datastore.Audit"]}], "unexpected": [], "forbidden": [],
           "unauthorized_exposure": [], "scope_reach": [], "verbs": []}
    monkeypatch.setattr(pa, "_verify_all", lambda *a, **k: {"provision": bad, "ok": False})


def test_a_failed_apply_restores_the_previous_content(w, owner, monkeypatch):  # noqa: F811
    _local(owner, content="iso,vztmpl,backup")
    s = sign_in(w, owner)
    base_ = {"name": "owner", "base_url": owner.url, "fingerprint_sha256": owner.fingerprint, "admin_session": s["id"]}
    _, j = run_as_admin(w, "provider.provision.plan_preview", {**base_, "policy": _pol(import_storages=["local"])})
    assert j["status"] == "succeeded" and _storage_steps(j["result"]["plan"])
    _failing_verification(monkeypatch)
    _, j2 = run_as_admin(w, "provider.provision.apply", {**base_, "preview_id": j["result"]["preview_id"], "plan_hash": j["result"]["plan_hash"]})
    assert j2["status"] == "failed", j2
    assert "storage~local:iso,vztmpl,backup,import" in owner.sim.changes                   # it was added ...
    assert owner.sim.storages["local"]["content"] == "iso,vztmpl,backup"                    # ... and put back exactly


def test_import_storage_that_can_hold_disks_on_other_nodes_stays_blocked(w, owner):  # noqa: F811
    owner.sim.add_storage("dirdisks", type_="dir", content="images,import", shared=False, nodes=list(ALL))
    plan = _preview(w, owner, _pol(import_storages=["dirdisks"]))
    assert any(b.startswith("storage dirdisks is also available on") for b in plan["blocked"]), plan["blocked"]


def test_import_storage_only_with_the_deploy_preset():
    with pytest.raises(ValueError, match="deploy preset"):
        Policy.model_validate({"preset": "monitoring", "scope_mode": "single_node", "scope": {"nodes": ["pve06"], "import_storages": ["local"]}})
    with pytest.raises(ValueError):
        Policy.model_validate(_pol(import_storages=["bad name"]))


def test_scope_change_adds_the_import_storage_later_and_image_import_uses_it(w, owner, rt, tmp_path, floor, monkeypatch):  # noqa: F811
    _local(owner, content="iso,vztmpl,backup")              # the real cluster: local has no `import` yet; the change enables it from the UI
    _, eid = _connect_policy(w, owner, _pol())
    before = _acl_by_token(owner)
    assert not any(p == "/storage/local" for p, _ in before["ics-prov"])
    assert _allowed_storage(rt, eid) == ["PVE06-Storage"]
    m = imageimport.ImageImport.model_validate(dict(endpoint_id=eid, pve_node="pve06", release="r1", expected_sha256=hashlib.sha256(BLOB).hexdigest(),
                                                    import_storage="local", target_storage="PVE06-Storage", pool="office-unbound"))
    configure(rt, tmp_path)
    with rt.session() as db:
        with pytest.raises(Exception, match="local"):
            imageimport.precheck(db, rt, m)                                                   # not authorized yet
    pv, p, j = change(w, owner, eid, {"mode": "single_node", "nodes": ["pve06"], "import_storages": ["local"]})
    assert pv["direction"] == "widen" and j["status"] == "succeeded", j
    assert [x["storage"] for x in pv["scope"]["diff"]["storage_content"]] == ["local"]
    assert any(n.startswith("Adds the 'import' content type to storage local") for n in pv["scope"]["impact"]["notes"])
    assert owner.sim.storages["local"]["content"] == "iso,vztmpl,backup,import"
    after = _acl_by_token(owner)
    assert after["ics-prov"] - before["ics-prov"] == {("/storage/local", "OfficeUnboundImageImport")}
    assert after["ics-inv"] == before["ics-inv"]
    assert _allowed_storage(rt, eid) == ["PVE06-Storage", "local"]
    with rt.session() as db:
        x = imageimport.precheck(db, rt, m)
        assert x["image"]["sha256"] == hashlib.sha256(BLOB).hexdigest()
        # and the granted rights are enough for the real upload + import against the simulator (upload: AllocateTemplate; import-from: Audit)
        with base.job_execution("test-import"):
            r = imageimport.exec_import(rt, db, m, None, [])
    vm = owner.sim.vms[r["vmid"]]
    assert vm["cfg"]["template"] == 1 and vm["pool"] == "office-unbound" and r["volid"].startswith("local:import/")


def test_a_failed_scope_change_restores_the_previous_content(w, owner, rt, monkeypatch):  # noqa: F811
    _local(owner, content="iso,vztmpl,backup")
    _, eid = _connect_policy(w, owner, _pol())
    before = _acl_by_token(owner)
    _failing_verification(monkeypatch)
    pv, p, j = change(w, owner, eid, {"mode": "single_node", "nodes": ["pve06"], "import_storages": ["local"]})
    assert j["status"] == "failed", j
    assert "storage~local:iso,vztmpl,backup,import" in owner.sim.changes
    assert owner.sim.storages["local"]["content"] == "iso,vztmpl,backup"
    assert _acl_by_token(owner) == before and _allowed_storage(rt, eid) == ["PVE06-Storage"]


def test_mode_b_package_adds_import_content_and_its_rollback_restores_it():
    pol = Policy.model_validate(_pol(import_storages=["local"]))
    facts = pp.Facts(version="9.2.21", major=9, nodes={n: "online" for n in ALL},
                     storages={"local": {"type": "dir", "shared": False, "content": "iso,vztmpl,backup", "nodes": list(ALL), "node_restricted": False},
                               "PVE06-Storage": {"type": "lvmthin", "shared": False, "content": "images,rootdir", "nodes": ["pve06"], "node_restricted": True}},
                     pools={"office-unbound"}, networks={"vmbr0": "localnetwork"}, bridge_nodes={"vmbr0": {"pve06"}})
    plan = pp.plan_for(pol, facts)
    assert not plan.blocked, plan.blocked
    d = pp.design_from_plan(plan, Policy.model_validate(plan.policy))
    assert "ensure_import_content local" in pp.generate_script(plan, d, {})
    assert "pvesm set local --content iso,vztmpl,backup   # restores the previous content types" in pp.generate_rollback(plan, d)
    assert "pvesm set local --content iso,vztmpl,backup,import" in pp.command_list(plan, d)
