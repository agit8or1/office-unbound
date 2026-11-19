"""Inventory sync (inventory/ledger.py): new / missing / moved / renamed / VMID identity changes are recorded and shown, NEVER granted; the
signed-in Manage-access discovery is annotated against the approved scope; a credential with MORE rights than approved stops mutations."""
from sqlalchemy import text

from ics.inventory import collector
from ics.provisioning import service as psvc
from .infra_fixtures import H
from .test_admin_session import run_as_admin, sign_in, w  # noqa: F401  (fixture)
from .test_provisioning import owner  # noqa: F401  (fixture)

POL = {"preset": "operations", "scope": {"nodes": ["pve06"], "pools": ["officeunbound-pve06"], "managed_vmids": [105, 106], "protected_vmids": [126]}}


def connect(w, owner):  # noqa: F811
    owner.sim.add_vm(105, "pve06", "app-a", status="running", storage="PVE06-Storage")
    owner.sim.add_vm(106, "pve06", "app-b", kind="lxc", status="running", storage="PVE06-Storage")
    owner.sim.add_vm(107, "pve06", "not-selected", status="running", storage="PVE06-Storage")
    s = sign_in(w, owner)
    base = {"name": "owner", "base_url": owner.url, "fingerprint_sha256": owner.fingerprint, "admin_session": s["id"]}
    _, j = run_as_admin(w, "provider.provision.plan_preview", {**base, "policy": POL})
    assert j["status"] == "succeeded", j
    _, j2 = run_as_admin(w, "provider.provision.apply", {**base, "preview_id": j["result"]["preview_id"], "plan_hash": j["result"]["plan_hash"]})
    assert j2["status"] == "succeeded", j2
    return j2["result"]["endpoint_id"]


def collect(rt, eid):
    with rt.session() as db:
        r = collector.collect_discovery(rt, db, eid)
    assert r["ok"], r
    return r


def access(w, eid):
    r = w.ad.get(f"{H}/endpoints/{eid}/access", headers=w.adh)
    assert r.status_code == 200, r.text
    return {(x["kind"], x["key"]): x for x in r.json()["resources"]}, r.json()["counts"]


def test_first_sync_is_the_baseline_and_changes_are_recorded_not_granted(w, owner, rt):  # noqa: F811
    eid = connect(w, owner)
    collect(rt, eid)
    res, counts = access(w, eid)
    assert counts["new"] == 0 and res[("guest", "105")]["authorization"] == "operated" and res[("guest", "105")]["state"] == "known"
    assert ("guest", "107") not in res                                              # the restricted token cannot see unselected guests
    owner.sim.add_vm(140, "pve06", "fresh-in-pool", status="stopped", storage="PVE06-Storage", pool="officeunbound-pve06")
    owner.sim.vms[105]["name"] = owner.sim.vms[105]["cfg"]["name"] = "app-a-renamed"
    del owner.sim.vms[106]
    r = collect(rt, eid)
    assert r["changes"] == {"new": 1, "changed": 1, "missing": 1}
    res, counts = access(w, eid)
    assert res[("guest", "140")]["state"] == "new" and res[("guest", "140")]["authorization"] == "deployment_pool"
    assert res[("guest", "105")]["state"] == "renamed" and res[("guest", "105")]["change"] == {"was": "app-a", "now": "app-a-renamed"}
    assert res[("guest", "106")]["state"] == "missing"
    assert w.ad.get(f"{H}/infra/summary", headers=w.adh).json()["new_resources"] >= 2
    # reviewing never authorizes anything
    with rt.session() as db:
        before = db.execute(text("SELECT allowed_pools, managed_vmids FROM endpoints WHERE id = :i"), {"i": eid}).first()
    assert w.o.post(f"{H}/endpoints/{eid}/access/acknowledge", json={}, headers=w.oh).json()["acknowledged"] == 2
    res, counts = access(w, eid)
    assert counts["new"] == 0 and res[("guest", "105")]["state"] == "known" and res[("guest", "106")]["state"] == "missing"
    with rt.session() as db:
        after = db.execute(text("SELECT allowed_pools, managed_vmids FROM endpoints WHERE id = :i"), {"i": eid}).first()
    assert tuple(before) == tuple(after) and 140 not in after.managed_vmids


def test_a_reused_vmid_is_an_identity_change_not_the_same_guest(w, owner, rt):  # noqa: F811
    eid = connect(w, owner)
    collect(rt, eid)
    del owner.sim.vms[105]
    owner.sim.add_vm(105, "pve06", "someone-elses", kind="lxc", status="running", storage="PVE06-Storage")
    owner.sim.acl_entries += []          # the sim keeps the /vms/105 ACL; real Proxmox removes it on destroy. The ICS still flags the identity change.
    collect(rt, eid)
    res, _ = access(w, eid)
    assert res[("guest", "105")]["state"] == "identity_changed"
    assert res[("guest", "105")]["change"]["was"]["type"] == "vm" and res[("guest", "105")]["change"]["now"]["type"] == "lxc"


def test_a_vmid_reused_after_the_guest_went_missing_is_a_new_guest_not_a_rename(w, owner, rt):  # noqa: F811
    """2026-11-19 on pve06: test VM 148 was destroyed (recorded missing), and the next golden-image import got VMID 148: the cluster page
    showed "1 authorized resource(s) were renamed, moved or re-created". A new guest under a reused ID is new, never a rename."""
    eid = connect(w, owner)
    owner.sim.add_vm(148, "pve06", "c-000000000000-e2e-fo6-files", status="stopped", storage="PVE06-Storage", pool="officeunbound-pve06")
    collect(rt, eid)
    assert w.o.post(f"{H}/endpoints/{eid}/access/acknowledge", json={}, headers=w.oh).status_code == 200
    del owner.sim.vms[148]
    assert collect(rt, eid)["changes"]["missing"] == 1
    owner.sim.add_vm(148, "pve06", "ou-tpl-ubuntu-2404", status="stopped", storage="PVE06-Storage", pool="officeunbound-pve06")
    assert collect(rt, eid)["changes"] == {"new": 1, "changed": 0, "missing": 0}
    res, counts = access(w, eid)
    assert res[("guest", "148")]["state"] == "new" and res[("guest", "148")]["change"] is None and res[("guest", "148")]["name"] == "ou-tpl-ubuntu-2404"
    assert counts["changed"] == 0 and counts["missing"] == 0
    # the same guest coming back (same name, e.g. access restored) is the same identity: no change, no rename (going missing already asked
    # for a fresh review, so it shows unreviewed until acknowledged)
    w.o.post(f"{H}/endpoints/{eid}/access/acknowledge", json={}, headers=w.oh)
    held = owner.sim.vms.pop(148)
    collect(rt, eid)
    owner.sim.vms[148] = held
    assert collect(rt, eid)["changes"] == {"new": 0, "changed": 0, "missing": 0}
    res, counts = access(w, eid)
    assert res[("guest", "148")]["state"] == "new" and res[("guest", "148")]["change"] is None and counts["changed"] == 0


def _record_deployment_vm(rt, eid, vmid, status="active"):
    with rt.session() as db:
        d = db.execute(text("INSERT INTO deployments (slug, customer_id, profile, profile_version, endpoint_id, status, desired_spec) "
                            "VALUES (:s, 'c-000000000000', 'custom', '1.0.0', :e, :st, '{}'::jsonb) RETURNING id"),
                       {"s": f"led-{vmid}", "e": eid, "st": status}).scalar()
        db.execute(text("INSERT INTO deployment_resources (deployment_id, kind, logical_name, provider_ref, desired, state) "
                        "VALUES (:d, 'vm', 'vm1', CAST(:r AS jsonb), '{}'::jsonb, 'present')"), {"d": d, "r": f'{{"node": "pve06", "vmid": {vmid}}}'})
        db.commit()


def _record_import(rt, eid, vmid, name):
    with rt.session() as db:
        u = db.execute(text("SELECT id FROM users LIMIT 1")).scalar()
        p = db.execute(text("INSERT INTO plans (action, params, risk, status, requested_by) VALUES ('image.import', CAST(:pa AS jsonb), 'high', "
                            "'approved', :u) RETURNING id"), {"pa": f'{{"endpoint_id": "{eid}"}}', "u": u}).scalar()
        db.execute(text("INSERT INTO jobs (plan_id, action, status, result) VALUES (:p, 'image.import', 'succeeded', CAST(:r AS jsonb))"),
                   {"p": p, "r": f'{{"vmid": {vmid}, "template": "{name}", "node": "pve06"}}'})
        db.commit()


def test_guests_office_unbound_created_are_not_reported_as_new(w, owner, rt):  # noqa: F811
    """2026-11-19: every sample deployment showed "2 new infrastructure resource(s) discovered" for its own two VMs. VMs a live deployment
    records and templates a successful image.import created are Office Unbound's own (decided from its records, never from Proxmox tags);
    everything else is still reported."""
    eid = connect(w, owner)
    collect(rt, eid)
    _record_deployment_vm(rt, eid, 150)
    _record_import(rt, eid, 152, "ou-tpl-ubuntu-2404")
    for v, n in ((150, "c-000000000000-x-id"), (151, "someone-elses"), (153, "tagged-but-not-ours")):
        owner.sim.add_vm(v, "pve06", n, status="running", storage="PVE06-Storage", pool="officeunbound-pve06")
    owner.sim.add_vm(152, "pve06", "ou-tpl-ubuntu-2404", status="stopped", storage="PVE06-Storage", pool="officeunbound-pve06", template=True)
    r = collect(rt, eid)
    res, counts = access(w, eid)
    assert res[("guest", "150")]["state"] == "known"                        # our deployment's VM
    assert res[("guest", "151")]["state"] == "new" and res[("guest", "153")]["state"] == "new"
    assert res[("guest", "152")]["state"] == "known" and res[("guest", "152")]["type"].startswith("template-")   # our imported template
    assert counts["new"] == 2 and r["changes"]["new"] == 2
    # cloned first, recorded after (the deployment records the VMID once the clone exists): known on the next sync
    owner.sim.add_vm(154, "pve06", "c-000000000000-x-files", status="running", storage="PVE06-Storage", pool="officeunbound-pve06")
    collect(rt, eid)
    assert access(w, eid)[0][("guest", "154")]["state"] == "new"
    _record_deployment_vm(rt, eid, 154)
    collect(rt, eid)
    assert access(w, eid)[0][("guest", "154")]["state"] == "known"
    # a VMID recorded by a DESTROYED deployment is not ours any more: a new guest under it is reported
    _record_deployment_vm(rt, eid, 155, status="destroyed")
    owner.sim.add_vm(155, "pve06", "after-destroy", status="running", storage="PVE06-Storage", pool="officeunbound-pve06")
    collect(rt, eid)
    assert access(w, eid)[0][("guest", "155")]["state"] == "new"


def test_manage_access_discovery_shows_everything_annotated(w, owner, rt):  # noqa: F811
    eid = connect(w, owner)
    collect(rt, eid)
    s = sign_in(w, owner)
    inv = w.ad.get(f"{H}/pve-sessions/{s['id']}/inventory", params={"endpoint_id": eid}, headers=w.adh).json()
    g = {x["vmid"]: x for x in inv["guests"]}
    assert g[105]["authorization"] == "operated" and g[105]["seen"] is True
    assert g[107]["authorization"] == "not_authorized" and g[107]["seen"] is False          # visible only through the sign-in, never granted
    assert g[300]["authorization"] == "not_authorized" and g[126]["authorization"] == "protected"
    assert inv["approved_scope"]["managed_vmids"] == [105, 106]
    n = {x["name"]: x for x in inv["nodes"]}
    assert n["pve06"]["authorization"] == "authorized" and n["pve01"]["authorization"] == "not_authorized"


def test_excess_privileges_stop_mutations_until_reviewed(w, owner, rt):  # noqa: F811
    eid = connect(w, owner)
    owner.sim.roles["SomeoneAdded"] = {"VM.Audit", "VM.PowerMgmt", "VM.Config.Disk"}      # granted in Proxmox by someone else, outside any plan
    owner.sim.acl_entries.append({"path": "/vms/107", "type": "token", "ugid": "ics-svc@pve!ics-prov", "roleid": "SomeoneAdded", "propagate": 0})
    owner.sim.acl_entries.append({"path": "/vms/107", "type": "user", "ugid": "ics-svc@pve", "roleid": "SomeoneAdded", "propagate": 0})
    with rt.session() as db:
        ep = db.execute(text("SELECT * FROM endpoints WHERE id = :i"), {"i": eid}).first()
        st = db.execute(text("SELECT * FROM endpoint_policy WHERE endpoint_id = :i"), {"i": eid}).first()
        rep = psvc.check_endpoint(rt, db, ep, st)
        db.commit()
    assert rep["ok"] is False and any(e["path"] == "/vms/107" for e in rep["kinds"]["provision"]["unexpected"])
    p, j = run_as_admin(w, "guest.power", {"endpoint_id": eid, "vmid": 105, "op": "shutdown"})
    assert j["status"] == "failed" and "MORE privileges than were approved" in str(j["error"])
    assert owner.sim.vms[105]["status"] == "running"
