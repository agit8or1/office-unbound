"""Manage access (reusable wizard, edit mode): incremental add/remove of operated guests and deployment targets through provider.scope.change with the
wizard's sign-in session. Existing access, users and tokens are kept; removing access never deletes a guest; repeating a change is a no-op."""
from sqlalchemy import text

from .infra_fixtures import H
from .test_admin_session import run_as_admin, sign_in, w  # noqa: F401  (fixture)
from .test_provisioning import owner  # noqa: F401  (fixture)

POL = {"preset": "operations", "scope_mode": "single_node", "scope": {"nodes": ["pve06"], "managed_vmids": [105, 106], "protected_vmids": [126]}}


def connect(w, owner):  # noqa: F811
    for vmid, name in ((105, "app-a"), (106, "app-b"), (107, "app-c"), (108, "app-d")):
        owner.sim.add_vm(vmid, "pve06", name, status="running", storage="PVE06-Storage")
    s = sign_in(w, owner)
    base = {"name": "owner", "base_url": owner.url, "fingerprint_sha256": owner.fingerprint, "admin_session": s["id"]}
    _, j = run_as_admin(w, "provider.provision.plan_preview", {**base, "policy": POL})
    assert j["status"] == "succeeded", j
    _, j2 = run_as_admin(w, "provider.provision.apply", {**base, "preview_id": j["result"]["preview_id"], "plan_hash": j["result"]["plan_hash"]})
    assert j2["status"] == "succeeded", j2
    return j2["result"]["endpoint_id"]


def change(w, owner, eid, target, expect_blocked=False):  # noqa: F811
    s = sign_in(w, owner)
    _, j = run_as_admin(w, "provider.provision.plan_preview", {"endpoint_id": eid, "purpose": "scope_change", "scope_target": target, "admin_session": s["id"]})
    assert j["status"] == "succeeded", j
    pv = j["result"]
    if expect_blocked:
        return pv
    assert not pv["blocked"], pv["blocked"]
    p, j2 = run_as_admin(w, "provider.scope.change", {"endpoint_id": eid, "preview_id": pv["preview_id"], "plan_hash": pv["plan_hash"],
                                                       "direction": pv["direction"], "detach": bool(pv["scope"]["detach"]), "admin_session": s["id"]})
    return pv, p, j2


def svc_acl(owner):  # noqa: F811
    return sorted((e["path"], e["roleid"]) for e in owner.sim.acl_entries if e["ugid"] == "ics-svc@pve!ics-prov")


def test_add_guests_keeps_existing_access_users_and_tokens(w, owner, rt):  # noqa: F811
    eid = connect(w, owner)
    toks = {k: dict(v) for k, v in owner.sim.tokens.items() if k.startswith("ics-svc@pve")}
    before = svc_acl(owner)
    pv, p, j = change(w, owner, eid, {"mode": "single_node", "nodes": ["pve06"], "managed_vmids": [105, 106, 107, 108]})
    assert pv["direction"] == "widen" and pv["scope"]["diff"]["operated_added"] == [107, 108] and p["risk"] == "high"
    assert j["status"] == "succeeded", j
    after = svc_acl(owner)
    assert set(before) < set(after) and {x for x in after if x[0] in ("/vms/107", "/vms/108")}
    assert {k: v["secret"] for k, v in owner.sim.tokens.items() if k.startswith("ics-svc@pve")} == {k: v["secret"] for k, v in toks.items()}   # no new tokens
    assert sum(1 for u in owner.sim.users if u.startswith("ics-svc")) == 1
    with rt.session() as db:
        assert sorted(db.execute(text("SELECT managed_vmids FROM endpoints WHERE id = :i"), {"i": eid}).scalar()) == [105, 106, 107, 108]
    p2, j2 = run_as_admin(w, "guest.power", {"endpoint_id": eid, "vmid": 108, "op": "shutdown"})
    assert j2["status"] == "succeeded", j2


def test_remove_access_never_deletes_the_guest_and_revokes_only_that_guest(w, owner, rt):  # noqa: F811
    eid = connect(w, owner)
    pv, p, j = change(w, owner, eid, {"mode": "single_node", "nodes": ["pve06"], "managed_vmids": [105]})
    assert pv["direction"] == "narrow" and pv["scope"]["diff"]["operated_removed"] == [106]
    assert any("keep running in Proxmox untouched" in n for n in pv["scope"]["impact"]["notes"])
    assert j["status"] == "succeeded", j
    assert 106 in owner.sim.vms and owner.sim.vms[106]["status"] == "running"                      # access removal is not deletion
    paths = [x[0] for x in svc_acl(owner)]
    assert "/vms/106" not in paths and "/vms/105" in paths
    r = w.ad.post(f"{H}/plans", json={"action": "guest.power", "params": {"endpoint_id": eid, "vmid": 106, "op": "stop"}}, headers=w.adh)
    assert r.status_code == 403


def test_repeating_the_same_change_is_a_no_op(w, owner):  # noqa: F811
    eid = connect(w, owner)
    target = {"mode": "single_node", "nodes": ["pve06"], "managed_vmids": [105, 106, 107]}
    change(w, owner, eid, target)
    acl1, toks1 = svc_acl(owner), sorted(owner.sim.tokens)
    pv = change(w, owner, eid, target, expect_blocked=True)
    assert pv["direction"] == "same" and not pv["scope"]["diff"]["acl_add"] and not pv["scope"]["diff"]["acl_remove"]
    assert svc_acl(owner) == acl1 and sorted(owner.sim.tokens) == toks1


def test_operations_to_deploy_is_an_edit_but_monitoring_needs_a_new_token(w, owner):  # noqa: F811
    eid = connect(w, owner)
    pv = change(w, owner, eid, {"mode": "single_node", "nodes": ["pve06"], "preset": "monitoring"}, expect_blocked=True)
    assert any("different set of Proxmox tokens" in b for b in pv["blocked"])


def test_manage_access_sign_in_by_integration_uses_its_own_address_and_anchor(w, owner):  # noqa: F811
    eid = connect(w, owner)
    r = w.ad.post(f"{H}/pve-sessions", json={"endpoint_id": eid, "username": "root", "realm": "pam", "password": owner.sim.ROOT_PW}, headers=w.adh)
    assert r.status_code == 201, r.text
    s = r.json()
    assert s["base_url"] == owner.url and s["trust"] == "fingerprint"
    inv = w.ad.get(f"{H}/pve-sessions/{s['id']}/inventory", params={"endpoint_id": eid}, headers=w.adh).json()
    assert inv["approved_scope"]["managed_vmids"] == [105, 106]
    _, j = run_as_admin(w, "provider.provision.plan_preview", {"endpoint_id": eid, "purpose": "scope_change", "admin_session": s["id"],
                                                               "scope_target": {"mode": "single_node", "nodes": ["pve06"], "managed_vmids": [105]}})
    assert j["status"] == "succeeded", j
    bad = w.ad.post(f"{H}/pve-sessions", json={"endpoint_id": eid, "base_url": "https://evil.example:8006", "username": "root", "password": "x"}, headers=w.adh)
    assert bad.status_code == 422


def test_repair_rotate_and_disconnect_through_the_sign_in(w, owner, rt):  # noqa: F811
    eid = connect(w, owner)
    # someone removed an ACL Office Unbound needs -> repair puts back exactly the approved entry
    owner.sim.acl_entries = [e for e in owner.sim.acl_entries if not (e["path"] == "/vms/106" and e["ugid"].startswith("ics-svc@pve"))]
    s = sign_in(w, owner)
    _, j = run_as_admin(w, "provider.provision.plan_preview", {"endpoint_id": eid, "purpose": "reconcile", "admin_session": s["id"]})
    assert j["status"] == "succeeded", j
    pv = j["result"]
    _, j2 = run_as_admin(w, "provider.permissions.reconcile", {"endpoint_id": eid, "preview_id": pv["preview_id"], "plan_hash": pv["plan_hash"], "admin_session": s["id"]})
    assert j2["status"] == "succeeded", j2
    assert any(e["path"] == "/vms/106" and e["ugid"] == "ics-svc@pve!ics-prov" for e in owner.sim.acl_entries)
    # rotation: new secrets, same rights, old ones revoked
    old = {k: v["secret"] for k, v in owner.sim.tokens.items() if k.startswith("ics-svc@pve")}
    s2 = sign_in(w, owner)
    _, j3 = run_as_admin(w, "provider.token.rotate", {"endpoint_id": eid, "admin_session": s2["id"]})
    assert j3["status"] == "succeeded", j3
    new = {k: v["secret"] for k, v in owner.sim.tokens.items() if k.startswith("ics-svc@pve")}
    assert new and all(new.get(k) != v for k, v in old.items())
    p, j4 = run_as_admin(w, "guest.power", {"endpoint_id": eid, "vmid": 105, "op": "reboot"})
    assert j4["status"] == "succeeded", j4                                             # the rotated credential works
    # disconnect: tokens revoked, guests untouched
    s3 = sign_in(w, owner)
    _, j5 = run_as_admin(w, "provider.token.revoke", {"endpoint_id": eid, "confirm_name": "owner", "admin_session": s3["id"]})
    assert j5["status"] == "succeeded", j5
    assert not any(k.startswith("ics-svc@pve!") for k in owner.sim.tokens) and {105, 106, 107, 108} <= set(owner.sim.vms)
