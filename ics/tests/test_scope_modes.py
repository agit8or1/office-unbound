"""Scope modes (single_node / whole_cluster) and the scope-change flow. Proxmox is the stateful SIMULATOR (a test double) shaped like the owner's
cluster: 6 nodes pve01 pve2 pve3 pve04 pve05 pve06, PVE06-Storage (lvmthin, local to pve06), ha-zfs (shared), PBS1. Passing here proves the ICS logic against the
simulator's model of PVE's permission system, not that the real cluster behaves identically (docs/status/provider-scope-modes.md)."""
import json

import pytest
from pydantic import ValidationError
from sqlalchemy import text

from ics import worker
from ics.providers import base
from ics.providers.base import ScopeViolation, VmCloneSpec
from ics.providers.proxmox import provisioning as pp, scope_change as scm
from ics.provisioning import service as psvc
from ics.provisioning.model import Policy
from ics.provisioning.scope_model import ScopeTarget
from .infra_fixtures import H, job  # noqa: F401
from .test_provisioning import POLICY, admin, direct, mutations_for, owner, preview, mode_a, reader, run_script, w  # noqa: F401
from ics.providers.proxmox.provider import EndpointScope

SINGLE = {**POLICY, "scope_mode": "single_node"}
WHOLE = {**POLICY, "scope_mode": "whole_cluster", "scope": {**POLICY["scope"], "nodes": []}}


def facts_of(srv):
    with admin(srv) as a:
        return pp.collect_facts(a)


# ======================================================================================= the single-node permission plan
def test_single_node_plan_has_no_cluster_wide_grant_no_shared_storage_no_migrate(owner):
    pl = pp.plan_for(Policy.model_validate(SINGLE), facts_of(owner))
    assert not pl.blocked, pl.blocked
    acl_paths = {s.detail["path"] for s in pl.steps if s.kind == "acl"}
    assert acl_paths == {"/nodes/pve06", "/pool/officeunbound-pve06", "/storage/PVE06-Storage", "/vms/9612", "/vms/131", "/sdn/zones/localnetwork/vmbr0"}
    assert "/" not in acl_paths and "/nodes" not in acl_paths and not any("ha-zfs" in p or "PBS1" in p for p in acl_paths)
    privs = set().union(*(set(s.detail["privileges"]) for s in pl.steps if s.kind == "role"))
    assert "VM.Migrate" not in privs and "Sys.Modify" not in privs
    # Sys.Audit is only on the node path, never on pool/storage paths
    d = pp.design_from_plan(pl, Policy.model_validate(SINGLE))
    audit_paths = {a.path for a in d.acl if "Sys.Audit" in d.roles[a.cap][1]}
    assert audit_paths == {"/nodes/pve06"}
    assert pl.facts["scope_mode"] == "single_node"


def test_every_restriction_is_labelled_proxmox_or_ics(owner):
    pl = pp.plan_for(Policy.model_validate(SINGLE), facts_of(owner))
    by = {e.control: e.enforced_by for e in pl.enforcement}
    assert by["Node visibility: only pve06"] == "proxmox" and by["Disk placement: node-local storage only"] == "proxmox"
    assert by["Which node a new guest is created on"] == "both" and by["Pool and network names are cluster-wide"] == "ics"
    assert by["No moving guests between nodes (VM.Migrate)"] == "proxmox"
    assert any("cluster-wide by name" in w for w in pl.warnings)                  # localnetwork zone caveat is stated


def test_shared_storage_refused_unless_explicit_high_risk_override(owner):
    pol = {**SINGLE, "scope": {**SINGLE["scope"], "storages": ["PVE06-Storage", "ha-zfs"]}}
    pl = pp.plan_for(Policy.model_validate(pol), facts_of(owner))
    assert any("ha-zfs" in b and "shared" in b for b in pl.blocked)
    ov = pp.plan_for(Policy.model_validate({**pol, "scope_risk_overrides": ["shared_storage:ha-zfs"]}), facts_of(owner))
    assert not ov.blocked and ov.risk == "high" and any("HIGH RISK" in w for w in ov.warnings) and ov.consequences
    assert any(s.risk == "high" and s.detail.get("path") == "/storage/ha-zfs" for s in ov.steps)


def test_single_node_refuses_migrate_cicustom_root_grants_and_templates_elsewhere(owner):
    with pytest.raises(ValidationError, match="VM.Migrate"):
        Policy.model_validate({**SINGLE, "allow_migrate": True})
    assert "VM.Migrate" in pp.role_privileges("deploy", Policy.model_validate({**SINGLE, "allow_migrate": True, "scope_risk_overrides": ["migrate"]}), 9)
    with pytest.raises(ValidationError, match="Sys.Modify"):
        Policy.model_validate({**SINGLE, "allow_cicustom": True})
    with pytest.raises(ValidationError):
        Policy.model_validate({**SINGLE, "scope": {**SINGLE["scope"], "nodes": []}})
    with pytest.raises(ValidationError):
        Policy.model_validate({"preset": "full_admin", "acknowledge_full_admin": True, "scope_mode": "single_node", "scope": {"nodes": ["pve06"], "pools": ["p"]}})
    cust = {"preset": "custom", "capabilities": ["deploy", "custom"], "scope_mode": "single_node", "scope": SINGLE["scope"]}
    for path in ("/", "/nodes", "/nodes/pve01", "/vms", "/storage"):
        pl = pp.plan_for(Policy.model_validate({**cust, "custom_grants": [{"path": path, "privileges": ["VM.Audit"]}]}), facts_of(owner))
        assert any("custom grant" in b for b in pl.blocked), path
    owner.sim.vms[131]["node"] = "pve05"
    pl = pp.plan_for(Policy.model_validate(SINGLE), facts_of(owner))
    assert any("template 131 lives on node pve05" in b for b in pl.blocked)


def test_whole_cluster_plan_audits_all_nodes_allows_shared_storage_and_migrate(owner):
    pol = {**WHOLE, "scope": {**WHOLE["scope"], "storages": ["PVE06-Storage", "ha-zfs"]}, "allow_migrate": True}
    pl = pp.plan_for(Policy.model_validate(pol), facts_of(owner))
    assert not pl.blocked, pl.blocked
    acl = {s.detail["path"]: s.detail["propagate"] for s in pl.steps if s.kind == "acl"}
    assert acl["/nodes"] == 1 and "/storage/ha-zfs" in acl and "/nodes/pve06" not in acl and "/" not in acl
    assert sorted(pl.policy["scope"]["nodes"]) == ["pve01", "pve04", "pve05", "pve06", "pve2", "pve3"]      # broker allowlist = the nodes found now
    assert any("VM.Migrate" in s.detail.get("privileges", []) for s in pl.steps if s.kind == "role")


# ======================================================================================= verification / drift
def test_injected_cluster_wide_grant_is_caught_by_verification_and_drift(owner):
    pol, pl, d, res, f = direct(owner, SINGLE)
    r = reader(owner, *res.secrets["inventory"])
    ok = pp.verify_token(r, d, pol, "inventory", sorted(f.nodes), sorted(f.storages))
    assert ok["ok"] and ok["scope_reach"] == []
    # somebody grants the monitor role on /nodes (all nodes) to the service account and its token
    for typ, ug in (("user", "ics-svc@pve"), ("token", "ics-svc@pve!ics-inv")):
        owner.sim.acl_entries.append({"path": "/nodes", "type": typ, "ugid": ug, "roleid": "OfficeUnboundMonitor", "propagate": 1})
    bad = pp.verify_token(r, d, pol, "inventory", sorted(f.nodes), sorted(f.storages))
    assert not bad["ok"] and any(x["path"] == "/nodes" and x["enforced_by"] == "proxmox" for x in bad["scope_reach"])
    assert bad["unauthorized_exposure"]                                                        # /nodes/pve01 etc. now readable
    dr = pp.drift_check(r, pol, {}, d, "inventory")
    assert not dr["ok"] and any(x["path"] == "/nodes" and "every node" in x["reaches"] for x in dr["scope_reach"])
    assert any("beyond the single-node scope" in s for s in dr["suggestion"])


def test_root_grant_is_also_flagged(owner):
    pol, pl, d, res, f = direct(owner, SINGLE)
    r = reader(owner, *res.secrets["provision"])
    for typ, ug in (("user", "ics-svc@pve"), ("token", "ics-svc@pve!ics-prov")):
        owner.sim.acl_entries.append({"path": "/", "type": typ, "ugid": ug, "roleid": "OfficeUnboundStorage", "propagate": 1})
    dr = pp.drift_check(r, pol, {}, d, "provision")
    assert not dr["ok"] and any(x["path"] == "/" and "cluster root" in x["reaches"] for x in dr["scope_reach"])


# ======================================================================================= the broker (ICS-enforced half)
def spec(**kw):
    d = dict(template_vmid=9612, template_node="pve06", new_vmid=2301, name="app01", pool="officeunbound-pve06", storage="PVE06-Storage", deployment_id="d1")
    d.update(kw)
    return VmCloneSpec(**d)


def test_broker_refuses_clone_to_pve05_even_when_proxmox_would_allow(owner, job):
    pol, pl, d, res, f = direct(owner, SINGLE)
    tid, sec = res.secrets["provision"]
    wide = EndpointScope(pools=("officeunbound-pve06",), storage=("PVE06-Storage",), networks=("vmbr0",), templates=(9612, 131), protected=(126,), nodes=("pve05", "pve06"))
    m_wide = mutations_for(owner, tid, sec, scope=wide)
    m_wide.clone_vm(spec(new_vmid=2300, target_node="pve05"))               # Proxmox (the simulator's PVE model) has no node restriction for pool members
    assert owner.sim.vms[2300]["node"] == "pve05"
    m = mutations_for(owner, tid, sec)                                       # scope nodes = (pve06,)
    n = len(owner.sim.seen)
    with pytest.raises(ScopeViolation, match="target node 'pve05'"):
        m.clone_vm(spec(target_node="pve05"))
    assert len(owner.sim.seen) == n and 2301 not in owner.sim.vms


# ======================================================================================= scope change (pure computation)
def stored_for(pol, res, d):
    return {"pve_major": d.major, "roles": {c: n for c, (n, _) in d.roles.items()}, "tokens": dict(d.tokens), "zones": {"vmbr0": "localnetwork"}}


def test_scope_diff_single_to_whole_and_narrowing_refusals(owner):
    pol, pl, d, res, f = direct(owner, SINGLE)
    st = pp.stored_design(pl)
    from ics.provisioning import actions as pa
    mg = pa._merge_managed({}, res)
    f2 = facts_of(owner)
    sc = scm.build(pol, st, ScopeTarget(mode="whole_cluster"), f2, mg)
    assert sc.direction == "widen" and sc.risk == "high" and not sc.blocked
    add = {(r["path"], tuple(r["subjects"])) for r in sc.diff["acl_add"]}
    assert any(p == "/nodes" for p, _ in add)
    assert [r["path"] for r in sc.diff["acl_remove"]] == ["/nodes/pve06"]
    assert sc.diff["ics_allowlist"]["nodes"]["after"] == ["pve01", "pve04", "pve05", "pve06", "pve2", "pve3"]
    assert {c["node"]: c["change"] for c in sc.impact["capacity"]}["pve05"] == "added"
    # narrow back while a managed guest lives on pve05 -> refused; explicit detach -> allowed but high risk
    wide = sc.new
    owner.sim.add_vm(500, "pve05", "guest-x", tags="ou-managed;ou-deployment-d9", pool="officeunbound-pve06")
    f3 = facts_of(owner)
    st2 = {**st}
    back = scm.build(wide, st2, ScopeTarget(mode="single_node", nodes=["pve06"]), f3, mg)
    assert back.direction == "narrow" and back.blocked and "500" in back.blocked[0] and "detach" in back.blocked[0]
    ok = scm.build(wide, st2, ScopeTarget(mode="single_node", nodes=["pve06"], detach_orphans=True), f3, mg)
    assert not ok.blocked and ok.detach == [500] and ok.risk == "high"
    del owner.sim.vms[500]
    clean = scm.build(wide, st2, ScopeTarget(mode="single_node", nodes=["pve06"]), facts_of(owner), mg)
    assert clean.direction == "narrow" and clean.risk == "normal" and not clean.blocked


# ======================================================================================= scope change through the action pipeline (Mode A)
CREDS = lambda srv: {"admin_username": "root@pam", "admin_password": srv.sim.ROOT_PW}  # noqa: E731


def provisioned_single(w, owner):
    pv, p, j = mode_a(w, owner, SINGLE)
    assert j["status"] == "succeeded", j
    return j["result"]["endpoint_id"]


def scope_preview(w, owner, eid, target, **extra):
    p, j = w.run("provider.provision.plan_preview", {"endpoint_id": eid, "purpose": "scope_change", "scope_target": target, **CREDS(owner), **extra})
    assert j["status"] == "succeeded", j
    return j["result"]


def apply_scope(w, owner, eid, pv, **extra):
    return w.run("provider.scope.change", {"endpoint_id": eid, "preview_id": pv["preview_id"], "plan_hash": pv["plan_hash"], "direction": pv["direction"],
                                           "detach": bool(pv["scope"]["detach"]), **CREDS(owner), **extra})


def sim_paths(owner):
    return sorted({e["path"] for e in owner.sim.acl_entries if e["ugid"].startswith("ics-svc@pve")})


def test_scope_change_widen_then_narrow_updates_pve_and_allowlists_atomically(w, owner, rt):
    eid = provisioned_single(w, owner)
    assert "/nodes/pve06" in sim_paths(owner) and "/nodes" not in sim_paths(owner)
    pv = scope_preview(w, owner, eid, {"mode": "whole_cluster"})
    assert pv["direction"] == "widen" and pv["risk"] == "high" and not pv["blocked"]
    p, j = apply_scope(w, owner, eid, pv)
    assert p["risk"] == "high" and p["approvals_required"] == 2 and j["status"] == "succeeded", j
    paths = sim_paths(owner)
    assert "/nodes" in paths and "/nodes/pve06" not in paths and "/" not in paths
    with rt.session() as db:
        ep = db.execute(text("SELECT allowed_nodes, allowed_storage FROM endpoints WHERE id = :i"), {"i": eid}).first()
        st = db.execute(text("SELECT policy, status, last_verification FROM endpoint_policy WHERE endpoint_id = :i"), {"i": eid}).first()
        assert sorted(ep.allowed_nodes) == ["pve01", "pve04", "pve05", "pve06", "pve2", "pve3"] and st.policy["scope_mode"] == "whole_cluster"
        assert st.last_verification["ok"] and st.status == "ok"
    v = w.v.get(f"{H}/providers/{eid}/permissions").json()
    assert v["scope_mode"] == "whole_cluster" and any(g["path"] == "/nodes" and g["propagate"] for g in v["grants"])
    # a managed guest on another node: narrowing is refused at plan time (409), nothing changed
    owner.sim.add_vm(500, "pve05", "guest-x", tags="ou-managed;ou-deployment-d9", pool="officeunbound-pve06")
    blocked = scope_preview(w, owner, eid, {"mode": "single_node", "nodes": ["pve06"]})
    assert blocked["blocked"] and blocked["direction"] == "narrow"
    w.plan("provider.scope.change", {"endpoint_id": eid, "preview_id": blocked["preview_id"], "plan_hash": blocked["plan_hash"], "direction": "narrow",
                                     **CREDS(owner)}, expect=409)
    before = list(owner.sim.changes)
    # explicit detach is a separately approved, high-risk choice
    det = scope_preview(w, owner, eid, {"mode": "single_node", "nodes": ["pve06"], "detach_orphans": True})
    assert not det["blocked"] and det["scope"]["detach"] == [500] and det["risk"] == "high"
    w.plan("provider.scope.change", {"endpoint_id": eid, "preview_id": det["preview_id"], "plan_hash": det["plan_hash"], "direction": "narrow",
                                     "detach": False, **CREDS(owner)}, expect=409)                   # cannot drop the detach flag to get a cheaper approval
    assert owner.sim.changes == before
    p2, j2 = apply_scope(w, owner, eid, det)
    assert p2["risk"] == "high" and j2["status"] == "succeeded", j2
    assert "/nodes/pve06" in sim_paths(owner) and "/nodes" not in sim_paths(owner)
    with rt.session() as db:
        assert db.execute(text("SELECT allowed_nodes FROM endpoints WHERE id = :i"), {"i": eid}).scalar() == ["pve06"]
        assert db.execute(text("SELECT managed FROM endpoint_policy WHERE endpoint_id = :i"), {"i": eid}).scalar()["detached_guests"] == [500]


def test_plain_narrowing_is_normal_risk_and_widening_needs_high(w, owner, rt):
    eid = provisioned_single(w, owner)
    wide = scope_preview(w, owner, eid, {"mode": "single_node", "nodes": ["pve05", "pve06"]})        # pve05 + pve06
    assert wide["direction"] == "widen" and wide["risk"] == "high"
    p, j = apply_scope(w, owner, eid, wide)
    assert j["status"] == "succeeded" and {"/nodes/pve05", "/nodes/pve06"} <= set(sim_paths(owner))
    nar = scope_preview(w, owner, eid, {"mode": "single_node", "nodes": ["pve06"]})
    assert nar["direction"] == "narrow" and nar["risk"] == "normal" and not nar["blocked"]
    p2, j2 = apply_scope(w, owner, eid, nar)
    assert p2["risk"] == "normal" and p2["approvals_required"] == 1 and j2["status"] == "succeeded", j2
    assert "/nodes/pve05" not in sim_paths(owner)


def test_failed_verification_restores_previous_permissions(w, owner, rt, monkeypatch):
    eid = provisioned_single(w, owner)
    pv = scope_preview(w, owner, eid, {"mode": "whole_cluster"})
    from ics.provisioning import actions as pa
    monkeypatch.setattr(pa, "_verify_all", lambda *a, **k: {"ok": False, "inventory": {"ok": False, "missing": [], "unexpected": [], "forbidden": [], "unauthorized_exposure": [], "scope_reach": [], "verbs": []}})
    before = sim_paths(owner)
    p, j = apply_scope(w, owner, eid, pv)
    assert j["status"] == "failed" and sim_paths(owner) == before
    with rt.session() as db:
        assert db.execute(text("SELECT allowed_nodes FROM endpoints WHERE id = :i"), {"i": eid}).scalar() == ["pve06"]


def test_ics_allowlist_mismatch_is_drift(w, owner, rt):
    eid = provisioned_single(w, owner)
    with rt.session() as db:
        from ics.actions import trust_binding
        e = db.execute(text("SELECT * FROM endpoints WHERE id = :i"), {"i": eid}).first()
        nodes = ["pve05", "pve06"]       # a (hypothetical) out-of-band change that also re-bound the credential: only the drift check can notice it
        db.execute(text("UPDATE endpoints SET allowed_nodes = :n, trust_binding = :b WHERE id = :i"),
                   {"i": eid, "n": nodes, "b": trust_binding(e.base_url, e.token_id, e.fingerprint_sha256, e.ca_pem, nodes)})
        db.commit()
    with rt.session() as db:
        ep = db.execute(text("SELECT * FROM endpoints WHERE id = :i"), {"i": eid}).first()
        st = db.execute(text("SELECT * FROM endpoint_policy WHERE endpoint_id = :i"), {"i": eid}).first()
        rep = psvc.check_endpoint(rt, db, ep, st)
        db.commit()
    assert not rep["ok"] and not rep["ics_scope"]["ok"] and rep["ics_scope"]["enforced_by"] == "ics"


# ======================================================================================= Mode B (customer runs the package)
def test_scope_change_mode_b_package_is_idempotent_and_confirm_updates_allowlists(w, owner, rt, tmp_path):
    eid = provisioned_single(w, owner)
    pv = scope_preview(w, owner, eid, {"mode": "whole_cluster"})
    p, j = w.run("provider.scope.package", {"endpoint_id": eid, "preview_id": pv["preview_id"], "plan_hash": pv["plan_hash"], "direction": "widen"})
    assert p["risk"] == "high" and j["status"] == "succeeded", j
    pkg = j["result"]["package_id"]
    files = w.ad.get(f"{H}/providers/{eid}/provisioning/packages/{pkg}").json()["files"]
    assert "remove_acl" in files["provision.sh"] and "ensure_acl /nodes " in files["provision.sh"] and "rollback" in files["rollback.sh"].lower()
    blob = " ".join(files.values())
    assert owner.sim.ROOT_PW not in blob
    confirm = {"endpoint_id": eid, "preview_id": pv["preview_id"], "plan_hash": pv["plan_hash"], "direction": "widen", "execution": "confirm_package", "package_id": pkg}
    pc, jc = w.run("provider.scope.change", confirm)
    assert jc["status"] == "failed" and "package been run" in jc["error"]["message"]                # Proxmox does not match yet: nothing committed
    with rt.session() as db:
        assert db.execute(text("SELECT allowed_nodes FROM endpoints WHERE id = :i"), {"i": eid}).scalar() == ["pve06"]
    r1 = run_script(owner, tmp_path, files["provision.sh"], "1")
    assert r1.returncode == 0, r1.stderr
    assert "NEW API TOKEN SECRET" not in r1.stdout and "/nodes" in sim_paths(owner) and "/nodes/pve06" not in sim_paths(owner)
    changed, writes = list(owner.sim.changes), len(owner.sim.write_calls)
    r2 = run_script(owner, tmp_path, files["provision.sh"], "2")
    assert r2.returncode == 0 and "changes made: 0" in r2.stdout
    assert owner.sim.changes == changed and len(owner.sim.write_calls) == writes                      # second run: zero changes, zero writes
    pc2, jc2 = w.run("provider.scope.change", confirm)
    assert jc2["status"] == "succeeded", jc2.get("error")
    with rt.session() as db:
        assert sorted(db.execute(text("SELECT allowed_nodes FROM endpoints WHERE id = :i"), {"i": eid}).scalar()) == ["pve01", "pve04", "pve05", "pve06", "pve2", "pve3"]
    # the rollback script restores the single-node scope
    r3 = run_script(owner, tmp_path, files["rollback.sh"], "rb")
    assert r3.returncode == 0, r3.stderr
    assert "/nodes/pve06" in sim_paths(owner) and "/nodes" not in sim_paths(owner)


def test_r5_l6_mode_b_confirm_refuses_when_a_managed_guest_appeared_outside_the_new_scope(w, owner, rt, tmp_path):
    eid = provisioned_single(w, owner)
    p, j = apply_scope(w, owner, eid, scope_preview(w, owner, eid, {"mode": "whole_cluster"}))
    assert j["status"] == "succeeded", j
    pv = scope_preview(w, owner, eid, {"mode": "single_node", "nodes": ["pve06"]})          # nothing is outside yet: previews cleanly
    assert pv["direction"] == "narrow" and not pv["blocked"]
    p, j = w.run("provider.scope.package", {"endpoint_id": eid, "preview_id": pv["preview_id"], "plan_hash": pv["plan_hash"], "direction": "narrow"})
    assert j["status"] == "succeeded", j
    pkg = j["result"]["package_id"]
    files = w.ad.get(f"{H}/providers/{eid}/provisioning/packages/{pkg}").json()["files"]
    assert run_script(owner, tmp_path, files["provision.sh"], "1").returncode == 0
    owner.sim.add_vm(500, "pve05", "guest-x", tags="ou-managed;ou-deployment-d9", pool="officeunbound-pve06")      # appears between preview and confirm
    confirm = {"endpoint_id": eid, "preview_id": pv["preview_id"], "plan_hash": pv["plan_hash"], "direction": "narrow", "execution": "confirm_package", "package_id": pkg}
    pc, jc = w.run("provider.scope.change", confirm)
    assert jc["status"] == "failed" and "outside the new scope" in jc["error"]["message"], jc
    with rt.session() as db:
        assert sorted(db.execute(text("SELECT allowed_nodes FROM endpoints WHERE id = :i"), {"i": eid}).scalar()) == ["pve01", "pve04", "pve05", "pve06", "pve2", "pve3"]


def test_customer_policy_applies_to_scope_actions():
    from ics.tenancy import policy as tp
    class P:  # noqa: D401
        direction = "widen"
    assert tp.classify("provider.scope.change", P()) == (True, "expand_permissions")
    P.direction = "narrow"
    assert tp.classify("provider.scope.change", P()) == (True, None)
    assert tp.classify("provider.scope.package", P())[0] is True
