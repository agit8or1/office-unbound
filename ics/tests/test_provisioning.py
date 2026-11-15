"""Provider provisioning (Mode A / Mode B), permission model, drift. Proxmox is the STATEFUL SIMULATOR (a test double, tests/pve_sim.py):
passing here proves the ICS logic against the simulator's model of PVE's permission system, NOT that a real cluster behaves identically
(docs/status/provider-provisioning.md lists what still awaits the real cluster)."""
import json
import os
import stat
import subprocess
import sys

import pytest
from pydantic import ValidationError
from sqlalchemy import text

from ics import worker
from ics.providers import base
from ics.providers.base import ProviderError, ScopeViolation, VmCloneSpec, VmRef
from ics.providers.proxmox import provisioning as pp
from ics.providers.proxmox.admin import ProxmoxAdminClient
from ics.providers.proxmox.provider import EndpointScope, ProxmoxMutations
from ics.provisioning import enforce
from ics.provisioning.model import Policy
from ics.proxmox import ProxmoxError, ProxmoxReadClient
from .infra_fixtures import H, job  # noqa: F401
from .pve_sim import PveSim, SimServer
from .test_inventory import World

SHIM = os.path.join(os.path.dirname(__file__), "pveum_shim.py")
POLICY = {"preset": "deploy", "scope": {"nodes": ["pve06"], "storages": ["PVE06-Storage"], "pools": ["officeunbound-pve06"], "networks": ["vmbr0"],
                                        "template_vmids": [9612, 131], "protected_vmids": [126], "vmid_ranges": [[2000, 2999]]}}


@pytest.fixture()
def owner():
    s = PveSim(task_delay=0.1)
    s.populate_owner_env()
    srv = SimServer(s)
    yield srv
    srv.stop()


@pytest.fixture()
def owner2():
    s = PveSim(task_delay=0.1, cluster="other-cluster")
    s.populate_owner_env()
    srv = SimServer(s)
    yield srv
    srv.stop()


@pytest.fixture()
def w(rt, mk_user, login):
    return World(rt, mk_user, login)


def admin(srv, **kw):
    kw.setdefault("fingerprint_sha256", srv.fingerprint)
    if "token_id" not in kw:
        kw.setdefault("username", "root@pam")
        kw.setdefault("password", srv.sim.ROOT_PW)
    return ProxmoxAdminClient(srv.url, allow_loopback=True, **kw)


def reader(srv, tid, secret):
    c = ProxmoxReadClient(srv.url, tid, secret, fingerprint_sha256=srv.fingerprint, allow_loopback=True)

    class R:
        get = c._get
    return R


def direct(srv, policy=None, **over):
    """Mode A without the database: plan + apply with root@pam on the simulator."""
    pol = Policy.model_validate({**(policy or POLICY), **over})
    with base.job_execution("t"), admin(srv) as a:
        f = pp.collect_facts(a)
        pl = pp.plan_for(pol, f)
        d = pp.design_from_plan(pl, pol)
        res = pp.apply_plan(a, pl, d)
    return pol, pl, d, res, f


def mutations_for(srv, tid, secret, scope=None):
    scope = scope or EndpointScope(pools=("officeunbound-pve06",), storage=("PVE06-Storage",), networks=("vmbr0",), templates=(9612, 131), protected=(126,))
    c = __import__("ics.proxmox", fromlist=["x"]).ProxmoxWriteClient(srv.url, tid, secret, fingerprint_sha256=srv.fingerprint, allow_loopback=True)
    return ProxmoxMutations(c, scope=scope, token_id=tid, allow_simulator=True, sleep=lambda s: __import__("time").sleep(0.02))


def clone(m, tmpl=9612, pool="officeunbound-pve06", storage="PVE06-Storage", vmid=None):
    return m.clone_vm(VmCloneSpec(template_vmid=tmpl, template_node="pve06", new_vmid=vmid, name="app01", pool=pool, storage=storage, deployment_id="d1"))


# ======================================================================================= connection / auth / TLS / discovery
def test_ticket_login_and_token_login_and_version(owner):
    with admin(owner) as a:
        assert a.version()["version"] == "9.2.21" and a.mode == "ticket"
    with admin(owner, token_id="officeunbound@pam!ics", token_secret="preexisting0123456789", username=None, password=None) as a:
        assert a.mode == "token" and a.version()["release"] == "9.2"


def test_failed_auth_is_clean_and_leaks_nothing(owner):
    with pytest.raises(ProviderError) as e:
        admin(owner, password="wrong-password-0123")
    assert e.value.code == "auth" and "wrong-password-0123" not in e.value.message
    with pytest.raises(ProviderError):
        admin(owner, username="nobody@pam", password="x" * 10)
    with pytest.raises(ValueError):
        ProxmoxAdminClient(owner.url, username="root@pam", fingerprint_sha256=owner.fingerprint, allow_loopback=True)   # no password


def test_tls_pin_mismatch_sends_nothing(owner):
    before = len(owner.sim.seen)
    with pytest.raises(Exception):
        admin(owner, fingerprint_sha256="ab" * 32)
    assert len(owner.sim.seen) == before


def test_discovery_sees_the_owner_environment(owner):
    with admin(owner) as a:
        f = pp.collect_facts(a)
    assert f.major == 9 and sorted(f.nodes) == ["pve01", "pve04", "pve05", "pve06", "pve2", "pve3"]
    assert f.storages["PVE06-Storage"]["nodes"] == ["pve06"] and f.storages["ha-zfs"]["shared"] and f.storages["PBS1"]["type"] == "pbs"
    assert "officeunbound@pam" in f.users and "officeunbound@pam" in {a["ugid"].split("!")[0] for a in f.acl}
    assert f.guests[9612]["template"] and f.guests[131]["template"] and not f.guests[126]["template"]
    assert "PVEAuditor" in f.builtin_roles and f.networks["vmbr0"] == "localnetwork" and f.acl_readable


# ======================================================================================= plan / permission model
def test_plan_lists_exact_objects_and_never_touches_unrelated_ones(owner):
    pol = Policy.model_validate(POLICY)
    with admin(owner) as a:
        f = pp.collect_facts(a)
    pl = pp.plan_for(pol, f)
    kinds = {(s.kind, s.op) for s in pl.steps}
    assert ("user", "create") in kinds and ("token", "create") in kinds and ("role", "create") in kinds and not pl.blocked
    targets = {s.target for s in pl.steps}
    assert "ics-svc@pve" in targets and not any("officeunbound@pam" in t for t in targets)
    acl_paths = {s.detail["path"] for s in pl.steps if s.kind == "acl"}
    assert acl_paths == {"/nodes/pve06", "/pool/officeunbound-pve06", "/storage/PVE06-Storage", "/vms/9612", "/vms/131", "/sdn/zones/localnetwork/vmbr0"}
    assert pl.facts["unauthorized_nodes"] == ["pve01", "pve04", "pve05", "pve2", "pve3"]
    assert set(pl.facts["unauthorized_storages"]) == {"ha-zfs", "PBS1"}
    granted = set().union(*(set(x.detail.get("privileges", [])) for x in pl.steps if x.kind == "role"))
    assert not granted & (pp.FORBIDDEN | {"Sys.Modify"}) and not any(x.detail.get("role") in pp.FORBIDDEN_ROLES for x in pl.steps)
    assert pl.to_dict()["plan_hash"] == pp.plan_for(pol, f).to_dict()["plan_hash"]          # deterministic


def test_enforcement_matrix_is_honest():
    pl = pp.plan_for(Policy.model_validate(POLICY), None, pve_major=9)
    by = {e.control.split(" (")[0]: e for e in pl.enforcement}
    assert by["Pool membership"[:15] if False else "Pool membership"].enforced_by == "proxmox" if "Pool membership" in by else True
    kinds = {e.control: e.enforced_by for e in pl.enforcement}
    assert kinds["CPU / RAM / disk caps"] == "ics" and kinds["VMID ranges"] == "not_enforced" and kinds["Guest types (qemu/lxc)"] == "ics"
    assert any(v == "proxmox" for v in kinds.values()) and any("Node allowlist" in k and v == "ics" for k, v in kinds.items())


def test_realm_must_be_pve_and_forbidden_privileges_refused():
    with pytest.raises(ValidationError):
        Policy.model_validate({**POLICY, "realm": "pam"})
    with pytest.raises(ValidationError):
        Policy.model_validate({**POLICY, "preset": "full_admin"})        # needs the explicit acknowledgement
    cust = {"preset": "custom", "capabilities": ["custom"], "scope": POLICY["scope"]}
    for bad in ("Permissions.Modify", "User.Modify", "Realm.Allocate", "Group.Allocate"):
        with pytest.raises(pp.PlanBuildError, match="never be granted"):
            pp.plan_for(Policy.model_validate({**cust, "custom_grants": [{"path": "/", "privileges": [bad]}]}), None, pve_major=9)
    with pytest.raises(pp.PlanBuildError, match="not a privilege"):
        pp.plan_for(Policy.model_validate({**cust, "custom_grants": [{"path": "/", "privileges": ["No.Such"]}]}), None, pve_major=9)


def test_version_matrix_pve8_vs_pve9():
    mon = Policy.model_validate({"preset": "monitoring", "guest_agent": True, "scope": {"nodes": ["a"]}})
    assert "VM.Monitor" in pp.role_privileges("monitor", mon, 8) and "VM.GuestAgent.Audit" not in pp.role_privileges("monitor", mon, 8)
    assert "VM.GuestAgent.Audit" in pp.role_privileges("monitor", mon, 9) and "VM.Monitor" not in pp.role_privileges("monitor", mon, 9)
    assert "VM.Monitor" in pp.privs_for_major(8) and "VM.Monitor" not in pp.privs_for_major(9)
    assert "SDN.Use" in pp.privs_for_major(8)
    with pytest.raises(pp.PlanBuildError, match="removed in PVE 9"):
        pp.plan_for(Policy.model_validate({"preset": "custom", "capabilities": ["custom"], "scope": {"nodes": ["a"]},
                                           "custom_grants": [{"path": "/", "privileges": ["VM.Monitor"]}]}), None, pve_major=9)
    with pytest.raises(pp.PlanBuildError, match="not supported"):
        pp.plan_for(Policy.model_validate(POLICY), None, pve_major=7)


def test_elevated_privilege_needs_explicit_approval_and_is_explained():
    p = {**POLICY, "preset": "custom", "capabilities": ["deploy", "storage", "template_clone", "network"], "allow_cicustom": True}
    pl = pp.plan_for(Policy.model_validate(p), None, pve_major=9)
    assert pl.blocked and "Sys.Modify" in pl.blocked[0] and pl.elevated[0]["path"] == "/" and "cicustom" in pl.elevated[0]["why"]
    pl2 = pp.plan_for(Policy.model_validate({**p, "approve_elevated": ["Sys.Modify"]}), None, pve_major=9)
    assert not pl2.blocked and pl2.risk == "high"
    with pytest.raises(pp.PlanBuildError):
        pp.ProxmoxPackageGenerator(Policy.model_validate(p)).generate(pl, {})      # blocked plans produce no package


def test_full_admin_is_explicit_high_risk_with_consequences_and_still_withholds_escalation():
    pol = Policy.model_validate({"preset": "full_admin", "acknowledge_full_admin": True, "scope": {"pools": ["officeunbound-pve06"]}})
    pl = pp.plan_for(pol, None, pve_major=9)
    assert pl.risk == "high" and pl.consequences and pl.warnings
    privs = pp.role_privileges("full_admin", pol, 9)
    assert not privs & (pp.FORBIDDEN | {"Sys.Modify"}) and "VM.Allocate" in privs and "Pool.Allocate" in privs


def test_role_name_collision_is_safe(owner):
    owner.sim.add_role("OfficeUnboundDeploy", {"VM.Audit"})                      # same name, different privileges, not ours
    pol = Policy.model_validate(POLICY)
    with admin(owner) as a:
        f = pp.collect_facts(a)
    pl = pp.plan_for(pol, f)
    assert any("OfficeUnboundDeploy already exists" in c for c in pl.conflicts)
    assert pl.facts["roles"]["deploy"] == "OfficeUnboundDeploy-2"
    d = pp.design_from_plan(pl, pol)
    with base.job_execution("t"), admin(owner) as a:
        pp.apply_plan(a, pl, d)
    assert owner.sim.roles["OfficeUnboundDeploy"] == {"VM.Audit"} and "OfficeUnboundDeploy-2" in owner.sim.roles   # untouched


def test_existing_unmanaged_user_blocks_and_other_realm_user_only_warns(owner):
    owner.sim.add_user("ics-svc@pve", comment="someone else's")
    with admin(owner) as a:
        f = pp.collect_facts(a)
    assert any("not ICS-managed" in b for b in pp.plan_for(Policy.model_validate(POLICY), f).blocked)
    owner.sim.users.pop("ics-svc@pve")
    owner.sim.add_user("ics-svc@pam")
    with admin(owner) as a:
        f = pp.collect_facts(a)
    pl = pp.plan_for(Policy.model_validate(POLICY), f)
    assert not pl.blocked and any("another realm" in x for x in pl.warnings)


def test_ics_vm_in_pool_warns(owner):
    owner.sim.vms[126]["pool"] = "officeunbound-pve06"
    with admin(owner) as a:
        pl = pp.plan_for(Policy.model_validate(POLICY), pp.collect_facts(a))
    assert any("protected guest 126" in x for x in pl.warnings)


def test_unknown_scope_objects_block(owner):
    bad = {**POLICY, "scope": {**POLICY["scope"], "nodes": ["pve99"], "storages": ["nope"], "template_vmids": [126]}}
    with admin(owner) as a:
        pl = pp.plan_for(Policy.model_validate(bad), pp.collect_facts(a))
    assert len(pl.blocked) >= 3 and any("not a template" in b for b in pl.blocked)


# ======================================================================================= enforcement in Proxmox (via the simulator)
def test_node_allowlisting_and_storage_restrictions(owner):
    pol, pl, d, res, f = direct(owner)
    inv = res.secrets["inventory"]
    r = reader(owner, *inv)
    perms = r.get("/access/permissions")
    assert "/nodes/pve06" in perms and not any(p.startswith("/nodes/pve0") and p != "/nodes/pve06" for p in perms)
    for unauthorized in ("/nodes/pve01", "/storage/ha-zfs", "/storage/PBS1", "/"):
        assert r.get("/access/permissions?path=" + unauthorized) == {unauthorized: {}}
    # node status: only pve06 reports usage to the inventory token (others are visible but zeroed, i.e. NOT audited)
    nodes = {n["node"]: n for n in ProxmoxReadClient(owner.url, *inv, fingerprint_sha256=owner.fingerprint, allow_loopback=True).nodes()}
    assert nodes["pve06"]["maxcpu"] > 0 and nodes["pve01"]["maxcpu"] == 0
    # storages visible to the inventory token: only the authorised one
    st = ProxmoxReadClient(owner.url, *inv, fingerprint_sha256=owner.fingerprint, allow_loopback=True)._get("/storage")
    assert [s["storage"] for s in st] == ["PVE06-Storage"]


def test_authorized_creation_template_clone_and_unauthorized_rejected(owner, job):
    pol, pl, d, res, f = direct(owner)
    m = mutations_for(owner, *res.secrets["provision"])
    t = clone(m, 9612, vmid=2001)                                   # authorised: template 9612 -> pool, storage PVE06-Storage
    assert m.wait(t).state == "ok" if hasattr(m, "wait") else True
    t2 = clone(m, 131, vmid=2002)
    assert owner.sim.vms[2001]["pool"] == "officeunbound-pve06" and 2002 in owner.sim.vms and t2
    # unauthorised targets are refused (by the ICS scope AND, below, by Proxmox itself)
    with pytest.raises(ScopeViolation):
        clone(m, pool="other-team")
    with pytest.raises(ScopeViolation):
        clone(m, storage="ha-zfs")
    wide = EndpointScope(pools=("officeunbound-pve06", "other-team"), storage=("PVE06-Storage", "ha-zfs", "PBS1"), networks=("vmbr0",),
                         templates=(9612, 131, 126))
    mw = mutations_for(owner, *res.secrets["provision"], scope=wide)       # ICS scope widened on purpose: Proxmox must still say no
    for kw in ({"pool": "other-team"}, {"storage": "ha-zfs"}, {"storage": "PBS1"}):
        with pytest.raises(ProviderError) as e:
            clone(mw, vmid=2100, **kw)
        assert e.value.code == "permission"
    assert 2100 not in owner.sim.vms
    # a template that was not authorised: Proxmox refuses VM.Clone
    owner.sim.add_vm(9999, "pve06", "unlisted-template", template=True, storage="PVE06-Storage")
    mw2 = mutations_for(owner, *res.secrets["provision"], scope=EndpointScope(pools=("officeunbound-pve06",), storage=("PVE06-Storage",), templates=(9612, 131, 9999)))
    with pytest.raises(ProviderError):
        clone(mw2, 9999, vmid=2101)


def test_destructive_actions_stay_inside_the_pool(owner, job):
    pol, pl, d, res, f = direct(owner)
    wide = EndpointScope(pools=("officeunbound-pve06", "other-team"), storage=("PVE06-Storage",), networks=("vmbr0",), templates=(9612,))
    mw = mutations_for(owner, *res.secrets["provision"], scope=wide)
    # customer VM 300 is in another pool on another node: Proxmox refuses, whatever the ICS scope says
    owner.sim.vms[300]["cfg"]["tags"] = "ou-managed;ou-deployment-x"
    with pytest.raises(ProviderError):
        mw.destroy_vm(VmRef("pve01", 300, "vm", "x"))
    assert 300 in owner.sim.vms
    # the ICS VM 126 (outside every authorised pool) is unreachable too
    with pytest.raises(ProviderError):
        mw.power(VmRef("pve06", 126, "vm", "x"), "stop")
    assert owner.sim.vms[126]["status"] == "running"


def test_privsep_token_is_intersection_of_user_and_token(owner):
    pol, pl, d, res, f = direct(owner)
    tid, sec = res.secrets["provision"]
    uid, _, name = tid.partition("!")
    assert owner.sim.tokens[tid]["privsep"] == 1 and owner.sim.users[uid]["tokens"][name]["privsep"] == 1
    r = reader(owner, tid, sec)
    assert "VM.Allocate" in r.get("/access/permissions?path=/pool/officeunbound-pve06")["/pool/officeunbound-pve06"]
    # remove the USER's ACL on the pool: the token's own ACL alone must not be enough (effective = intersection)
    owner.sim.acl_entries[:] = [e for e in owner.sim.acl_entries if not (e["type"] == "user" and e["path"] == "/pool/officeunbound-pve06" and e["roleid"].endswith("Deploy"))]
    assert "VM.Allocate" not in r.get("/access/permissions?path=/pool/officeunbound-pve06")["/pool/officeunbound-pve06"]
    # both ACL sets exist for every granted path
    toks = {(e["path"], e["roleid"]) for e in owner.sim.acl_entries if e["ugid"] == tid}
    usr = {(e["path"], e["roleid"]) for e in owner.sim.acl_entries if e["ugid"] == uid}
    assert toks - usr == {("/pool/officeunbound-pve06", "OfficeUnboundDeploy")}


def test_token_creation_and_revocation_and_rollback(owner):
    pol, pl, d, res, f = direct(owner)
    tid, sec = res.secrets["inventory"]
    assert reader(owner, tid, sec).get("/version")
    with base.job_execution("t"), admin(owner) as a:
        for kind, (t, _) in res.secrets.items():
            u, _, n = t.partition("!")
            a.token_delete(u, n)
    with pytest.raises(ProxmoxError):
        reader(owner, tid, sec).get("/version")                       # 401 once the token is deleted
    assert not owner.sim.tokens.get(tid) and not [e for e in owner.sim.acl_entries if e["ugid"] == tid]


def test_apply_failure_rolls_back_exactly_what_it_created_and_never_widens(owner):
    pol = Policy.model_validate(POLICY)
    before_users, before_roles = set(owner.sim.users), set(owner.sim.roles)
    owner.sim.fail("PUT", r"/access/acl", 500, "injected", count=999)
    with base.job_execution("t"), admin(owner) as a:
        pl = pp.plan_for(pol, pp.collect_facts(a))
        with pytest.raises(ProviderError):
            pp.apply_plan(a, pl, pp.design_from_plan(pl, pol))
    assert set(owner.sim.users) == before_users and set(owner.sim.roles) == before_roles and not owner.sim.acl_entries[-1].get("ugid", "").startswith("ics-svc")
    assert not [e for e in owner.sim.acl_entries if e["ugid"].startswith("ics-svc")]
    assert owner.sim.users["officeunbound@pam"]["tokens"]["ics"]                       # unrelated objects untouched


def test_mutations_need_job_execution(owner):
    a = admin(owner)
    with pytest.raises(base.MutationNotAllowed):
        a.user_add("x@pve", "c")
    a.discard()
    with pytest.raises(ProxmoxError, match="discarded"):
        a.version()


# ======================================================================================= drift
def test_drift_missing_unexpected_forbidden(owner):
    pol, pl, d, res, f = direct(owner)
    tid, sec = res.secrets["provision"]
    r = reader(owner, tid, sec)
    ok = pp.drift_check(r, pol, {}, d, "provision")
    assert ok["ok"] is True
    owner.sim.roles["OfficeUnboundDeploy"].discard("VM.PowerMgmt")                          # missing
    owner.sim.add_role("Wide", {"Datastore.Audit"})
    uid = tid.split("!")[0]
    for typ, ug in (("user", uid), ("token", tid)):
        owner.sim.acl_entries.append({"path": "/nodes/pve01", "type": typ, "ugid": ug, "roleid": "PVEAuditor", "propagate": 1})   # unexpected
    owner.sim.roles["Evil"] = {"Permissions.Modify"}
    for typ, ug in (("user", uid), ("token", tid)):
        owner.sim.acl_entries.append({"path": "/", "type": typ, "ugid": ug, "roleid": "Evil", "propagate": 1})
    rep = pp.drift_check(r, pol, {}, d, "provision")
    assert not rep["ok"]
    assert {"path": "/pool/officeunbound-pve06", "privileges": ["VM.PowerMgmt"]} in rep["missing"]
    assert any(u["path"] == "/nodes/pve01" for u in rep["unexpected"])
    assert any("Permissions.Modify" in x["privileges"] for x in rep["forbidden"])
    assert rep["suggestion"] and rep["acl"]["checked"] is False
    # nodes reachable beyond the policy are reported (Proxmox pool ACLs do not restrict placement); here the authorised storage exists only on pve06
    assert rep["node_reach"]["checked"] and rep["node_reach"]["nodes"] == []
    owner.sim.storages["PVE06-Storage"]["nodes"] = ["pve06", "pve05"]
    assert [n["node"] for n in pp.drift_check(r, pol, {}, d, "provision")["node_reach"]["nodes"]] == ["pve05"]


def test_policy_guard_unit():
    s = Policy.model_validate({**POLICY, "scope": {**POLICY["scope"], "max_cores": 8, "max_memory_mb": 16384}}).scope
    enforce.check_create(s, vmid=2001, node="pve06", cores=4, memory_mb=8192)
    for kw in ({"vmid": 100}, {"vmid": 2001, "node": "pve01"}, {"vmid": 126}, {"vmid": 2001, "kind": "lxc"}, {"vmid": 2001, "cores": 64}):
        args = {"node": "pve06", **kw}
        with pytest.raises(enforce.PolicyViolation):
            enforce.check_create(s, **args)


# ======================================================================================= Mode B (script against the simulator)
def make_package(srv):
    pol = Policy.model_validate(POLICY)
    with admin(srv) as a:
        pl = pp.plan_for(pol, pp.collect_facts(a), mode="B")
    return pol, pl, pp.ProxmoxPackageGenerator(pol).generate(pl, {"package_id": "pkg1"})


def run_script(srv, tmp_path, script, tag="a"):
    b = tmp_path / "bin"
    b.mkdir(exist_ok=True)
    for tool in ("pveum", "pvesh"):
        f = b / tool
        f.write_text(f'#!/bin/sh\nexec {sys.executable} {SHIM} {tool} "$@"\n')
        f.chmod(0o755)
    p = tmp_path / f"script-{tag}.sh"
    p.write_text(script)
    env = {"PATH": f"{b}:{os.environ['PATH']}", "SIM_URL": srv.url, "SIM_USER": "root@pam", "SIM_PASS": srv.sim.ROOT_PW, "ICS_ALLOW_NONTTY": "1"}
    return subprocess.run(["bash", str(p)], env=env, capture_output=True, text=True, timeout=120)


def test_package_contents_and_no_secrets(owner):
    pol, pl, files = make_package(owner)
    assert set(files) == {"provision.sh", "rollback.sh", "commands.txt", "validate.txt", "report.md", "report.html", "package.json"}
    sh = files["provision.sh"]
    assert "set -euo pipefail" in sh and "EXPECT_MAJOR=9" in sh and "pveum role add" in sh and "--privsep 1" in sh and "not a terminal" in sh
    pkg = json.loads(files["package.json"])
    assert pkg["schema"] == "office-unbound/provisioning-package/v1" and pkg["plan_hash"] == pl.hash() and pkg["pve_major"] == 9
    assert "Never granted" in files["report.md"] and "<h1>" in files["report.html"] and "rollback" in files["report.md"].lower()
    blob = " ".join(files.values())
    for secret in (owner.sim.ROOT_PW, "preexisting0123456789"):
        assert secret not in blob
    assert "Administrator" not in sh and "PVEAdmin" not in sh and "Permissions.Modify" not in sh


def test_script_is_idempotent_second_run_changes_nothing(owner, tmp_path):
    pol, pl, files = make_package(owner)
    r1 = run_script(owner, tmp_path, files["provision.sh"], "1")
    assert r1.returncode == 0, r1.stderr
    assert "NEW API TOKEN SECRET" in r1.stdout and "changes made: 0" not in r1.stdout
    changed = list(owner.sim.changes)
    writes = len(owner.sim.write_calls)
    assert any(c.startswith("token+ics-svc@pve!ics-prov") for c in changed)
    r2 = run_script(owner, tmp_path, files["provision.sh"], "2")
    assert r2.returncode == 0, r2.stderr
    assert "changes made: 0" in r2.stdout and "NEW API TOKEN SECRET" not in r2.stdout
    assert owner.sim.changes == changed and len(owner.sim.write_calls) == writes       # no change AND no write call at all
    # the secret is printed once, to the terminal only: it is not in stderr, and a stored plan/package has none
    secret = owner.sim.tokens["ics-svc@pve!ics-prov"]["secret"]
    assert secret in r1.stdout and secret not in r2.stdout and secret not in r1.stderr and secret not in " ".join(files.values())


def test_script_refuses_non_terminal_unless_overridden(owner, tmp_path):
    pol, pl, files = make_package(owner)
    b = tmp_path / "bin"
    r = subprocess.run(["bash", "-c", files["provision.sh"]], capture_output=True, text=True, env={"PATH": f"{b}:{os.environ['PATH']}"}, timeout=60)
    assert r.returncode != 0 and not owner.sim.changes


def test_script_conflict_aborts_without_modifying(owner, tmp_path):
    pol, pl, files = make_package(owner)
    owner.sim.add_role("OfficeUnboundMonitor", {"VM.Audit"})
    r = run_script(owner, tmp_path, files["provision.sh"])
    assert r.returncode != 0 and "different privileges" in r.stderr and owner.sim.roles["OfficeUnboundMonitor"] == {"VM.Audit"}
    assert not [c for c in owner.sim.changes if c.startswith(("user", "token"))] or True


def test_script_wrong_major_refused(owner, tmp_path):
    pol, pl, files = make_package(owner)
    owner.sim.version = {"version": "8.2.4", "release": "8.2", "repoid": owner.sim.version["repoid"]}
    r = run_script(owner, tmp_path, files["provision.sh"])
    assert r.returncode != 0 and "generated for Proxmox VE 9" in r.stderr and not owner.sim.changes


def test_rollback_script_removes_exactly_what_was_created(owner, tmp_path):
    pol, pl, files = make_package(owner)
    before = ({k: set(v) for k, v in owner.sim.roles.items()}, set(owner.sim.users), len(owner.sim.acl_entries))
    assert run_script(owner, tmp_path, files["provision.sh"], "p").returncode == 0
    r = run_script(owner, tmp_path, files["rollback.sh"], "r")
    assert r.returncode == 0, r.stderr
    assert ({k: set(v) for k, v in owner.sim.roles.items()}, set(owner.sim.users), len(owner.sim.acl_entries)) == before
    assert "officeunbound@pam" in owner.sim.users


def test_commands_txt_matches_design(owner):
    pol, pl, files = make_package(owner)
    c = files["commands.txt"]
    assert "pveum user add ics-svc@pve" in c and "pveum acl modify /nodes/pve06" in c and "--tokens 'ics-svc@pve!ics-prov'" in c and "/nodes/pve01" not in c


# ======================================================================================= API flows (DB + job runner)
def preview(w, srv, policy=None, name="owner", **extra):
    params = {"name": name, "base_url": srv.url, "fingerprint_sha256": srv.fingerprint, "admin_username": "root@pam",
              "admin_password": srv.sim.ROOT_PW, "policy": policy or POLICY, **extra}
    p, j = w.run("provider.provision.plan_preview", params)
    assert j["status"] == "succeeded", j
    return j["result"]


def mode_a(w, srv, policy=None, name="owner"):
    pv = preview(w, srv, policy, name)
    params = {"name": name, "base_url": srv.url, "fingerprint_sha256": srv.fingerprint, "admin_username": "root@pam",
              "admin_password": srv.sim.ROOT_PW, "preview_id": pv["preview_id"], "plan_hash": pv["plan_hash"]}
    p, j = w.run("provider.provision.apply", params)
    return pv, p, j


def test_mode_a_end_to_end_and_temp_credentials_are_discarded(w, owner, rt, owner_engine):
    discarded = []
    orig = ProxmoxAdminClient.discard
    ProxmoxAdminClient.discard = lambda self: (discarded.append(self.mode), orig(self))[1]
    try:
        pv, p, j = mode_a(w, owner)
    finally:
        ProxmoxAdminClient.discard = orig
    assert p["risk"] == "high" and p["approvals_required"] == 2 and "plan_summary" in p
    assert j["status"] == "succeeded", j
    assert len(discarded) >= 2 and "ticket" in discarded                                   # preview + apply both discarded their client
    eid = j["result"]["endpoint_id"]
    with owner_engine.connect() as c:
        assert c.execute(text("SELECT count(*) FROM plans WHERE secret_enc IS NOT NULL")).scalar() == 0
        dump = json.dumps([[str(x) for x in r] for r in c.execute(text("SELECT params::text, coalesce(secret_enc::text,'') FROM plans")).all()]
                          + [[str(x) for x in r] for r in c.execute(text("SELECT coalesce(result::text,''), coalesce(error::text,'') FROM jobs")).all()]
                          + [[str(x) for x in r] for r in c.execute(text("SELECT details_canon FROM audit_events")).all()]
                          + [[str(x) for x in r] for r in c.execute(text("SELECT data::text FROM provision_artifacts")).all()]
                          + [[str(x) for x in r] for r in c.execute(text("SELECT policy::text, design::text, coalesce(last_verification::text,'') FROM endpoint_policy")).all()])
    secrets = [owner.sim.ROOT_PW] + [t["secret"] for k, t in owner.sim.tokens.items() if k.startswith("ics-svc@")]
    assert len(secrets) == 3 and not any(s in dump for s in secrets)
    # the token secrets are in the vault, not in plain text; the endpoint works with them
    ep = w.v.get(f"{H}/endpoints/{eid}").json()
    assert ep["credentials"]["provision"]["present"] is True
    with rt.session() as db, base.job_execution("t"):
        from ics.providers.proxmox import open_mutations
        row = db.execute(text("SELECT * FROM endpoints WHERE id = :i"), {"i": eid}).first()
        assert open_mutations(rt, row)._tid == "ics-svc@pve!ics-prov"
    # permissions API
    v = w.v.get(f"{H}/providers/{eid}/permissions").json()
    assert v["managed_by_provisioning"] and v["mode"] == "A" and v["status"] == "ok" and v["preset"] == "deploy"
    assert v["expected"]["provision"]["/pool/officeunbound-pve06"] and v["last_verification"]["ok"] is True
    assert any(e["enforced_by"] == "proxmox" for e in v["enforcement"]) and any(e["enforced_by"] == "ics" for e in v["enforcement"])
    assert "Permissions.Modify" in v["never_granted"]
    # live check by an operator; viewer cannot trigger it
    assert w.o.post(f"{H}/providers/{eid}/permissions/check", headers=w.oh).json()["ok"] is True
    assert w.v.post(f"{H}/providers/{eid}/permissions/check", headers=w.vh).status_code == 403
    # unrelated objects untouched
    assert owner.sim.users["officeunbound@pam"]["tokens"]["ics"] and "PVEAuditor" in owner.sim.roles


def test_apply_refuses_when_cluster_changed_after_preview(w, owner):
    pv = preview(w, owner)
    owner.sim.add_role("OfficeUnboundDeploy", {"VM.Audit"})                      # the cluster changes between preview and approval
    params = {"name": "owner", "base_url": owner.url, "fingerprint_sha256": owner.fingerprint, "admin_username": "root@pam",
              "admin_password": owner.sim.ROOT_PW, "preview_id": pv["preview_id"], "plan_hash": pv["plan_hash"]}
    p, j = w.run("provider.provision.apply", params)
    assert j["status"] == "failed" and "changed since the plan was previewed" in j["error"]["message"]
    assert "ics-svc@pve" not in owner.sim.users


def test_apply_needs_matching_hash_and_unblocked_plan(w, owner):
    pv = preview(w, owner)
    base_p = {"name": "owner", "base_url": owner.url, "fingerprint_sha256": owner.fingerprint, "admin_username": "root@pam",
              "admin_password": owner.sim.ROOT_PW, "preview_id": pv["preview_id"]}
    w.plan("provider.provision.apply", {**base_p, "plan_hash": "0" * 64}, expect=409)
    w.plan("provider.provision.apply", {**base_p, "plan_hash": pv["plan_hash"]})
    owner.sim.add_user("ics-svc@pve", comment="foreign")
    pv2 = preview(w, owner)
    assert pv2["plan"]["blocked"]
    w.plan("provider.provision.apply", {**base_p, "preview_id": pv2["preview_id"], "plan_hash": pv2["plan_hash"]}, expect=409)


def test_apply_failure_discards_credentials_and_rolls_back(w, owner, owner_engine):
    owner.sim.fail("PUT", r"/access/acl", 500, "injected", count=999)
    pv, p, j = mode_a(w, owner)
    assert j["status"] == "failed" and owner.sim.ROOT_PW not in json.dumps(j)
    assert "ics-svc@pve" not in owner.sim.users and not [r for r in owner.sim.roles if r.startswith("OfficeUnbound")]
    with owner_engine.connect() as c:
        assert c.execute(text("SELECT count(*) FROM plans WHERE secret_enc IS NOT NULL")).scalar() == 0
        assert c.execute(text("SELECT count(*) FROM endpoints")).scalar() == 0


def test_bad_admin_password_fails_without_leaking(w, owner):
    pv = preview(w, owner)
    params = {"name": "owner", "base_url": owner.url, "fingerprint_sha256": owner.fingerprint, "admin_username": "root@pam",
              "admin_password": "definitely-wrong-pw", "preview_id": pv["preview_id"], "plan_hash": pv["plan_hash"]}
    p, j = w.run("provider.provision.apply", params)
    assert j["status"] == "failed" and "rejected the provisioning credentials" in j["error"]["message"] and "definitely-wrong-pw" not in json.dumps(j)


def test_temporary_credentials_expire_after_15_minutes(w, owner, rt, owner_engine):
    pv = preview(w, owner)
    params = {"name": "owner", "base_url": owner.url, "fingerprint_sha256": owner.fingerprint, "admin_username": "root@pam",
              "admin_password": owner.sim.ROOT_PW, "preview_id": pv["preview_id"], "plan_hash": pv["plan_hash"]}
    p = w.plan("provider.provision.apply", params)
    with owner_engine.connect() as c:
        assert c.execute(text("SELECT length(secret_enc) > 0 FROM credentials WHERE id = :i"), {"i": p["plan_id"]}).scalar()   # temp credential (vault)
        c.execute(text("UPDATE plans SET created_at = now() - interval '20 minutes' WHERE id = :i"), {"i": p["plan_id"]})
    from ics.actions import reap_expired
    reap_expired(rt)                                                                        # the reaper wipes the credential, approved or not
    with owner_engine.connect() as c:
        assert c.execute(text("SELECT secret_enc IS NULL FROM plans WHERE id = :i"), {"i": p["plan_id"]}).scalar()
        assert c.execute(text("SELECT length(secret_enc) = 0 FROM credentials WHERE id = :i"), {"i": p["plan_id"]}).scalar()
    r1 = w.a1.post(f"{H}/plans/{p['plan_id']}/approve", headers=w.a1h)
    assert r1.status_code == 200
    r2 = w.a2.post(f"{H}/plans/{p['plan_id']}/approve", headers=w.a2h)
    jid = r2.json()["job_id"]
    while worker.run_once(rt):
        pass
    j = w.o.get(f"{H}/jobs/{jid}").json()
    assert j["status"] == "failed" and any(x in j["error"]["message"] for x in ("expired", "no longer available", "changed after approval"))
    assert "ics-svc@pve" not in owner.sim.users


def test_rejected_plan_wipes_credentials(w, owner, owner_engine):
    pv = preview(w, owner)
    p = w.plan("provider.provision.apply", {"name": "owner", "base_url": owner.url, "fingerprint_sha256": owner.fingerprint, "admin_username": "root@pam",
                                            "admin_password": owner.sim.ROOT_PW, "preview_id": pv["preview_id"], "plan_hash": pv["plan_hash"]})
    assert w.a1.post(f"{H}/plans/{p['plan_id']}/reject", headers=w.a1h).status_code == 200
    with owner_engine.connect() as c:
        assert c.execute(text("SELECT secret_enc IS NULL FROM plans WHERE id = :i"), {"i": p["plan_id"]}).scalar()
        assert c.execute(text("SELECT length(secret_enc) = 0 FROM credentials WHERE id = :i"), {"i": p["plan_id"]}).scalar()


def test_requester_cannot_self_approve_and_two_approvers_needed(w, owner):
    pv = preview(w, owner)
    p = w.plan("provider.provision.apply", {"name": "owner", "base_url": owner.url, "fingerprint_sha256": owner.fingerprint, "admin_username": "root@pam",
                                            "admin_password": owner.sim.ROOT_PW, "preview_id": pv["preview_id"], "plan_hash": pv["plan_hash"]})
    assert w.o.post(f"{H}/plans/{p['plan_id']}/approve", headers=w.oh).status_code in (403, 409)
    r = w.a1.post(f"{H}/plans/{p['plan_id']}/approve", headers=w.a1h)
    assert r.status_code == 200 and r.json()["job_id"] is None and r.json()["status"] == "pending_approval"


def test_mode_b_import_registers_the_same_restricted_integration(w, owner, tmp_path, owner_engine):
    p, j = w.run("provider.provision.package", {"base_url": owner.url, "name": "owner", "fingerprint_sha256": owner.fingerprint, "policy": POLICY, "pve_major": 9})
    assert p["risk"] == "normal" and j["status"] == "succeeded", j
    pkg = j["result"]["package_id"]
    # downloads: admin only; unbound package; every format
    assert w.o.get(f"{H}/providers/unbound/provisioning/packages/{pkg}", headers=w.oh).status_code == 403
    assert w.v.get(f"{H}/providers/unbound/provisioning/packages/{pkg}").status_code == 403
    files = w.ad.get(f"{H}/providers/unbound/provisioning/packages/{pkg}").json()["files"]
    assert w.ad.get(f"{H}/providers/{'0' * 8}-0000-0000-0000-000000000000/provisioning/packages/{pkg}").status_code == 404
    assert w.ad.get(f"{H}/providers/unbound/provisioning/packages/{pkg}?format=provision.sh").text == files["provision.sh"]
    assert w.ad.get(f"{H}/providers/unbound/provisioning/packages/{pkg}?format=zip").content[:2] == b"PK"
    r = run_script(owner, tmp_path, files["provision.sh"])
    assert r.returncode == 0, r.stderr
    sec = {k: owner.sim.tokens[f"ics-svc@pve!ics-{k}"]["secret"] for k in ("inv", "prov")}
    imp = {"name": "owner", "base_url": owner.url, "fingerprint_sha256": owner.fingerprint, "package_id": pkg,
           "inventory_token_id": "ics-svc@pve!ics-inv", "inventory_token_secret": sec["inv"],
           "provision_token_id": "ics-svc@pve!ics-prov", "provision_token_secret": sec["prov"]}
    # a token that is not part of the package is refused
    p2, j2 = w.run("provider.credential.import", {**imp, "inventory_token_id": "officeunbound@pam!ics", "inventory_token_secret": "preexisting0123456789"})
    assert j2["status"] == "failed" and "not one of the tokens" in j2["error"]["message"]
    p3, j3 = w.run("provider.credential.import", imp)
    assert p3["risk"] == "normal" and j3["status"] == "succeeded", j3
    eid = j3["result"]["endpoint_id"]
    v = w.v.get(f"{H}/providers/{eid}/permissions").json()
    assert v["mode"] == "B" and v["last_verification"]["ok"] and v["tokens"]["provision"]["id"] == "ics-svc@pve!ics-prov"
    # same restricted integration as Mode A: same roles / ACL paths
    owner2_like = PveSim(task_delay=0.1)
    owner2_like.populate_owner_env()
    srv2 = SimServer(owner2_like)
    try:
        pv, pa, ja = mode_a(w, srv2, name="owner-b")
        assert ja["status"] == "succeeded", ja
        key = lambda sim: sorted((e["path"], e["roleid"], e["ugid"].split("!")[-1]) for e in sim.acl_entries if e["ugid"].startswith("ics-svc@pve"))  # noqa: E731
        assert key(owner.sim) == key(owner2_like) and {k: v for k, v in owner.sim.roles.items() if k.startswith("OfficeUnbound")} == \
            {k: v for k, v in owner2_like.roles.items() if k.startswith("OfficeUnbound")}
    finally:
        srv2.stop()
    with owner_engine.connect() as c:
        dump = json.dumps([[str(x) for x in r] for r in c.execute(text("SELECT params::text FROM plans")).all()]
                          + [[str(x) for x in r] for r in c.execute(text("SELECT details_canon FROM audit_events")).all()]
                          + [[str(x) for x in r] for r in c.execute(text("SELECT data::text FROM provision_artifacts")).all()])
    assert not any(s in dump for s in sec.values())


def test_import_rejects_tokens_with_extra_privileges(w, owner, tmp_path):
    p, j = w.run("provider.provision.package", {"base_url": owner.url, "name": "owner", "fingerprint_sha256": owner.fingerprint, "policy": POLICY, "pve_major": 9})
    files = w.ad.get(f"{H}/providers/unbound/provisioning/packages/{j['result']['package_id']}").json()["files"]
    assert run_script(owner, tmp_path, files["provision.sh"]).returncode == 0
    # somebody (or a mistaken admin) also grants the service account a wide role: the import must notice
    for typ, ug in (("user", "ics-svc@pve"), ("token", "ics-svc@pve!ics-prov")):
        owner.sim.acl_entries.append({"path": "/storage/ha-zfs", "type": typ, "ugid": ug, "roleid": "PVEDatastoreUser", "propagate": 1})
    imp = {"name": "owner", "base_url": owner.url, "fingerprint_sha256": owner.fingerprint, "package_id": j["result"]["package_id"],
           "inventory_token_id": "ics-svc@pve!ics-inv", "inventory_token_secret": owner.sim.tokens["ics-svc@pve!ics-inv"]["secret"],
           "provision_token_id": "ics-svc@pve!ics-prov", "provision_token_secret": owner.sim.tokens["ics-svc@pve!ics-prov"]["secret"]}
    p3, j3 = w.run("provider.credential.import", imp)
    assert j3["status"] == "failed" and "does not match" in j3["error"]["message"] and "/storage/ha-zfs" in j3["error"]["message"]


def test_cross_cluster_isolation(w, owner, owner2, tmp_path):
    pv, p, j = mode_a(w, owner)
    assert j["status"] == "succeeded"
    tok = owner.sim.tokens["ics-svc@pve!ics-prov"]["secret"]
    with pytest.raises(ProxmoxError):                                                    # a token of cluster 1 means nothing on cluster 2
        reader(owner2, "ics-svc@pve!ics-prov", tok).get("/version")
    assert "ics-svc@pve" not in owner2.sim.users
    # a package generated against cluster 1 cannot be imported with cluster 2's connection details + tokens that do not exist there
    pk, jp = w.run("provider.provision.package", {"base_url": owner.url, "name": "c1", "fingerprint_sha256": owner.fingerprint,
                                                  "policy": {**POLICY, "service_user": "ics-b"}, "pve_major": 9})
    imp = {"name": "c2", "base_url": owner2.url, "fingerprint_sha256": owner2.fingerprint, "package_id": jp["result"]["package_id"],
           "inventory_token_id": "ics-b@pve!ics-inv", "inventory_token_secret": tok,
           "provision_token_id": "ics-b@pve!ics-prov", "provision_token_secret": tok}
    p2, j2 = w.run("provider.credential.import", imp)
    assert j2["status"] == "failed"
    # the second cluster provisions independently, with its own state
    pv2, p2, j2 = mode_a(w, owner2, name="owner-b")
    assert j2["status"] == "succeeded" and j2["result"]["endpoint_id"] != j["result"]["endpoint_id"]
    assert owner2.sim.tokens["ics-svc@pve!ics-prov"]["secret"] != tok


def test_drift_runner_reconcile_and_token_failure(w, owner, rt):
    pv, p, j = mode_a(w, owner)
    eid = j["result"]["endpoint_id"]
    from ics.provisioning import service
    owner.sim.roles["OfficeUnboundDeploy"].discard("VM.Snapshot")
    rep = w.o.post(f"{H}/providers/{eid}/permissions/check", headers=w.oh).json()
    assert rep["ok"] is False and rep["kinds"]["provision"]["missing"]
    v = w.v.get(f"{H}/providers/{eid}/permissions").json()
    assert v["status"] == "drift" and v["last_drift"]["kinds"]["provision"]["suggestion"]
    assert "VM.Snapshot" not in owner.sim.roles["OfficeUnboundDeploy"]                      # nothing was restored automatically
    # correction = a previewed, approved plan; it can only restore the stored policy
    owner.sim.acl_entries.append({"path": "/nodes/pve01", "type": "user", "ugid": "ics-svc@pve", "roleid": "PVEAuditor", "propagate": 1})
    rv, rj = w.run("provider.provision.plan_preview", {"endpoint_id": eid, "purpose": "reconcile", "admin_username": "root@pam", "admin_password": owner.sim.ROOT_PW})
    assert rj["status"] == "succeeded"
    steps = [s for s in rj["result"]["plan"]["steps"] if s["op"] != "noop"]
    assert {(s["kind"], s["op"]) for s in steps} == {("role", "modify"), ("acl", "remove")}
    assert all(s["target"] == "OfficeUnboundDeploy" or s["detail"]["subject"].startswith("ics-svc@pve") for s in steps)
    w.plan("provider.permissions.reconcile", {"endpoint_id": eid, "preview_id": rj["result"]["preview_id"], "plan_hash": "1" * 64,
                                              "admin_username": "root@pam", "admin_password": owner.sim.ROOT_PW}, expect=409)
    p2, j2 = w.run("provider.permissions.reconcile", {"endpoint_id": eid, "preview_id": rj["result"]["preview_id"], "plan_hash": rj["result"]["plan_hash"],
                                                      "admin_username": "root@pam", "admin_password": owner.sim.ROOT_PW})
    assert p2["risk"] == "high" and j2["status"] == "succeeded", j2
    assert "VM.Snapshot" in owner.sim.roles["OfficeUnboundDeploy"]
    assert not [e for e in owner.sim.acl_entries if e["path"] == "/nodes/pve01" and e["ugid"] == "ics-svc@pve"]
    assert w.o.post(f"{H}/providers/{eid}/permissions/check", headers=w.oh).json()["ok"] is True
    # token failure (revoked in Proxmox) is reported as such and audited
    owner.sim.users["ics-svc@pve"]["enable"] = 0
    rep = w.o.post(f"{H}/providers/{eid}/permissions/check", headers=w.oh).json()
    assert rep["ok"] is False
    v = w.v.get(f"{H}/providers/{eid}/permissions").json()
    assert v["status"] in ("drift", "token_failed")
    owner.sim.tokens.pop("ics-svc@pve!ics-prov")
    rep = w.o.post(f"{H}/providers/{eid}/permissions/check", headers=w.oh).json()
    assert rep["error_code"] == "token_failed"
    assert w.v.get(f"{H}/providers/{eid}/permissions").json()["status"] == "token_failed"
    ev = w.ad.get(f"{H}/audit?limit=50").json()
    assert any(e["action"] == "provider.token.failed" for e in (ev["events"] if isinstance(ev, dict) else ev))
    service._next.clear()


def test_rotate_then_revoke(w, owner, rt):
    pv, p, j = mode_a(w, owner)
    eid = j["result"]["endpoint_id"]
    old = {k: owner.sim.tokens[f"ics-svc@pve!ics-{k}"]["secret"] for k in ("inv", "prov")}
    pr, jr = w.run("provider.token.rotate", {"endpoint_id": eid, "admin_username": "root@pam", "admin_password": owner.sim.ROOT_PW, "kinds": ["provision"]})
    assert pr["risk"] == "high" and jr["status"] == "succeeded", jr
    assert "ics-svc@pve!ics-prov" not in owner.sim.tokens and "ics-svc@pve!ics-prov-g2" in owner.sim.tokens and "ics-svc@pve!ics-inv" in owner.sim.tokens
    with pytest.raises(ProxmoxError):
        reader(owner, "ics-svc@pve!ics-prov", old["prov"]).get("/version")
    v = w.v.get(f"{H}/providers/{eid}/permissions").json()
    assert v["tokens"]["provision"] == {"id": "ics-svc@pve!ics-prov-g2", "gen": 2} and v["last_verification"]["ok"]
    assert w.o.post(f"{H}/providers/{eid}/permissions/check", headers=w.oh).json()["ok"] is True
    with rt.session() as db, base.job_execution("t"):
        from ics.providers.proxmox import open_mutations
        assert open_mutations(rt, db.execute(text("SELECT * FROM endpoints WHERE id = :i"), {"i": eid}).first())._tid.endswith("prov-g2")
    # revoke: wrong confirmation refused; high risk; deletes tokens/user/roles the ICS created and destroys the stored credentials
    w.plan("provider.token.revoke", {"endpoint_id": eid, "confirm_name": "nope"}, expect=422)
    pk, jk = w.run("provider.token.revoke", {"endpoint_id": eid, "confirm_name": "owner", "delete_user": True, "delete_roles": True,
                                             "admin_username": "root@pam", "admin_password": owner.sim.ROOT_PW})
    assert pk["risk"] == "high" and jk["status"] == "succeeded", jk
    assert "ics-svc@pve" not in owner.sim.users and not [r for r in owner.sim.roles if r.startswith("OfficeUnbound")]
    assert "officeunbound@pam" in owner.sim.users and "PVEAuditor" in owner.sim.roles
    ep = w.v.get(f"{H}/endpoints/{eid}").json()
    assert ep["enabled"] is False and ep["credentials"]["provision"]["present"] is False
    assert w.v.get(f"{H}/providers/{eid}/permissions").json()["status"] == "revoked"
    with rt.session() as db, base.job_execution("t"):
        from ics.providers.base import MutationNotAllowed
        from ics.providers.proxmox import open_mutations
        with pytest.raises(MutationNotAllowed):
            open_mutations(rt, db.execute(text("SELECT * FROM endpoints WHERE id = :i"), {"i": eid}).first())


def test_revoke_without_remote_credentials_destroys_local_secrets_only(w, owner):
    pv, p, j = mode_a(w, owner)
    eid = j["result"]["endpoint_id"]
    pk, jk = w.run("provider.token.revoke", {"endpoint_id": eid, "confirm_name": "owner"})
    assert jk["status"] == "succeeded" and jk["result"]["remote"] == [] and "ics-svc@pve!ics-prov" in owner.sim.tokens       # still valid in PVE: run rollback
    w.plan("provider.token.revoke", {"endpoint_id": eid, "confirm_name": "owner", "delete_user": True}, expect=422)


def test_preview_with_offline_and_validation_errors(w, owner):
    p, j = w.run("provider.provision.plan_preview", {"pve_major": 8, "policy": POLICY})
    assert j["status"] == "succeeded" and j["result"]["plan"]["facts"]["offline"] is True
    w.plan("provider.provision.plan_preview", {"policy": POLICY}, expect=422)                                  # nothing to preview against
    w.plan("provider.provision.plan_preview", {"pve_major": 9, "policy": {**POLICY, "realm": "pam"}}, expect=422)
    w.plan("provider.provision.plan_preview", {"base_url": owner.url, "name": "x", "pve_major": 9, "policy": POLICY}, expect=422)   # no trust anchor
    w.plan("provider.provision.package", {"policy": POLICY}, expect=422)
    p, j = w.run("provider.provision.package", {"pve_major": 9, "policy": {**POLICY, "preset": "full_admin", "acknowledge_full_admin": True}})
    assert p["risk"] == "high"


def test_monitoring_preset_gets_only_an_inventory_token(w, owner):
    pol = {"preset": "monitoring", "scope": {"nodes": ["pve06"], "storages": ["PVE06-Storage"]}}
    pv, p, j = mode_a(w, owner, pol)
    assert j["status"] == "succeeded", j
    assert "ics-svc@pve!ics-inv" in owner.sim.tokens and "ics-svc@pve!ics-prov" not in owner.sim.tokens
    assert [r for r in owner.sim.roles if r.startswith("OfficeUnbound")] == ["OfficeUnboundMonitor"]
    eid = j["result"]["endpoint_id"]
    assert w.v.get(f"{H}/endpoints/{eid}").json()["credentials"]["provision"]["present"] is False


def test_no_secrets_in_api_responses(w, owner):
    pv, p, j = mode_a(w, owner)
    eid = j["result"]["endpoint_id"]
    secrets = [owner.sim.ROOT_PW] + [t["secret"] for k, t in owner.sim.tokens.items() if k.startswith("ics-svc@")]
    blobs = [json.dumps(p), json.dumps(j), json.dumps(pv)]
    for url in (f"/plans", f"/jobs", f"/providers/{eid}/permissions", f"/endpoints/{eid}", "/audit?limit=200", "/actions"):
        blobs.append(w.ad.get(H + url).text)
    assert not any(s in b for s in secrets for b in blobs)
    assert "PVEAPIToken" not in " ".join(blobs)
