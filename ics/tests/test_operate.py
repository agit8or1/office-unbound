"""Operations preset: individually authorized EXISTING guests (scope.managed_vmids) -> per-VMID Proxmox ACLs (VM.Audit + VM.PowerMgmt only) and the
guest.power typed action. Proxmox is the stateful simulator; the session sign-in is the wizard's (test_admin_session)."""
import pytest
from pydantic import ValidationError

from ics import actions
from ics.providers.proxmox import provisioning as pp
from ics.provisioning.model import Policy
from ics.proxmox import ProxmoxReadClient
from .infra_fixtures import H
from .test_admin_session import run_as_admin, sign_in, w  # noqa: F401  (fixture)
from .test_provisioning import owner  # noqa: F401  (fixture)

OPS = {"preset": "operations", "scope": {"nodes": ["pve06"], "managed_vmids": [105, 106], "protected_vmids": [126]}}


def test_operations_design_grants_power_on_exactly_the_selected_guests():
    p = Policy.model_validate(OPS)
    d = pp.design(p, 9)
    paths = {(a.path, a.cap) for a in d.acl}
    assert ("/vms/105", "operate") in paths and ("/vms/106", "operate") in paths
    assert d.roles["operate"][1] == frozenset({"VM.Audit", "VM.PowerMgmt"})
    assert not any(a.path in ("/", "/vms", "/nodes") for a in d.acl)                          # never a broad path
    assert all(a.propagate == 0 for a in d.acl if a.path.startswith("/vms/"))
    node_caps = {d.roles[a.cap][1] for a in d.acl if a.path.startswith("/nodes/")}
    assert all(not (caps & {"VM.PowerMgmt", "VM.Allocate", "VM.Config.Disk"}) for caps in node_caps)   # selecting a node grants no guest control
    sn = pp.design(Policy.model_validate({**OPS, "scope_mode": "single_node"}), 9)                 # the wizard's mode: node ACLs carry Sys.Audit only
    assert {sn.roles[a.cap][1] for a in sn.acl if a.path.startswith("/nodes/")} == {frozenset({"Sys.Audit"})}
    notes = " ".join(n.control for n in pp.enforcement_matrix(p))
    assert "Existing guests operated by Office Unbound (2)" in notes and "Selecting a node does not select its guests" in notes


@pytest.mark.parametrize("bad, msg", [
    ({"preset": "operations", "scope": {"nodes": ["pve06"]}}, "needs at least one existing guest"),
    ({"preset": "operations", "scope": {"managed_vmids": [126], "protected_vmids": [126]}}, "protected guest"),
    ({"preset": "deploy", "scope": {"pools": ["p"], "template_vmids": [9612], "managed_vmids": [9612]}}, "template"),
])
def test_operations_policy_guards(bad, msg):
    with pytest.raises(ValidationError, match=msg):
        Policy.model_validate(bad)


def _setup(w, owner):  # noqa: F811
    owner.sim.add_vm(105, "pve06", "app-a", status="running", storage="PVE06-Storage")
    owner.sim.add_vm(106, "pve01", "app-b", kind="lxc", status="running", storage="ha-zfs")
    owner.sim.add_vm(107, "pve06", "not-selected", status="running", storage="PVE06-Storage")
    s = sign_in(w, owner)
    base = {"name": "owner", "base_url": owner.url, "fingerprint_sha256": owner.fingerprint, "admin_session": s["id"]}
    p, j = run_as_admin(w, "provider.provision.plan_preview", {**base, "policy": OPS})
    assert j["status"] == "succeeded", j
    pv = j["result"]
    p2, j2 = run_as_admin(w, "provider.provision.apply", {**base, "preview_id": pv["preview_id"], "plan_hash": pv["plan_hash"]})
    assert j2["status"] == "succeeded", j2
    return j2["result"]["endpoint_id"]


def test_operations_end_to_end_power_on_selected_guests_only(w, owner):  # noqa: F811
    eid = _setup(w, owner)
    ep = w.ad.get(f"{H}/endpoints/{eid}", headers=w.adh).json()
    assert ep["scope"]["managed_vmids"] == [105, 106]
    for vmid, op in ((105, "shutdown"), (106, "reboot")):                                         # across nodes, qemu and lxc
        p, j = run_as_admin(w, "guest.power", {"endpoint_id": eid, "vmid": vmid, "op": op})
        assert j["status"] == "succeeded", j.get("error")                                          # also proves the plan digest binding verifies
        assert j["result"]["node"] == owner.sim.vms[vmid]["node"]
    assert owner.sim.vms[105]["status"] == "stopped"
    for vmid, code in ((107, 403), (126, 403), (300, 403)):
        r = w.ad.post(f"{H}/plans", json={"action": "guest.power", "params": {"endpoint_id": eid, "vmid": vmid, "op": "stop"}}, headers=w.adh)
        assert r.status_code == code, (vmid, r.text)
    assert owner.sim.vms[107]["status"] == "running" and owner.sim.vms[300]["status"] == "running"


def test_proxmox_itself_refuses_unselected_guests_for_the_service_token(w, owner):  # noqa: F811
    _setup(w, owner)
    tid = "ics-svc@pve!ics-prov"
    c = ProxmoxReadClient(owner.url, tid, owner.sim.tokens[tid]["secret"], fingerprint_sha256=owner.fingerprint, allow_loopback=True)
    try:
        perms = c._get("/access/permissions")
    finally:
        c.close()
    assert "VM.PowerMgmt" in perms.get("/vms/105", {}) and "VM.PowerMgmt" in perms.get("/vms/106", {})
    assert not any("VM.PowerMgmt" in v for k, v in perms.items() if k not in ("/vms/105", "/vms/106"))
    assert not owner.sim.can(tid, "vm", 107, "VM.PowerMgmt") and not owner.sim.can(tid, "vm", 300, "VM.Audit")
    assert not owner.sim.can(tid, "vm", 105, "VM.Allocate") and not owner.sim.can(tid, "vm", 105, "VM.Config.Disk")


def test_ep_bound_actions_bind_the_endpoint_on_create_and_verify():
    assert {"image.import", "guest.power"} <= actions.EP_BOUND
