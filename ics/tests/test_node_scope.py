"""Authorized nodes (deny by default) and the real PVE clone UPID. Simulator-based: evidence about the code paths, not about a real cluster."""
import dataclasses

import pytest

from ics.providers.base import MutationNotAllowed, ScopeViolation, VmCloneSpec, VmRef
from ics.providers.proxmox.provider import EndpointScope
from .infra_fixtures import SCOPE, job, mutations, read_provider, sim  # noqa: F401, E402


def ref(vmid=150, node="pve1", dep="d1"):
    return VmRef(node, vmid, "vm", dep)


def clone_spec(**kw):
    d = dict(template_vmid=9000, template_node="pve1", new_vmid=None, name="app01", pool="ou-lab", storage="local-lvm", deployment_id="d9")
    d.update(kw)
    return VmCloneSpec(**d)


NODE1 = EndpointScope(pools=("ou-lab",), storage=("local-lvm",), networks=("vmbr1",), nodes=("pve1",))


def test_clone_upid_carries_the_source_template_vmid_and_finalize_checks_it(sim, job):
    """PVE 9: `qmclone:<SOURCE template vmid>:<user>` (not the new vmid). Regression: the old check (id == new vmid) can never succeed there."""
    m = mutations(sim)
    t = m.clone_vm(clone_spec())
    assert t.vmid == 101 and t.template_vmid == 9000 and t.name == "app01"
    assert ":qmclone:9000:" in t.upid and ":qmclone:101:" not in t.upid
    m.wait(t, timeout=5)
    m.wait(m.finalize_clone(t), timeout=5)
    assert "ou-managed" in sim.sim.vms[101]["cfg"]["tags"]
    for bad in (dataclasses.replace(t, template_vmid=101),      # the new vmid is not the UPID id
                dataclasses.replace(t, template_vmid=None),
                dataclasses.replace(t, name="other"),           # target guest name must equal the clone spec name
                dataclasses.replace(t, vmid=100)):              # some other guest
        with pytest.raises(ScopeViolation):
            m.finalize_clone(bad)


def test_finalize_refuses_guest_with_another_deployments_tags(sim, job):
    m = mutations(sim)
    t = m.clone_vm(clone_spec())
    m.wait(t, timeout=5)
    sim.sim.vms[101]["cfg"]["tags"] = "ou-managed;ou-deployment-someone-else"
    with pytest.raises(ScopeViolation, match="another deployment"):
        m.finalize_clone(t)


def test_mutations_refuse_when_no_node_is_authorized(sim, job):
    with pytest.raises(MutationNotAllowed, match="authorized node"):
        mutations(sim, EndpointScope(pools=("ou-lab",), storage=("local-lvm",), networks=("vmbr1",)))


def test_clone_target_or_template_node_outside_scope_is_refused_before_any_api_call(sim, job):
    m = mutations(sim, NODE1)
    n = len(sim.sim.seen)
    with pytest.raises(ScopeViolation, match="target node 'pve2'"):
        m.clone_vm(clone_spec(target_node="pve2"))       # template on the allowed node, target unauthorized
    with pytest.raises(ScopeViolation, match="template node 'pve2'"):
        m.clone_vm(clone_spec(template_node="pve2"))
    assert len(sim.sim.seen) == n                        # not a single request reached the cluster


def test_guest_verbs_and_migrate_respect_authorized_nodes(sim, job):
    m = mutations(sim, NODE1)
    with pytest.raises(ScopeViolation, match="authorized node"):
        m.power(ref(150, node="pve2"), "start")          # the ref names an unauthorized node
    m2 = mutations(sim, EndpointScope(pools=("ou-lab",), storage=("local-lvm",), networks=("vmbr1",), nodes=("pve2",)))
    with pytest.raises(ScopeViolation, match="authorized node"):
        m2.power(ref(150, node="pve1"), "start")         # the guest lives on pve1, which this scope does not authorize
    with pytest.raises(ScopeViolation, match="target node 'pve2'"):
        m.migrate(ref(150), "pve2", online=False)


def test_discovery_shows_unauthorized_nodes_as_unmanaged(sim):
    p = read_provider(sim, scope=EndpointScope(pools=("ou-lab",), nodes=("pve1",)))
    d = p.discover()
    by = {n["name"]: n for n in d.nodes}
    assert by["pve1"]["managed"] is True and by["pve2"]["managed"] is False and by["pve2"]["cpu_total"] is None
    assert not [s for s in d.storage if s["node"] == "pve2"]
