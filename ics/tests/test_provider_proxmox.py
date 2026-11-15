"""Proxmox provider against the STATEFUL SIMULATOR (a test double: results are NOT evidence about a real cluster)."""
import json
import dataclasses
from datetime import datetime, timedelta, timezone

import pytest

from ics.providers import base
from ics.providers.base import (IpConfig, MutationNotAllowed, NicSpec, ProviderError, ProviderTimeout, Scope, ScopeViolation, TaskRef,
                                VmCloneSpec, VmConfigSpec, VmRef)
from ics.providers.proxmox.provider import EndpointScope, ProxmoxProvider, SelfIdentity
from .infra_fixtures import INV, LAB, SCOPE, job, mutations, read_provider, real_sim, ro, rw, sim  # noqa: F401
from .pve_sim import SIM_MARKER

KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl ops@host"
REAL = ("officeunbound@pam!ics", "realsecret0123456789")


def ref(vmid=150, node="pve1", dep="d1", kind="vm"):
    return VmRef(node, vmid, kind, dep)


# ---------------------------------------------------------------- probe / permission mapping
def test_probe_ok_and_all_verbs_mapped(sim):
    r = read_provider(sim).probe()
    assert r.ok and r.tls == {"trust": "fingerprint", "ok": True} and r.cluster_name == "simcluster" and r.nodes == 2
    assert r.simulator is True and r.version == "8.2.4"
    verbs = {v.verb: v for v in r.verbs}
    assert set(verbs) == {"discover", "metrics", "clone_vm", "configure_vm", "resize_disk", "power", "snapshot", "rollback", "migrate", "destroy_vm"}
    assert all(v.ok for v in verbs.values()), [v for v in verbs.values() if not v.ok]


def test_probe_reports_missing_privileges_per_verb_with_fix(sim):
    scope = EndpointScope(pools=("ou-lab", "other"), storage=("local-lvm", "other-lvm"), networks=("vmbr0", "vmbr1"), nodes=("pve1", "pve2"))
    v = {x.verb: x for x in read_provider(sim, scope).probe().verbs}
    assert not v["clone_vm"].ok
    paths = {m["path"] for m in v["clone_vm"].missing}
    assert paths == {"/pool/other", "/storage/other-lvm"}
    cfg = v["configure_vm"]
    assert {m["path"] for m in cfg.missing} == {"/pool/other", "/storage/other-lvm", "/sdn/zones/localnetwork/vmbr0"}
    sdn = next(m for m in cfg.missing if m["path"].startswith("/sdn"))
    assert sdn["privileges"] == ["SDN.Use"]
    assert sdn["fix"] == "pveum acl modify /sdn/zones/localnetwork/vmbr0 --tokens 'ics-lab@pve!lab' --roles PVESDNUser"
    assert "NIC" in cfg.note
    assert v["discover"].ok  # inventory verbs unaffected


def test_inventory_only_token_cannot_provision(sim):
    p = ProxmoxProvider(ro(sim), scope=SCOPE, inventory_token_id=INV[0], provision_probe=ro(sim, INV), provision_token_id=INV[0],
                        allow_simulator=True)
    v = {x.verb: x for x in p.probe().verbs}
    assert v["discover"].ok and not v["clone_vm"].ok and not v["power"].ok
    assert "VM.PowerMgmt" in v["power"].missing[0]["privileges"]


def test_probe_without_provision_credential(sim):
    r = read_provider(sim, with_prov=False).probe()
    assert r.ok and r.credentials["provision"]["authenticated"] is False
    assert all(not v.ok and v.note for v in r.verbs if v.verb == "clone_vm")


def test_probe_tls_pin_mismatch_sends_no_request(sim):
    seen = len(sim.sim.seen)
    p = ProxmoxProvider(ro(sim, fingerprint_sha256="ab" * 32), scope=SCOPE, allow_simulator=True)
    r = p.probe()
    assert not r.ok and r.tls["ok"] is False and "pinned" in r.tls["error"]
    assert len(sim.sim.seen) == seen


def test_probe_bad_secret_is_unauthenticated_and_never_leaks(sim):
    bad = "wrongsecret0123456789"
    from ics.proxmox import ProxmoxReadClient
    c = ProxmoxReadClient(sim.url, INV[0], bad, fingerprint_sha256=sim.fingerprint, allow_loopback=True)
    r = ProxmoxProvider(c, scope=SCOPE, inventory_token_id=INV[0], allow_simulator=True).probe()
    assert not r.ok and r.tls["ok"] is True and r.credentials["inventory"]["authenticated"] is False
    assert bad not in json.dumps(dataclasses.asdict(r)) and "401" in r.errors[0]


def test_simulator_marker_refused_when_not_allowed(sim):
    p = ProxmoxProvider(ro(sim), scope=SCOPE, allow_simulator=False)
    r = p.probe()
    assert not r.ok and "test double" in r.errors[0]
    with pytest.raises(ProviderError):
        p.discover()


def test_real_cluster_scenario_probe(real_sim):
    ident = SelfIdentity(macs=frozenset({"bc:24:11:e7:f0:24"}))
    scope = EndpointScope(pools=("officeunbound-pve06",), storage=("PVE06-Storage",), networks=("vmbr0",), nodes=("pve06",))
    p = ProxmoxProvider(ro(real_sim, REAL), scope=scope, inventory_token_id=REAL[0], provision_probe=ro(real_sim, REAL),
                        provision_token_id=REAL[0], self_identity=ident)
    r = p.probe()
    v = {x.verb: x for x in r.verbs}
    assert r.ok and r.version == "9.2.21" and not r.simulator
    assert v["discover"].ok and v["clone_vm"].ok and v["power"].ok and v["snapshot"].ok and v["destroy_vm"].ok
    assert not v["configure_vm"].ok
    fix = [m["fix"] for m in v["configure_vm"].missing]
    assert fix == ["pveum acl modify /sdn/zones/localnetwork/vmbr0 --tokens 'officeunbound@pam!ics' --roles PVESDNUser"]
    w = " | ".join(r.warnings)
    assert "VM.Console" in w and "Pool.Audit missing" in w and "1 of 6 cluster nodes" in w
    assert "DANGER" in w and "VM 126" in w
    assert r.self_vm["vmid"] == 126 and r.self_vm["mutable"] is True
    caps = {c["name"]: c for c in r.capabilities}
    assert caps["vm_disks"]["ok"] and not caps["cloudinit_snippets"]["ok"] and not caps["template_import"]["ok"]


# ---------------------------------------------------------------- discovery
def test_discover_normalizes_everything(sim):
    d = read_provider(sim).discover()
    assert {n["name"] for n in d.nodes} == {"pve1", "pve2"} and all(n["managed"] for n in d.nodes)
    assert d.clusters[0]["name"] == "simcluster" and d.clusters[0]["quorate"] is True and d.clusters[0]["nodes_online"] == 2
    st = {(s["name"], s["node"]): s for s in d.storage}
    assert st[("local", "pve1")]["content"] == ["iso", "backup", "vztmpl", "snippets"]
    assert st[("local-lvm", "pve1")]["used"] > 0
    nets = {(n["kind"], n["name"]): n for n in d.networks}
    assert nets[("bridge", "vmbr1")]["vlan_aware"] is True and nets[("bridge", "vmbr0")]["vlan_aware"] is False
    assert ("sdn_zone", "zlab") in nets and nets[("sdn_vnet", "vn1")]["tag"] == 100
    g = {x["vmid"]: x for x in d.guests}
    assert g[150]["ou_managed"] and g[150]["ou_deployment_id"] == "d1" and g[160]["ou_managed"] is False and g[100]["status"] == "running"
    assert {t["vmid"] for t in d.templates} == {9000, 9100} and 9000 not in g
    assert {"clusters", "nodes", "storage", "networks", "guests", "templates"} <= d.complete and not d.warnings


def test_discover_real_cluster_unaudited_nodes_are_not_idle_capacity(real_sim):
    p = ProxmoxProvider(ro(real_sim, REAL), scope=EndpointScope(), inventory_token_id=REAL[0])
    d = p.discover()  # also proves gzip-encoded responses are decoded (the simulator gzips like pveproxy)
    nodes = {n["name"]: n for n in d.nodes}
    assert len(nodes) == 6 and nodes["pve06"]["managed"] and nodes["pve06"]["cpu_total"] == 56
    for n in ("pve01", "pve2", "pve3", "pve04", "pve05"):
        assert nodes[n]["managed"] is False and nodes[n]["cpu_total"] is None and nodes[n]["mem_total"] is None
    assert sum("not managed" in w for w in d.warnings) == 5
    assert {(s["name"], s["node"]) for s in d.storage} == {("PVE06-Storage", "pve06")}
    assert [g["vmid"] for g in d.guests] == [126]


def test_discover_partial_failure_keeps_other_kinds(sim):
    sim.sim.fail("GET", r"/nodes/pve2/storage", 500, "storage backend down", count=5)
    d = read_provider(sim).discover()
    assert any("storage on pve2" in w for w in d.warnings)
    assert "storage" not in d.complete and "guests" in d.complete


def test_metrics_normalized(sim):
    p = read_provider(sim)
    since = datetime.now(timezone.utc) - timedelta(minutes=30)
    s = p.metrics(Scope("node", node="pve1"), since, 60)
    names = {x.metric for x in s}
    assert {"cpu_pct", "mem_used_bytes", "mem_total_bytes", "net_in_bps", "net_out_bps"} <= names
    assert all(x.ts >= since and x.scope_key == "pve1" for x in s)
    assert 20 <= len([x for x in s if x.metric == "cpu_pct"]) <= 31   # trailing empty row skipped
    assert 9 < next(x for x in s if x.metric == "cpu_pct").value < 20  # fraction -> percent
    g = p.metrics(Scope("guest", node="pve1", vmid=100), since, 60)
    assert {"disk_read_bps", "disk_write_bps"} <= {x.metric for x in g} and g[0].scope_key == "100"


# ---------------------------------------------------------------- structural guard
def test_mutations_only_inside_job_execution(sim):
    with pytest.raises(MutationNotAllowed):
        mutations(sim)
    assert not hasattr(read_provider(sim), "clone_vm") and not hasattr(read_provider(sim), "destroy_vm")
    with base.job_execution("j1"):
        m = mutations(sim)
    with pytest.raises(MutationNotAllowed):   # even a retained object refuses once the job context is gone
        m.power(ref(), "start")
    assert base.current_job() is None


def test_mutations_need_an_allowed_pool(sim):
    with base.job_execution("j"):
        with pytest.raises(MutationNotAllowed):
            mutations(sim, EndpointScope())


# ---------------------------------------------------------------- clone + finalize
def clone_spec(**kw):
    d = dict(template_vmid=9000, template_node="pve1", new_vmid=None, name="app01", pool="ou-lab", storage="local-lvm", deployment_id="d9")
    d.update(kw)
    return VmCloneSpec(**d)


def test_clone_wait_finalize_tags_ownership(sim, job):
    m = mutations(sim)
    t = m.clone_vm(clone_spec())
    assert t.upid.startswith("UPID:pve1:") and t.vmid == 101 and t.kind == "qmclone"
    assert m.task_status(t).state == "running"
    assert m.wait(t, timeout=5).state == "ok"
    m.wait(m.finalize_clone(t), timeout=5)
    vm = sim.sim.vms[101]
    assert vm["pool"] == "ou-lab" and "ou-managed" in vm["cfg"]["tags"] and "ou-deployment-d9" in vm["cfg"]["tags"]
    # it can now be managed under that deployment id, and only that one
    m.power(ref(101, dep="d9"), "start")
    with pytest.raises(ScopeViolation):
        m.power(ref(101, dep="d1"), "stop")


def test_linked_clone_and_target_node(sim, job):
    m = mutations(sim)
    t = m.clone_vm(clone_spec(full=False, new_vmid=300))
    assert m.wait(t, timeout=5).state == "ok"
    with pytest.raises(ScopeViolation, match="authorized node"):
        m.clone_vm(clone_spec(target_node="pve9", new_vmid=301))


@pytest.mark.parametrize("over,msg", [
    ({"pool": "other"}, "allowed pools"),
    ({"storage": "other-lvm"}, "allowed storage"),
    ({"template_vmid": 9100}, "template"),          # foreign pool: invisible to the token
    ({"template_vmid": 100}, "template"),           # a plain VM is not a template
    ({"template_node": "pve2"}, "template"),
    ({"deployment_id": "BAD ID!"}, "deployment id"),
])
def test_clone_scope_refusals(sim, job, over, msg):
    with pytest.raises(ScopeViolation, match=msg):
        mutations(sim).clone_vm(clone_spec(**over))
    assert not [r for r in sim.sim.seen if r[0] == "POST"]  # refused BEFORE any mutating request


def test_finalize_clone_refuses_foreign_tasks(sim, job):
    m = mutations(sim)
    t = m.clone_vm(clone_spec())
    m.wait(t, timeout=5)
    with pytest.raises(ScopeViolation):
        m.finalize_clone(TaskRef("pve1", t.upid, 150, "qmclone", "d1"))   # vmid does not match the task
    p = m.power(ref(150), "start")
    m.wait(p, timeout=5)
    with pytest.raises(ScopeViolation):
        m.finalize_clone(TaskRef("pve1", p.upid, 150, "qmclone", "d1"))   # not a clone task


# ---------------------------------------------------------------- scope enforcement on existing guests
@pytest.mark.parametrize("r,msg", [
    (ref(160), "ownership tags"),            # in the pool but untagged
    (ref(170), "ownership tags"),            # tagged for another deployment
    (ref(200, "pve2"), "not visible"),       # tagged, but in a pool the token cannot see / is not allowed
    (ref(100), "not visible"),               # not in any pool
    (ref(9000), "template"),
    (ref(150, dep=None), "deployment id"),
    (ref(150, node="pve2"), "not a vm on node"),
])
def test_guest_scope_refusals(sim, job, r, msg):
    m = mutations(sim)
    for call in (lambda: m.power(r, "start"), lambda: m.snapshot(r, "s1"), lambda: m.destroy_vm(r), lambda: m.resize_disk(r, "scsi0", 99),
                 lambda: m.migrate(r, "pve2", False), lambda: m.configure_vm(r, VmConfigSpec(cores=2)), lambda: m.rollback(r, "s1")):
        with pytest.raises(ScopeViolation, match=msg):
            call()
    assert not [x for x in sim.sim.seen if x[0] in ("POST", "PUT", "DELETE")]


def test_wrong_pool_even_when_tagged_is_refused_by_scope_not_only_acl(sim, job):
    # an operator widened the token's ACL to the foreign pool; the endpoint allowlist still refuses
    sim.sim.tokens[LAB[0]]["acl"].append(("/pool/other", "OULabProvisioner"))
    with pytest.raises(ScopeViolation, match="allowed pools"):
        mutations(sim).power(ref(200, "pve2"), "start")


def test_configure_nics_bridge_and_vlan_scope(sim, job):
    m = mutations(sim)
    for nic, msg in ((NicSpec(0, "vmbr0"), "allowed networks"), (NicSpec(0, "vmbr9"), "allowed networks")):
        with pytest.raises(ScopeViolation, match=msg):
            m.configure_vm(ref(), VmConfigSpec(nics=(nic,)))
    narrow = EndpointScope(pools=("ou-lab",), storage=("local-lvm",), networks=("vmbr1/20",), nodes=("pve1", "pve2"))
    mm = mutations(sim, narrow)
    with pytest.raises(ScopeViolation):
        mm.configure_vm(ref(), VmConfigSpec(nics=(NicSpec(0, "vmbr1", 30),)))
    with pytest.raises(ScopeViolation):
        mm.configure_vm(ref(), VmConfigSpec(nics=(NicSpec(0, "vmbr1", None),)))
    mm.configure_vm(ref(), VmConfigSpec(nics=(NicSpec(0, "vmbr1", 20),)))
    assert "bridge=vmbr1,tag=20" in sim.sim.vms[150]["cfg"]["net0"]


def test_configure_cloud_init_fields_and_validation(sim, job):
    m = mutations(sim)
    t = m.configure_vm(ref(), VmConfigSpec(cores=4, memory_mb=8192, cloudinit_storage="local-lvm", ciuser="ops", sshkeys=(KEY,),
                                           ipconfigs=(IpConfig(0, "10.1.2.3/24", "10.1.2.1"),), nameserver="10.1.2.1", searchdomain="lab.example",
                                           new_disks=(("scsi1", "local-lvm", 20),)))
    assert m.wait(t).state == "ok"  # synchronous change: no UPID to poll
    c = sim.sim.vms[150]["cfg"]
    assert c["cores"] == 4 and c["memory"] == 8192 and c["ipconfig0"] == "ip=10.1.2.3/24,gw=10.1.2.1" and c["ciuser"] == "ops"
    assert c["ide2"].endswith("cloudinit,media=cdrom") and "size=20G" in c["scsi1"]
    for bad in (VmConfigSpec(ciuser="Robert; rm -rf"), VmConfigSpec(sshkeys=("ssh-rsa AAAA\ncommand=evil",)), VmConfigSpec(sshkeys=("not a key",)),
                VmConfigSpec(ipconfigs=(IpConfig(0, "10.0.0.1/99"),)), VmConfigSpec(searchdomain="a b"), VmConfigSpec(nameserver="x"),
                VmConfigSpec(cores=0), VmConfigSpec()):
        with pytest.raises(ProviderError):
            m.configure_vm(ref(), bad)
    with pytest.raises(ScopeViolation, match="storage"):
        m.configure_vm(ref(), VmConfigSpec(new_disks=(("scsi2", "other-lvm", 5),)))
    with pytest.raises(ScopeViolation, match="storage"):
        m.configure_vm(ref(), VmConfigSpec(cloudinit_storage="local"))


def test_cicustom_needs_endpoint_opt_in_and_allowed_storage(sim, job):
    spec = VmConfigSpec(cicustom="user=local:snippets/ou-user.yaml")
    with pytest.raises(ScopeViolation, match="not enabled"):
        mutations(sim).configure_vm(ref(), spec)
    on = EndpointScope(pools=("ou-lab",), storage=("local-lvm",), networks=("vmbr1",), allow_cicustom=True, nodes=("pve1", "pve2"))
    with pytest.raises(ScopeViolation, match="storage"):                       # snippets storage 'local' is not allowed
        mutations(sim, on).configure_vm(ref(), spec)
    with pytest.raises(ProviderError):
        mutations(sim, on).configure_vm(ref(), VmConfigSpec(cicustom="user=local-lvm:../../etc/passwd"))
    on2 = EndpointScope(pools=("ou-lab",), storage=("local-lvm", "local"), networks=("vmbr1",), allow_cicustom=True, nodes=("pve1", "pve2"))
    with pytest.raises(ProviderError, match="denied"):                         # PVE itself restricts cicustom: mapped 403
        mutations(sim, on2).configure_vm(ref(), spec)


def test_pve_denied_nic_attach_is_mapped_to_actionable_message(sim, job):
    wide = EndpointScope(pools=("ou-lab",), storage=("local-lvm",), networks=("vmbr0",), nodes=("pve1", "pve2"))   # scope allows it, the token lacks SDN.Use
    with pytest.raises(ProviderError) as e:
        mutations(sim, wide).configure_vm(ref(), VmConfigSpec(nics=(NicSpec(0, "vmbr0"),)))
    assert e.value.code == "permission" and "SDN.Use" in e.value.message and "probe" in e.value.message


def test_resize_rules(sim, job):
    m = mutations(sim)
    for gb in (8, 4):
        with pytest.raises(ProviderError, match="only grow"):
            m.resize_disk(ref(), "scsi0", gb)
    with pytest.raises(ProviderError):
        m.resize_disk(ref(), "scsi0; rm", 20)
    with pytest.raises(ProviderError, match="no sized disk"):
        m.resize_disk(ref(), "scsi5", 20)
    sim.sim.vms[150]["cfg"]["scsi0"] = "other-lvm:vm-150-disk-0,size=8G"
    with pytest.raises(ScopeViolation, match="storage"):
        m.resize_disk(ref(), "scsi0", 20)
    sim.sim.vms[150]["cfg"]["scsi0"] = "local-lvm:vm-150-disk-0,size=8G"
    m.wait(m.resize_disk(ref(), "scsi0", 20))
    assert "size=20G" in sim.sim.vms[150]["cfg"]["scsi0"]


def test_power_snapshot_rollback_migrate_destroy_lifecycle(sim, job):
    m = mutations(sim)
    m.wait(m.power(ref(), "start"), timeout=5)
    assert sim.sim.vms[150]["status"] == "running"
    with pytest.raises(ProviderError, match="running"):
        m.destroy_vm(ref())
    m.wait(m.snapshot(ref(), "before-upgrade"), timeout=5)
    sim.sim.vms[150]["cfg"]["cores"] = 9
    m.wait(m.power(ref(), "stop"), timeout=5)
    m.wait(m.rollback(ref(), "before-upgrade"), timeout=5)
    assert sim.sim.vms[150]["cfg"]["cores"] == 2
    with pytest.raises(ProviderError, match="does not exist"):
        m.rollback(ref(), "nope")
    with pytest.raises(ProviderError, match="name"):
        m.snapshot(ref(), "bad name;")
    with pytest.raises(ScopeViolation, match="target node"):
        m.migrate(ref(), "pve1", False)
    with pytest.raises(ScopeViolation, match="target node"):
        m.migrate(ref(), "pve7", False)
    m.wait(m.migrate(ref(), "pve2", False), timeout=5)
    assert sim.sim.vms[150]["node"] == "pve2"
    m.wait(m.destroy_vm(ref(150, "pve2")), timeout=5)
    assert 150 not in sim.sim.vms


def test_migrate_refuses_disks_on_unapproved_storage(sim, job):
    sim.sim.vms[150]["cfg"]["scsi1"] = "other-lvm:vm-150-disk-1,size=2G"
    with pytest.raises(ScopeViolation, match="storage"):
        mutations(sim).migrate(ref(), "pve2", False)


# ---------------------------------------------------------------- tasks, timeouts, error mapping
def test_task_timeout_does_not_claim_failure(sim, job):
    m = mutations(sim)
    sim.sim.hang_tasks = True
    t = m.power(ref(), "start")
    with pytest.raises(ProviderTimeout, match="may complete"):
        m.wait(t, timeout=0.3, interval=0.05)


def test_task_failure_is_readable(sim, job):
    m = mutations(sim)
    sim.sim.fail_task_exit = "unable to activate storage 'local-lvm'"
    t = m.power(ref(), "start")
    with pytest.raises(ProviderError) as e:
        m.wait(t, timeout=5)
    assert e.value.code == "task_failed" and "activate storage" in e.value.message


def test_task_ref_validation(sim):
    p = read_provider(sim)
    for bad in ("UPID:pve1:zz", "not-a-upid", "UPID:pve2:00000001:00000001:00000001:qmstart:150:x@pve:"):
        with pytest.raises(ProviderError):
            p.task_status(TaskRef("pve1", bad))
    assert p.task_status(TaskRef("pve1", None)).state == "ok"


@pytest.mark.parametrize("status,reason,code", [(500, "VM is locked (backup)", "locked"), (595, "No route to host", "node_unreachable"),
                                                (403, "Permission check failed (/vms/150, VM.PowerMgmt)", "permission"),
                                                (401, "No ticket", "auth"), (400, "Parameter verification failed", "invalid_request")])
def test_error_mapping(sim, job, status, reason, code):
    m = mutations(sim)
    sim.sim.fail("POST", r"/status/start", status, reason)
    with pytest.raises(ProviderError) as e:
        m.power(ref(), "start")
    assert e.value.code == code and e.value.message


def test_tls_pin_mismatch_in_mutation_path(sim, job):
    from .infra_fixtures import rw as _rw
    from ics.providers.proxmox.provider import ProxmoxMutations
    m = ProxmoxMutations(_rw(sim, fingerprint_sha256="cd" * 32), scope=SCOPE, token_id=LAB[0], allow_simulator=True)
    before = len(sim.sim.seen)
    with pytest.raises(ProviderError) as e:
        m.power(ref(), "start")
    assert e.value.code == "tls" and len(sim.sim.seen) == before


# ---------------------------------------------------------------- HARD RULE: never touch the ICS's own VM
def test_ics_own_vm_is_never_mutated_regardless_of_acl(real_sim, job):
    ident = SelfIdentity(macs=frozenset({"bc:24:11:e7:f0:24"}))
    scope = EndpointScope(pools=("officeunbound-pve06",), storage=("PVE06-Storage",), networks=("vmbr0",), nodes=("pve06",))
    from ics.providers.proxmox.provider import ProxmoxMutations
    m = ProxmoxMutations(rw(real_sim, REAL), scope=scope, token_id=REAL[0], allow_simulator=True, self_identity=ident)
    r = VmRef("pve06", 126, "vm", "d1")
    # make it otherwise fully eligible: in the allowed pool and tagged for the deployment
    vm = real_sim.sim.vms[126]
    vm["pool"] = "officeunbound-pve06"
    vm["cfg"]["tags"] = "ou-managed;ou-deployment-d1"
    for call in (lambda: m.power(r, "stop"), lambda: m.power(r, "reboot"), lambda: m.configure_vm(r, VmConfigSpec(cores=1)),
                 lambda: m.resize_disk(r, "scsi0", 99), lambda: m.snapshot(r, "x"), lambda: m.rollback(r, "x"),
                 lambda: m.migrate(r, "pve05", False), lambda: m.destroy_vm(r)):
        with pytest.raises(ScopeViolation, match="ICS host itself"):
            call()
    assert not [x for x in real_sim.sim.seen if x[0] in ("POST", "PUT", "DELETE")]
    assert vm["status"] == "running"


def test_self_match_by_smbios_uuid_and_fail_closed(real_sim, job):
    from ics.providers.proxmox.provider import ProxmoxMutations
    scope = EndpointScope(pools=("officeunbound-pve06",), storage=("PVE06-Storage",), networks=("vmbr0",), nodes=("pve06",))
    vm = real_sim.sim.vms[126]
    vm["pool"], vm["cfg"]["tags"] = "officeunbound-pve06", "ou-managed;ou-deployment-d1"
    vm["cfg"]["net0"] = "virtio=BC:24:11:00:00:01,bridge=vmbr0"           # MAC differs; UUID still identifies it
    m = ProxmoxMutations(rw(real_sim, REAL), scope=scope, token_id=REAL[0], allow_simulator=True,
                         self_identity=SelfIdentity(uuids=frozenset({"11111111-2222-3333-4444-555555555555"})))
    with pytest.raises(ScopeViolation, match="ICS host itself"):
        m.power(VmRef("pve06", 126, "vm", "d1"), "stop")
    real_sim.sim.fail("GET", r"/126/config", 500, "boom", count=3)       # cannot verify -> refuse
    with pytest.raises(ScopeViolation, match="cannot verify"):
        m.power(VmRef("pve06", 126, "vm", "d1"), "stop")


def test_protected_vmids_block_every_verb_and_clone_into(sim, job):
    sc = EndpointScope(pools=("ou-lab",), storage=("local-lvm",), networks=("vmbr1",), protected=(150, 555), nodes=("pve1", "pve2"))
    m = mutations(sim, sc)
    with pytest.raises(ScopeViolation, match="protected"):
        m.power(ref(150), "start")
    with pytest.raises(ScopeViolation, match="protected"):
        m.clone_vm(clone_spec(new_vmid=555))
    with pytest.raises(ScopeViolation, match="protected"):
        m.clone_vm(clone_spec(template_vmid=150))
    assert not [x for x in sim.sim.seen if x[0] in ("POST", "PUT", "DELETE")]


# ---------------------------------------------------------------- secrets
def test_no_secret_in_any_provider_error_or_result(sim, job):
    secrets = {INV[1], LAB[1]}
    out = []
    p = read_provider(sim)
    out.append(json.dumps(dataclasses.asdict(p.probe())))
    out.append(json.dumps(dataclasses.asdict(p.discover()), default=str))
    m = mutations(sim)
    for code in (401, 403, 500, 595):
        sim.sim.fail("POST", r"/status/start", code, "injected")
        try:
            m.power(ref(), "start")
        except ProviderError as e:
            out.append(e.message)
    blob = " ".join(out)
    assert not any(s in blob for s in secrets) and "PVEAPIToken" not in blob


# ---------------------------------------------------------------- real cluster after the owner's ACL fixes
@pytest.fixture()
def fixed_sim():
    from .pve_sim import PveSim, SimServer
    s = PveSim(task_delay=0.15)
    s.populate_realworld(fixed=True)
    srv = SimServer(s)
    yield srv
    srv.stop()


def test_fixed_real_cluster_probe_clone_from_template_131_and_pool_membership_is_not_ownership(fixed_sim):
    from ics.providers.proxmox.provider import ProxmoxMutations
    ident = SelfIdentity(macs=frozenset({"bc:24:11:e7:f0:24"}))
    scope = EndpointScope(pools=("officeunbound-pve06",), storage=("PVE06-Storage",), networks=("vmbr0",), nodes=("pve06",))
    pr = ProxmoxProvider(ro(fixed_sim, REAL), scope=scope, inventory_token_id=REAL[0], provision_probe=ro(fixed_sim, REAL),
                         provision_token_id=REAL[0], self_identity=ident).probe()
    # the owner's role has no VM.Migrate: the probe says so (migrate is the only verb not available), everything else is fine
    assert pr.ok and [v.verb for v in pr.verbs if not v.ok] == ["migrate"]
    w = " | ".join(pr.warnings)
    assert "inside the managed pool" in w and "Pool membership is never treated as ownership" in w and "DANGER" in w
    assert "Pool.Audit missing" not in w and "VM.Console" not in w
    caps = {c["name"]: c for c in pr.capabilities}
    assert caps["vlan_tagging"]["ok"] is False and "VLAN tagging unavailable" in caps["vlan_tagging"]["detail"]
    with base.job_execution("j"):
        m = ProxmoxMutations(rw(fixed_sim, REAL), scope=scope, token_id=REAL[0], self_identity=ident)
        t = m.clone_vm(VmCloneSpec(131, "pve06", None, "ou-app01", "officeunbound-pve06", "PVE06-Storage", "d1"))
        m.wait(t, timeout=5)
        m.wait(m.finalize_clone(t), timeout=5)
        assert "ou-deployment-d1" in fixed_sim.sim.vms[t.vmid]["cfg"]["tags"]
        # the ICS VM is a pool member: neither pool membership nor the pool ACL makes it mutable (tags AND identity)
        with pytest.raises(ScopeViolation, match="ICS host itself"):
            m.power(VmRef("pve06", 126, "vm", "d1"), "stop")
        m2 = ProxmoxMutations(rw(fixed_sim, REAL), scope=scope, token_id=REAL[0])          # even without identity: no ownership tags
        with pytest.raises(ScopeViolation, match="ownership tags"):
            m2.power(VmRef("pve06", 126, "vm", "d1"), "stop")


def test_thin_storage_reports_provisioned_vs_physical(sim):
    sim.sim.storages["local-lvm"]["type"] = "lvmthin"
    sim.sim.storages["local-lvm"]["total"] = 10 << 30
    sim.sim.storages["local-lvm"]["hidden_volumes"] = [20 << 30]
    d = read_provider(sim).discover()
    s = next(x for x in d.storage if x["name"] == "local-lvm" and x["node"] == "pve1")
    assert s["thin"] is True and s["total"] == 10 << 30 and s["provisioned_bytes"] > 20 << 30


def test_destroy_uses_live_status_when_cluster_cache_lags(sim, job):
    """Real PVE 9.2 (2026-11-15): right after a successful stop, /cluster/resources still reported 'running' for a few
    seconds and destroy refused. The precondition must use the authoritative /status/current."""
    m = mutations(sim)
    m.wait(m.power(ref(), "start"), timeout=5)
    m.wait(m.power(ref(), "stop"), timeout=5)
    sim.sim.vms[150]["cached_status"] = "running"          # stale cache, VM actually stopped
    st = m.wait(m.destroy_vm(ref()), timeout=5)
    assert st.state == "ok" and 150 not in sim.sim.vms


def test_destroy_still_refuses_genuinely_running_guest(sim, job):
    m = mutations(sim)
    m.wait(m.power(ref(), "start"), timeout=5)
    with pytest.raises(ProviderError, match="running"):
        m.destroy_vm(ref())
