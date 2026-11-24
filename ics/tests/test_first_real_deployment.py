"""Regression tests for the defects found by the first REAL deployment on pve06 (docs/status/first-real-deployment.md): each test fails on the code
as it was before the fix. Provider tests run against the simulator (a test double, extended to model the real behaviour)."""
import base64
import hashlib
import hmac
import json
import types

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import text

from ics import proxmox
from ics.deploy import agentport
from ics.deploy.ports import StepFailed
from ics.guest import cloudinit, sshboot
from ics.providers.base import IpConfig, ProviderError, VmCloneSpec, VmConfigSpec, VmRef
from .infra_fixtures import job, mutations, sim  # noqa: F401
from .test_guest_bootstrap import spec as _spec
from .test_provider_proxmox import clone_spec, ref


# ---------------------------------------------------------------- provider: real PVE behaviour
def test_configure_does_not_create_a_second_cloud_init_drive(sim, job):
    """The template already carries ide2 vm-<id>-cloudinit; asking PVE for another one failed with 'Logical Volume ... already exists'."""
    m = mutations(sim)
    sim.sim.vms[150]["cfg"]["ide2"] = "local-lvm:vm-150-cloudinit,media=cdrom"
    t = m.configure_vm(ref(), VmConfigSpec(cores=2, cloudinit_storage="local-lvm"))
    assert m.wait(t).state == "ok" and sim.sim.vms[150]["cfg"]["ide2"] == "local-lvm:vm-150-cloudinit,media=cdrom"
    del sim.sim.vms[150]["cfg"]["ide2"]
    m.wait(m.configure_vm(ref(), VmConfigSpec(cloudinit_storage="local-lvm")))      # a template without a drive still gets one
    assert sim.sim.vms[150]["cfg"]["ide2"].endswith("cloudinit,media=cdrom")


def test_configure_sets_bootstrap_material_through_smbios_and_disables_first_boot_upgrade(sim, job):
    m = mutations(sim)
    sim.sim.vms[150]["cfg"]["smbios1"] = "uuid=3041632a-47b0-4ee7-a8bd-d49a3a6021df"
    m.wait(m.configure_vm(ref(), VmConfigSpec(ciuser="ou-boot", ciupgrade=False, smbios_serial="ab" * 24, ipconfigs=(IpConfig(0, "dhcp"),))))
    c = sim.sim.vms[150]["cfg"]
    assert c["ciupgrade"] == 0 and c["ipconfig0"] == "ip=dhcp"
    assert c["smbios1"] == "uuid=3041632a-47b0-4ee7-a8bd-d49a3a6021df,base64=1,serial=" + base64.b64encode(("ab" * 24).encode()).decode()
    for bad in ("short", "has space " * 3, "x" * 200, "semi;colon-secret-1234"):
        with pytest.raises(ProviderError):
            m.configure_vm(ref(), VmConfigSpec(smbios_serial=bad))


def test_finalize_clone_survives_the_cluster_resources_cache_lag(sim, job):
    """Real PVE 9.2: right after a clone /cluster/resources lists the guest WITHOUT a name ('guest 137 is named None'); the live config is authoritative."""
    sim.sim.clone_res_lag = 3
    m = mutations(sim)
    t = m.clone_vm(clone_spec())
    m.wait(t, timeout=5)
    m.wait(m.finalize_clone(t), timeout=5)
    assert "ou-managed" in sim.sim.vms[t.vmid]["cfg"]["tags"]
    # ... and the check still refuses a guest whose LIVE name is not the one this clone asked for
    t2 = m.clone_vm(clone_spec(name="app02"))
    m.wait(t2, timeout=5)
    sim.sim.vms[t2.vmid]["cfg"]["name"] = "someone-elses"
    with pytest.raises(Exception, match="named 'someone-elses'"):
        m.finalize_clone(t2)


def test_guest_mac_and_disk_size_are_read_only_helpers(sim, job):
    m = mutations(sim)
    sim.sim.vms[150]["cfg"]["net0"] = "virtio=BC:24:11:96:19:C5,bridge=vmbr1"
    sim.sim.vms[150]["cfg"]["scsi0"] = "local-lvm:vm-150-disk-0,size=3G"
    assert m.guest_mac(ref()) == "bc:24:11:96:19:c5"
    assert m.disk_size_gb(ref(), "scsi0") == 3 and m.disk_size_gb(ref(), "scsi9") is None
    with pytest.raises(Exception):
        m.guest_mac(ref(160))                          # an untagged guest is never inspected


def test_inventory_tolerates_a_token_without_sys_audit_on_root(monkeypatch):
    """pve06 token: Sys.Audit only on /nodes/<node>, so GET /cluster/status is 403 and the whole inventory.refresh used to fail."""
    c = proxmox.ProxmoxReadClient.__new__(proxmox.ProxmoxReadClient)

    def fake_get(path):
        if path == "/cluster/status":
            raise proxmox.ProxmoxHTTPError("GET", path, 403, "Permission check failed (/, Sys.Audit)")
        return {"/version": {"version": "9.2.21"}, "/nodes": [{"node": "pve06", "status": "online"}]}.get(path, [])
    monkeypatch.setattr(c, "_get", fake_get, raising=False)
    inv = proxmox.ProxmoxReadClient.inventory(c)
    assert inv["cluster_status"] == [] and inv["cluster_status_unavailable"] == "permission" and inv["nodes"][0]["node"] == "pve06"

    def other_error(path):
        raise proxmox.ProxmoxHTTPError("GET", path, 500, "boom")
    monkeypatch.setattr(c, "_get", other_error, raising=False)
    with pytest.raises(proxmox.ProxmoxHTTPError):       # only the permission case is tolerated
        proxmox.ProxmoxReadClient.inventory(c)


# ---------------------------------------------------------------- the ICS-driven first boot




def test_link_local_address_is_eui64_of_the_mac():
    assert sshboot.link_local("bc:24:11:44:38:7d", "eth0") == "fe80::be24:11ff:fe44:387d%eth0"   # verified against a real VM on pve06
    with pytest.raises(sshboot.BootstrapError):
        sshboot.link_local("zz:24:11:44:38:7d", "eth0")
    with pytest.raises(sshboot.BootstrapError):
        sshboot.link_local("bc:24:11:44:38:7d", "eth0; reboot")










# ---------------------------------------------------------------- guest user-data for the ICS-driven bootstrap


def test_bootstrap_user_and_break_glass_key_are_exclusive_and_user_name_is_validated():
    with pytest.raises(ValueError):
        _spec(bootstrap_user="ou-boot", break_glass_ssh_key="ssh-ed25519 " + "A" * 60)
    with pytest.raises(ValueError):
        _spec(bootstrap_user="ou-boot; id")


def test_insecure_registries_must_be_listed_registries_and_reach_the_agent_config(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    pub = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    der = serialization.load_pem_public_key(pub.encode()).public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    base = dict(image_registries=["192.168.22.167:5000"], image_signing_pubkey_pem=pub, image_signing_key_sha256=hashlib.sha256(der).hexdigest())   # (the helper's own registry is replaced)
    with pytest.raises(ValueError, match="subset"):
        _spec(**base, insecure_registries=["other.example:5000"])
    s = _spec(**base, insecure_registries=["192.168.22.167:5000"])
    cfg = cloudinit.agent_config(s)
    assert cfg["runbooks"]["podman.pull_verified"]["insecure"] == ["192.168.22.167:5000"] and "insecure" not in cfg["runbooks"]["podman.deploy_unit"]
    conf = {f["path"]: f["content"] for f in cloudinit.build(s)["write_files"]}["/etc/containers/registries.conf.d/50-ou-insecure.conf"]
    assert 'location = "192.168.22.167:5000"' in conf and "insecure = true" in conf
    from ou_agent import guestspec as gs
    gs.validate_runbook_config("podman.pull_verified", cfg["runbooks"]["podman.pull_verified"])
    with pytest.raises(ValueError):
        gs.validate_runbook_config("podman.pull_verified", {"registries": ["a.example"], "insecure": ["b.example"]})
    with pytest.raises(ValueError):
        gs.validate_runbook_config("podman.deploy_unit", {"registries": ["a.example"], "evil": 1})


# ---------------------------------------------------------------- executor + agent port








def test_run_runbook_turns_agent_refusals_and_failed_verification_into_step_failures(rt, tmp_path, monkeypatch):
    from .test_lab_ssh_bootstrap import _port
    port = _port(rt, tmp_path, monkeypatch)

    def reply(resp):
        monkeypatch.setattr(agentport.agentcall, "execute", lambda *a, **k: resp)
    reply({"status": "ok", "result": {"returncode": 0, "result": {"verified": True, "digest": "sha256:" + "a" * 64}}})
    assert port.run_runbook("n", "podman.pull_verified", {})["verified"] is True
    reply({"status": "ok", "result": {"returncode": 0, "result": {"verified": False, "error": "no valid signature"}}})
    with pytest.raises(StepFailed, match="no valid signature") as e:
        port.run_runbook("n", "podman.pull_verified", {})
    assert e.value.retryable is False                     # an unsigned image is never retried into acceptance
    reply({"status": "ok", "result": {"returncode": 0, "rejected": {"code": "image_not_verified", "message": "not pulled"}}})
    with pytest.raises(StepFailed, match="image_not_verified"):
        port.run_runbook("n", "podman.deploy_unit", {})
    reply({"status": "ok", "result": {"returncode": 0, "result": {"started": False, "active_state": "failed"}}})
    with pytest.raises(StepFailed, match="failed"):
        port.run_runbook("n", "podman.deploy_unit", {})
    # the agent's own refusal (before the helper runs) carries its reason in result.message (e2e-fo1 showed "bad_params: " and nothing else)
    reply({"status": "rejected", "code": "bad_params", "result": {"message": "file path does not match the allowed pattern"}})
    with pytest.raises(StepFailed, match="bad_params: file path does not match"):
        port.run_runbook("n", "cfg.volume_files", {})
    reply({"status": "ok", "result": {"returncode": 0, "result": {"started": False, "active_state": "failed", "log": "Error: mkdir /sys/fs/cgroup/x: read-only file system"}}})
    with pytest.raises(StepFailed, match="unit log: Error: mkdir"):
        port.run_runbook("n", "podman.deploy_unit", {})




def test_settings_read_the_guest_and_job_timeout_knobs(tmp_path, monkeypatch):
    from ics.config import load_settings
    f = tmp_path / "e.env"
    f.write_text("ICS_DATABASE_URL=x\nICS_VAULT_KEY_FILE=v\nICS_AUDIT_KEY_FILE=a\nICS_JOB_TIMEOUT_SECONDS=3000\nICS_GUEST_IMAGE_REGISTRIES=a:5000, b.example\n"
                 "ICS_GUEST_INSECURE_REGISTRIES=a:5000\nICS_ENVIRONMENT=lab\nICS_LAB_SSH_BOOTSTRAP=true\nICS_GUEST_KEEP_BOOTSTRAP_SSH=true\n")
    monkeypatch.setenv("ICS_ENV_FILE", str(f))
    s = load_settings()
    assert s.job_timeout_seconds == 3000 and s.guest_image_registries == ("a:5000", "b.example") and s.guest_insecure_registries == ("a:5000",)
    assert s.guest_keep_bootstrap_ssh is True and load_settings.__module__ == "ics.config"


def test_podman_runbook_unit_does_not_stack_seccomp_and_mount_sandboxing():
    """Real Debian 12 VM: PrivateTmp/ProtectControlGroups (mount namespace) + LockPersonality/RestrictRealtime/ProtectKernel* (seccomp) in the SAME
    unit make rootless podman fail with `newuidmap: write to uid_map failed: Operation not permitted`. Each group alone works. The unit must
    never carry both again (and must stay a non-root, NoNewPrivileges-free unit, which rootless podman needs)."""
    import os
    path = os.path.join(os.path.dirname(__file__), "..", "agent", "deploy", "runbooks", "ou-rb-podman@.service")
    lines = [l.strip() for l in open(path) if l.strip() and not l.lstrip().startswith("#")]
    keys = {l.split("=", 1)[0] for l in lines if "=" in l}
    mount = {"PrivateTmp", "ProtectControlGroups", "ProtectSystem", "ProtectHome", "PrivateDevices", "ReadOnlyPaths", "InaccessiblePaths"}
    seccomp = {"LockPersonality", "RestrictRealtime", "ProtectKernelModules", "ProtectKernelTunables", "SystemCallFilter", "MemoryDenyWriteExecute",
               "RestrictNamespaces", "RestrictSUIDSGID", "ProtectClock", "ProtectKernelLogs"}
    assert not (keys & mount and keys & seccomp), (keys & mount, keys & seccomp)
    assert "PrivateTmp" not in keys and "PrivateTmp=true" not in lines          # the image store keeps temporary files in /var/tmp across runbook runs
    assert "User=ou-svc" in lines and "NoNewPrivileges=true" not in lines and "NoNewPrivileges=yes" not in lines


def test_ownership_is_read_from_the_live_config_not_the_lagging_resources_cache(sim, job):
    """Real pve06 2026-11-19 (deployment e2e-id1): right after finalize_clone set the ownership tags, /cluster/resources still listed the
    template's tags, so configure_vm refused its own guest ("is not a guest of this deployment"). The live config is authoritative."""
    sim.sim.tag_cache_lag = 5
    m = mutations(sim)
    t = m.clone_vm(clone_spec())
    m.wait(t, timeout=5)
    m.wait(m.finalize_clone(t), timeout=5)
    r = VmRef(node=t.node, vmid=t.vmid, kind="vm", deployment_id=t.deployment_id)
    m.wait(m.configure_vm(r, VmConfigSpec(cores=2)), timeout=5)                 # refused before the fix
    assert m.guest_owned(r, "app01", t.deployment_id)["vmid"] == t.vmid
    sim.sim.vms[t.vmid]["cfg"]["tags"] = "ou-managed;ou-deployment-other"      # the live config decides in both directions
    assert m.guest_owned(r, "app01", t.deployment_id) is None
    with pytest.raises(Exception, match="ownership tags"):
        m.configure_vm(r, VmConfigSpec(cores=2))


def test_a_clone_does_not_keep_the_golden_image_markers_of_its_template(sim, job):
    """Real pve06: a clone inherits the template's tags (ou-image;ou-rel-...); the deployed guest must not look like a golden image."""
    sim.sim.clone_inherits_tags = True
    sim.sim.vms[9000]["cfg"]["tags"] = "ou-image;ou-managed;ou-rel-ubuntu-24.04-20261118;keep-me"
    m = mutations(sim)
    t = m.clone_vm(clone_spec())
    m.wait(t, timeout=5)
    m.wait(m.finalize_clone(t), timeout=5)
    assert sorted(sim.sim.vms[t.vmid]["cfg"]["tags"].split(";")) == ["keep-me", "ou-deployment-d9", "ou-managed"]


@pytest.mark.parametrize("unit", ["ou-rb-podman@.service", "ou-rb-cfg@.service"])
def test_units_that_run_podman_create_no_mount_namespace(unit):
    """Real VM e2e-id5 (2026-11-19): the first podman command of ou-svc creates the long-lived rootless `pause` process; every later podman
    command of the user, including the Quadlet units started by the user manager, joins its user+mount namespaces. ProtectControlGroups in
    the runbook unit froze a read-only /sys/fs/cgroup into it and every unit start failed ("mkdir .../runtime: read-only file system").
    Any unit that runs podman as ou-svc must therefore carry no mount-namespace option at all."""
    import os
    path = os.path.join(os.path.dirname(__file__), "..", "agent", "deploy", "runbooks", unit)
    keys = {l.split("=", 1)[0].strip() for l in open(path) if "=" in l and not l.lstrip().startswith("#")}
    mount = {"PrivateTmp", "ProtectControlGroups", "ProtectSystem", "ProtectHome", "PrivateDevices", "ReadOnlyPaths", "InaccessiblePaths", "ProtectKernelTunables",
             "ProtectKernelModules", "ProtectKernelLogs", "ProtectProc", "ProtectClock", "PrivateMounts", "BindPaths", "BindReadOnlyPaths", "TemporaryFileSystem",
             "ReadWritePaths", "ProtectHostname", "PrivateNetwork", "PrivateIPC", "PrivateUsers"}
    assert not keys & mount, keys & mount


def test_guest_facts_keep_what_the_running_agent_server_adds(rt, tmp_path, monkeypatch):
    """officeunbound8 (2026-11-23): the agent server (>= 0.10.1) puts its capabilities, its own version and its start time NEXT TO the
    helper's facts. The port used to return only the helper's dict, so agent.update saw the version on disk and never the capabilities
    ("cannot extend its allowlists") nor `started` (the restart wait could never finish)."""
    from .test_lab_ssh_bootstrap import _port
    port = _port(rt, tmp_path, monkeypatch)

    def reply(resp):
        monkeypatch.setattr(agentport.agentcall, "execute", lambda *a, **k: resp)
    helper = {"agent_version": "0.10.1", "hostname": "vm", "units": []}
    reply({"status": "ok", "result": {"returncode": 0, "result": helper, "agent_version": "0.10.1", "started": 1795467073,
                                      "capabilities": {"cfg.agent_allow": {"enabled": True}}}})
    f = port.run_runbook("n", "guest.facts", {})
    assert f["started"] == 1795467073 and "cfg.agent_allow" in f["capabilities"] and f["hostname"] == "vm"
    # an old server (0.9.4) adds nothing: the helper's facts only, so the update keeps waiting for a server that reports `started`
    reply({"status": "ok", "result": {"returncode": 0, "result": {**helper, "agent_version": "0.10.1"}}})
    f = port.run_runbook("n", "guest.facts", {})
    assert "started" not in f and "capabilities" not in f
    # the RUNNING version wins over the code on disk (new files unpacked, old server still answering is the 0.9.4 case above)
    reply({"status": "ok", "result": {"returncode": 0, "result": {**helper, "agent_version": "0.10.2"}, "agent_version": "0.10.1", "started": 5}})
    assert port.run_runbook("n", "guest.facts", {})["agent_version"] == "0.10.1"
    # other runbooks are unchanged: the helper's result only
    reply({"status": "ok", "result": {"returncode": 0, "result": {"verified": True}, "agent_version": "0.10.1"}})
    assert "agent_version" not in port.run_runbook("n", "podman.pull_verified", {})


def test_the_controller_may_send_every_runbook_the_node_agent_offers():
    """officeunbound8 (job eda57650): agent 0.10.1 offered cfg.agent_allow and cfg.keycloak_realm, but the controller's own list refused to
    send them ("not a guest runbook"), so every real in-place agent update failed; the tests ran against a fake port that skipped the list."""
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
    from ou_agent import cfgspec, diagspec, guestspec, probespec
    from ics.guest.agentcall import GUEST_RUNBOOKS
    agent = set(cfgspec.CFG_RUNBOOKS) | set(guestspec.GUEST_RUNBOOKS) | {probespec.PROBE_RUNBOOK, diagspec.DIAG_RUNBOOK}
    assert agent == set(GUEST_RUNBOOKS)
