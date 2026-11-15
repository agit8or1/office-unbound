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
from ics.deploy import agentport, executor
from ics.deploy.ports import ExecEnv, StepFailed
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
def key(b=b"\x01"):
    return Ed25519PrivateKey.from_private_bytes(b * 32)


def test_boot_identity_is_deterministic_per_vm_and_never_the_token_itself_in_userdata():
    a, a2, b, c = (sshboot.identity(key(), "dep", "vm1"), sshboot.identity(key(), "dep", "vm1"), sshboot.identity(key(), "dep", "vm2"),
                   sshboot.identity(key(b"\x02"), "dep", "vm1"))
    assert (a.ssh_public, a.psk, a.enroll_token, a.enroll_token_sha256) == (a2.ssh_public, a2.psk, a2.enroll_token, a2.enroll_token_sha256)   # (the OpenSSH PEM has a random check value)
    assert len({a.psk, b.psk, c.psk}) == 3 and len({a.ssh_public, b.ssh_public, c.ssh_public}) == 3
    assert hashlib.sha256(a.enroll_token.encode()).hexdigest() == a.enroll_token_sha256 and len(a.psk) == 48
    assert a.ssh_public.startswith("ssh-ed25519 ") and b"OPENSSH PRIVATE KEY" in a.ssh_private_openssh


def test_link_local_address_is_eui64_of_the_mac():
    assert sshboot.link_local("bc:24:11:44:38:7d", "eth0") == "fe80::be24:11ff:fe44:387d%eth0"   # verified against a real VM on pve06
    with pytest.raises(sshboot.BootstrapError):
        sshboot.link_local("zz:24:11:44:38:7d", "eth0")
    with pytest.raises(sshboot.BootstrapError):
        sshboot.link_local("bc:24:11:44:38:7d", "eth0; reboot")


def _fake_ssh(monkeypatch, answer):
    seen = {}

    def run(argv, input=None, **kw):
        seen["argv"], seen["script"] = argv, input.decode()
        nonce = input.decode().split("printf '%s\\n%s' '")[1].split("'")[0]
        return types.SimpleNamespace(returncode=0, stdout=answer(nonce).encode(), stderr=b"")
    monkeypatch.setattr(sshboot.subprocess, "run", run)
    return seen


def test_guest_answers_are_accepted_only_with_the_smbios_proof(monkeypatch):
    ident = sshboot.identity(key(), "dep", "vm1")
    g = sshboot.Guest(ident, "fe80::1%eth0", ssh_bin="/usr/bin/ssh")
    seen = _fake_ssh(monkeypatch, lambda n: "addr=192.168.22.5\ndone=0\nOU-MAC " + sshboot.mac_of(ident.psk, n, "addr=192.168.22.5\ndone=0") + "\n")
    assert g.call("echo hi") == {"addr": "192.168.22.5", "done": "0"}
    a = seen["argv"]
    assert a[0] == "/usr/bin/ssh" and "sudo -n /bin/sh -s" == a[-1] and "BatchMode=yes" in a and "IdentitiesOnly=yes" in a      # fixed remote command
    assert ident.psk not in seen["script"] and ident.enroll_token not in seen["script"]                                       # the PSK never goes to the guest
    for bad in (lambda n: "addr=192.168.22.5\nOU-MAC " + "0" * 64 + "\n",                       # wrong key (an impostor)
                lambda n: "addr=192.168.22.5\n",                                                # no proof at all
                lambda n: "addr=1.2.3.4\nOU-MAC " + sshboot.mac_of(ident.psk, "othernonce", "addr=1.2.3.4") + "\n"):   # replayed proof
        _fake_ssh(monkeypatch, bad)
        with pytest.raises(sshboot.ProofFailed):
            g.call("echo hi")


def test_unreachable_guest_is_retryable_not_a_proof_failure(monkeypatch):
    monkeypatch.setattr(sshboot.subprocess, "run", lambda *a, **k: types.SimpleNamespace(returncode=255, stdout=b"", stderr=b"Connection refused"))
    with pytest.raises(sshboot.NotReady) as e:
        sshboot.Guest(sshboot.identity(key(), "d", "v"), "fe80::1%eth0").call("true")
    assert "Connection refused" not in str(e.value)       # ssh stderr is never echoed


def test_install_body_has_only_validated_interpolations():
    body = sshboot.install_body("#cloud-config\nhostname: x\n", "ou-boot-0123456789abcdef", "vm-1")
    assert "base64 -d > $D/user-data <<'OU_SEED_END'" in body and "fs_label: null" in body and "systemd-run --quiet --no-block --unit=ou-bootstrap-run" in body
    for bad in (("a;b", "vm"), ("ou-boot-0123456789abcdef", "vm;reboot"), ("ou-boot-0123456789abcdef", "VM")):
        with pytest.raises(sshboot.BootstrapError):
            sshboot.install_body("x", *bad)


# ---------------------------------------------------------------- guest user-data for the ICS-driven bootstrap
def test_bootstrap_user_keeps_ssh_until_sealed_and_only_for_link_local():
    s = _spec(os="debian-12", bootstrap_user="ou-boot", agent_address="192.168.22.9", mgmt_sources=["192.168.22.167/32"])
    cfg = cloudinit.build(s)
    files = {f["path"]: f["content"] for f in cfg["write_files"]}
    assert "/usr/local/sbin/ou-bootstrap-seal" in files
    seal = files["/usr/local/sbin/ou-bootstrap-seal"]
    assert "mask ssh.socket ssh.service" in seal and "passwd -l ou-boot" in seal and "authorized_keys" in seal
    boot = files["/usr/local/sbin/ou-guest-bootstrap"]
    assert "ou-bootstrap-seal-timer --on-active=3600" in boot and "mask ssh" not in boot      # sealed by the ICS, with a dead-man timer
    nft = files["/etc/nftables.conf"]
    assert "ip6 saddr fe80::/10 tcp dport 22 accept" in nft and "tcp dport 22 accept" not in nft.replace("ip6 saddr fe80::/10 tcp dport 22 accept", "")
    plain = cloudinit.build(_spec(os="debian-12"))
    assert not any(f["path"].endswith("ou-bootstrap-seal") for f in plain["write_files"]) and "ssh" in files["/usr/local/sbin/ou-guest-bootstrap"] + "ssh"


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
class FakeGuest:
    def __init__(self, ident, addr, **kw):
        self.ident, self.addr, self.calls, FakeGuest.last = ident, addr, [], self

    def probe(self):
        self.calls.append("probe")
        return {"addr": "192.168.22.50", "done": "0", "running": "inactive"}

    def install(self, ud, iid, host):
        self.calls.append("install")
        assert ud.startswith("#cloud-config") and host == "vm1" and self.ident.enroll_token not in ud and self.ident.psk not in ud
        assert self.ident.enroll_token_sha256 in ud                 # only the HASH of the one-time token reaches the guest
        return {"state": "started"}

    def status(self):
        self.calls.append("status")
        return {"done": "1", "rc": "0", "running": "inactive", "log": ""}

    def fingerprints(self):
        return json.dumps({"address": "192.168.22.50", "port": 8443, "tls_fingerprint_sha256": "ab" * 32, "agent_key_fingerprint_sha256": "cd" * 32})

    def seal(self):
        self.calls.append("seal")


def _port(rt, tmp_path, monkeypatch, **kw):
    sk = tmp_path / "sign.key"
    sk.write_bytes(b"\x07" * 32)
    sk.chmod(0o600)
    object.__setattr__(rt.settings, "signing_key_file", str(sk))
    with rt.session() as db:
        uid = db.execute(text("INSERT INTO users (username, role, enrolled) VALUES ('agentport-u', 'operator', true) RETURNING id")).scalar()
        eid = db.execute(text("INSERT INTO endpoints (name, type, base_url, token_id, token_secret_enc, fingerprint_sha256) VALUES "
                              "('ep', 'proxmox', 'https://pve.test:8006', 'u@pve!t', :s, :f) RETURNING id"), {"s": b"x", "f": "ab" * 32}).scalar()
        did = db.execute(text("INSERT INTO deployments (slug, customer_id, profile, profile_version, endpoint_id, status, desired_spec) VALUES "
                              "('dep1', 'c', 'lab', '1.0.0', :e, 'provisioning', '{}'::jsonb) RETURNING id"), {"e": str(eid)}).scalar()
        db.execute(text("INSERT INTO deployment_resources (deployment_id, kind, logical_name, state, desired, provider_ref) VALUES "
                        "(:d, 'vm', 'vm1', 'creating', '{}'::jsonb, '{\"node\": \"pve06\", \"vmid\": 140}'::jsonb)"), {"d": str(did)})
        db.commit()
    plan = {"vms": [{"name": "vm1", "os_image": {"id": "debian-12"}}], "firewall": [{"vm": "vm1", "port": 2525, "proto": "tcp", "from": "ics-control", "purpose": "x"},
                                                                                    {"vm": "vm1", "port": 8443, "proto": "tcp", "from": "ics-control", "purpose": "agent"}]}
    prov = types.SimpleNamespace(guest_mac=lambda r: "bc:24:11:44:38:7d")
    monkeypatch.setattr(sshboot, "default_iface", lambda: "eth0")
    monkeypatch.setattr(agentport.GuestAgentPort, "_source_towards", staticmethod(lambda a: "192.168.22.167"))
    return agentport.GuestAgentPort(rt, {"slug": "dep1", "id": str(did), "created_by": str(uid), "plan": plan}, prov, sleep=lambda s: None,
                                    guest_factory=FakeGuest, **kw)


def test_wait_enrollment_bootstraps_enrolls_over_the_pinned_channel_and_seals(rt, tmp_path, monkeypatch):
    port = _port(rt, tmp_path, monkeypatch)
    sent = {}
    monkeypatch.setattr(agentport.agentclient, "identity", lambda a, p, fp, **k: sent.update(identity=(a, p, fp)) or {"agent_pubkey": base64.b64encode(b"k" * 32).decode()})
    monkeypatch.setattr(agentport.agentclient, "key_fingerprint", lambda k: "cd" * 32)
    monkeypatch.setattr(agentport.agentclient, "enroll", lambda a, p, fp, **k: sent.update(enroll=(a, p, fp, k["token"])) or {"capabilities": {"guest.facts": {}}, "agent_version": "0.1.0"})
    monkeypatch.setattr(agentport, "_agent_dir", lambda rt: __import__("os").path.join(__import__("os").path.dirname(__file__), "..", "agent"))
    nid = port.wait_enrollment("vm1", 600)
    assert sent["identity"] == ("192.168.22.50", 8443, "ab" * 32) and sent["enroll"][:3] == ("192.168.22.50", 8443, "ab" * 32)
    assert sent["enroll"][3] == sshboot.identity(port._key(), "dep1", "vm1").enroll_token            # the plaintext token goes only to the pinned agent
    assert FakeGuest.last.calls == ["probe", "install", "status", "seal"] and FakeGuest.last.addr == "fe80::be24:11ff:fe44:387d%eth0"
    with rt.session() as db:
        n = db.execute(text("SELECT * FROM nodes")).one()
        assert str(n.id) == nid and n.name == "dep1-vm1-140" and n.address == "192.168.22.50" and n.tls_fingerprint_sha256 == "ab" * 32
    assert port.wait_enrollment("vm1", 600) == nid and FakeGuest.last.calls[-1] == "seal"            # idempotent: no second bootstrap
    assert port.address("vm1") == "192.168.22.50"
    with pytest.raises(StepFailed, match="not implemented"):
        port.tls_trust(nid, 443)


def test_wait_enrollment_refuses_an_impostor_and_a_bad_agent_fingerprint(rt, tmp_path, monkeypatch):
    port = _port(rt, tmp_path, monkeypatch)

    class Impostor(FakeGuest):
        def probe(self):
            raise sshboot.ProofFailed("SMBIOS proof mismatch")
    port._guest_factory = Impostor
    with pytest.raises(StepFailed) as e:
        port.wait_enrollment("vm1", 600)
    assert e.value.retryable is False and "nothing was sent" in e.value.explanation
    port._guest_factory = FakeGuest
    monkeypatch.setattr(agentport.agentclient, "identity", lambda *a, **k: {"agent_pubkey": base64.b64encode(b"k" * 32).decode()})
    monkeypatch.setattr(agentport.agentclient, "key_fingerprint", lambda k: "ee" * 32)        # not the fingerprint the guest reported
    monkeypatch.setattr(agentport, "_agent_dir", lambda rt: __import__("os").path.join(__import__("os").path.dirname(__file__), "..", "agent"))
    with pytest.raises(StepFailed, match="does not match the fingerprint"):
        port.wait_enrollment("vm1", 600)
    with rt.session() as db:
        assert db.execute(text("SELECT count(*) FROM nodes")).scalar() == 0


def test_run_runbook_turns_agent_refusals_and_failed_verification_into_step_failures(rt, tmp_path, monkeypatch):
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


def test_configure_step_hands_the_guest_its_first_contact_material(rt, monkeypatch):
    sent = {}

    class P:
        def configure_vm(self, r, spec):
            sent["spec"] = spec
            return types.SimpleNamespace(upid=None)
        def task_status(self, t):
            return types.SimpleNamespace(state="ok")
    agent = types.SimpleNamespace(bootstrap_config=lambda vm: {"ciuser": "ou-boot", "sshkeys": ("ssh-ed25519 AAAA x",), "smbios_serial": "ab" * 24})
    env = ExecEnv(provider=P(), agent=agent)
    ctx = executor.StepCtx(rt, env, "j", "d", "dep1", {}, "u", 1, {"target": "vm1", "op": "configure_vm", "params": {
        "cores": 1, "memory_mb": 512, "disks": [{"name": "root", "storage": "s", "size_gb": 10}], "nics": [{"bridge": "vmbr0"}],
        "cloud_init": {"hostname": "vm1", "agent_enrollment": True}}}, {})
    monkeypatch.setattr(ctx, "vm_ref", lambda vm: VmRef("n", 1, "vm", "dep1"))
    executor.h_provider_task(ctx)
    s = sent["spec"]
    assert s.ciuser == "ou-boot" and s.smbios_serial == "ab" * 24 and s.ciupgrade is False and s.ipconfigs == (IpConfig(0, "dhcp"),) and s.cloudinit_storage == "s"


def test_settings_read_the_guest_and_job_timeout_knobs(tmp_path, monkeypatch):
    from ics.config import load_settings
    f = tmp_path / "e.env"
    f.write_text("ICS_DATABASE_URL=x\nICS_VAULT_KEY_FILE=v\nICS_AUDIT_KEY_FILE=a\nICS_JOB_TIMEOUT_SECONDS=3000\nICS_GUEST_IMAGE_REGISTRIES=a:5000, b.example\n"
                 "ICS_GUEST_INSECURE_REGISTRIES=a:5000\nICS_GUEST_KEEP_BOOTSTRAP_SSH=true\n")
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
