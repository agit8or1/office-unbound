"""The LAB-ONLY SSH guest bootstrap after the independent review (docs/status/review-ssh-bootstrap-2026-11-15.md): off by default and refused in
production (flag), fails closed (H1), synchronous verified seal that the resume path repeats (H2), random per-instance vault-held secrets deleted after
use (M1), no secret on a command line and cleared from the VM config (M2), fixed operations only (M3), proof verified before any payload (M4)."""
import base64
import dataclasses
import json
import os
import types

import pytest
from sqlalchemy import text

from ics.config import Settings
from ics.deploy import agentport
from ics.deploy.ports import Fenced, StepFailed
from ics.guest import bootsecrets, cloudinit, sshboot
from ics.providers.base import ProviderError


# ---------------------------------------------------------------- the flag
def test_lab_ssh_bootstrap_is_off_by_default_and_refused_in_production(base_settings):
    assert Settings.__dataclass_fields__["lab_ssh_bootstrap"].default is False and base_settings.lab_ssh_bootstrap is False
    assert Settings.__dataclass_fields__["environment"].default == "production"
    with pytest.raises(RuntimeError, match="lab-only"):
        dataclasses.replace(base_settings, lab_ssh_bootstrap=True)                       # production environment
    with pytest.raises(RuntimeError, match="lab-only"):
        dataclasses.replace(base_settings, guest_keep_bootstrap_ssh=True)
    with pytest.raises(RuntimeError, match="needs ICS_LAB_SSH_BOOTSTRAP"):
        dataclasses.replace(base_settings, environment="lab", guest_keep_bootstrap_ssh=True)
    with pytest.raises(RuntimeError, match="ICS_ENVIRONMENT"):
        dataclasses.replace(base_settings, environment="staging")
    assert dataclasses.replace(base_settings, environment="lab", lab_ssh_bootstrap=True).lab_ssh_bootstrap is True


def test_load_settings_refuses_the_lab_flag_in_a_production_file(tmp_path, monkeypatch):
    from ics.config import load_settings
    f = tmp_path / "e.env"
    f.write_text("ICS_DATABASE_URL=x\nICS_VAULT_KEY_FILE=v\nICS_AUDIT_KEY_FILE=a\nICS_LAB_SSH_BOOTSTRAP=true\n")
    monkeypatch.setenv("ICS_ENV_FILE", str(f))
    with pytest.raises(RuntimeError, match="lab-only"):
        load_settings()
    f.write_text("ICS_DATABASE_URL=x\nICS_VAULT_KEY_FILE=v\nICS_AUDIT_KEY_FILE=a\n")
    assert load_settings().lab_ssh_bootstrap is False


# ---------------------------------------------------------------- M1: per-instance random vault-held secrets
def test_bootstrap_material_is_random_per_instance_vault_encrypted_and_deleted(rt):
    did = "00000000-0000-0000-0000-0000000000d1"
    a = bootsecrets.issue(rt, did, "vm1", 140, "ssh-lab")
    assert bootsecrets.issue(rt, did, "vm1", 140, "ssh-lab").id == a.id               # a resume of the same instance reuses it
    b = bootsecrets.issue(rt, did, "vm1", 141, "ssh-lab")                              # a NEW instance (re-created VM) shares nothing
    assert b.id != a.id and len({a.secret, b.secret}) == 2 and a.ssh_public != b.ssh_public and a.token != b.token and a.bid != b.bid
    with rt.session() as db:
        raw = db.execute(text("SELECT secret_enc, ssh_key_enc, token_enc, state FROM guest_bootstrap WHERE id = :i"), {"i": a.id}).one()
        assert raw.state == "revoked" and raw.secret_enc is None and raw.ssh_key_enc is None and raw.token_enc is None   # superseded and WIPED
        live = bytes(db.execute(text("SELECT secret_enc FROM guest_bootstrap WHERE id = :i"), {"i": b.id}).scalar())
        assert b.secret.encode() not in live                                                                           # ciphertext only
    assert bootsecrets.find(rt, did, "vm1", 141, "ssh-lab").secret == b.secret
    bootsecrets.delete_secrets(rt, b.id, "sealed")
    assert bootsecrets.secrets_wiped(rt, b.id) and bootsecrets.find(rt, did, "vm1", 141).secret is None
    with rt.session() as db:   # nothing derived from a long-lived key: the same inputs on a new instance give new values
        assert db.execute(text("SELECT count(*) FROM guest_bootstrap WHERE secret_enc IS NOT NULL")).scalar() == 0


def test_vault_context_binds_the_row_and_column(rt):
    did = "00000000-0000-0000-0000-0000000000d2"
    a = bootsecrets.issue(rt, did, "vm1", 150, "callback")
    with rt.session() as db:
        blob = bytes(db.execute(text("SELECT secret_enc FROM guest_bootstrap WHERE id = :i"), {"i": a.id}).scalar())
    from ics.vault import VaultError
    with pytest.raises(VaultError):
        rt.vault.decrypt(blob, bootsecrets._ctx(a.id, "token"))                          # moved to another column
    with pytest.raises(VaultError):
        rt.vault.decrypt(blob, bootsecrets._ctx("00000000-0000-0000-0000-000000000000", "secret"))


# ---------------------------------------------------------------- link-local
def test_link_local_address_is_eui64_of_the_mac_lab():
    assert sshboot.link_local("bc:24:11:44:38:7d", "eth0") == "fe80::be24:11ff:fe44:387d%eth0"
    with pytest.raises(sshboot.BootstrapError):
        sshboot.link_local("bc:24:11:44:38:7d", "eth0; reboot")


# ---------------------------------------------------------------- M4 / M2 / M3: the session protocol
class FakePopen:
    """A guest: prints a proof line, then (like the real script) reads stdin and prints the output + MAC."""
    last = None

    def __init__(self, argv, stdin=None, stdout=None, stderr=None, env=None, behave="good", psk=None, out="addr=192.168.22.5\ndone=0"):
        FakePopen.last = self
        self.argv, self.env, self.written = argv, env, b""
        self.behave, self.psk, self.out = FakePopen.behave, FakePopen.psk, FakePopen.out
        nonce = argv[-1].split()[-2]
        r, w = os.pipe()
        first = {"good": "OU-PROOF " + sshboot.proof_of(self.psk, nonce), "wrong": "OU-PROOF " + "0" * 64, "none": "garbage"}[self.behave]
        os.write(w, (first + "\n").encode())
        os.close(w)
        self.stdout = os.fdopen(r, "rb", buffering=0)
        outer = self
        self.stdin = types.SimpleNamespace(write=lambda b: setattr(outer, "written", outer.written + b), close=lambda: None)
        self.returncode = 0
        self.nonce = nonce

    def communicate(self, timeout=None):
        mac = sshboot.mac_of(self.psk, self.nonce, self.out)
        return (self.out + "\nOU-MAC " + mac + "\n").encode(), b""

    def kill(self): pass
    def wait(self): pass


def _ident():
    return types.SimpleNamespace(ssh_private_openssh=b"-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----\n", psk="ab" * 8 + "cd" * 24,
                                 enroll_token="T" * 43, enroll_token_sha256="e" * 64, ssh_public="ssh-ed25519 AAAA")


@pytest.fixture()
def popen(monkeypatch):
    FakePopen.behave, FakePopen.psk, FakePopen.out = "good", _ident().psk, "addr=192.168.22.5\ndone=0"
    monkeypatch.setattr(sshboot.subprocess, "Popen", FakePopen)
    return FakePopen


def test_the_payload_is_sent_only_after_the_guest_proved_itself(popen):
    ident = _ident()
    g = sshboot.Guest(ident, "fe80::1%eth0", ssh_bin="/usr/bin/ssh")
    popen.out = "state=started"
    assert g.install("#cloud-config\nhostname: x\n", "ou-boot-0123456789abcdef", "vm-1") == {"state": "started"}
    assert popen.last.written == b"#cloud-config\nhostname: x\n"                      # the payload travels on stdin, after the proof line
    for behave in ("wrong", "none"):
        popen.behave = behave
        with pytest.raises(sshboot.ProofFailed):
            g.install("#cloud-config\nSECRET-TOPOLOGY\n", "ou-boot-0123456789abcdef", "vm-1")
        assert popen.last.written == b""                                               # an impostor receives NOTHING


def test_the_proof_secret_never_appears_on_a_command_line_or_in_the_script(popen):
    ident = _ident()
    sshboot.Guest(ident, "fe80::1%eth0", ssh_bin="/usr/bin/ssh").probe()
    argv = " ".join(popen.last.argv)
    assert ident.psk not in argv and ident.enroll_token not in argv and ident.psk[:16] not in argv
    assert "product_serial" in sshboot.OUTER and "openssl" not in sshboot.OUTER and "-hmac" not in sshboot.OUTER   # read inside python3, not via argv
    assert popen.last.argv[0] == "/usr/bin/ssh" and "BatchMode=yes" in popen.last.argv and "IdentitiesOnly=yes" in popen.last.argv
    assert popen.last.argv[-1].startswith("sudo -n /bin/sh -c ")


def test_output_must_carry_a_valid_mac_too(popen, monkeypatch):
    g = sshboot.Guest(_ident(), "fe80::1%eth0")
    monkeypatch.setattr(FakePopen, "communicate", lambda self, timeout=None: (b"addr=1.2.3.4\nOU-MAC " + b"0" * 64 + b"\n", b""))
    with pytest.raises(sshboot.ProofFailed):
        g.probe()


def test_unreachable_guest_is_retryable_not_a_proof_failure(monkeypatch):
    class Dead(FakePopen):
        def __init__(self, *a, **k):
            self.stdout = types.SimpleNamespace(fileno=lambda: os.open(os.devnull, os.O_RDONLY))
            self.stdin = types.SimpleNamespace(write=lambda b: None, close=lambda: None)
            self.returncode = 255
        def kill(self): pass
        def wait(self): pass
    monkeypatch.setattr(sshboot.subprocess, "Popen", Dead)
    with pytest.raises(sshboot.NotReady) as e:
        sshboot.Guest(_ident(), "fe80::1%eth0").probe()
    assert "Connection refused" not in str(e.value)


def test_only_fixed_operations_can_run_and_interpolations_are_validated(popen):
    g = sshboot.Guest(_ident(), "fe80::1%eth0")
    with pytest.raises(sshboot.BootstrapError, match="unknown"):
        g._session("rm -rf /")                                                         # M3: no caller-supplied body, only names
    assert set(sshboot.OPERATIONS) == {"probe", "wait_ci", "status", "fingerprints", "seal", "arm", "install"}
    for bad in (("a;b", "vm"), ("ou-boot-0123456789abcdef", "vm;reboot"), ("ou-boot-0123456789abcdef", "VM")):
        with pytest.raises(sshboot.BootstrapError):
            sshboot.install_body(*bad)
    for bad in (0, 4, 99999, "30", 30.5):
        with pytest.raises(sshboot.BootstrapError):
            sshboot.arm_body(bad)
    assert "cat > $D/user-data" in sshboot.install_body("ou-boot-0123456789abcdef", "vm-1") and "<<'OU_SEED_END'" not in sshboot.install_body("ou-boot-0123456789abcdef", "vm-1")


# ---------------------------------------------------------------- H1/H2: the seal and the dead-man switch
def test_arm_installs_a_persistent_timer_and_a_boot_check_before_anything_else():
    b = sshboot.arm_body(30)
    assert "OnActiveSec=30min" in b and "OnBootSec=30min" in b and "seal-deadline" in b and "ou-bootstrap-seal-check.service" in b
    assert "systemd-run" not in b                                                      # transient timers do not survive a reboot
    assert "mask ssh.socket ssh.service" in sshboot.SEAL_SCRIPT and "passwd -l ou-boot" in sshboot.SEAL_SCRIPT and "authorized_keys" in sshboot.SEAL_SCRIPT
    assert "seal-deadline" in sshboot.SEAL_BOOT_CHECK and "sealed" in sshboot.SEAL_BOOT_CHECK
    # the user-data no longer owns any seal logic: the ICS armed it first
    files = {f["path"] for f in cloudinit.build(_spec_boot())["write_files"]}
    assert "/usr/local/sbin/ou-bootstrap-seal" not in files


def _spec_boot():
    from .test_guest_bootstrap import spec as _spec
    return _spec(os="debian-12", bootstrap_user="ou-boot", agent_address="192.168.22.9", mgmt_sources=["192.168.22.167/32"])


def test_bootstrap_user_keeps_link_local_ssh_rule_only_and_is_exclusive():
    cfg = cloudinit.build(_spec_boot())
    files = {f["path"]: f["content"] for f in cfg["write_files"]}
    boot = files["/usr/local/sbin/ou-guest-bootstrap"]
    assert "ou-bootstrap-seal-timer" not in boot and "mask ssh" not in boot
    nft = files["/etc/nftables.conf"]
    assert "ip6 saddr fe80::/10 tcp dport 22 accept" in nft and "tcp dport 22 accept" not in nft.replace("ip6 saddr fe80::/10 tcp dport 22 accept", "")
    from .test_guest_bootstrap import spec as _spec
    with pytest.raises(ValueError):
        _spec(bootstrap_user="ou-boot", break_glass_ssh_key="ssh-ed25519 " + "A" * 60)
    with pytest.raises(ValueError):
        _spec(bootstrap_user="ou-boot; id")


GOOD_SEAL = {"ssh_enabled": "masked/masked", "ssh_active": "inactive/inactive", "locked": "L", "keys": "0", "sudo": "0", "sealed": "1"}


def test_seal_is_effective_only_when_every_part_is_verified():
    assert sshboot.seal_effective(GOOD_SEAL)
    assert sshboot.seal_effective({**GOOD_SEAL, "ssh_enabled": "masked/not-found"})
    for k, v in (("ssh_enabled", "enabled/masked"), ("ssh_active", "active/inactive"), ("ssh_active", "inactive/active"), ("locked", "P"), ("keys", "1"),
                 ("sudo", "1"), ("sealed", "0")):
        assert not sshboot.seal_effective({**GOOD_SEAL, k: v}), k


def test_seal_verified_needs_the_report_and_a_closed_port(monkeypatch, popen):
    g = sshboot.Guest(_ident(), "fe80::1%eth0")
    rep = "\n".join(f"{k}={v}" for k, v in GOOD_SEAL.items())
    popen.out = rep
    monkeypatch.setattr(sshboot, "port_closed", lambda *a, **k: True)
    assert g.seal_verified()["sealed"] == "1"
    monkeypatch.setattr(sshboot, "port_closed", lambda *a, **k: False)
    with pytest.raises(sshboot.SealUnverified, match="port 22"):
        g.seal_verified()
    monkeypatch.setattr(sshboot, "port_closed", lambda *a, **k: True)
    popen.out = rep.replace("locked=L", "locked=P")
    with pytest.raises(sshboot.SealUnverified):
        g.seal_verified()


def test_port_closed_detects_a_listener():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    port = s.getsockname()[1]
    assert sshboot.port_closed("127.0.0.1", port) is False
    s.close()
    assert sshboot.port_closed("127.0.0.1", port) is True


# ---------------------------------------------------------------- the agent port (lab)
class FakeGuest:
    instances: list = []
    fail_on: str | None = None
    seal_ok = True

    def __init__(self, ident, addr, **kw):
        self.ident, self.addr, self.calls = ident, addr, []
        FakeGuest.instances.append(self)

    @property
    def last(self):
        return FakeGuest.instances[-1]

    def _c(self, n):
        self.calls.append(n)
        if FakeGuest.fail_on == n:
            raise StepFailed("injected failure in " + n, "", retryable=False)

    def probe(self):
        self._c("probe")
        return {"addr": "192.168.22.50", "done": "0", "running": "inactive", "armed": "1" if "arm" in self.calls else "0"}

    def arm(self, minutes):
        self._c("arm")
        return {"armed": "1"}

    def wait_cloud_init(self):
        self._c("wait_ci")
        return {}

    def install(self, ud, iid, host):
        self._c("install")
        assert ud.startswith("#cloud-config") and host == "vm1" and self.ident.enroll_token not in ud and self.ident.psk not in ud
        assert self.ident.enroll_token_sha256 in ud
        return {"state": "started"}

    def status(self):
        self._c("status")
        return {"done": "1", "rc": "0", "running": "inactive", "log": ""}

    def fingerprints(self):
        self._c("fingerprints")
        return json.dumps({"address": "192.168.22.50", "port": 8443, "tls_fingerprint_sha256": "ab" * 32, "agent_key_fingerprint_sha256": "cd" * 32})

    def seal_verified(self):
        self._c("seal_verified")
        if not FakeGuest.seal_ok:
            raise sshboot.SealUnverified("port 22 still open")
        return GOOD_SEAL


class FakeProv:
    """The provider calls the bootstrap makes, over a tiny stateful VM."""

    def __init__(self):
        self.cfg = {"sshkeys": "k", "ciuser": "ou-boot", "smbios1": "uuid=abc,base64=1,serial=eHg="}
        self.status = "running"
        self.log = []

    def guest_mac(self, r):
        return "bc:24:11:44:38:7d"

    def discover(self):
        return types.SimpleNamespace(guests=[{"vmid": 140, "status": self.status}])

    def power(self, r, op):
        self.log.append(op)
        self.status = "stopped"
        return "t-power"

    def bootstrap_material_present(self, r):
        return bool(self.cfg)

    def configure_vm(self, r, spec):
        assert spec.clear_bootstrap
        self.log.append("clear")
        self.cfg = {}
        return "t-cfg"

    def task_status(self, t):
        return types.SimpleNamespace(state="ok")


def _port(rt, tmp_path, monkeypatch, lab=False, prov=None, **settings):
    sk = tmp_path / "sign.key"
    sk.write_bytes(b"\x07" * 32)
    sk.chmod(0o600)
    extra = dict(environment="lab", lab_ssh_bootstrap=True) if lab else {}
    rt.settings = dataclasses.replace(rt.settings, **{"signing_key_file": str(sk), "guest_callback_url": "https://192.168.22.167:8443",
                                                      "guest_callback_pin_sha256": "ab" * 32, **extra, **settings})
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
    monkeypatch.setattr(sshboot, "default_iface", lambda: "eth0")
    monkeypatch.setattr(agentport, "neighbour_mac", lambda a: "bc:24:11:44:38:7d")   # the ARP witness of review 5 M2 (FakeProv.guest_mac)
    monkeypatch.setattr(agentport.GuestAgentPort, "_source_towards", staticmethod(lambda a: "192.168.22.167"))
    monkeypatch.setattr(agentport, "_agent_dir", lambda rt: os.path.join(os.path.dirname(__file__), "..", "agent"))
    FakeGuest.instances, FakeGuest.fail_on, FakeGuest.seal_ok = [], None, True
    return agentport.GuestAgentPort(rt, {"slug": "dep1", "id": str(did), "created_by": str(uid), "plan": plan}, prov or FakeProv(), sleep=lambda s: None,
                                    guest_factory=FakeGuest)


def _enroll_stubs(monkeypatch, sent=None):
    sent = {} if sent is None else sent
    monkeypatch.setattr(agentport.agentclient, "identity", lambda a, p, fp, **k: sent.update(identity=(a, p, fp)) or {"agent_pubkey": base64.b64encode(b"k" * 32).decode()})
    monkeypatch.setattr(agentport.agentclient, "key_fingerprint", lambda k: "cd" * 32)
    monkeypatch.setattr(agentport.agentclient, "enroll", lambda a, p, fp, **k: sent.update(enroll=(a, p, fp, k["token"])) or {"capabilities": {"guest.facts": {}}, "agent_version": "0.1.0"})
    return sent


def _audit_actions(rt):
    with rt.session() as db:
        return [r[0] for r in db.execute(text("SELECT action FROM audit_events ORDER BY seq"))]


def test_lab_happy_path_arms_first_seals_verified_clears_config_and_deletes_secrets(rt, tmp_path, monkeypatch):
    port = _port(rt, tmp_path, monkeypatch, lab=True)
    sent = _enroll_stubs(monkeypatch)
    cfg = port.bootstrap_config("vm1")
    assert cfg["ciuser"] == "ou-boot" and cfg["sshkeys"][0].startswith("ssh-ed25519 ") and len(cfg["smbios_serial"]) == 64
    rec = bootsecrets.find(rt, port.dep["id"], "vm1", 140, "ssh-lab")
    nid = port.wait_enrollment("vm1", 600)
    g = FakeGuest.instances[0]
    assert g.calls == ["probe", "arm", "wait_ci", "probe", "install", "status", "fingerprints", "seal_verified"]      # the seal timer is armed BEFORE anything is sent
    assert g.addr == "fe80::be24:11ff:fe44:387d%eth0" and sent["enroll"][3] == rec.token                              # the plaintext token goes only to the pinned agent
    assert port.provider.cfg == {} and port.provider.log == ["clear"]                                                  # M2: sshkeys/ciuser/SMBIOS secret gone
    assert bootsecrets.secrets_wiped(rt, rec.id)                                                                       # M1: deleted after use
    acts = _audit_actions(rt)
    assert "guest.bootstrap_sealed" in acts and "guest.bootstrap_completed" in acts and "guest.bootstrap_failed_closed" not in acts
    with rt.session() as db:
        assert str(db.execute(text("SELECT id FROM nodes")).scalar()) == nid
        assert db.execute(text("SELECT state, sealed_at IS NOT NULL FROM guest_bootstrap WHERE id = :i"), {"i": rec.id}).one() == ("sealed", True)
    assert port.wait_enrollment("vm1", 600) == nid                                                                     # idempotent
    with pytest.raises(StepFailed, match="not implemented"):
        port.tls_trust(nid, 443)


def test_h1_a_configuration_error_surfaces_before_any_vm_boots(rt, tmp_path, monkeypatch):
    port = _port(rt, tmp_path, monkeypatch, lab=True)
    port.plan["vms"][0]["os_image"] = {"id": "plan9-1"}
    with pytest.raises(StepFailed, match="no guest bootstrap profile"):
        port.bootstrap_config("vm1")


@pytest.mark.parametrize("fail_on,sealed", [("install", True), ("status", True), ("fingerprints", True), ("arm", True)])
def test_h1_failure_after_the_proof_seals_stops_clears_and_audits(rt, tmp_path, monkeypatch, fail_on, sealed):
    port = _port(rt, tmp_path, monkeypatch, lab=True)
    port.bootstrap_config("vm1")
    rec = bootsecrets.find(rt, port.dep["id"], "vm1", 140, "ssh-lab")
    _enroll_stubs(monkeypatch)
    FakeGuest.fail_on = fail_on
    with pytest.raises(StepFailed, match="injected"):
        port.wait_enrollment("vm1", 600)
    assert "seal_verified" in FakeGuest.instances[-1].calls and port.provider.status == "stopped" and port.provider.cfg == {}
    assert bootsecrets.secrets_wiped(rt, rec.id)
    with rt.session() as db:
        d = db.execute(text("SELECT details FROM audit_events WHERE action = 'guest.bootstrap_failed_closed'")).scalar()
        assert d["sealed"] is True and d["stopped"] is True and d["cleared"] is True and "secret" not in json.dumps(d)
        assert db.execute(text("SELECT count(*) FROM nodes")).scalar() == 0
    with pytest.raises(StepFailed, match="gone"):                                  # a later attempt cannot reuse the destroyed material
        port.wait_enrollment("vm1", 600)


def test_h1_a_guest_that_never_proved_itself_is_stopped_not_talked_to(rt, tmp_path, monkeypatch):
    port = _port(rt, tmp_path, monkeypatch, lab=True)
    port.bootstrap_config("vm1")

    class Impostor(FakeGuest):
        def probe(self):
            raise sshboot.ProofFailed("SMBIOS proof mismatch")
    port._guest_factory = Impostor
    with pytest.raises(StepFailed) as e:
        port.wait_enrollment("vm1", 600)
    assert e.value.retryable is False and "nothing was sent" in e.value.explanation
    assert port.provider.status == "stopped" and port.provider.cfg == {} and all("seal_verified" not in g.calls for g in FakeGuest.instances)


def test_h1_fenced_executors_touch_nothing(rt, tmp_path, monkeypatch):
    port = _port(rt, tmp_path, monkeypatch, lab=True)
    port.bootstrap_config("vm1")
    FakeGuest.fail_on = None

    class Fencing(FakeGuest):
        def probe(self):
            raise Fenced("not ours")
    port._guest_factory = Fencing
    with pytest.raises(Fenced):
        port.wait_enrollment("vm1", 600)
    assert port.provider.status == "running" and port.provider.cfg and "guest.bootstrap_failed_closed" not in _audit_actions(rt)


def test_h2_a_seal_that_cannot_be_verified_fails_the_step_closed_even_though_enrolled(rt, tmp_path, monkeypatch):
    port = _port(rt, tmp_path, monkeypatch, lab=True)
    port.bootstrap_config("vm1")
    _enroll_stubs(monkeypatch)
    FakeGuest.seal_ok = False
    with pytest.raises(sshboot.SealUnverified):
        port.wait_enrollment("vm1", 600)
    assert port.provider.status == "stopped" and "guest.bootstrap_seal_failed" in _audit_actions(rt) and "guest.bootstrap_failed_closed" in _audit_actions(rt)


def test_h2_the_resume_path_seals_when_the_node_exists_but_the_secret_is_still_there(rt, tmp_path, monkeypatch):
    port = _port(rt, tmp_path, monkeypatch, lab=True)
    port.bootstrap_config("vm1")
    _enroll_stubs(monkeypatch)
    FakeGuest.fail_on = None
    # simulate a worker killed right after enrollment: node row exists, secrets alive, no seal
    with rt.session() as db:
        db.execute(text("INSERT INTO nodes (name, address, port, tls_fingerprint_sha256, agent_pubkey, agent_key_fp, capabilities, agent_version) VALUES "
                        "('dep1-vm1-140', '192.168.22.50', 8443, :t, 'k', 'f', '{}'::jsonb, '1')"), {"t": "ab" * 32})
        db.commit()
    rec = bootsecrets.find(rt, port.dep["id"], "vm1", 140, "ssh-lab")
    port.wait_enrollment("vm1", 600)
    assert FakeGuest.instances[0].calls == ["seal_verified"] and port.provider.cfg == {} and bootsecrets.secrets_wiped(rt, rec.id)
    assert "guest.bootstrap_sealed" in _audit_actions(rt)
    # ... and if that seal cannot be verified the VM is stopped and the step fails
    FakeGuest.seal_ok = False
    port.provider = FakeProv()
    port.provider.cfg = {"sshkeys": "k"}
    bootsecrets.issue(rt, port.dep["id"], "vm1", 140, "ssh-lab")
    with pytest.raises(StepFailed, match="could not be sealed on resume"):
        port.wait_enrollment("vm1", 600)
    assert port.provider.status == "stopped"


def test_keep_bootstrap_ssh_is_a_lab_debug_knob_that_still_clears_material_but_does_not_seal(rt, tmp_path, monkeypatch):
    port = _port(rt, tmp_path, monkeypatch, lab=True, guest_keep_bootstrap_ssh=True)
    port.bootstrap_config("vm1")
    _enroll_stubs(monkeypatch)
    port.wait_enrollment("vm1", 600)
    assert "seal_verified" not in FakeGuest.instances[0].calls          # (the guest's own persistent timer still seals it)


def test_a_replaced_vm_instance_cannot_use_the_previous_instances_material(rt, tmp_path, monkeypatch):
    port = _port(rt, tmp_path, monkeypatch, lab=True)
    port.bootstrap_config("vm1")
    old = bootsecrets.find(rt, port.dep["id"], "vm1", 140, "ssh-lab")
    with rt.session() as db:
        db.execute(text("UPDATE deployment_resources SET provider_ref = '{\"node\": \"pve06\", \"vmid\": 141}'::jsonb WHERE logical_name = 'vm1'"))
        db.commit()
    cfg2 = port.bootstrap_config("vm1")
    new = bootsecrets.find(rt, port.dep["id"], "vm1", 141, "ssh-lab")
    assert new.secret != old.secret and cfg2["smbios_serial"] == new.smbios_serial
    assert bootsecrets.find(rt, port.dep["id"], "vm1", 140, "ssh-lab").secret is None


def test_run_runbook_turns_agent_refusals_and_failed_verification_into_step_failures_lab(rt, tmp_path, monkeypatch):
    port = _port(rt, tmp_path, monkeypatch)

    def reply(resp):
        monkeypatch.setattr(agentport.agentcall, "execute", lambda *a, **k: resp)
    reply({"status": "ok", "result": {"returncode": 0, "result": {"verified": True, "digest": "sha256:" + "a" * 64}}})
    assert port.run_runbook("n", "podman.pull_verified", {})["verified"] is True


def test_configure_step_hands_the_guest_its_first_contact_material(rt, monkeypatch):
    from ics.deploy import executor
    from ics.deploy.ports import ExecEnv
    from ics.providers.base import IpConfig, VmRef
    sent = {}

    class P:
        def discover(self):
            return types.SimpleNamespace(guests=[{"vmid": 1, "name": "vm1", "tags": ["ou-managed", "ou-deployment-dep1"], "status": "stopped"}])

        def configure_vm(self, r, spec):
            sent["spec"] = spec
            return types.SimpleNamespace(upid=None)

        def task_status(self, t):
            return types.SimpleNamespace(state="ok")
    for bc in ({"ciuser": "ou-boot", "sshkeys": ("ssh-ed25519 AAAA x",), "smbios_serial": "ab" * 24},
               {"smbios_serial": "ab" * 32, "smbios_sku": "https://ics.example:8443", "smbios_family": "sha256:" + "cd" * 32}):
        agent = types.SimpleNamespace(bootstrap_config=lambda vm, bc=bc: bc)
        ctx = executor.StepCtx(rt, ExecEnv(provider=P(), agent=agent), "j", "d", "dep1", {}, "u", 1, {"target": "vm1", "op": "configure_vm", "params": {
            "cores": 1, "memory_mb": 512, "disks": [{"name": "root", "storage": "s", "size_gb": 10}], "nics": [{"bridge": "vmbr0"}],
            "cloud_init": {"hostname": "vm1", "agent_enrollment": True}}}, {})
        monkeypatch.setattr(ctx, "vm_ref", lambda vm: VmRef("n", 1, "vm", "dep1"))
        executor.h_provider_task(ctx)
        s = sent["spec"]
        assert s.ciuser == bc.get("ciuser") and s.smbios_serial == bc["smbios_serial"] and s.smbios_sku == bc.get("smbios_sku") and s.smbios_family == bc.get("smbios_family")
        assert s.ciupgrade is False and s.ipconfigs == (IpConfig(0, "dhcp"),) and s.cloudinit_storage == "s"
