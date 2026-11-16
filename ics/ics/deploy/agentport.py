"""The real AgentPort of the deployment executor (ports.AgentPort): guest bootstrap + enrollment + signed runbooks.

TWO bootstrap modes (ADR-0009 section 5 addendum, docs/status/bootstrap-v2.md):

  * PRODUCTION (default): golden image + authenticated callback, no SSH at any point. `bootstrap_config` draws a random per-VM-instance secret
    (guest/bootsecrets.py) and hands it to the guest through SMBIOS together with the ICS callback URL and certificate pin; the image's first-boot
    unit calls the ICS back (guest/callback.py). `await_callback` waits for the verified report, `wait_enrollment` enrolls the agent over pinned TLS
    with the fingerprints from that report and then clears the secret from the VM config and the vault.
  * LAB ONLY (ICS_LAB_SSH_BOOTSTRAP=true + ICS_ENVIRONMENT=lab): the ICS-driven SSH bootstrap of the stock template (guest/sshboot.py), hardened per the
    review: fails closed (seal timer armed first; any terminal failure seals+stops the guest), synchronous verified seal, random per-instance secrets,
    no secret on a command line, proof verified before any payload is sent.

Both modes: `wait_enrollment` is idempotent and resumable; every failure that could leave a guest reachable ends in `fail_closed`."""
import ipaddress
import json
import logging
import re
import socket
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import text

from .. import agentclient, audit
from ..agentclient import AgentError
from ..guest import agentcall, bootsecrets, cloudinit, neigh, sshboot
from ..proxmox import normalize_fingerprint
from ..providers.base import ProviderError, VmConfigSpec, VmRef
from . import state
from .ports import Fenced, StepFailed

log = logging.getLogger("ics.deploy.agentport")
AGENT_PORT = 8443
neighbour_mac = neigh.mac_of     # replaced by tests


def _agent_dir(rt) -> str:
    return rt.settings.guest_agent_dir or str(Path(__file__).resolve().parents[2] / "agent")


class GuestAgentPort:
    def __init__(self, rt, dep: dict, provider, *, sleep=None, clock=None, guest_factory=None):
        import time
        self.rt, self.dep, self.provider = rt, dep, provider
        self.slug, self.plan = dep["slug"], dep.get("plan") or {}
        self.sleep, self.clock = sleep or time.sleep, clock or time.monotonic
        self._guest_factory = guest_factory or sshboot.Guest
        self._signing = None

    # ---- helpers ------------------------------------------------------------------------------------------------
    def _key(self):
        if self._signing is None:
            try:
                self._signing = agentclient.load_signing_key(self.rt.settings.signing_key_file)
            except AgentError as e:
                raise StepFailed(str(e), "The ICS signing key is required to bootstrap and enroll guests.", retryable=False) from None
        return self._signing

    def node_name(self, vm: str) -> str:
        """Unique per VM INSTANCE (the vmid is part of the name), so re-creating a deployment never collides with its decommissioned predecessor."""
        with self.rt.session() as db:
            ref = state.provider_ref(db, self.dep["id"], vm) or {}
        return f"{self.slug}-{vm}"[:50] + f"-{ref.get('vmid', 'x')}"

    def _node(self, name: str):
        with self.rt.session() as db:
            return db.execute(text("SELECT * FROM nodes WHERE name = :n"), {"n": name}).first()

    def _vm(self, vm: str) -> dict:
        v = next((x for x in self.plan.get("vms", []) if x["name"] == vm), None)
        if v is None:
            raise StepFailed(f"VM {vm} is not part of the plan", "", retryable=False)
        return v

    # ---- shared helpers ------------------------------------------------------------------------------------------------
    @property
    def lab(self) -> bool:
        return bool(self.rt.settings.lab_ssh_bootstrap)

    @property
    def mode(self) -> str:
        return "ssh-lab" if self.lab else "callback"

    def _pref(self, vm: str) -> dict:
        with self.rt.session() as db:
            pref = state.provider_ref(db, self.dep["id"], vm)
        if not pref or pref.get("vmid") is None:
            raise StepFailed(f"VM {vm} has no provider reference", "", retryable=False)
        return pref

    def _vmref(self, vm: str) -> VmRef:
        pref = self._pref(vm)
        return VmRef(pref["node"], int(pref["vmid"]), "vm", self.slug)

    def _audit(self, action: str, vm: str, **details) -> None:
        with self.rt.session() as db:
            audit.append(db, action, actor_name="worker", resource="vm", resource_id=f"{self.slug}/{vm}",
                         details={"deployment": self.slug, "vm": vm, **details})
            db.commit()

    def _task(self, task, what: str, timeout: float = 300.0) -> None:
        t0 = self.clock()
        while True:
            st = self.provider.task_status(task)
            if st.state == "ok":
                return
            if st.state == "error":
                raise StepFailed(f"{what} failed: {(st.message or st.exitstatus or 'unknown error')[:200]}", "", retryable=True)
            if self.clock() - t0 > timeout:
                raise StepFailed(f"{what} did not finish in time", "", retryable=True)
            self.sleep(2)

    def _clear_material(self, ref: VmRef) -> bool:
        """Review M2: remove the SMBIOS secret/URL/pin, `sshkeys` and `ciuser` from the VM config (idempotent)."""
        if not self.provider.bootstrap_material_present(ref):
            return False
        self._task(self.provider.configure_vm(ref, VmConfigSpec(clear_bootstrap=True)), "clear the bootstrap material from the VM config")
        return True

    def _expect_material(self, vm: str, mode: str):
        ref = self._vmref(vm)
        return ref, bootsecrets.find(self.rt, self.dep["id"], vm, ref.vmid, mode)

    # ---- executor-facing API --------------------------------------------------------------------------------------
    def bootstrap_config(self, vm: str) -> dict:
        """Values for `configure_vm`: fresh random per-instance material (never derived from a long-lived key; vault-encrypted; deleted after use)."""
        s = self.rt.settings
        ref = self._vmref(vm)
        if self.lab:
            rec = bootsecrets.issue(self.rt, self.dep["id"], vm, ref.vmid, "ssh-lab")
            ident = sshboot.identity(rec)
            # review H1(a): a configuration error must surface BEFORE a VM boots with an open bootstrap account
            self._render(vm, ident, "192.0.2.10")
            return {"ciuser": sshboot.BOOT_USER, "sshkeys": (ident.ssh_public,), "smbios_serial": rec.smbios_serial}
        url, pin = s.guest_callback_url, (s.guest_callback_pin_sha256 or "").lower()
        if not url or not re.fullmatch(r"https://[A-Za-z0-9.:\[\]-]{1,100}", url) or not re.fullmatch(r"[0-9a-f]{64}", pin):
            raise StepFailed("the golden-image bootstrap is not configured (ICS_GUEST_CALLBACK_URL and ICS_GUEST_CALLBACK_PIN_SHA256)",
                             "Set the HTTPS URL the guests call back (reachable from the VM network) and the SHA-256 of the certificate they must pin.",
                             retryable=False)
        rec = bootsecrets.issue(self.rt, self.dep["id"], vm, ref.vmid, "callback", config=self._callback_config(vm))
        return {"smbios_serial": rec.smbios_serial, "smbios_sku": url, "smbios_family": "sha256:" + pin}

    def await_callback(self, vm: str, timeout_s: int) -> dict:
        """Step `guest.await_callback`: wait until the guest's first-boot unit has reported (HMAC-verified, single use) or fail closed."""
        if self.lab:
            return {"skipped": "lab SSH bootstrap (no callback)"}
        if self._node(self.node_name(vm)) is not None:
            return {"already": True}
        ref, rec = self._expect_material(vm, "callback")
        if rec is None:
            raise StepFailed(f"no bootstrap record for {vm}", "The VM was not configured with bootstrap material; destroy and re-create it.", retryable=False)
        deadline = self.clock() + min(max(timeout_s, 60), self.rt.settings.guest_bootstrap_timeout_seconds)
        try:
            while True:
                rec2 = bootsecrets.find(self.rt, self.dep["id"], vm, ref.vmid, "callback")
                if rec2 is not None and rec2.state in ("reported", "enrolled"):
                    return {"reported": True}
                if rec2 is None or rec2.state in ("failed", "revoked", "expired") or rec2.secret is None:
                    raise StepFailed("the bootstrap material of this VM instance is gone",
                                     "A previous attempt failed closed; destroy and re-create the deployment.", retryable=False)
                if rec2.expires_at <= datetime.now(timezone.utc):
                    bootsecrets.set_state(self.rt, rec2.id, "expired")
                    raise StepFailed("the bootstrap secret expired before the guest called back", "Check the VM console in Proxmox.", retryable=False)
                if self.clock() >= deadline:
                    raise StepFailed("the guest did not call back in time", "Check the VM console in Proxmox: the golden image's ou-bootstrap.service, "
                                     "the callback URL's reachability from the VM network and the certificate pin.", retryable=False)
                self.sleep(3)
        except Fenced:
            raise
        except BaseException as e:   # noqa: BLE001  fail closed, then re-raise
            self.fail_closed(vm, type(e).__name__)
            raise

    def wait_enrollment(self, vm: str, timeout_s: int) -> str:
        name = self.node_name(vm)
        n = self._node(name)
        if n is not None:
            self._finish_resume(vm)
            return str(n.id)
        try:
            nid = self._wait_lab(vm, name, timeout_s) if self.lab else self._enroll_from_callback(vm, name)
        except Fenced:
            raise   # not ours any more: touch nothing
        except BaseException as e:   # noqa: BLE001  fail closed (review H1), then re-raise
            self.fail_closed(vm, type(e).__name__)
            raise
        self._finish(vm)
        return nid

    # ---- production path: enroll from the verified callback report ----------------------------------------------------
    def _enroll_from_callback(self, vm: str, name: str) -> str:
        ref, rec = self._expect_material(vm, "callback")
        if rec is None or rec.state != "reported" or not rec.token:
            raise StepFailed("no verified bootstrap report for this VM", "The guest has not called back (or its report was already consumed).",
                             retryable=False)
        with self.rt.session() as db:
            rep = db.execute(text("SELECT report FROM guest_bootstrap WHERE id = :i"), {"i": rec.id}).scalar() or {}
        fps = {"address": rep.get("address"), "port": rep.get("port"), "tls_fingerprint_sha256": rep.get("tls_fingerprint_sha256"),
               "agent_key_fingerprint_sha256": rep.get("agent_key_fingerprint_sha256")}
        if any(v is None for v in fps.values()):
            raise StepFailed("the guest's report lacks its agent fingerprints", "", retryable=False)
        self._bind_to_vm(vm, ref, fps["address"])
        nid = self._enroll_retry(name, fps, rec.token)
        bootsecrets.set_state(self.rt, rec.id, "enrolled")
        return nid

    def _bind_to_vm(self, vm: str, ref: VmRef, address: str) -> None:
        """Review 5 M2: possession of the secret is not enough. The address that reported must be the one the VM's own NIC (MAC from the
        Proxmox config, net0) answers for in the ICS host's neighbour table. Unknown/other MAC => fail closed (the caller stops the VM)."""
        if not self.rt.settings.guest_require_nic_binding:
            return
        want = self.provider.guest_mac(ref).lower()
        got = neighbour_mac(address)
        if got is None:
            self._audit("guest.bootstrap_nic_unverified", vm, address=address)
            raise StepFailed("the reporting address could not be tied to the VM's network card (no neighbour entry)",
                             "The VM must be on a segment the ICS host is attached to (or set ICS_GUEST_REQUIRE_NIC_BINDING=false for routed guest networks, "
                             "which weakens the binding).", retryable=False)
        if got != want:
            self._audit("guest.bootstrap_nic_mismatch", vm, address=address, expected_mac=want, seen_mac=got)
            raise StepFailed("the host that reported is not the VM Proxmox created (hardware address mismatch)",
                             "Someone else used the bootstrap secret, or the VM's NIC changed. The VM was stopped; see the audit log.", retryable=False)

    def _enroll_retry(self, name: str, fps: dict, token: str) -> str:
        last = None
        for _ in range(10):   # the guest opens the agent port only AFTER the callback was acknowledged: allow it a moment
            try:
                return self._enroll(name, fps, token)
            except StepFailed as e:
                if not e.retryable:
                    raise
                last = e
                self.sleep(5)
        raise last

    def _finish(self, vm: str) -> None:
        """After a successful enrollment (outside the fail-closed region): clear the VM config, wipe the vault copies, audit. A resume repeats it."""
        ref, rec = self._expect_material(vm, self.mode)
        try:
            cleared = self._clear_material(ref)
        except ProviderError as e:
            raise StepFailed(f"could not clear the bootstrap material from the VM config: {e.message[:200]}", "Retrying.", retryable=True) from None
        if rec is not None and rec.secret is not None:
            bootsecrets.delete_secrets(self.rt, rec.id, "sealed" if self.lab else "enrolled")
            # a RUNNING VM keeps the old smbios1 in its ACTIVE config until it is stopped and started again (the clear is only `pending`): say so
            held = False
            state = getattr(self.provider, "bootstrap_material_state", None)
            if cleared and state is not None:
                try:
                    held = bool(state(ref)["current"])
                except ProviderError:
                    held = False
            self._audit("guest.bootstrap_completed", vm, mode=self.mode, config_cleared=cleared, secrets_deleted=True, active_config_holds_material_until_restart=held)

    def _finish_resume(self, vm: str) -> None:
        """The node exists (a crash after enrollment, or a repeated step): make sure the guest is sealed (lab) and the material is gone (review H2)."""
        ref, rec = self._expect_material(vm, self.mode)
        if self.lab and rec is not None and rec.secret is not None and not self.rt.settings.guest_keep_bootstrap_ssh:
            try:
                guest = self._guest_factory(sshboot.identity(rec), sshboot.link_local(self.provider.guest_mac(ref), sshboot.default_iface()))
                self._seal_and_audit(vm, guest, resumed=True)
            except (sshboot.BootstrapError, ProviderError) as e:
                self.fail_closed(vm, "resume could not seal")
                raise StepFailed("the guest could not be sealed on resume: " + str(e)[:200], "The VM was stopped.", retryable=False) from None
        self._finish(vm)

    # ---- lab path ----------------------------------------------------------------------------------------------------
    def _seal_and_audit(self, vm: str, guest, *, resumed: bool = False) -> None:
        try:
            guest.seal_verified()
        except sshboot.BootstrapError as e:
            self._audit("guest.bootstrap_seal_failed", vm, error=str(e)[:200], resumed=resumed)
            raise
        self._audit("guest.bootstrap_sealed", vm, verified=True, resumed=resumed)

    def _wait_lab(self, vm: str, name: str, timeout_s: int) -> str:
        s = self.rt.settings
        deadline = self.clock() + max(timeout_s, s.guest_bootstrap_timeout_seconds)
        ref, rec = self._expect_material(vm, "ssh-lab")
        if rec is None or rec.secret is None or rec.state in ("failed", "revoked", "sealed", "expired"):
            raise StepFailed("the bootstrap material of this VM instance is gone", "A previous attempt failed closed (the VM was sealed/stopped); "
                             "destroy and re-create the deployment.", retryable=False)
        ident = sshboot.identity(rec)
        try:
            guest = self._guest_factory(ident, sshboot.link_local(self.provider.guest_mac(ref), sshboot.default_iface()))
        except sshboot.BootstrapError as e:
            raise StepFailed(str(e), "The guest's link-local address could not be derived.", retryable=False) from None
        # 1. the guest proves itself (nothing is sent to it); 2. FIRST action: arm the persistent dead-man seal; 3. only then anything else
        probe = self._until(lambda: guest.probe(), deadline, "the guest to accept the ICS's bootstrap key")
        bootsecrets.set_state(self.rt, rec.id, "reported")
        if probe.get("armed") != "1":
            self._until(lambda: guest.arm(max(5, s.guest_bootstrap_ttl_seconds // 60)), deadline, "the guest to arm its seal timer")
        self._until(lambda: guest.wait_cloud_init(), deadline, "the guest's first cloud-init run")
        while True:
            probe = self._until(lambda: guest.probe(), deadline, "the guest's network")
            addr = probe.get("addr", "")
            try:
                ipaddress.IPv4Address(addr)
                break
            except ValueError:
                if self.clock() >= deadline:
                    raise StepFailed("the guest has no IPv4 address", "DHCP did not hand the VM an address; check the LAN's DHCP service "
                                     "and the bridge/VLAN of the VM.", retryable=False) from None
                self.sleep(5)
        if probe.get("done") != "1":
            ud = self._render(vm, ident, addr)
            if probe.get("running") != "active":
                st = self._until(lambda: guest.install(ud, "ou-boot-" + ident.enroll_token_sha256[:16], vm), deadline, "the guest to take the seed")
                log.info("guest %s bootstrap: %s", vm, st.get("state"))
            self._until(lambda: self._finished(guest), deadline, "the guest bootstrap to finish")
        fps = json.loads(self._until(lambda: guest.fingerprints(), deadline, "the agent fingerprints") or "{}")
        for k in ("address", "port", "tls_fingerprint_sha256", "agent_key_fingerprint_sha256"):
            if k not in fps:
                raise StepFailed("the guest did not report its agent fingerprints", "The bootstrap ended without a usable agent.", retryable=False)
        if fps["address"] != addr:
            raise StepFailed("the guest's agent address does not match its DHCP address", "The lease changed during the bootstrap.", retryable=False)
        nid = self._enroll_retry(name, fps, ident.enroll_token)
        bootsecrets.set_state(self.rt, rec.id, "enrolled")
        if not s.guest_keep_bootstrap_ssh:
            self._seal_and_audit(vm, guest)   # synchronous and verified; a failure here fails closed (stop) although the node is enrolled
        return nid

    def _until(self, fn, deadline: float, what: str):
        last = ""
        while True:
            try:
                return fn()
            except sshboot.ProofFailed as e:
                raise StepFailed(str(e), "Something other than the VM Proxmox created answered on its link-local address. Investigate "
                                 "the LAN before re-running; nothing was sent to it.", retryable=False) from None
            except sshboot.NotReady as e:
                last = str(e)
            except sshboot.BootstrapError as e:
                raise StepFailed(str(e), "The guest bootstrap step failed.", retryable=False) from None
            if self.clock() >= deadline:
                raise StepFailed(f"timed out waiting for {what}: {last}", "Check the VM console in Proxmox (cloud-init, network).", retryable=False)
            self.sleep(5)

    # ---- fail closed (review H1) ---------------------------------------------------------------------------------------
    def fail_closed(self, vm: str, reason: str) -> None:
        """Called on every terminal failure of the bootstrap. Best effort, never raises. Lab: seal (verified) if the guest ever proved itself, then
        STOP the VM; callback: STOP the VM. Always: clear the secrets from the VM config, wipe them from the vault, audit."""
        result = {"sealed": False, "stopped": False, "cleared": False}
        try:
            ref = self._vmref(vm)
            rec = bootsecrets.find(self.rt, self.dep["id"], vm, ref.vmid, self.mode)
            if self.lab and rec is not None and rec.secret is not None and rec.state in ("reported", "enrolled"):
                try:
                    guest = self._guest_factory(sshboot.identity(rec), sshboot.link_local(self.provider.guest_mac(ref), sshboot.default_iface()))
                    guest.seal_verified()
                    result["sealed"] = True
                except Exception as e:  # noqa: BLE001
                    log.warning("fail_closed(%s): seal not verified: %s", vm, type(e).__name__)
            try:
                g = next((x for x in self.provider.discover().guests if int(x["vmid"]) == ref.vmid), None)
                if g is None or g.get("status") != "stopped":
                    self._task(self.provider.power(ref, "stop"), "stop the guest", 120)
                result["stopped"] = True
            except Exception as e:  # noqa: BLE001
                log.error("fail_closed(%s): could not stop the guest: %s", vm, type(e).__name__)
            try:
                self._clear_material(ref)
                result["cleared"] = True
            except Exception as e:  # noqa: BLE001
                log.error("fail_closed(%s): could not clear the bootstrap material: %s", vm, type(e).__name__)
            if rec is not None:
                bootsecrets.delete_secrets(self.rt, rec.id, "failed")
            self._audit("guest.bootstrap_failed_closed", vm, reason=reason[:120], mode=self.mode, **result)
        except Exception as e:  # noqa: BLE001
            log.error("fail_closed(%s) itself failed: %s", vm, type(e).__name__)

    def _finished(self, guest):
        st = guest.status()
        if st.get("done") == "1":
            return st
        if st.get("rc") not in (None, "", "none") and st.get("running") != "active":
            raise StepFailed(f"the guest bootstrap failed (cloud-init exit {st.get('rc')}): {st.get('log', '')[-300:]}",
                             "See /var/log/ou-bootstrap-run.log on the VM.", retryable=False)
        raise sshboot.NotReady("bootstrap still running " + st.get("log", "")[-120:])

    def _spec(self, vm: str, token_sha256: str, addr: str | None, mgmt: list[str], *, lab: bool, bundle: bytes | None) -> cloudinit.GuestSpec:
        s = self.rt.settings
        v = self._vm(vm)
        os_id = (v.get("os_image") or {}).get("id", "debian-12")
        if os_id not in cloudinit.SUITES:
            raise StepFailed(f"OS image {os_id!r} has no guest bootstrap profile", "", retryable=False)
        ports = []
        for f in self.plan.get("firewall", []):
            if f["vm"] != vm or f["port"] == AGENT_PORT:   # the agent port is always opened (to the management sources) by the ruleset itself
                continue
            if f["from"] == "any":
                ports.append({"port": f["port"], "proto": f["proto"], "sources": []})
            elif f["from"] == "ics-control":
                ports.append({"port": f["port"], "proto": f["proto"], "sources": mgmt})
        pub = key_sha = None
        if s.guest_image_signing_pubkey_file:
            pub = Path(s.guest_image_signing_pubkey_file).read_text()
            key_sha = s.guest_image_signing_key_sha256
        import base64
        import hashlib
        raw = bundle if bundle is not None else b"golden-image"   # the golden image carries the agent; only the rendering rules are needed here
        try:
            return cloudinit.GuestSpec(
                hostname=vm, os=os_id, agent_address=addr, agent_port=AGENT_PORT, mgmt_sources=mgmt, declared_ports=ports,
                image_registries=list(s.guest_image_registries) if pub else [], insecure_registries=list(s.guest_insecure_registries) if pub else [],
                image_signing_pubkey_pem=pub, image_signing_key_sha256=key_sha, bootstrap_user=sshboot.BOOT_USER if lab else None,
                enroll_token_sha256=token_sha256, enroll_ttl_seconds=3600,
                agent_bundle_b64=base64.b64encode(raw).decode(), agent_bundle_sha256=hashlib.sha256(raw).hexdigest(),
                subid_start=100000, subid_count=65536)
        except ValueError as e:
            raise StepFailed("the guest specification is invalid: " + str(e)[:200], "Check the ICS_GUEST_* settings.", retryable=False) from None

    def _render(self, vm: str, ident: sshboot.BootIdentity, addr: str) -> str:
        mgmt = list(self.rt.settings.guest_mgmt_sources) or [self._source_towards(addr) + "/32"]
        bundle = cloudinit.build_agent_bundle(_agent_dir(self.rt))
        return cloudinit.render(self._spec(vm, ident.enroll_token_sha256, addr, mgmt, lab=True, bundle=bundle))

    def _callback_config(self, vm: str) -> dict:
        """What the golden image's first-boot unit applies after the ICS authenticated itself (closed schema, validated again on the guest).
        `mgmt_sources` null = the ICS address towards the guest (known only at callback time)."""
        s = self.rt.settings
        spec = self._spec(vm, "0" * 64, None, list(s.guest_mgmt_sources) or ["192.0.2.1/32"], lab=False, bundle=None)
        ports = []
        for f in self.plan.get("firewall", []):
            if f["vm"] != vm or f["port"] == AGENT_PORT:
                continue
            if f["from"] == "any":
                ports.append({"port": f["port"], "proto": f["proto"], "sources": []})
            elif f["from"] == "ics-control":
                ports.append({"port": f["port"], "proto": f["proto"], "sources": list(s.guest_mgmt_sources) or None})
        return {"v": 1, "hostname": vm, "agent_port": AGENT_PORT, "mgmt_sources": list(s.guest_mgmt_sources) or None, "ports": ports,
                "agent_config": cloudinit.agent_config(spec), "image_registries": spec.image_registries, "insecure_registries": spec.insecure_registries,
                "signing_pubkey_pem": spec.image_signing_pubkey_pem, "signing_key_sha256": spec.image_signing_key_sha256,
                "enroll_ttl_seconds": spec.enroll_ttl_seconds}

    @staticmethod
    def _source_towards(addr: str) -> str:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sk:
            sk.connect((addr, 9))   # no packet is sent: this only asks the kernel which local address routes there
            return sk.getsockname()[0]

    def _enroll(self, name: str, fps: dict, token: str) -> str:
        """Same protocol and bookkeeping as the node.enroll executor, with fingerprints that arrived over the authenticated bootstrap channel."""
        rt = self.rt
        lb = rt.settings.allow_loopback_endpoints
        priv = self._key()
        a, p, tls = fps["address"], int(fps["port"]), normalize_fingerprint(fps["tls_fingerprint_sha256"])
        try:
            ident = agentclient.identity(a, p, tls, allow_loopback=lb)
            if agentclient.key_fingerprint(ident["agent_pubkey"]) != fps["agent_key_fingerprint_sha256"]:
                raise StepFailed("the agent's public key does not match the fingerprint the guest reported", "", retryable=False)
            if ident.get("enrolled"):
                raise StepFailed("the guest's agent is already enrolled but the ICS has no node record for it",
                                 "Re-arm the agent on the VM (ou-agent arm-enroll) or destroy and recreate the VM.", retryable=False)
            nid = uuid.uuid4()
            resp = agentclient.enroll(a, p, tls, token=token, ics_pubkey_b64=agentclient.pub_b64(priv.public_key()), node_id=str(nid),
                                      expect_agent_pubkey_b64=ident["agent_pubkey"], allow_loopback=lb)
        except AgentError as e:
            raise StepFailed(f"enrollment failed: {e}", "The agent on the VM could not be enrolled.", retryable=True) from None
        with rt.session() as db:
            db.execute(text(
                "INSERT INTO nodes (id, name, address, port, tls_fingerprint_sha256, agent_pubkey, agent_key_fp, capabilities, agent_version, "
                "last_seen_at, created_by, customer_id) VALUES (:id, :n, :a, :p, :t, :k, :f, CAST(:c AS jsonb), :v, now(), :cb, "
                "COALESCE((SELECT e.customer_id FROM deployments d JOIN endpoints e ON e.id = d.endpoint_id WHERE d.id = CAST(:dep AS uuid)), "
                "'00000000-0000-0000-0000-00000000a001'))"),
                {"id": str(nid), "n": name, "a": a, "p": p, "t": tls, "k": ident["agent_pubkey"], "f": fps["agent_key_fingerprint_sha256"],
                 "c": audit.canon(audit.sanitize(resp.get("capabilities", {}))), "v": str(audit.sanitize(resp.get("agent_version")))[:40],
                 "cb": self.dep.get("created_by"), "dep": str(self.dep["id"])})
            audit.append(db, "node.enrolled", actor_name="worker", resource="node", resource_id=str(nid),
                         details={"name": name, "address": a, "port": p, "via": "deployment bootstrap", "tls_fingerprint": tls,
                                  "agent_key_fingerprint": fps["agent_key_fingerprint_sha256"], "capabilities": resp.get("capabilities", {})})
            db.commit()
        return str(nid)

    def run_runbook(self, node_id: str, runbook: str, params: dict) -> dict:
        try:
            resp = agentcall.execute(self.rt, node_id, runbook, params, deadline=900.0)
        except (AgentError, ValueError) as e:
            raise StepFailed(f"{runbook}: {e}", "The agent could not be reached or refused the request.", retryable=True) from None
        res = resp.get("result") if isinstance(resp.get("result"), dict) else {}
        if resp.get("status") != "ok" or "rejected" in res:
            rej = res.get("rejected") or {}
            raise StepFailed(f"{runbook} refused: {rej.get('code') or resp.get('code')}: {str(rej.get('message') or '')[:200]}",
                             "The node agent rejected the runbook request.", retryable=False)
        inner = res.get("result") if isinstance(res.get("result"), dict) else res
        if inner.get("verified") is False:
            raise StepFailed(f"{runbook}: image verification failed: {str(inner.get('error', ''))[:300]}",
                             "The image is not signed by the pinned key, or its digest differs from the plan.", retryable=False)
        if inner.get("started") is False or inner.get("error"):
            raise StepFailed(f"{runbook} failed: {str(inner.get('error') or inner.get('active_state'))[:300]}", "The unit did not start.", retryable=False)
        return inner

    def address(self, vm: str) -> str:
        n = self._node(self.node_name(vm))
        if n is None:
            raise StepFailed(f"no enrolled node for {vm}", "", retryable=False)
        return n.address

    def tls_trust(self, node_id: str, port: int) -> dict:
        raise StepFailed("TLS trust discovery for guest services is not implemented",
                         "Only checks without TLS (smtp_banner) can be registered by the engine until the agent can report service certificates.",
                         retryable=False)
