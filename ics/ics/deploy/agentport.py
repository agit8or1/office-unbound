"""The real AgentPort of the deployment executor (ports.AgentPort): guest bootstrap + enrollment + signed runbooks.

Flow of `wait_enrollment(vm)` (the `agent.enroll` step; idempotent, resumable):
  1. a node row named `<deployment>-<vm>` already exists  ->  done (a crash after enrollment is harmless);
  2. MAC of the guest from Proxmox -> its IPv6 link-local address; wait for SSH and prove (SMBIOS PSK) that the host is the VM Proxmox started;
  3. render the guest user-data (guest/cloudinit.py: agent bundle, firewall, rootless podman, signed-image policy pinned to the operator's key)
     and apply it over SSH as a NoCloud seed (guest/sshboot.py); wait until the bootstrap reports done;
  4. read the agent's TLS + agent-key fingerprints (MAC-authenticated), enroll over the pinned TLS channel with the one-time token (only its hash
     was ever in the user-data), record the node;
  5. seal the guest (SSH disabled and masked, bootstrap account locked).
Everything after that uses the same signed-request channel as every other node (guest/agentcall.py)."""
import ipaddress
import json
import logging
import socket
import uuid
from pathlib import Path

from sqlalchemy import text

from .. import agentclient, audit
from ..agentclient import AgentError
from ..guest import agentcall, cloudinit, sshboot
from ..proxmox import normalize_fingerprint
from ..providers.base import VmRef
from . import state
from .ports import StepFailed

log = logging.getLogger("ics.deploy.agentport")
AGENT_PORT = 8443


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

    # ---- executor-facing API --------------------------------------------------------------------------------------
    def bootstrap_config(self, vm: str) -> dict:
        """Cloud-init drive / SMBIOS values for `configure_vm`: only public material and the per-VM proof secret derived from the signing key."""
        ident = sshboot.identity(self._key(), self.slug, vm)
        return {"ciuser": sshboot.BOOT_USER, "sshkeys": (ident.ssh_public,), "smbios_serial": ident.psk}

    def wait_enrollment(self, vm: str, timeout_s: int) -> str:
        name = self.node_name(vm)
        n = self._node(name)
        if n is not None:
            return str(n.id)
        s = self.rt.settings
        deadline = self.clock() + max(timeout_s, s.guest_bootstrap_timeout_seconds)
        ident = sshboot.identity(self._key(), self.slug, vm)
        with self.rt.session() as db:
            pref = state.provider_ref(db, self.dep["id"], vm)
        if not pref or pref.get("vmid") is None:
            raise StepFailed(f"VM {vm} has no provider reference", "", retryable=False)
        try:
            mac = self.provider.guest_mac(VmRef(pref["node"], int(pref["vmid"]), "vm", self.slug))
            guest = self._guest_factory(ident, sshboot.link_local(mac, sshboot.default_iface()))
        except sshboot.BootstrapError as e:
            raise StepFailed(str(e), "The guest's link-local address could not be derived.", retryable=False) from None
        probe = self._until(lambda: guest.probe(), deadline, "the guest to accept the ICS's bootstrap key")
        addr = probe.get("addr", "")
        try:
            ipaddress.IPv4Address(addr)
        except ValueError:
            raise StepFailed("the guest has no IPv4 address yet", "DHCP did not hand the VM an address; check the LAN's DHCP service "
                             "and the bridge/VLAN of the VM.", retryable=True) from None
        if probe.get("done") != "1":
            ud = self._render(vm, ident, addr)
            if probe.get("running") != "active":
                st = guest.install(ud, "ou-boot-" + ident.enroll_token_sha256[:16], vm)
                log.info("guest %s bootstrap: %s", vm, st.get("state"))
            self._until(lambda: self._finished(guest), deadline, "the guest bootstrap to finish")
        fps = json.loads(guest.fingerprints() or "{}")
        for k in ("address", "port", "tls_fingerprint_sha256", "agent_key_fingerprint_sha256"):
            if k not in fps:
                raise StepFailed("the guest did not report its agent fingerprints", "The bootstrap ended without a usable agent.", retryable=False)
        if fps["address"] != addr:
            raise StepFailed("the guest's agent address does not match its DHCP address", "The lease changed during the bootstrap.", retryable=True)
        nid = self._enroll(name, fps, ident.enroll_token)
        if not self.rt.settings.guest_keep_bootstrap_ssh:
            guest.seal()
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
            if self.clock() >= deadline:
                raise StepFailed(f"timed out waiting for {what}: {last}", "Check the VM console in Proxmox (cloud-init, network).", retryable=False)
            self.sleep(5)

    def _finished(self, guest):
        st = guest.status()
        if st.get("done") == "1":
            return st
        if st.get("rc") not in (None, "", "none") and st.get("running") != "active":
            raise StepFailed(f"the guest bootstrap failed (cloud-init exit {st.get('rc')}): {st.get('log', '')[-300:]}",
                             "See /var/log/ou-bootstrap-run.log on the VM.", retryable=False)
        raise sshboot.NotReady("bootstrap still running " + st.get("log", "")[-120:])

    def _render(self, vm: str, ident: sshboot.BootIdentity, addr: str) -> str:
        s = self.rt.settings
        v = self._vm(vm)
        os_id = (v.get("os_image") or {}).get("id", "debian-12")
        if os_id not in cloudinit.SUITES:
            raise StepFailed(f"OS image {os_id!r} has no guest bootstrap profile", "", retryable=False)
        mgmt = list(s.guest_mgmt_sources) or [self._source_towards(addr) + "/32"]
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
        bundle = cloudinit.build_agent_bundle(_agent_dir(self.rt))
        import base64
        import hashlib
        try:
            spec = cloudinit.GuestSpec(
                hostname=vm, os=os_id, agent_address=addr, agent_port=AGENT_PORT, mgmt_sources=mgmt, declared_ports=ports,
                image_registries=list(s.guest_image_registries) if pub else [], insecure_registries=list(s.guest_insecure_registries) if pub else [],
                image_signing_pubkey_pem=pub, image_signing_key_sha256=key_sha, bootstrap_user=sshboot.BOOT_USER,
                enroll_token_sha256=ident.enroll_token_sha256, enroll_ttl_seconds=3600,
                agent_bundle_b64=base64.b64encode(bundle).decode(), agent_bundle_sha256=hashlib.sha256(bundle).hexdigest(),
                subid_start=100000, subid_count=65536)
        except ValueError as e:
            raise StepFailed("the guest specification is invalid: " + str(e)[:200], "Check the ICS_GUEST_* settings.", retryable=False) from None
        return cloudinit.render(spec)

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
                "last_seen_at, created_by) VALUES (:id, :n, :a, :p, :t, :k, :f, CAST(:c AS jsonb), :v, now(), :cb)"),
                {"id": str(nid), "n": name, "a": a, "p": p, "t": tls, "k": ident["agent_pubkey"], "f": fps["agent_key_fingerprint_sha256"],
                 "c": audit.canon(audit.sanitize(resp.get("capabilities", {}))), "v": str(audit.sanitize(resp.get("agent_version")))[:40],
                 "cb": self.dep.get("created_by")})
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
