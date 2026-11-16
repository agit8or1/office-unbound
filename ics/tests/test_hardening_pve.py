"""Hardening: what Proxmox itself records about the one-time SMBIOS secret (cluster log, pending config of a running VM).
Source of the facts: docs/status/hardening-results.md (qemu-server PVE/API2/Qemu.pm update_vm_api, pve-manager PVE/API2/Cluster.pm, pve-cluster logger.c)."""
import base64

from ics.providers.base import VmConfigSpec

from .infra_fixtures import job, mutations, sim  # noqa: F401
from .test_guest_callback import ref

UUID = "uuid=3041632a-47b0-4ee7-a8bd-d49a3a6021df"


def _spec():
    return VmConfigSpec(ciuser="ou-boot", sshkeys=("ssh-ed25519 " + "A" * 60,), smbios_serial="ab" * 32, smbios_sku="https://192.168.22.167:8444",
                        smbios_family="sha256:" + "cd" * 32)


def test_pve_cluster_log_receives_the_secret_value_and_it_is_detected(sim, job):
    """PVE logs `update VM <id>: -smbios1 <value>` (cluster log + syslog) for every config update, sync PUT included."""
    m = mutations(sim)
    sim.sim.vms[150]["cfg"]["smbios1"] = UUID
    spec = _spec()
    needles = [spec.smbios_serial, base64.b64encode(spec.smbios_serial.encode()).decode()]
    assert m.cluster_log_mentions(needles) is False
    m.wait(m.configure_vm(ref(), spec))
    assert m.cluster_log_mentions(needles) is True                                    # the base64 form is what PVE logs
    assert m.cluster_log_mentions(["no-such-value"]) is False
    assert m.cluster_log_mentions([]) is False
    m.wait(m.configure_vm(ref(), VmConfigSpec(clear_bootstrap=True)))
    assert m.bootstrap_material_state(ref()) == {"effective": False, "current": False}   # stopped VM: applied at once


def test_running_vm_keeps_the_secret_in_the_active_config_until_restart(sim, job):
    """smbios1 is not hot-pluggable: on a running VM the clear is only `pending`. The default GET config (pending applied) hides it; `current=1` does not."""
    m = mutations(sim)
    vm = sim.sim.vms[150]
    vm["cfg"]["smbios1"] = UUID
    m.wait(m.configure_vm(ref(), _spec()))
    vm["status"] = "running"
    m.wait(m.configure_vm(ref(), VmConfigSpec(clear_bootstrap=True)))
    assert m.bootstrap_material_state(ref()) == {"effective": False, "current": True}
    assert m.bootstrap_material_present(ref()) is True                                # no longer reported as gone
    vm["status"] = "stopped"
    m.wait(m.power(ref(), "start"))                                                   # a (re)start applies the pending delete
    assert m.bootstrap_material_state(ref()) == {"effective": False, "current": False}
