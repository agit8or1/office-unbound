"""Application-level scope guard for the controls Proxmox's ACL model cannot express (node isolation inside a pool, VMID ranges,
guest types, CPU/RAM/disk caps). Pure functions over the stored policy so any broker can call them before a mutation.

STATUS: implemented and unit-tested here; wiring into ProxmoxMutations is an integration step (docs/status/provider-provisioning.md)."""
from __future__ import annotations

from .model import AccessScope


class PolicyViolation(Exception):
    pass


def check_vmid(scope: AccessScope, vmid: int) -> None:
    if vmid in scope.protected_vmids:
        raise PolicyViolation(f"vmid {vmid} is protected")
    if scope.vmid_ranges and not any(a <= vmid <= b for a, b in scope.vmid_ranges):
        raise PolicyViolation(f"vmid {vmid} is outside the authorised VMID ranges")


def check_node(scope: AccessScope, node: str) -> None:
    if scope.nodes and node not in scope.nodes:
        raise PolicyViolation(f"node {node} is not authorised for this integration")


def check_guest_type(scope: AccessScope, kind: str) -> None:
    if kind not in scope.guest_types:
        raise PolicyViolation(f"guest type {kind} is not authorised")


def check_caps(scope: AccessScope, cores: int | None = None, memory_mb: int | None = None, disk_gb: int | None = None) -> None:
    for val, cap, label in ((cores, scope.max_cores, "cores"), (memory_mb, scope.max_memory_mb, "memory"), (disk_gb, scope.max_disk_gb, "disk")):
        if val is not None and cap is not None and val > cap:
            raise PolicyViolation(f"{label} {val} exceeds the policy cap {cap}")


def check_create(scope: AccessScope, *, vmid: int, node: str, kind: str = "qemu", cores=None, memory_mb=None, disk_gb=None) -> None:
    check_vmid(scope, vmid)
    check_node(scope, node)
    check_guest_type(scope, kind)
    check_caps(scope, cores, memory_mb, disk_gb)
