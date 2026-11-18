"""Privileges each ADR-0009 verb needs on which ACL paths, and the evaluation of /access/permissions against them.

Derived from the PVE 8/9 API definitions (pve-docs "Permission Management" + the privilege checks of the API calls we use);
re-verify against the real cluster (docs/status/provider-proxmox.md lists this as awaiting real-cluster confirmation).
"""
from __future__ import annotations

from ..base import VerbCheck

INVENTORY_VERBS = ("discover", "metrics")
PROVISION_VERBS = ("clone_vm", "configure_vm", "resize_disk", "power", "snapshot", "rollback", "migrate", "destroy_vm")

# verb -> privileges needed on each kind of path
VERB_PRIVS: dict[str, dict[str, list[str]]] = {
    "discover": {"root": ["Sys.Audit", "VM.Audit", "Datastore.Audit"]},
    "metrics": {"root": ["Sys.Audit", "VM.Audit"]},
    "clone_vm": {"pool": ["VM.Allocate", "VM.Clone", "VM.Audit", "VM.Config.Disk"], "storage": ["Datastore.AllocateSpace"]},
    "configure_vm": {"pool": ["VM.Config.CPU", "VM.Config.Memory", "VM.Config.Network", "VM.Config.Disk", "VM.Config.Cloudinit",
                              "VM.Config.Options", "VM.Config.HWType", "VM.Audit"],
                     "storage": ["Datastore.AllocateSpace"], "network": ["SDN.Use"]},
    "resize_disk": {"pool": ["VM.Config.Disk", "VM.Audit"], "storage": ["Datastore.AllocateSpace"]},
    "power": {"pool": ["VM.PowerMgmt", "VM.Audit"]},
    "snapshot": {"pool": ["VM.Snapshot", "VM.Audit"]},
    "rollback": {"pool": ["VM.Snapshot.Rollback", "VM.Audit"]},
    "migrate": {"pool": ["VM.Migrate", "VM.Audit"], "storage": ["Datastore.AllocateSpace"]},
    "destroy_vm": {"pool": ["VM.Allocate", "VM.Audit"]},
    # image.import is NOT part of PROVISION_VERBS (an owner-enabled capability, see IMPORT_STORAGE_PRIVS): uploading to a directory storage needs
    # Datastore.AllocateTemplate there; creating the template VM from it needs the usual pool + target-storage rights
    "import_image": {"pool": ["VM.Allocate", "VM.Audit", "VM.Config.Disk", "VM.Config.CPU", "VM.Config.Memory", "VM.Config.Network", "VM.Config.Options"],
                     "storage": ["Datastore.AllocateSpace"]},
}
IMPORT_STORAGE_PRIVS = ["Datastore.AllocateTemplate", "Datastore.Audit"]   # on the `import` directory storage (upload; import-from needs Audit; never AllocateSpace)
CICUSTOM_PRIVS = {"root": ["Sys.Modify"]}   # PVE restricts `cicustom` to highly privileged users
UNNECESSARY = ("VM.Console", "VM.Backup", "Sys.Console", "Sys.Modify", "Sys.PowerMgmt", "Permissions.Modify")  # flagged as more than ICS needs

# Where the verb checks live is a statement about PVE's ACL tree; a verb is satisfied on a pool OR on its guest paths.
# Some clusters (see docs/status/provider-proxmox.md) grant the VM privileges on /pool/<p> only; some also on /vms/<id>.


def network_path(name: str, vnet_zones: dict[str, str]) -> str:
    """ACL path guarding a bridge / SDN vnet (PVE 8: /sdn/zones/<zone>/<vnet>; classic bridges live in zone localnetwork)."""
    return f"/sdn/zones/{vnet_zones.get(name, 'localnetwork')}/{name}"


def required(verb: str, pools, storage, networks, vnet_zones: dict[str, str], cicustom: bool = False) -> list[tuple[str, list[str]]]:
    spec = VERB_PRIVS[verb]
    out: list[tuple[str, list[str]]] = []
    if "root" in spec:
        out.append(("/", spec["root"]))
    if "pool" in spec:
        out += [(f"/pool/{p}", spec["pool"]) for p in pools]
    if "storage" in spec:
        out += [(f"/storage/{s}", spec["storage"]) for s in storage]
    if "network" in spec:
        out += [(network_path(n, vnet_zones), spec["network"]) for n in networks]
    if verb == "configure_vm" and cicustom:
        out.append(("/", CICUSTOM_PRIVS["root"]))
    return out


def fix_hint(path: str, privs: list[str], token_id: str | None) -> str:
    """Exact operator command that grants what is missing (printed in the setup report)."""
    who = f"--tokens '{token_id}'" if token_id else "--tokens '<token-id>'"
    if path.startswith("/sdn/"):
        return f"pveum acl modify {path} {who} --roles PVESDNUser"
    if path.startswith("/storage/"):
        return f"pveum acl modify {path} {who} --roles PVEDatastoreUser"
    if path == "/":
        return f"pveum acl modify / {who} --roles PVEAuditor   # (inventory credential; read-only)"
    return f"pveum role modify <ICS-role> --privs \"{' '.join(privs)}\" --append 1   # then: pveum acl modify {path} {who} --roles <ICS-role>"


def evaluate(verb: str, reqs: list[tuple[str, list[str]]], perms_at, token_id: str | None = None) -> VerbCheck:
    """perms_at(path) -> set of effective privileges at that path (inheritance already applied by PVE)."""
    missing = []
    for path, privs in reqs:
        have = perms_at(path)
        lack = [p for p in privs if p not in have]
        if lack:
            missing.append({"path": path, "privileges": lack, "fix": fix_hint(path, lack, token_id)})
    note = None
    if verb == "configure_vm" and any(m["path"].startswith("/sdn/") for m in missing):
        note = "attaching a NIC to the listed bridge(s) will fail until SDN.Use is granted on them"
    return VerbCheck(verb, not missing, missing, note)
