"""Proxmox provisioning: privilege matrix per PVE major version, capability -> role/ACL design, plan computation (diff against the
discovered cluster), Mode A apply (with rollback of what this run created), permission verification and drift, and the Mode B package.

Everything that decides WHAT is granted lives in `design()`; the plan, the Mode A executor, the Mode B script and the drift check all derive
from that single function, so both modes end in the same restricted integration.

Privilege facts below are taken from the Proxmox VE documentation (pveum(1) "Privileges", chapter "User Management", the API viewer's
per-call permission lines, and the PVE 9.0 release notes). They are NOT yet confirmed against the owner's real cluster
(docs/status/provider-provisioning.md lists that as outstanding).
"""
from __future__ import annotations

import html
import json
import re
import shlex
from dataclasses import dataclass, field

from ...provisioning.drift import compare_permissions
from ...provisioning.model import ConflictChoices, Policy
from ...provisioning.plan import EnforcementNote, ProvisioningPlan, Step
from ...proxmox import ProxmoxError
from . import privileges as priv
from .admin import ProxmoxAdminClient

MARK = "ICS-managed"
PKG_SCHEMA = "office-unbound/provisioning-package/v1"
MIN_MAJOR = 8
DOCS = {
    "pveum": "https://pve.proxmox.com/pve-docs/pveum.1.html",
    "user-management": "https://pve.proxmox.com/pve-docs/chapter-pveum.html",
    "api-viewer": "https://pve.proxmox.com/pve-docs/api-viewer/index.html",
    "pve9-release-notes": "https://pve.proxmox.com/wiki/Roadmap#Proxmox_VE_9.0",
}

# ---------------------------------------------------------------------------------------------------- privilege matrix
# priv -> (introduced_in_major or None, removed_in_major or None, what ICS uses it for, documentation anchor)
PRIV_MATRIX: dict[str, tuple[int | None, int | None, str, str]] = {
    "Sys.Audit": (None, None, "read node status, metrics, network (GET /nodes/{node}/status|network|rrddata)", "api-viewer: /nodes/{node}/status"),
    "VM.Audit": (None, None, "list/read guests and configs (GET /nodes/{node}/qemu|lxc, .../config)", "api-viewer: /nodes/{node}/qemu"),
    "Datastore.Audit": (None, None, "list storages and contents", "api-viewer: /storage, /nodes/{node}/storage"),
    "Pool.Audit": (None, None, "read pool membership (GET /pools/{poolid})", "api-viewer: /pools/{poolid}"),
    "VM.Allocate": (None, None, "create/destroy guests (POST qemu|lxc clone target, DELETE qemu/{vmid}) on /vms/{vmid} or /pool/{pool}", "api-viewer: /nodes/{node}/qemu/{vmid}/clone"),
    "VM.Clone": (None, None, "clone a template/guest (on the SOURCE /vms/{vmid})", "api-viewer: /nodes/{node}/qemu/{vmid}/clone"),
    "VM.PowerMgmt": (None, None, "start/stop/shutdown/reboot", "api-viewer: /nodes/{node}/qemu/{vmid}/status/*"),
    "VM.Config.CPU": (None, None, "set cores/sockets", "api-viewer: /nodes/{node}/qemu/{vmid}/config"),
    "VM.Config.Memory": (None, None, "set memory/balloon", "api-viewer: /nodes/{node}/qemu/{vmid}/config"),
    "VM.Config.Disk": (None, None, "add/resize disks", "api-viewer: .../config, .../resize"),
    "VM.Config.Network": (None, None, "add/modify NICs", "api-viewer: .../config"),
    "VM.Config.Cloudinit": (None, None, "cloud-init user/network settings", "api-viewer: .../config"),
    "VM.Config.Options": (None, None, "name, tags, description, onboot", "api-viewer: .../config"),
    "VM.Config.HWType": (None, None, "machine/bios/hardware type", "api-viewer: .../config"),
    "VM.Config.CDROM": (None, None, "attach cloud-init/ISO media", "api-viewer: .../config"),
    "VM.Snapshot": (None, None, "create/delete snapshots", "api-viewer: .../snapshot"),
    "VM.Snapshot.Rollback": (None, None, "roll back to a snapshot", "api-viewer: .../snapshot/{snapname}/rollback"),
    "VM.Migrate": (None, None, "migrate guests between nodes (opt-in)", "api-viewer: .../migrate"),
    "VM.Backup": (None, None, "vzdump a guest (Backup capability only)", "api-viewer: /nodes/{node}/vzdump"),
    "Datastore.AllocateSpace": (None, None, "allocate disks/clones on a storage", "api-viewer: .../clone, .../config"),
    "SDN.Use": (8, None, "attach a NIC to a bridge / vnet (path /sdn/zones/{zone}/{vnet}; classic bridges live in zone localnetwork since PVE 8)", "pveum: privileges 'SDN.Use'"),
    "VM.Monitor": (None, 9, "guest agent / monitor commands on PVE 8; REMOVED in PVE 9", "pve9-release-notes"),
    "VM.GuestAgent.Audit": (9, None, "read guest-agent information on PVE 9 (replaces VM.Monitor for read-only use)", "pve9-release-notes"),
    "VM.GuestAgent.FileRead": (9, None, "read files through the guest agent (never granted by a preset)", "pve9-release-notes"),
    "VM.GuestAgent.FileWrite": (9, None, "write files through the guest agent (never granted by a preset)", "pve9-release-notes"),
    "VM.GuestAgent.FileSystemMgmt": (9, None, "freeze/trim through the guest agent (never granted by a preset)", "pve9-release-notes"),
    "VM.GuestAgent.Unrestricted": (9, None, "all guest-agent commands (never granted by a preset)", "pve9-release-notes"),
    "VM.Console": (None, None, "console access (never granted by a preset)", "pveum: privileges"),
    "Sys.Console": (None, None, "node shell (never granted by a preset)", "pveum: privileges"),
    "Sys.PowerMgmt": (None, None, "node reboot/shutdown (full_admin only)", "pveum: privileges"),
    "Sys.Syslog": (None, None, "node syslog (full_admin only)", "pveum: privileges"),
    "Sys.Incoming": (None, None, "incoming data (full_admin only)", "pveum: privileges"),
    "Sys.Modify": (None, None, "ELEVATED: node/cluster configuration; needed for cicustom snippets", "api-viewer: .../qemu/{vmid}/config cicustom"),
    "Datastore.Allocate": (None, None, "create/remove storages (full_admin only)", "pveum: privileges"),
    "Datastore.AllocateTemplate": (None, None, "upload ISOs/templates/import images (full_admin; deploy only on an approved image import storage)", "api-viewer: /nodes/{node}/storage/{storage}/upload"),
    "Pool.Allocate": (None, None, "create/delete pools (full_admin only)", "pveum: privileges"),
    "SDN.Allocate": (None, None, "change SDN configuration (full_admin only)", "pveum: privileges"),
    "SDN.Audit": (None, None, "read SDN configuration", "pveum: privileges"),
    "Mapping.Audit": (None, None, "read resource mappings", "pveum: privileges"),
    "Mapping.Use": (None, None, "use resource mappings (full_admin only)", "pveum: privileges"),
    "Mapping.Modify": (None, None, "change resource mappings (never granted)", "pveum: privileges"),
    # permanently refused
    "Permissions.Modify": (None, None, "FORBIDDEN: change ACLs (privilege escalation)", "pveum: privileges"),
    "User.Modify": (None, None, "FORBIDDEN: create/modify users and tokens", "pveum: privileges"),
    "Group.Allocate": (None, None, "FORBIDDEN: groups", "pveum: privileges"),
    "Realm.Allocate": (None, None, "FORBIDDEN: authentication realms", "pveum: privileges"),
    "Realm.AllocateUser": (None, None, "FORBIDDEN: realm user assignment", "pveum: privileges"),
}
FORBIDDEN = {"Permissions.Modify", "User.Modify", "Group.Allocate", "Realm.Allocate", "Realm.AllocateUser"}
FORBIDDEN_ROLES = {"Administrator", "PVEAdmin"}
ELEVATED = {"Sys.Modify": "needed for `cicustom` cloud-init snippets; also lets the holder change node-level configuration",
            "Sys.Console": "shell access to the node", "Sys.PowerMgmt": "reboot/shutdown nodes", "VM.Console": "console access to guests",
            "Datastore.Allocate": "create/remove storages", "Pool.Allocate": "create/delete pools", "SDN.Allocate": "change SDN configuration",
            "Mapping.Modify": "change resource mappings", "VM.GuestAgent.Unrestricted": "run any guest-agent command inside guests",
            "VM.GuestAgent.FileWrite": "write files inside guests", "VM.GuestAgent.FileSystemMgmt": "freeze/trim guest filesystems"}


def privs_for_major(major: int) -> set[str]:
    return {p for p, (since, until, _, _) in PRIV_MATRIX.items() if (since is None or major >= since) and (until is None or major < until)}


def matrix_for_docs() -> dict:
    return {"8": sorted(privs_for_major(8)), "9": sorted(privs_for_major(9)), "forbidden": sorted(FORBIDDEN), "elevated": ELEVATED,
            "details": {p: {"introduced": a, "removed": b, "used_for": c, "doc": DOCS.get(d.split(":")[0], d)} for p, (a, b, c, d) in PRIV_MATRIX.items()}}


class PlanBuildError(ValueError):
    pass


READ_ONLY_AUDIT = frozenset({"Sys.Audit", "VM.Audit", "Datastore.Audit", "Pool.Audit"})


# ---------------------------------------------------------------------------------------------------- design
CAP_ROLE_SUFFIX = {"monitor_cluster": "ClusterMonitor", "monitor": "Monitor", "operate": "Operate", "deploy": "Deploy", "storage": "Storage", "template_clone": "TemplateClone", "network": "Network",
                   "backup": "Backup", "custom": "Custom", "full_admin": "FullAdmin", "node_audit": "NodeAudit",
                   "import_storage": "ImageImport"}
# image.import (provider.import_image): POST /nodes/<n>/storage/<s>/upload needs Datastore.AllocateTemplate on /storage/<s>; the `import-from=<s>:import/<f>`
# volume of the template VM is checked like an ISO/vztmpl volume (Datastore.Audit OR AllocateSpace on /storage/<s>); listing the storage on the node needs
# Datastore.Audit too. Datastore.AllocateSpace (VM disks) is deliberately NOT part of it: an import storage can never receive a VM disk through this grant.
IMPORT_STORAGE_PRIVS = frozenset({"Datastore.AllocateTemplate", "Datastore.Audit"})
# Storage types whose Proxmox plugin accepts the `import` content type (file-based storage; PVE 8.4+ / 9). Office Unbound adds `import` to such a
# storage with the administrator's sign-in when it is missing (a disclosed plan step); any other type is refused.
IMPORT_CONTENT_TYPES = ("dir", "nfs", "cifs", "cephfs")
_DISK_CONTENT = {"images", "rootdir"}


def scope_storages(policy: Policy) -> set[str]:
    """Every storage the ICS broker allowlists for this policy (deployment, backup and image import storages)."""
    s = policy.scope
    return set(s.storages) | set(s.backup_storages) | set(s.import_storages)


def capabilities(policy: Policy) -> list[str]:
    caps = _base_capabilities(policy)
    if policy.scope_mode and "full_admin" not in caps:
        # scope modes: Sys.Audit lives in its own role so it is granted ONLY on /nodes paths (never on pool/storage/vm paths)
        caps.insert(1, "node_audit")
    if policy.monitor_cluster and "full_admin" not in caps:
        caps.append("monitor_cluster")       # read-only, '/' for the inventory token: never a reason for a write token
    return caps


def _base_capabilities(policy: Policy) -> list[str]:
    if policy.preset == "monitoring":
        return ["monitor"]
    if policy.preset == "operations":
        return ["monitor", "operate"]
    if policy.preset == "deploy":
        caps = ["monitor", "deploy", "storage"] + (["operate"] if policy.scope.managed_vmids else [])
        if policy.scope.template_vmids:
            caps.append("template_clone")
        if policy.scope.networks:
            caps.append("network")
        if policy.scope.import_storages:
            caps.append("import_storage")
        return caps
    if policy.preset == "full_admin":
        return ["monitor", "full_admin"]
    return ["monitor"] + [c for c in policy.capabilities if c != "monitor"]


def role_privileges(cap: str, policy: Policy, major: int) -> set[str]:
    if major < MIN_MAJOR:
        raise PlanBuildError(f"Proxmox VE {major} is not supported (need 8 or 9)")
    if cap == "node_audit":
        p = {"Sys.Audit"}
    elif cap == "monitor":
        p = {"VM.Audit", "Datastore.Audit", "Pool.Audit"} if (policy.scope_mode and policy.preset != "full_admin") else {"Sys.Audit", "VM.Audit", "Datastore.Audit", "Pool.Audit"}
        if policy.guest_agent:
            p.add("VM.GuestAgent.Audit" if major >= 9 else "VM.Monitor")
    elif cap == "monitor_cluster":
        p = set(READ_ONLY_AUDIT)                                                    # read-only, whole cluster, inventory token only
    elif cap == "deploy":
        p = {"VM.Allocate", "VM.Audit", "VM.PowerMgmt", "VM.Config.CPU", "VM.Config.Memory", "VM.Config.Disk", "VM.Config.Network",
             "VM.Config.Cloudinit", "VM.Config.Options", "VM.Config.HWType", "VM.Config.CDROM", "VM.Snapshot", "VM.Snapshot.Rollback", "VM.Clone", "Pool.Audit"}
        if policy.allow_migrate:
            p.add("VM.Migrate")
    elif cap == "operate":
        p = {"VM.Audit", "VM.PowerMgmt"}       # start/stop/shutdown/reboot of individually authorized existing guests; nothing else
    elif cap == "storage":
        p = {"Datastore.AllocateSpace", "Datastore.Audit"}
    elif cap == "template_clone":
        p = {"VM.Clone", "VM.Audit"}
    elif cap == "network":
        p = {"SDN.Use"}
    elif cap == "import_storage":
        p = set(IMPORT_STORAGE_PRIVS)          # upload + import-from only; never Datastore.AllocateSpace (no VM disks)
    elif cap == "backup":
        p = {"VM.Backup", "Datastore.AllocateSpace", "Datastore.Audit"}
    elif cap == "custom":
        p = {x for g in policy.custom_grants for x in g.privileges}
        if policy.allow_cicustom:
            p.add("Sys.Modify")
    elif cap == "full_admin":
        p = privs_for_major(major) - FORBIDDEN - {"Sys.Modify", "VM.GuestAgent.FileWrite", "VM.GuestAgent.FileSystemMgmt",
                                                  "VM.GuestAgent.Unrestricted", "Mapping.Modify", "VM.Console", "Sys.Console"}
    else:
        raise PlanBuildError(f"unknown capability {cap}")
    return p


def check_privileges(policy: Policy, major: int) -> list[dict]:
    """Reject forbidden/unknown privileges; return the ELEVATED ones the policy asks for (each must be explicitly approved)."""
    known = privs_for_major(major)
    elev: list[dict] = []
    wanted: dict[str, str] = {}
    for g in policy.custom_grants:
        for x in g.privileges:
            wanted[x] = g.path
    if policy.allow_cicustom:
        wanted.setdefault("Sys.Modify", "/")
    for x, path in wanted.items():
        if x in FORBIDDEN:
            raise PlanBuildError(f"{x} can never be granted to the integration (it would allow privilege escalation)")
        if x not in known:
            raise PlanBuildError(f"{x} is not a privilege of Proxmox VE {major}"
                                 + (" (removed in PVE 9; use VM.GuestAgent.*)" if x == "VM.Monitor" else ""))
        if x in ELEVATED:
            elev.append({"privilege": x, "path": path, "why": ELEVATED[x], "what_it_grants": PRIV_MATRIX[x][2]})
    approved = set(policy.approve_elevated)
    for e in elev:
        e["approved"] = e["privilege"] in approved
    return elev


@dataclass
class AclSpec:
    path: str
    cap: str
    propagate: int
    tokens: tuple[str, ...]            # which tokens carry it ("inventory", "provision"); the user always carries it


@dataclass
class Design:
    userid: str
    roles: dict[str, tuple[str, frozenset]]      # cap -> (role name, privileges)
    tokens: dict[str, str]                       # kind -> token name
    acl: list[AclSpec]
    major: int
    pools: list[str]
    withheld: frozenset = frozenset()            # privileges the design deliberately lacks (a role used as is, by the approver's choice)


def role_name(policy: Policy, cap: str) -> str:
    return policy.role_names.get(cap) or policy.role_prefix + CAP_ROLE_SUFFIX[cap]


def design(policy: Policy, major: int, final_names: dict[str, str] | None = None, token_names: dict[str, str] | None = None,
           vnet_zones: dict[str, str] | None = None, role_privs: dict[str, list[str]] | None = None) -> Design:
    """`role_privs`: per capability, the privileges of an existing role the approver chose to use AS IS (always a subset of what the
    capability needs; the difference is `withheld`)."""
    caps = capabilities(policy)
    s = policy.scope
    zones = vnet_zones or {}
    roles, withheld = {}, set()
    for c in caps:
        need = frozenset(role_privileges(c, policy, major))
        have = frozenset((role_privs or {}).get(c, need))
        if not have <= need:
            raise PlanBuildError(f"an existing role used as is for '{c}' must not grant more than the capability needs")
        withheld |= need - have
        roles[c] = ((final_names or {}).get(c) or role_name(policy, c), have)
    both, prov = ("inventory", "provision"), ("provision",)
    nodecap = "node_audit" if "node_audit" in caps else "monitor"
    acl: list[AclSpec] = []
    if "full_admin" in caps:
        acl = [AclSpec("/", "monitor", 1, ("inventory",)), AclSpec("/", "full_admin", 1, prov)]
    else:
        if policy.mode() == "whole_cluster":
            acl.append(AclSpec("/nodes", nodecap, 1, both))          # every current and future node: Sys.Audit with propagation
        else:
            acl += [AclSpec(f"/nodes/{n}", nodecap, 1, both) for n in s.nodes]   # single_node / legacy: exactly the selected nodes, never /nodes or /
        if "monitor_cluster" in caps:
            acl.append(AclSpec("/", "monitor_cluster", 1, ("inventory",)))   # read-only everywhere, for the READ token only (never the write token)
        acl += [AclSpec(f"/pool/{p}", "monitor", 1, both) for p in s.pools]
        acl += [AclSpec(f"/storage/{x}", "monitor", 1, both) for x in s.storages]
        acl += [AclSpec(f"/vms/{t}", "monitor", 0, both) for t in s.template_vmids]
        acl += [AclSpec(f"/vms/{v}", "monitor", 0, both) for v in s.managed_vmids]        # per-guest ACL: Proxmox enforces it natively
        if "operate" in caps:
            acl += [AclSpec(f"/vms/{v}", "operate", 0, prov) for v in s.managed_vmids]
        if "deploy" in caps:
            acl += [AclSpec(f"/pool/{p}", "deploy", 1, prov) for p in s.pools]
        if "storage" in caps:
            acl += [AclSpec(f"/storage/{x}", "storage", 1, prov) for x in s.storages]
        if "template_clone" in caps:
            acl += [AclSpec(f"/vms/{t}", "template_clone", 0, prov) for t in s.template_vmids]
        if "import_storage" in caps:
            acl += [AclSpec(f"/storage/{x}", "import_storage", 1, prov) for x in s.import_storages]
        if "network" in caps:
            acl += [AclSpec(f"/sdn/zones/{zones.get(n, 'localnetwork')}/{n}", "network", 1, prov) for n in s.networks]
        if "backup" in caps:
            acl += [AclSpec(f"/pool/{p}", "backup", 1, prov) for p in s.pools]
            acl += [AclSpec(f"/storage/{x}", "backup", 1, prov) for x in s.backup_storages]
        if "custom" in caps:
            acl += [AclSpec(g.path, "custom", 1, prov) for g in policy.custom_grants]
            if policy.allow_cicustom:
                acl.append(AclSpec("/", "custom", 1, prov))
    kinds = ["inventory"] + (["provision"] if len([c for c in caps if c not in ("node_audit", "monitor_cluster")]) > 1 else [])
    base = policy.token_base
    toks = {k: (token_names or {}).get(k) or f"{base}-{'inv' if k == 'inventory' else 'prov'}" for k in kinds}
    # monitoring-only: the single token is the inventory token
    acl = [a for a in acl if a.tokens != prov or "provision" in toks]
    # de-duplicate
    seen, uniq = set(), []
    for a in acl:
        k = (a.path, a.cap)
        if k in seen:
            continue
        seen.add(k)
        uniq.append(a)
    return Design(f"{policy.service_user}@{policy.realm}", roles, toks, uniq, major, list(s.pools), frozenset(withheld))


def acl_entries(d: Design) -> list[tuple[str, str, str, int]]:
    """Flat (path, subject, role, propagate) entries: the user plus each token that carries the spec."""
    out = []
    for a in d.acl:
        role = d.roles[a.cap][0]
        out.append((a.path, d.userid, role, a.propagate))
        for k in a.tokens:
            if k in d.tokens:
                out.append((a.path, f"{d.userid}!{d.tokens[k]}", role, a.propagate))
    return out


def expected_permissions(d: Design, kind: str) -> dict[str, set[str]]:
    exp: dict[str, set[str]] = {}
    for a in d.acl:
        if kind in a.tokens:
            exp.setdefault(a.path, set()).update(d.roles[a.cap][1])
    return exp


# ---------------------------------------------------------------------------------------------------- facts
@dataclass
class Facts:
    version: str
    major: int
    nodes: dict[str, str] = field(default_factory=dict)
    storages: dict[str, dict] = field(default_factory=dict)
    pools: set[str] = field(default_factory=set)
    pool_comments: dict[str, str] = field(default_factory=dict)
    pool_members: dict[str, int] = field(default_factory=dict)      # only for pools carrying the Office Unbound marker (cleanup candidates)
    guests: dict[int, dict] = field(default_factory=dict)
    networks: dict[str, str] = field(default_factory=dict)         # bridge/vnet -> zone
    bridge_nodes: dict[str, set] = field(default_factory=dict)     # classic bridge -> nodes that have it
    users: dict[str, dict] = field(default_factory=dict)
    roles: dict[str, frozenset] = field(default_factory=dict)
    builtin_roles: set[str] = field(default_factory=set)
    acl: list[dict] = field(default_factory=list)
    acl_readable: bool = True
    notes: list[str] = field(default_factory=list)

    def summary(self) -> dict:
        return {"pve_version": self.version, "nodes": sorted(self.nodes), "storages": sorted(self.storages), "pools": sorted(self.pools),
                "networks": sorted(self.networks), "guests": len(self.guests), "users": len(self.users), "roles": len(self.roles),
                "acl_entries": len(self.acl), "acl_readable": self.acl_readable}


def major_of(version: str) -> int:
    m = re.match(r"(\d+)", version or "")
    if not m:
        raise ProxmoxError("could not determine the Proxmox VE version")
    return int(m.group(1))


def collect_facts(c) -> Facts:
    """Read-only discovery through any client with `.get(path)` (admin or token). Failures of optional parts become notes."""
    v = c.get("/version")
    f = Facts(version=str(v.get("version", "")), major=major_of(str(v.get("version", ""))))
    for n in c.get("/nodes"):
        f.nodes[n["node"]] = n.get("status", "unknown")
    for s in c.get("/storage"):
        f.storages[s["storage"]] = {"type": s.get("type"), "shared": bool(s.get("shared")), "content": s.get("content", ""),
                                    "nodes": [x for x in (s.get("nodes") or "").split(",") if x] or sorted(f.nodes),
                                    "node_restricted": bool(s.get("nodes"))}
    for p in _opt(c, "/pools", f, "pools") or []:
        f.pools.add(p["poolid"])
        f.pool_comments[p["poolid"]] = p.get("comment") or ""
    for r in _opt(c, "/cluster/resources?type=vm", f, "guests") or []:
        if "vmid" in r:
            f.guests[int(r["vmid"])] = {"node": r.get("node"), "name": r.get("name"), "pool": r.get("pool"), "template": bool(r.get("template")), "type": r.get("type"),
                                      "tags": r.get("tags") or "", "status": r.get("status")}
    for z in _opt(c, "/cluster/sdn/vnets", f, "SDN vnets") or []:
        f.networks[z["vnet"]] = z.get("zone", "localnetwork")
    for n, st in f.nodes.items():
        if st == "online":
            for i in _opt(c, f"/nodes/{n}/network", f, f"network of {n}") or []:
                if i.get("type") in ("bridge", "OVSBridge"):
                    f.networks.setdefault(i["iface"], "localnetwork")
                    f.bridge_nodes.setdefault(i["iface"], set()).add(n)
    for u in _opt(c, "/access/users?full=1", f, "users") or []:
        f.users[u["userid"]] = {"comment": u.get("comment", ""), "enable": u.get("enable", 1),
                                "tokens": {t["tokenid"]: t for t in u.get("tokens", []) or []}}
    for r in _opt(c, "/access/roles", f, "roles") or []:
        f.roles[r["roleid"]] = frozenset(x for x in re.split(r"[,\s]+", r.get("privs") or "") if x)
        if r.get("special"):
            f.builtin_roles.add(r["roleid"])
    acl = _opt(c, "/access/acl", f, "ACL")
    f.acl_readable = acl is not None
    f.acl = acl or []
    for pid, com in f.pool_comments.items():
        if MARK in com:      # leftover candidates only: count members (guests AND storages) so a non-empty pool is never offered for removal
            got = _opt(c, f"/pools/{pid}", f, f"members of pool {pid}")
            f.pool_members[pid] = len((got or {}).get("members") or []) if got is not None else -1
    return f


def _opt(c, path, f: Facts, what: str):
    try:
        return c.get(path)
    except ProxmoxError as e:
        f.notes.append(f"could not read {what}: {str(e)[:120]}")
        return None


# ---------------------------------------------------------------------------------------------------- plan
def enforcement_matrix(policy: Policy) -> list[EnforcementNote]:
    s = policy.scope
    E = EnforcementNote
    out = [
        E("Pool membership (which guests may be created/changed)", "proxmox", "ACL on /pool/<pool>; Proxmox refuses VM.* operations on guests outside the pools."),
        E("Storage allowlist", "proxmox", "Datastore.AllocateSpace only on /storage/<name> for the authorised storages; others are refused by Proxmox."),
        E("Bridge / SDN vnet allowlist", "proxmox", "SDN.Use only on /sdn/zones/<zone>/<vnet>; NICs on other bridges are refused by Proxmox."),
        E("Clone sources (templates by VMID)", "proxmox", "VM.Clone only on /vms/<template vmid> for the listed templates."),
        E("Privilege separation of the API tokens", "proxmox", "privsep=1: effective rights are the intersection of the token's and the service user's ACLs."),
        E("No ACL/user/realm administration", "proxmox", "Permissions.Modify, User.Modify, Realm.*, Group.Allocate, Sys.Modify are never granted (checked after every apply)."),
        E("Ownership tags and pool membership of mutated guests", "ics", "Every mutation re-checks the ou-managed / ou-deployment-<id> tags and the pool allowlist (ProxmoxMutations)."),
        E("Protected guests (incl. the ICS's own VM)", "ics", "Proxmox ACLs cannot deny: a protected guest inside an authorised pool is still permitted by Proxmox; the ICS refuses it."),
        E("Node allowlist" + (f" ({', '.join(s.nodes)})" if s.nodes else ""), "ics",
          "APPLICATION-enforced. Proxmox pool ACLs do NOT restrict which node a pooled guest is created, cloned or migrated to; Proxmox only scopes node "
          "VISIBILITY (Sys.Audit on /nodes/<n>), and a clone to another node is stopped only incidentally when the storage does not exist there. "
          "The policy `scope.nodes` is persisted and checked by provisioning/enforce.py; the broker enforces it too (EndpointScope.nodes, deny-by-default) and the credential trust binding covers it."),
        E("VMID ranges", "not_enforced" if s.vmid_ranges else "ics", "Proxmox ACLs cannot express VMID ranges. Policy guard implemented (provisioning/enforce.py); broker wiring pending."),
        E("Guest types (qemu/lxc)", "ics", "Not expressible in Proxmox ACLs. Policy guard implemented; broker wiring pending."),
        E("CPU / RAM / disk caps", "ics", "Proxmox has no per-user resource quota in ACLs. Policy guard implemented; broker wiring pending."),
    ]
    if s.managed_vmids:
        out += [
            E(f"Existing guests operated by Office Unbound ({len(s.managed_vmids)})", "proxmox",
              "ACL on /vms/<vmid> for exactly the selected guests (propagate=0): Proxmox refuses every other guest. Power control only "
              "(VM.Audit + VM.PowerMgmt); no configuration, disk or deletion rights. Proxmox removes a guest's ACL entries when the guest is destroyed."),
            E("Selecting a node does not select its guests", "proxmox",
              "Node ACLs carry Sys.Audit only; no VM.* privilege is ever granted on /nodes, /vms or / for operated guests."),
            E("Operated guests follow their VMID", "ics",
              "A selected guest may be migrated inside the cluster and stays authorized (Proxmox ACLs follow the VMID). Inventory sync flags a VMID whose "
              "name or type changed so a reused VMID never silently inherits access."),
        ]
    for x in s.import_storages:
        out.append(E(f"Image import storage {x}", "proxmox",
                     f"Datastore.AllocateTemplate + Datastore.Audit on /storage/{x} for the write token only (upload of signed golden images, content type "
                     f"`import`). The permission covers {x} on every node: Office Unbound can upload import files there on any node; it cannot place VM disks "
                     f"there (Datastore.AllocateSpace is not granted)."))
    return out + scope_enforcement(policy)


def scope_enforcement(policy: Policy) -> list[EnforcementNote]:
    """What the chosen scope mode is held by, control by control. 'proxmox' = Proxmox refuses it itself (ACLs/privileges); 'ics' = only the
    Office Unbound broker stops it; 'both' = Proxmox stops it incidentally and the broker stops it deliberately."""
    s, E = policy.scope, EnforcementNote
    mode = policy.mode()
    if mode == "single_node":
        nodes = ", ".join(s.nodes)
        return [
            E(f"Node visibility: only {nodes}", "proxmox", "Sys.Audit is granted on /nodes/<node> for the selected node(s) only. Never on /nodes and never on /; Proxmox shows nothing else."),
            E("Disk placement: node-local storage only", "proxmox",
              "Datastore.AllocateSpace only on storages that exist on the selected node(s) and are not shared (checked when the plan is built). Proxmox refuses a disk anywhere else, "
              "so a VM cannot be given storage on another node."),
            E("No moving guests between nodes (VM.Migrate)", "proxmox", "VM.Migrate is not in any role (unless the explicit high-risk 'migrate' override was approved)."),
            E("Which node a new guest is created on", "both",
              "Proxmox pools are cluster-wide: a pool ACL cannot say 'only on node X'. Placement on another node is blocked incidentally by Proxmox (the node-local storage does not exist there) "
              "and deliberately by the Office Unbound broker (EndpointScope.nodes, deny by default). It relies on the broker alone if a shared-storage override was approved."),
            E("Pool and network names are cluster-wide", "ics",
              "Pool ACLs (/pool/<pool>) and the classic-bridge SDN zone (/sdn/zones/localnetwork/<bridge>) apply to the whole cluster by name. Guests of the pool on other nodes would be "
              "permitted by Proxmox; Office Unbound refuses them through the node allowlist."),
            E("Nothing at the cluster root or on other nodes", "proxmox", "Checked after every apply and by drift checks: any effective grant on /, /nodes, another node or an unlisted storage is reported."),
        ]
    if mode == "whole_cluster":
        return [
            E("Node visibility: every node", "proxmox", "Sys.Audit is granted on /nodes with propagation, so it also covers nodes that join later."),
            E("Which nodes Office Unbound may change", "ics",
              "The broker's node allowlist is the set of nodes found when the scope was chosen (" + (", ".join(s.nodes) or "all nodes at plan time") + "). A node added to the cluster later is NOT used until the scope is updated."),
            E("Shared storage and moving guests", "proxmox", "Shared storage can be selected; VM.Migrate is only available when the migrate option is on."),
        ]
    return []


def _path_reach(path: str, nodes: set[str]) -> str | None:
    """Why an ACL path would let the integration act outside the selected nodes (None = it does not). Used for custom grants and permission checks."""
    p = path.rstrip("/") or "/"
    if p == "/":
        return "the cluster root: every node, storage and guest"
    if p in ("/nodes", "/vms", "/storage", "/pool", "/sdn", "/sdn/zones", "/access", "/access/groups", "/access/realm"):
        return f"every {p.strip('/').split('/')[0].rstrip('s')} in the cluster"
    m = re.match(r"/nodes/([^/]+)", p)
    if m and m.group(1) not in nodes:
        return f"node {m.group(1)}"
    return None


def scope_reach(actual: dict[str, set[str]], policy: Policy, storages_allowed: set[str]) -> list[dict]:
    """Effective permissions (from /access/permissions) that reach beyond a single_node scope. Every finding is a Proxmox-level grant, so the
    label is 'proxmox' (the fix has to happen in Proxmox, not in the ICS)."""
    if policy.mode() != "single_node":
        return []
    nodes = set(policy.scope.nodes)
    out = []
    for path, privs in sorted(actual.items()):
        if not privs:
            continue
        why = _path_reach(path, nodes)
        if why is None and path.startswith("/storage/") and path.split("/")[2] not in storages_allowed:
            why = f"storage {path.split('/')[2]}, which is not part of the approved scope"
        if why:
            out.append({"path": path, "privileges": sorted(privs), "reaches": why, "enforced_by": "proxmox"})
    return out


def _content_list(v) -> list[str]:
    return [c.strip() for c in str(v or "").split(",") if c.strip()]


def _single_node_checks(plan: ProvisioningPlan, policy: Policy, facts: Facts) -> set[str]:
    """Extra validation for scope_mode=single_node against the discovered cluster. Returns ACL paths whose grant is a high-risk override."""
    s = policy.scope
    sel = set(s.nodes)
    ov = set(policy.scope_risk_overrides)
    risky: set[str] = set()
    for x in sorted(scope_storages(policy)):
        st = facts.storages.get(x)
        if st is None:
            continue
        content = set((st.get("content") or "").split(","))
        if not content & _DISK_CONTENT:
            continue      # backup-only / ISO storage cannot hold VM disks, so it cannot place a guest on another node
        if (not st["shared"]) and set(st["nodes"]) <= sel:
            continue
        where = "shared between nodes" if st["shared"] else "also available on " + ", ".join(sorted(set(st["nodes"]) - sel))
        if f"shared_storage:{x}" in ov:
            risky.add(f"/storage/{x}")
            plan.warnings.append(f"HIGH RISK OVERRIDE: storage {x} is {where}. Disks can be created on it for guests on nodes outside the selection; only the ICS node allowlist keeps guests on the selected node(s).")
            plan.consequences.append(f"Storage {x} is {where}: Proxmox will let this integration allocate disks there. The node limit then rests on Office Unbound alone.")
        else:
            plan.blocked.append(f"storage {x} is {where}, so a VM disk could be placed outside the selected node(s). Choose a storage local to {', '.join(sorted(sel))}, "
                                f"or approve the explicit override 'shared_storage:{x}' (high risk)")
    for t in s.template_vmids:
        g = facts.guests.get(t)
        if g is not None and g.get("node") not in sel:
            plan.blocked.append(f"template {t} lives on node {g.get('node')}, outside the selected node(s); clones would have to read it across nodes")
    for pname in s.pools:
        elsewhere = sorted(v for v, g in facts.guests.items() if g.get("pool") == pname and g.get("node") not in sel)
        if elsewhere:
            plan.warnings.append(f"pool {pname} already holds guest(s) {', '.join(map(str, elsewhere[:8]))} on other node(s). Proxmox pools are cluster-wide, so the integration would be permitted to act on them; "
                                 "the Office Unbound node allowlist refuses it.")
            plan.facts.setdefault("pool_guests_elsewhere", {})[pname] = elsewhere
    for n in s.networks:
        have = facts.bridge_nodes.get(n)
        if have is not None and not sel <= have:
            plan.warnings.append(f"bridge {n} was not found on node(s) {', '.join(sorted(sel - have))}: a VM there could not attach to it")
        if facts.networks.get(n, "localnetwork") == "localnetwork":
            plan.warnings.append(f"bridge {n}: the permission /sdn/zones/localnetwork/{n} is cluster-wide by name (it covers the bridge of that name on every node). Proxmox cannot limit it per node.")
    for g in policy.custom_grants:
        why = _path_reach(g.path, sel)
        if why:
            plan.blocked.append(f"custom grant on {g.path} would reach {why}: not allowed in single_node scope")
    for n in sorted(sel):
        if facts.nodes.get(n) not in (None, "online"):
            plan.warnings.append(f"node {n} is {facts.nodes.get(n)}")
    return risky


# ---------------------------------------------------------------------------------------------------- ownership (conflict choices, leftovers)
CHOICE_ACTIONS = ("use_existing", "overwrite", "recreate", "create_new")


class _Own:
    """Who an existing Proxmox object belongs to. `owned` = what EVERY connected (not removed) Office Unbound integration in the ICS database
    holds (users, tokens, roles, pools); `managed` = this integration's own objects. Ownership is 'known' only when both the connected
    integrations and the cluster's ACL list could be read; otherwise nothing is ever offered for removal or overwrite."""

    def __init__(self, facts: Facts | None, owned: dict | None, managed: dict):
        self.known = owned is not None and facts is not None and facts.acl_readable
        o = owned or {}
        self.users, self.tokens = set(o.get("users") or []), set(o.get("tokens") or [])
        self.roles, self.pools = set(o.get("roles") or []), set(o.get("pools") or [])
        self.m_user, self.m_tokens = managed.get("user"), set(managed.get("tokens") or [])
        users = facts.users if facts else {}
        self.marked_users = {u for u, x in users.items() if MARK in (x.get("comment") or "") and u.endswith("@pve")}
        self.marked_tokens = {f"{u}!{t}" for u in self.marked_users for t, td in (users[u].get("tokens") or {}).items()
                              if str(td.get("comment") or "").startswith(MARK)}

    def other_integration(self, ugid: str) -> bool:
        if "!" in ugid:
            return ugid in self.tokens and ugid not in self.m_tokens
        return ugid in self.users and ugid != self.m_user

    def leftover(self, ugid: str) -> bool:
        """Provably Office Unbound's (marker comment) and owned by no connected integration."""
        if not self.known or self.other_integration(ugid) or ugid == self.m_user or ugid in self.m_tokens:
            return False
        if "!" in ugid:
            return ugid in self.marked_tokens
        return ugid in self.marked_users and not any(t.startswith(ugid + "!") for t in self.tokens)

    def classify(self, ugid: str, typ: str | None) -> str:
        if typ == "group":
            return "foreign"
        if self.other_integration(ugid):
            return "other_integration"
        if ugid == self.m_user or ugid in self.m_tokens:
            return "this_integration"
        return "ou_leftover" if self.leftover(ugid) else "foreign"


def _ou_role_re(policy: Policy) -> re.Pattern:
    sfx = "|".join(sorted(map(re.escape, CAP_ROLE_SUFFIX.values())))
    pre = "|".join(sorted({re.escape(policy.role_prefix), "OfficeUnbound"}))
    return re.compile(rf"^(?:{pre})(?:{sfx})(?:-\d+)?$")


def _acl_id(a: dict) -> str:
    return f"{a['path']}|{a['ugid']}|{a['roleid']}"


def _acl_rm(a: dict, why: str) -> Step:
    return Step("acl", "remove", _acl_id(a), {"path": a["path"], "subject": a["ugid"], "role": a["roleid"], "phase": "before"}, why)


def plan_for(policy: Policy, facts: Facts | None, *, pve_major: int | None = None, managed: dict | None = None, prune: bool = False,
             mode: str = "A", choices: ConflictChoices | None = None, owned: dict | None = None) -> ProvisioningPlan:
    """Compute the plan. `facts=None` => offline plan (Mode B without connectivity): every object is a `create`, the script re-checks at run time.

    `choices`: the approver's decision per conflicting pre-existing object (use as is / overwrite / remove and recreate / create a new one
    alongside) and the leftovers of failed earlier attempts to remove. Every option is listed in `facts.conflict_options` with the reason an
    option is not available; a chosen action that is not available blocks the plan. `owned`: users/tokens/roles/pools held by every connected
    integration (from the ICS database); without it nothing is offered for removal or overwrite."""
    major = facts.major if facts else pve_major
    if not major:
        raise PlanBuildError("the Proxmox VE major version (8 or 9) is required when no cluster is reachable")
    if policy.realm != "pve":
        raise PlanBuildError("the service account must live in the @pve realm")
    managed = managed or {}
    elevated = check_privileges(policy, major)
    for e in elevated:
        e["approved"] = e["privilege"] in policy.approve_elevated
    if policy.mode() == "whole_cluster" and facts and not policy.scope.nodes:
        # the broker allowlist of a whole-cluster scope is the explicit list of nodes found now (deny by default for nodes that join later)
        policy = policy.model_copy(update={"scope": policy.scope.model_copy(update={"nodes": sorted(facts.nodes)})})
    plan = ProvisioningPlan("proxmox", policy.model_dump(mode="json"))
    plan.enforcement = enforcement_matrix(policy)
    plan.elevated = elevated
    if any(not e["approved"] for e in elevated):
        plan.blocked.append("elevated privileges need explicit approval: " + ", ".join(e["privilege"] for e in elevated if not e["approved"])
                            + " (set approve_elevated)")
    if policy.preset == "full_admin":
        plan.consequences = [
            "The integration may create, change and destroy ANY guest, storage allocation, pool and network attachment in the whole cluster.",
            "Proxmox no longer limits it to the chosen pools/storages/bridges; only the ICS broker's own checks remain.",
            "Sys.Modify, Permissions.Modify, User.Modify and Realm.* are still withheld (an ICS compromise cannot grant itself more or add users).",
        ]
        plan.warnings.append("Full cluster administration selected: this is never a default and must be a conscious customer decision.")
    plan.facts = facts.summary() if facts else {"offline": True, "pve_major": major}
    zones = facts.networks if facts else {}
    own = _Own(facts, owned, managed)
    ch = choices or ConflictChoices()
    used: set[tuple[str, str]] = set()
    options: list[dict] = []
    unknown = "ownership could not be checked (the connected integrations or the cluster's ACL list are unknown)"

    def pick(kind: str, target: str, avail: dict[str, str | None], default: str | None, existing: dict):
        c = ch.get(kind, target)
        if c is not None:
            used.add((kind, target))
        act = c.action if c else default
        options.append({"kind": kind, "target": target, "default": default, "chosen": act, "existing": existing,
                        "options": [{"action": a, "available": avail.get(a) is None, "why_not": avail.get(a)} for a in CHOICE_ACTIONS]})
        if act is not None and avail.get(act) is not None:
            plan.blocked.append(f"{kind} {target}: '{act}' is not possible: {avail[act]}")
            return None, c
        return act, c

    # --- service user (decided first: 'create a new one alongside' changes the service account name)
    userid = f"{policy.service_user}@{policy.realm}"
    ex_u = facts.users.get(userid) if facts else None
    user_recreate: dict | None = None
    if ex_u is not None and managed.get("user") != userid:
        marked = MARK in (ex_u.get("comment") or "")
        utoks = {f"{userid}!{t}": td for t, td in (ex_u.get("tokens") or {}).items()}
        why_rc = ("this user was not created by Office Unbound" if not marked else unknown if not own.known
                  else "it is used by a connected Office Unbound integration" if (userid in own.users or set(utoks) & own.tokens)
                  else "it carries API tokens Office Unbound did not create" if set(utoks) - own.marked_tokens else None)
        avail = {"use_existing": None if marked else "this user was not created by Office Unbound and is never reused",
                 "overwrite": "a user carries no privileges of its own; choose 'remove and recreate' instead",
                 "recreate": why_rc, "create_new": None}
        act, _ = pick("user", userid, avail, "use_existing" if marked else None,
                      {"created_by_office_unbound": marked, "tokens": sorted(utoks)})
        if act == "create_new":
            base = policy.service_user[:28]
            n = 2
            while f"{base}-{n}@{policy.realm}" in facts.users:
                n += 1
            policy = policy.model_copy(update={"service_user": f"{base}-{n}"})
            plan.policy = policy.model_dump(mode="json")
            plan.conflicts.append(f"user {userid} already exists; it will NOT be touched, a new service account {base}-{n}@{policy.realm} is created instead")
            userid = f"{base}-{n}@{policy.realm}"
            ex_u = None
        elif act == "recreate":
            user_recreate = {"id": userid, "tokens": sorted(utoks)}
    d0 = design(policy, major, vnet_zones=zones)
    userid = d0.userid

    # --- validation against discovered facts
    if facts:
        s = policy.scope
        for n in s.nodes:
            if n not in facts.nodes:
                plan.blocked.append(f"node {n} does not exist in the cluster")
        for x in s.storages + s.backup_storages:
            if x not in facts.storages:
                plan.blocked.append(f"storage {x} does not exist")
            else:
                st = facts.storages[x]
                if s.nodes and not set(st["nodes"]) & set(s.nodes):
                    plan.warnings.append(f"storage {x} is not available on any authorised node")
                if st["shared"]:
                    plan.warnings.append(f"storage {x} is shared: it is reachable from nodes outside the node allowlist")
        for x in s.import_storages:
            st = facts.storages.get(x)
            if st is None:
                if x not in s.storages + s.backup_storages:
                    plan.blocked.append(f"storage {x} does not exist")
                continue
            content = _content_list(st.get("content"))
            if "import" not in content:
                if st.get("type") not in IMPORT_CONTENT_TYPES:
                    plan.blocked.append(f"storage {x} is of type {st.get('type')}, which cannot hold the `import` content type (Proxmox supports it on "
                                        f"{', '.join(IMPORT_CONTENT_TYPES)} storage only). Choose a directory-based storage as the image import storage")
                else:
                    after = [c for c in content if c != "none"] + ["import"]
                    plan.steps.append(Step("storage", "modify", x, {"change": "content_add", "add": "import", "before": content, "after": after,
                                                                    "storage_type": st.get("type")},
                                           "the image import storage needs the `import` content type; the existing content types are kept exactly"))
                    plan.consequences.append(f"Adds the 'import' content type to storage {x} on every node where it is defined; existing content is "
                                             f"unchanged ({','.join(content) or 'none'} -> {','.join(after)}). This changes the cluster-wide storage "
                                             f"definition with your sign-in; it is put back to the previous list if a later step fails.")
            if s.nodes and not set(st["nodes"]) & set(s.nodes):
                plan.blocked.append(f"image import storage {x} is not available on any authorised node ({', '.join(s.nodes)})")
        for n in s.networks:
            if n not in facts.networks:
                plan.blocked.append(f"network {n} was not found as a bridge or SDN vnet")
        for t in s.template_vmids:
            g = facts.guests.get(t)
            if g is None:
                plan.blocked.append(f"template vmid {t} does not exist")
            elif not g["template"]:
                plan.blocked.append(f"vmid {t} is not a template")
        for pname in s.pools:
            if pname in facts.pools:
                for vmid, g in facts.guests.items():
                    if g.get("pool") == pname and vmid in s.protected_vmids:
                        plan.warnings.append(f"pool {pname} contains protected guest {vmid}: Proxmox would allow changes to it; the ICS refuses them")
            else:
                plan.steps.append(Step("pool", "create", pname, {}, "authorised pool does not exist yet (needs Pool.Allocate from the provisioning identity)"))
        risky_paths = _single_node_checks(plan, policy, facts) if policy.mode() == "single_node" else set()
        unauthorised = sorted(set(facts.nodes) - set(s.nodes)) if s.nodes else []
        if unauthorised:
            plan.facts["unauthorized_nodes"] = unauthorised
        unauth_st = sorted(set(facts.storages) - scope_storages(policy))
        if unauth_st:
            plan.facts["unauthorized_storages"] = unauth_st
        if not facts.acl_readable:
            plan.warnings.append("the provisioning identity cannot read /access/acl: ACL conflicts cannot be fully checked")
        plan.warnings += facts.notes
    else:
        risky_paths = set()
        if policy.mode() == "single_node":
            for g in policy.custom_grants:
                if _path_reach(g.path, set(policy.scope.nodes)):
                    plan.blocked.append(f"custom grant on {g.path} would reach beyond the selected node(s): not allowed in single_node scope")
            plan.warnings.append("offline plan: node-local storage could not be verified; preview the plan against the cluster before applying it")
        if policy.scope.import_storages:
            plan.warnings.append("offline plan: the `import` content type of the image import storage could not be checked; the script adds it if missing")
        plan.warnings.append("offline plan: nothing was discovered; the script checks conflicts on the node at run time")
        for pname in policy.scope.pools:
            plan.steps.append(Step("pool", "create", pname, {}, "created only if it does not exist"))

    # --- roles (collision-safe; the approver may choose another option per conflicting role)
    final: dict[str, str] = {}
    existing_roles = facts.roles if facts else {}
    taken = set(existing_roles)
    mroles = set(managed.get("roles", []))
    role_choice: dict[str, tuple[str, frozenset, list, list]] = {}
    role_privs: dict[str, list[str]] = {}
    for cap, (name, privs) in d0.roles.items():
        if name in FORBIDDEN_ROLES:
            plan.blocked.append(f"role name {name} is reserved: Administrator/PVEAdmin are never used or generated")
        chosen = name
        ex = existing_roles.get(name)
        builtin = bool(facts) and name in facts.builtin_roles
        if ex is not None and (builtin or (ex != privs and name not in mroles)):
            refs = [a for a in facts.acl if a.get("roleid") == name]
            by: dict[str, list[str]] = {}
            for a in refs:
                by.setdefault(own.classify(a["ugid"], a.get("type")), []).append(f"{a['ugid']} on {a['path']}")
            foreign, other = by.get("foreign", []), by.get("other_integration", [])
            fixed = ("a built-in Proxmox role is never modified or removed" if builtin
                     else "Administrator/PVEAdmin are never used or changed" if name in FORBIDDEN_ROLES else None)
            in_use = (f"it is used by a connected Office Unbound integration ({'; '.join(other[:5]) or name})"
                      if (other or (name in own.roles and name not in mroles)) else None)
            avail = {
                "use_existing": (None if (ex and ex <= privs and name not in FORBIDDEN_ROLES)
                                 else "it has no privileges" if not ex
                                 else f"it grants more than Office Unbound needs ({', '.join(sorted(ex - privs)[:12])})"),
                "overwrite": fixed or (unknown if not own.known else in_use),
                "recreate": fixed or (unknown if not own.known else in_use) or (
                    f"ACL entries Office Unbound did not create use it ({'; '.join(foreign[:5])}); removing it would take their rights away" if foreign else None),
                "create_new": None,
            }
            act, c = pick("role", name, avail, "create_new",
                          {"privileges": sorted(ex), "builtin": builtin, "needed": sorted(privs), "would_add": sorted(privs - ex),
                           "would_remove": sorted(ex - privs), "used_by_others": foreign, "used_by_integrations": other})
            if act == "overwrite" and foreign and not (c and c.acknowledge_shared):
                plan.blocked.append(f"role {name} is also used by ACL entries Office Unbound did not create ({'; '.join(foreign[:5])}): overwriting it "
                                    "changes their rights too. Confirm this explicitly (acknowledge_shared) or choose another option")
            if act in ("use_existing", "overwrite", "recreate"):
                role_choice[cap] = (act, ex, refs, foreign)
                if act == "use_existing":
                    role_privs[cap] = sorted(ex)
            else:
                n = 2
                while f"{name}-{n}" in taken:
                    n += 1
                chosen = f"{name}-{n}"
                plan.conflicts.append(f"role {name} already exists with {'a built-in definition' if builtin else 'different privileges'}"
                                      f" ({', '.join(sorted(ex))}); it will NOT be touched, a new role {chosen} is created instead")
        taken.add(chosen)
        final[cap] = chosen

    # --- token names (a conflicting token can be replaced, or a new one created alongside)
    tnames: dict[str, str] = {}
    token_recreate: set[str] = set()
    if ex_u is not None and user_recreate is None:
        u_marked = MARK in (ex_u.get("comment") or "")
        for kind, tname in d0.tokens.items():
            full = f"{userid}!{tname}"
            if tname not in (ex_u.get("tokens") or {}) or full in managed.get("tokens", []):
                continue
            t_marked = str(ex_u["tokens"][tname].get("comment") or "").startswith(MARK)
            why_rc = ("this token was not created by Office Unbound" if not t_marked else "its user was not created by Office Unbound" if not u_marked
                      else unknown if not own.known else "it is used by a connected Office Unbound integration" if full in own.tokens else None)
            avail = {"use_existing": "a token secret is shown only once, when the token is created; Office Unbound cannot use a token it did not capture",
                     "overwrite": "Proxmox cannot issue a new secret for an existing token; choose 'remove and recreate' instead",
                     "recreate": why_rc, "create_new": None}
            act, _ = pick("token", full, avail, None, {"created_by_office_unbound": t_marked})
            if act == "create_new":
                n = 2
                while f"{tname}-{n}" in ex_u["tokens"]:
                    n += 1
                tnames[kind] = f"{tname}-{n}"
                plan.conflicts.append(f"token {full} already exists; it will NOT be touched, a new token {userid}!{tname}-{n} is created instead")
            elif act == "recreate":
                token_recreate.add(full)
    d = design(policy, major, final, token_names=tnames or None, vnet_zones=zones, role_privs=role_privs or None)
    gone_subjects: set[str] = set()
    gone_roles: set[str] = set()
    for cap, (name, privs) in d.roles.items():
        ex = existing_roles.get(name)
        det = {"privileges": sorted(privs), "capability": cap}
        rc = role_choice.get(cap)
        if rc and rc[0] == "use_existing":
            lack = sorted(role_privileges(cap, policy, major) - privs)
            plan.steps.append(Step("role", "noop", name, {**det, "choice": "use_existing", "withheld": lack}, "existing role used as is (your choice)"))
            if lack:
                plan.warnings.append(f"role {name} is used as is: Office Unbound will NOT have {', '.join(lack)} for '{cap}'; actions that need them will fail")
        elif rc and rc[0] == "overwrite":
            nf = len(rc[3])
            plan.steps.append(Step("role", "modify", name, {**det, "was": sorted(ex), "added": sorted(privs - ex), "removed": sorted(ex - privs),
                                                            "choice": "overwrite", "affects": rc[3]},
                                   "overwrite the pre-existing role (your choice)"
                                   + (f"; this also changes the rights of {nf} ACL entr{'y' if nf == 1 else 'ies'} Office Unbound did not create" if nf else ""),
                                   "high" if nf else "normal"))
        elif rc and rc[0] == "recreate":
            for a in rc[2]:
                plan.steps.append(_acl_rm(a, f"uses role {name}, which is removed and recreated"))
            plan.steps.append(Step("role", "remove", name, {"privileges": sorted(ex), "phase": "before", "choice": "recreate"},
                                   "remove the pre-existing role (your choice: remove and recreate)"))
            plan.steps.append(Step("role", "create", name, det, f"capability '{cap}' (recreated)"))
            gone_roles.add(name)
        elif ex is None:
            plan.steps.append(Step("role", "create", name, det, f"capability '{cap}'"))
        elif ex == privs:
            plan.steps.append(Step("role", "noop", name, det, "already exists with exactly these privileges"))
        else:  # only reachable for a role this ICS manages (reconcile)
            plan.steps.append(Step("role", "modify", name, {**det, "was": sorted(ex)}, "restore the approved privilege set"))

    # --- user
    if user_recreate is not None:
        subj = {userid} | set(user_recreate["tokens"])
        for a in facts.acl:
            if a["ugid"] in subj:
                plan.steps.append(_acl_rm(a, f"belongs to {a['ugid']}, which is removed and recreated"))
        for t in user_recreate["tokens"]:
            plan.steps.append(Step("token", "remove", t, {"phase": "before"}, "token of the service account that is removed and recreated"))
        plan.steps.append(Step("user", "remove", userid, {"phase": "before", "choice": "recreate", "tokens": user_recreate["tokens"]},
                               "remove the pre-existing Office Unbound service account (your choice: remove and recreate)"))
        gone_subjects |= subj
        ex_u = None
    if facts:
        for other in facts.users:
            if other.split("@")[0] == policy.service_user and other != userid:
                plan.warnings.append(f"a user named {other} exists in another realm; it is unrelated and will not be touched")
    if ex_u is None:
        plan.steps.append(Step("user", "create", userid, {"realm": policy.realm, "password": None, "comment": f"{MARK} Office Unbound service account"},
                               "dedicated service account in the Proxmox VE realm (no password, no shell, no OS account)"))
    elif MARK in (ex_u.get("comment") or "") or managed.get("user") == userid:
        plan.steps.append(Step("user", "noop", userid, {}, "existing ICS-managed service account"))
    else:
        plan.steps.append(Step("user", "conflict", userid, {}, "a user with this id exists and was not created by the ICS"))
        plan.blocked.append(f"user {userid} already exists and is not ICS-managed; choose a different service_user")
    # --- tokens
    for kind, tname in d.tokens.items():
        full = f"{userid}!{tname}"
        if full in token_recreate:
            for a in facts.acl:
                if a["ugid"] == full:
                    plan.steps.append(_acl_rm(a, f"belongs to {full}, which is removed and recreated"))
            plan.steps.append(Step("token", "remove", full, {"phase": "before", "choice": "recreate"},
                                   "remove the pre-existing Office Unbound token (your choice: remove and recreate)"))
            gone_subjects.add(full)
            plan.steps.append(Step("token", "create", full, {"kind": kind, "privsep": 1},
                                   "privilege-separated token; the secret is shown once and captured straight into the vault"))
        elif ex_u is not None and tname in ex_u.get("tokens", {}):
            if full in managed.get("tokens", []):
                plan.steps.append(Step("token", "noop", full, {"kind": kind, "privsep": 1}, "existing ICS-managed token"))
            else:
                plan.steps.append(Step("token", "conflict", full, {"kind": kind}, "a token with this name exists and was not created by the ICS"))
                plan.blocked.append(f"token {full} already exists; choose a different token_base")
        else:
            plan.steps.append(Step("token", "create", full, {"kind": kind, "privsep": 1},
                                   "privilege-separated token; the secret is shown once and captured straight into the vault" if mode == "A"
                                   else "privilege-separated token; the secret is printed once on the customer's terminal"))
    if "provision" in d.tokens and not (policy.scope.pools or policy.scope.managed_vmids):
        plan.blocked.append("a provisioning (write) credential needs at least one authorised pool or selected existing guest")
    # --- ACL entries
    have = {(a["path"], a["ugid"], a["roleid"]) for a in (facts.acl if facts else []) if a["ugid"] not in gone_subjects and a["roleid"] not in gone_roles}
    want = acl_entries(d)
    for path, subj, role, prop in want:
        key = f"{path}|{subj}|{role}"
        step_risk = "high" if path in risky_paths else "normal"
        if path == "/" and policy.preset != "full_admin" and role not in (d.roles.get("monitor", ("",))[0], d.roles.get("monitor_cluster", ("",))[0]):
            step_risk = "high"
        if (path, subj, role) in have:
            plan.steps.append(Step("acl", "noop", key, {"path": path, "subject": subj, "role": role, "propagate": prop}, "already present"))
        else:
            plan.steps.append(Step("acl", "create", key, {"path": path, "subject": subj, "role": role, "propagate": prop},
                                   f"grants {role} at {path}" + (" (propagates)" if prop else " (this path only)"), step_risk))
    if prune and facts:
        mine = {userid} | {f"{userid}!{t}" for t in d.tokens.values()} | set(managed.get("tokens", []))
        wantk = {(p, s, r) for p, s, r, _ in want}
        for a in facts.acl:
            if a["ugid"] in mine and (a["path"], a["ugid"], a["roleid"]) not in wantk:
                plan.steps.append(Step("acl", "remove", f"{a['path']}|{a['ugid']}|{a['roleid']}",
                                       {"path": a["path"], "subject": a["ugid"], "role": a["roleid"]}, "not part of the approved policy"))
    # --- leftovers of failed earlier attempts (offered for removal; removed only when chosen)
    if facts is not None:
        los = _leftovers(policy, facts, own, d, want, gone_subjects, gone_roles) if own.known else []
        plan.facts["leftovers"] = [{k: v for k, v in x.items() if k != "steps"} for x in los]
        by_id = {x["id"]: x for x in los}
        have_steps = {(s.kind, s.op, s.target) for s in plan.steps}
        for lid in ch.cleanup:
            lo = by_id.get(lid)
            if lo is None or not lo["removable"]:
                plan.blocked.append(f"cleanup {lid}: " + (lo["kept_because"] if lo else "not a removable Office Unbound leftover in this cluster"))
                continue
            for st in lo["steps"]:
                if (st.kind, st.op, st.target) not in have_steps:
                    have_steps.add((st.kind, st.op, st.target))
                    plan.steps.append(st)
    elif not ch.empty():
        plan.blocked.append("conflict choices and cleanup need a preview against the cluster")
    for c in ch.items:
        if (c.kind, c.target) not in used:
            plan.warnings.append(f"the choice for {c.kind} {c.target} was not needed: it does not conflict with this plan")
    removals = [s for s in plan.steps if s.op == "remove" and s.detail.get("phase") == "before"]
    if removals:
        plan.consequences.append(f"{len(removals)} pre-existing Office Unbound object(s) or permission(s) are removed BEFORE anything is created. "
                                 "A removal is not undone if a later step fails; what this run created is still rolled back.")
    plan.choices = {} if ch.empty() else ch.model_dump(mode="json")
    plan.facts["conflict_options"] = options
    plan.facts["pve_major"] = major
    plan.facts["scope_mode"] = policy.mode()
    plan.facts["service_user"] = userid
    plan.facts["roles"] = {cap: n for cap, (n, _) in d.roles.items()}
    plan.facts["tokens"] = dict(d.tokens)
    if role_privs:
        plan.facts["role_privileges"] = role_privs
    return plan


def _leftovers(policy: Policy, facts: Facts, own: _Own, d: Design, want, gone_subjects: set[str], gone_roles: set[str]) -> list[dict]:
    """Office Unbound objects (marker comment on users/tokens/pools, Office Unbound role names) that NO connected integration owns.
    Each entry says whether it may be removed and, if not, why. Never offered: built-in roles, objects without the marker, a role that ACL
    entries of anyone else use, a user with tokens that are not Office Unbound's, a pool that is not empty."""
    out: list[dict] = []
    planned_tokens = {f"{d.userid}!{t}" for t in d.tokens.values()}
    planned_roles = {n for n, _ in d.roles.values()}
    wantk = {(p, s, r) for p, s, r, _ in want}

    def acl_of(subjects: set[str]) -> list[dict]:
        return [a for a in facts.acl if a["ugid"] in subjects]

    def entry(kind, target, why, steps, kept=None, **extra):
        return {"id": f"{kind}:{target}", "kind": kind, "target": target, "why": why, "removable": kept is None, "kept_because": kept,
                "removes": [f"{s.kind} {s.target}" for s in steps], "steps": steps, **extra}

    # users (with their tokens and ACL entries)
    for u in sorted(own.marked_users - {d.userid} - gone_subjects):
        if not own.leftover(u):
            continue
        toks = sorted(f"{u}!{t}" for t in (facts.users[u].get("tokens") or {}))
        bad = [t for t in toks if not own.leftover(t)]
        steps = [_acl_rm(a, f"permission of leftover {a['ugid']}") for a in acl_of({u, *toks})]
        steps += [Step("token", "remove", t, {"phase": "before", "cleanup": True}, "leftover Office Unbound token") for t in toks]
        steps.append(Step("user", "remove", u, {"phase": "before", "cleanup": True, "tokens": toks}, "leftover Office Unbound service account"))
        out.append(entry("user", u, "service account with the Office Unbound marker that no connected integration uses", steps,
                         f"it carries tokens that are not removable Office Unbound leftovers ({', '.join(bad)})" if bad else None))
    listed_users = {x["target"] for x in out}
    # tokens of accounts that stay (the planned one, or one a connected integration uses)
    for t in sorted(own.marked_tokens - planned_tokens - gone_subjects):
        if t.split("!")[0] in listed_users or not own.leftover(t):
            continue
        steps = [_acl_rm(a, f"permission of leftover {t}") for a in acl_of({t})]
        steps.append(Step("token", "remove", t, {"phase": "before", "cleanup": True}, "leftover Office Unbound token"))
        out.append(entry("token", t, "API token with the Office Unbound marker that no connected integration uses", steps))
    # stale permissions of the reused (leftover) service account and of its planned tokens
    if own.leftover(d.userid):
        for a in facts.acl:
            if a["ugid"] in gone_subjects or (a["path"], a["ugid"], a["roleid"]) in wantk:
                continue
            if a["ugid"] == d.userid or a["ugid"] in planned_tokens:
                st = _acl_rm(a, "stale permission from an earlier attempt")
                out.append(entry("acl", _acl_id(a), f"{a['roleid']} on {a['path']} for {a['ugid']} is not part of this plan", [st]))
    # roles named like Office Unbound roles that nothing connected uses
    rx = _ou_role_re(policy)
    for r in sorted(facts.roles):
        if not rx.match(r) or r in facts.builtin_roles or r in FORBIDDEN_ROLES or r in own.roles or r in planned_roles or r in gone_roles:
            continue
        refs = [a for a in facts.acl if a.get("roleid") == r]
        blockers = [f"{a['ugid']} on {a['path']}" for a in refs if own.classify(a["ugid"], a.get("type")) != "ou_leftover"]
        steps = [_acl_rm(a, f"uses leftover role {r}") for a in refs]
        steps.append(Step("role", "remove", r, {"phase": "before", "cleanup": True, "privileges": sorted(facts.roles[r])}, "leftover Office Unbound role"))
        out.append(entry("role", r, "role with an Office Unbound name that no connected integration uses", steps,
                         f"it is used by {'; '.join(blockers[:5])}" if blockers else None))
    # pools: only empty ones
    for pid in sorted(facts.pools):
        if MARK not in facts.pool_comments.get(pid, "") or pid in own.pools or pid in policy.scope.pools:
            continue
        members = facts.pool_members.get(pid, -1)
        guests = [v for v, g in facts.guests.items() if g.get("pool") == pid]
        kept = ("its members could not be read" if members < 0 else f"it is not empty ({max(members, len(guests))} member(s))" if (members or guests) else None)
        out.append(entry("pool", pid, "pool with the Office Unbound marker that no connected integration uses",
                         [Step("pool", "remove", pid, {"phase": "before", "cleanup": True}, "leftover empty Office Unbound pool")], kept))
    return out


def design_from_plan(plan: ProvisioningPlan, policy: Policy) -> Design:
    zones = {}
    for st in plan.steps:
        if st.kind == "acl" and st.detail["path"].startswith("/sdn/zones/"):
            _, _, _, zone, vnet = st.detail["path"].split("/")
            zones[vnet] = zone
    return design(policy, plan.facts["pve_major"], plan.facts["roles"], plan.facts["tokens"], zones, plan.facts.get("role_privileges"))


def stored_design(plan: ProvisioningPlan) -> dict:
    """What must be remembered to recompute the design later (drift, rotate, revoke)."""
    d = design_from_plan(plan, Policy.model_validate(plan.policy))
    zones = {a.path.split("/")[4]: a.path.split("/")[3] for a in d.acl if a.path.startswith("/sdn/zones/")}
    out = {"pve_major": d.major, "roles": plan.facts["roles"], "tokens": plan.facts["tokens"], "zones": zones}
    if plan.facts.get("role_privileges"):
        out["role_privileges"] = plan.facts["role_privileges"]
    return out


def design_from_stored(policy: Policy, st: dict) -> Design:
    return design(policy, st["pve_major"], st["roles"], st["tokens"], st.get("zones") or {}, st.get("role_privileges"))


# ---------------------------------------------------------------------------------------------------- Mode A apply
@dataclass
class ApplyResult:
    secrets: dict[str, tuple[str, str]] = field(default_factory=dict)     # kind -> (full token id, secret)
    created: dict = field(default_factory=lambda: {"pools": [], "roles": [], "user": None, "tokens": [], "acl": [], "adopted_roles": []})
    log: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)                  # pre-existing objects removed by choice (not restorable)
    modified_roles: list[list] = field(default_factory=list)          # [name, previous privileges]: put back on rollback
    storage_content: list[list] = field(default_factory=list)         # [storage, previous content list]: put back on rollback


def apply_plan(admin: ProxmoxAdminClient, plan: ProvisioningPlan, d: Design) -> ApplyResult:
    """Executes create/modify/remove steps in dependency order. If a step fails, everything THIS RUN created is removed again
    (never touches pre-existing objects) and the original error is raised. Permissions are never widened to make a step pass."""
    res = ApplyResult()
    steps = [s for s in plan.steps if s.op in ("create", "modify", "remove")]
    order = {"pool": 0, "role": 1, "user": 2, "token": 3, "acl": 4, "storage": 5}
    first = {"acl": 0, "token": 1, "user": 2, "role": 3, "pool": 4}       # removals chosen by the approver run first, dependants before owners

    def key(s):
        before = s.op == "remove" and s.detail.get("phase") == "before"
        return (0, first[s.kind]) if before else (1, order[s.kind], s.op == "remove")
    steps.sort(key=key)
    kinds = {v: k for k, v in d.tokens.items()}
    try:
        for s in steps:
            if s.op == "remove" and s.kind != "acl":
                if s.kind == "pool":
                    admin.pool_delete(s.target)
                elif s.kind == "role":
                    admin.role_delete(s.target)
                elif s.kind == "user":
                    admin.user_delete(s.target)
                elif s.kind == "token":
                    uid, _, name = s.target.partition("!")
                    admin.token_delete(uid, name)
                res.removed.append(f"{s.kind} {s.target}")
            elif s.kind == "storage":
                _storage_content_add(admin, s, res)
            elif s.kind == "pool":
                admin.pool_add(s.target, MARK)
                res.created["pools"].append(s.target)
            elif s.kind == "role" and s.op == "create":
                admin.role_add(s.target, s.detail["privileges"])
                res.created["roles"].append(s.target)
            elif s.kind == "role" and s.op == "modify":
                admin.role_set(s.target, s.detail["privileges"])
                res.modified_roles.append([s.target, list(s.detail.get("was") or [])])
                if s.detail.get("choice") == "overwrite":
                    res.created["adopted_roles"].append(s.target)
            elif s.kind == "user":
                admin.user_add(s.target, s.detail["comment"])
                res.created["user"] = s.target
            elif s.kind == "token":
                uid, _, name = s.target.partition("!")
                out = admin.token_add(uid, name, f"{MARK} {s.detail['kind']}", 1)
                if str(out.get("info", {}).get("privsep", "1")) != "1":
                    raise ProxmoxError("Proxmox created the token without privilege separation; refusing to continue")
                res.secrets[kinds.get(name, s.detail["kind"])] = (s.target, out["value"])
                res.created["tokens"].append(s.target)
            elif s.kind == "acl":
                dt = s.detail
                subj = dt["subject"]
                if s.op == "remove":
                    admin.acl_set(dt["path"], dt["role"], **({"token": subj} if "!" in subj else {"user": subj}), delete=True)
                else:
                    admin.acl_set(dt["path"], dt["role"], **({"token": subj} if "!" in subj else {"user": subj}), propagate=dt["propagate"])
                    res.created["acl"].append([dt["path"], subj, dt["role"]])
            res.log.append(f"{s.kind} {s.op} {s.target}")
    except Exception:
        rollback_created(admin, res)
        raise
    return res


def _storage_cfg(admin, name: str) -> dict | None:
    return next((x for x in admin.get("/storage") if x.get("storage") == name), None)


def _storage_content_add(admin, s: Step, res: ApplyResult) -> None:
    """Add exactly the `import` content type to one storage definition (PUT /storage/<s>, needs Datastore.Allocate there: the administrator's
    sign-in). Every existing content type is kept; the result is read back and verified."""
    cur = _storage_cfg(admin, s.target)
    if cur is None:
        raise ProxmoxError(f"storage {s.target} no longer exists")
    have = _content_list(cur.get("content"))
    if "import" in have:
        res.log.append(f"storage {s.target}: import content already present")
        return
    if set(have) != set(s.detail["before"]):
        raise ProxmoxError(f"the content types of storage {s.target} changed since the plan was approved ({','.join(have)}); preview again")
    after = [c for c in have if c != "none"] + ["import"]
    admin.storage_content_set(s.target, after)
    res.storage_content.append([s.target, have])
    now = _content_list((_storage_cfg(admin, s.target) or {}).get("content"))
    if set(now) != set(after):
        raise ProxmoxError(f"storage {s.target} reports content {','.join(now)} after the change, expected {','.join(after)}")


def rollback_storage_content(admin, res: ApplyResult) -> list[str]:
    """Put back the previous content list of every storage this run changed."""
    left = []
    for name, was in reversed(res.storage_content):
        try:
            admin.storage_content_set(name, was or ["none"])
        except Exception:  # noqa: BLE001
            left.append(f"storage {name} (previous content {','.join(was)})")
    res.storage_content = []
    return left


def rollback_created(admin: ProxmoxAdminClient, res: ApplyResult) -> list[str]:
    """Delete exactly what this run created (best effort, reverse order) and restore changed storage content. Returns what could not be undone."""
    left = rollback_storage_content(admin, res)
    c = res.created
    for path, subj, role in reversed(c["acl"]):
        try:
            admin.acl_set(path, role, **({"token": subj} if "!" in subj else {"user": subj}), delete=True)
        except Exception:  # noqa: BLE001
            left.append(f"acl {path}|{subj}|{role}")
    for tid in reversed(c["tokens"]):
        try:
            u, _, n = tid.partition("!")
            admin.token_delete(u, n)
        except Exception:  # noqa: BLE001
            left.append(f"token {tid}")
    if c["user"]:
        try:
            admin.user_delete(c["user"])
        except Exception:  # noqa: BLE001
            left.append(f"user {c['user']}")
    for r in reversed(c["roles"]):
        try:
            admin.role_delete(r)
        except Exception:  # noqa: BLE001
            left.append(f"role {r}")
    for name, was in reversed(res.modified_roles):
        if not was:
            continue
        try:
            admin.role_set(name, was)
        except Exception:  # noqa: BLE001
            left.append(f"role {name} (previous privileges)")
    return left


# ---------------------------------------------------------------------------------------------------- verification
VERBS_BY_CAP = {"deploy": ["clone_vm", "configure_vm", "resize_disk", "power", "snapshot", "rollback", "destroy_vm"]}


def _perm_sets(raw: dict) -> dict[str, set[str]]:
    return {p: {k for k, v in (privs or {}).items() if v} for p, privs in (raw or {}).items() if privs}


def verify_token(reader, d: Design, policy: Policy, kind: str, facts_nodes: list[str], facts_storages: list[str]) -> dict:
    """`reader`: any client with .get(). Uses the token ITSELF: GET /access/permissions (+ per-path probes), compares with the design,
    probes unauthorised nodes/storages/root, and dry-checks the verbs the capability profile needs against the effective privileges."""
    exp = expected_permissions(d, kind)
    actual = _perm_sets(reader.get("/access/permissions"))
    rep = compare_permissions(exp, actual, FORBIDDEN | {"Sys.Modify"} - set(policy.approve_elevated))
    s = policy.scope
    probes = [f"/nodes/{n}" for n in facts_nodes if s.nodes and n not in s.nodes]
    probes += [f"/storage/{x}" for x in facts_storages if x not in scope_storages(policy)]
    if "full_admin" not in capabilities(policy):
        probes.append("/")
        if policy.mode() == "single_node":
            probes += ["/nodes", "/vms", "/storage"]
    exposure = []
    for p in probes:
        got = _perm_sets(reader.get("/access/permissions?path=" + p)).get(p, set())
        if got:
            exposure.append({"path": p, "privileges": sorted(got)})
    cache: dict[str, set[str]] = {}

    def perms_at(path):
        if path not in cache:
            cache[path] = _perm_sets(reader.get("/access/permissions?path=" + path)).get(path, set())
        return cache[path]

    verbs = []
    caps = capabilities(policy)
    if kind == "inventory" or "monitor" in caps:
        nodes = s.nodes or facts_nodes
        reqs = [(f"/nodes/{n}", ["Sys.Audit"]) for n in nodes] + [(f"/pool/{p}", ["VM.Audit"]) for p in s.pools] \
               + [(f"/storage/{x}", ["Datastore.Audit"]) for x in s.storages]
        if "full_admin" in caps:
            reqs = [("/", ["Sys.Audit", "VM.Audit", "Datastore.Audit"])]
        verbs.append(priv.evaluate("discover", reqs, perms_at))
    if kind == "provision":
        zones = {a.path.split("/")[-1]: a.path.split("/")[3] for a in d.acl if a.path.startswith("/sdn/zones/")}
        for verb in VERBS_BY_CAP["deploy"] if "deploy" in caps or "full_admin" in caps else []:
            reqs = priv.required(verb, s.pools, s.storages, s.networks, zones)
            verbs.append(priv.evaluate(verb, reqs, perms_at))
        if "import_storage" in caps:
            verbs.append(priv.evaluate("image_import", [(f"/storage/{x}", sorted(IMPORT_STORAGE_PRIVS)) for x in s.import_storages], perms_at))
        if "template_clone" in caps:
            verbs.append(priv.evaluate("clone_template", [(f"/vms/{t}", ["VM.Clone", "VM.Audit"]) for t in s.template_vmids], perms_at))
    # a verb that fails ONLY for privileges the approver chose to withhold (an existing role used as is) is disclosed, not a failure
    bad = [v for v in verbs if not v.ok and not (d.withheld and all(set(m["privileges"]) <= d.withheld for m in v.missing))]
    reach = scope_reach(actual, policy, scope_storages(policy))
    seen = {r["path"] for r in reach}
    reach += [{**e, "reaches": _path_reach(e["path"], set(s.nodes)) or "outside the approved scope", "enforced_by": "proxmox"}
              for e in exposure if policy.mode() == "single_node" and e["path"] not in seen]
    if kind == "inventory" and policy.monitor_cluster:
        # owner-approved cluster-wide READ monitoring: read-only audit privileges anywhere are expected for the READ token (never for the write token);
        # anything beyond them is still exposure
        exposure = [e for e in exposure if not set(e["privileges"]) <= READ_ONLY_AUDIT]
        reach = [r for r in reach if not set(r.get("privileges", ())) <= READ_ONLY_AUDIT or not r.get("privileges")]
    ok = rep.ok and not exposure and not bad and not reach
    return {"kind": kind, "ok": ok, "missing": rep.missing, "unexpected": rep.unexpected, "forbidden": rep.forbidden, "unauthorized_exposure": exposure, "scope_reach": reach,
            "verbs": [{"verb": v.verb, "ok": v.ok, "missing": v.missing} for v in verbs], "suggestion": rep.suggestion,
            "expected": {p: sorted(x) for p, x in exp.items()}}


def node_reach(reader, policy: Policy, exp: dict[str, set[str]]) -> dict:
    """Nodes the token can reach BEYOND the policy. Proxmox does not limit pooled guests to nodes, so this lists every online node outside
    scope.nodes where an authorised storage exists (a clone/migration there would succeed at the Proxmox level); the ICS broker must refuse them."""
    if not policy.scope.nodes:
        return {"checked": False, "nodes": [], "note": "policy has no node allowlist"}
    try:
        nodes = [n for n in reader.get("/nodes") if n.get("status") == "online"]
        stor = {x["storage"]: x for x in reader.get("/storage")}
    except ProxmoxError as e:
        return {"checked": False, "nodes": [], "note": str(e)[:120]}
    can_alloc = any("VM.Allocate" in p for p in exp.values())
    names = {n["node"] for n in nodes}
    reach = []
    for n in sorted(names - set(policy.scope.nodes)):
        via = [x for x in policy.scope.storages if x in stor and (not stor[x].get("nodes") or n in stor[x]["nodes"].split(","))]
        if can_alloc and (via or not policy.scope.storages):
            reach.append({"node": n, "via_storage": via})
    return {"checked": True, "nodes": reach, "enforced_by": "ics",
            "note": "Proxmox would permit guest creation/migration on these nodes; only the ICS broker's node allowlist stops it" if reach else "none"}


def drift_check(reader, policy: Policy, plan_facts: dict, d: Design, kind: str) -> dict:
    """Periodic check with the token itself (no admin credential). Report only."""
    exp = expected_permissions(d, kind)
    actual = _perm_sets(reader.get("/access/permissions"))
    rep = compare_permissions(exp, actual, FORBIDDEN)
    rep.acl = {"checked": False, "note": "the token cannot read /access/acl; ACL-level comparison needs a provisioning identity (run a reconcile preview)"}
    out = rep.to_dict()
    out["node_reach"] = node_reach(reader, policy, exp)
    reach = scope_reach(actual, policy, scope_storages(policy))
    out["scope_reach"] = reach
    if reach:
        out["ok"] = False
        out["suggestion"] = list(out.get("suggestion", [])) + [f"remove {', '.join(r['privileges'])} on {r['path']}: it reaches {r['reaches']}, beyond the single-node scope" for r in reach]
    return out


# ---------------------------------------------------------------------------------------------------- Mode B package
def _sh(x) -> str:
    return shlex.quote(str(x))


def generate_script(plan: ProvisioningPlan, d: Design, meta: dict) -> str:
    major = d.major
    L = ["#!/usr/bin/env bash",
         "# Office Unbound - Proxmox provisioning (Mode B). Run as root on ONE Proxmox VE node of the cluster.",
         f"# plan_hash: {plan.hash()}",
         f"# generated for Proxmox VE {major}.x   package: {meta.get('package_id', 'n/a')}",
         "# This script contains NO secrets. It is idempotent: a second run changes nothing.",
         "# The new API token secret is printed ONCE, to this terminal only, at the very end.",
         "set -euo pipefail", "",
         f"EXPECT_MAJOR={major}", "CHANGES=0", "ISSUED=''",
         'log() { printf "%s\\n" "$*"; }',
         'die() { printf "ERROR: %s\\n" "$*" >&2; exit 1; }',
         'command -v pveum >/dev/null 2>&1 || die "pveum not found - run this on a Proxmox VE node"',
         'command -v pvesh >/dev/null 2>&1 || die "pvesh not found - run this on a Proxmox VE node"',
         'VER=$(pvesh get /version --output-format json | grep -o \'"version" *: *"[0-9][0-9.]*"\' | head -1 | grep -o \'[0-9][0-9.]*\')',
         'MAJOR=${VER%%.*}',
         '[ "${MAJOR:-0}" -ge 8 ] || die "Proxmox VE ${VER:-unknown} is not supported (need 8 or 9)"',
         '[ "$MAJOR" = "$EXPECT_MAJOR" ] || die "this package was generated for Proxmox VE $EXPECT_MAJOR.x but this is $VER (privilege names differ between majors); regenerate it"',
         'if [ ! -t 1 ] && [ "${ICS_ALLOW_NONTTY:-0}" != "1" ]; then die "stdout is not a terminal: the token secret is printed to your own terminal only. Run this interactively."; fi',
         "",
         'exists() { pvesh get "$1" --output-format json >/dev/null 2>&1; }',
         'role_privs() { pvesh get "/access/roles/$1" --output-format json 2>/dev/null | grep -o \'"[A-Za-z][A-Za-z.]*"\' | tr -d \'"\' | sort | tr "\\n" " "; }',
         'acl_has() { pvesh get /access/acl --output-format json | tr -d " \\n" | sed "s/},{/}\\n{/g" | grep -F "\\"path\\":\\"$1\\"" | grep -F "\\"ugid\\":\\"$2\\"" | grep -F "\\"roleid\\":\\"$3\\"" >/dev/null; }',
         "",
         "ensure_pool() {",
         '  if exists "/pools/$1"; then log "pool $1: exists"; return; fi',
         f'  pveum pool add "$1" --comment {_sh(MARK)}; CHANGES=$((CHANGES+1)); log "pool $1: created"',
         "}",
         "ensure_role() {  # name, privileges (space separated)",
         '  local want have',
         '  want=$(printf "%s\\n" $2 | sort | tr "\\n" " ")',
         '  if exists "/access/roles/$1"; then',
         '    have=$(role_privs "$1")',
         '    if [ "$have" = "$want" ]; then log "role $1: ok"; return; fi',
         '    die "role $1 already exists with different privileges (have: $have / want: $want). It is NOT modified. Regenerate the package with another role name."',
         "  fi",
         '  pveum role add "$1" --privs "$2"; CHANGES=$((CHANGES+1)); log "role $1: created"',
         "}",
         "ensure_user() {",
         '  if exists "/access/users/$1"; then',
         f'    if pvesh get "/access/users/$1" --output-format json | grep -q {_sh(MARK)}; then log "user $1: ok"; return; fi',
         '    die "user $1 exists but was not created by Office Unbound; refusing to reuse it. Regenerate the package with another service_user."',
         "  fi",
         f'  pveum user add "$1" --comment {_sh(MARK + " Office Unbound service account")} --enable 1; CHANGES=$((CHANGES+1)); log "user $1: created (no password)"',
         "}",
         "ensure_token() {  # user, token name, kind",
         '  local out sec',
         '  if exists "/access/users/$1/token/$2"; then log "token $1!$2: exists (its secret cannot be shown again; delete and re-run to re-issue)"; return; fi',
         f'  out=$(pveum user token add "$1" "$2" --privsep 1 --comment "{MARK} $3" --output-format json)',
         '  sec=$(printf "%s" "$out" | grep -o \'"value" *: *"[^"]*"\' | sed \'s/.*: *"\\(.*\\)"/\\1/\')',
         '  [ -n "$sec" ] || die "could not read the new token secret"',
         '  ISSUED="${ISSUED}$1!$2   $sec\\n"; CHANGES=$((CHANGES+1)); log "token $1!$2: created (privsep=1)"',
         "}",
         "ensure_acl() {  # path, subject, role, propagate, user|token",
         '  if acl_has "$1" "$2" "$3"; then log "acl $1 $2 $3: ok"; return; fi',
         '  if [ "$5" = token ]; then pveum acl modify "$1" --roles "$3" --tokens "$2" --propagate "$4"; else pveum acl modify "$1" --roles "$3" --users "$2" --propagate "$4"; fi',
         '  CHANGES=$((CHANGES+1)); log "acl $1 $2 $3: granted"',
         "}",
         "remove_acl() {  # path, subject, role, user|token  (scope change: narrowing)",
         '  if ! acl_has "$1" "$2" "$3"; then log "acl $1 $2 $3: already absent"; return; fi',
         '  if [ "$4" = token ]; then pveum acl delete "$1" --roles "$3" --tokens "$2"; else pveum acl delete "$1" --roles "$3" --users "$2"; fi',
         '  CHANGES=$((CHANGES+1)); log "acl $1 $2 $3: removed"',
         "}",
         "ensure_import_content() {  # storage: adds the `import` content type, keeping every existing content type",
         '  local cur',
         '  cur=$(pvesh get "/storage/$1" --output-format json | grep -o \'"content" *: *"[^"]*"\' | sed \'s/.*: *"\\(.*\\)"/\\1/\')',
         '  case ",$cur," in *,import,*) log "storage $1: import content ok"; return;; esac',
         '  if [ -z "$cur" ] || [ "$cur" = none ]; then pvesm set "$1" --content import; else pvesm set "$1" --content "$cur,import"; fi',
         '  CHANGES=$((CHANGES+1)); log "storage $1: import content added (was: ${cur:-none})"',
         "}",
         "update_role() {  # name, old privileges, new privileges (scope change): only a role that still has exactly the old privileges is changed",
         '  local want have new',
         '  new=$(printf "%s\\n" $3 | sort | tr "\\n" " ")',
         '  have=$(role_privs "$1")',
         '  if [ "$have" = "$new" ]; then log "role $1: ok"; return; fi',
         '  want=$(printf "%s\\n" $2 | sort | tr "\\n" " ")',
         '  [ "$have" = "$want" ] || die "role $1 has unexpected privileges (have: $have). It is NOT modified."',
         '  pveum role modify "$1" --privs "$3"; CHANGES=$((CHANGES+1)); log "role $1: privileges updated"',
         "}", ""]
    sc = (meta or {}).get("scope_change") or {}
    for s in plan.steps:
        if s.kind == "pool":
            L.append(f"ensure_pool {_sh(s.target)}")
    for s in plan.steps:
        if s.kind == "role":
            ru = (sc.get("role_updates") or {}).get(s.target)
            if ru:
                L.append(f"update_role {_sh(s.target)} {_sh(' '.join(ru['old']))} {_sh(' '.join(ru['new']))}")
            else:
                L.append(f"ensure_role {_sh(s.target)} {_sh(' '.join(sorted(s.detail['privileges'])))}")
    L.append(f"ensure_user {_sh(d.userid)}")
    for kind, name in d.tokens.items():
        L.append(f"ensure_token {_sh(d.userid)} {_sh(name)} {_sh(kind)}")
    for path, subj, role, prop in acl_entries(d):
        L.append(f"ensure_acl {_sh(path)} {_sh(subj)} {_sh(role)} {prop} {'token' if '!' in subj else 'user'}")
    for path, subj, role, prop in sc.get("remove_acl") or []:
        L.append(f"remove_acl {_sh(path)} {_sh(subj)} {_sh(role)} {'token' if '!' in subj else 'user'}")
    for s in plan.steps:
        if s.kind == "storage" and s.detail.get("change") == "content_add":
            L.append(f"ensure_import_content {_sh(s.target)}")
    L += ["", 'log "changes made: $CHANGES"',
          'if [ -n "$ISSUED" ]; then',
          '  printf "\\n==================== NEW API TOKEN SECRET(S) - SHOWN ONCE ====================\\n"',
          '  printf "%b" "$ISSUED"',
          '  printf "=================================================================================\\n"',
          '  printf "Hand these over securely (password manager / encrypted channel). Do NOT e-mail or paste into chat.\\n"',
          '  printf "Enter them in Office Unbound under Settings > Infrastructure > Import credential.\\n"',
          "fi", "exit 0", ""]
    return "\n".join(L)


def generate_scope_rollback(plan: ProvisioningPlan, meta: dict) -> str:
    """Scope change rollback: put the previous ACL entries back and remove the ones the change added. Never deletes users, tokens or roles."""
    sc = meta["scope_change"]
    L = ["#!/usr/bin/env bash", "# Office Unbound - scope change rollback: restores the previous scope. Contains no secrets.",
         f"# plan_hash: {plan.hash()}", "set -euo pipefail",
         'log() { printf "%s\\n" "$*"; }',
         'acl_has() { pvesh get /access/acl --output-format json | tr -d " \\n" | sed "s/},{/}\\n{/g" | grep -F "\\"path\\":\\"$1\\"" | grep -F "\\"ugid\\":\\"$2\\"" | grep -F "\\"roleid\\":\\"$3\\"" >/dev/null; }']
    for path, subj, role, prop in sc["restore_acl"]:
        flag = "--tokens" if "!" in subj else "--users"
        L.append(f'if ! acl_has {_sh(path)} {_sh(subj)} {_sh(role)}; then pveum acl modify {_sh(path)} --roles {_sh(role)} {flag} {_sh(subj)} --propagate {prop}; log "acl restored: {path} {subj} {role}"; fi')
    for path, subj, role, prop in sc["undo_acl"]:
        flag = "--tokens" if "!" in subj else "--users"
        L.append(f'if acl_has {_sh(path)} {_sh(subj)} {_sh(role)}; then pveum acl delete {_sh(path)} --roles {_sh(role)} {flag} {_sh(subj)}; log "acl removed: {path} {subj} {role}"; fi')
    for name, ru in (sc.get("role_updates") or {}).items():
        L.append(f'pveum role modify {_sh(name)} --privs {_sh(" ".join(ru["old"]))}   # restores the previous privileges')
    L += _storage_rollback_lines(plan)
    L += ['log "scope rollback complete"', ""]
    return "\n".join(L)


def generate_rollback(plan: ProvisioningPlan, d: Design) -> str:
    L = ["#!/usr/bin/env bash", "# Office Unbound - rollback: removes exactly the objects the provisioning script created. Contains no secrets.",
         f"# plan_hash: {plan.hash()}", "set -euo pipefail",
         'log() { printf "%s\\n" "$*"; }',
         'exists() { pvesh get "$1" --output-format json >/dev/null 2>&1; }',
         'acl_has() { pvesh get /access/acl --output-format json | tr -d " \\n" | sed "s/},{/}\\n{/g" | grep -F "\\"path\\":\\"$1\\"" | grep -F "\\"ugid\\":\\"$2\\"" | grep -F "\\"roleid\\":\\"$3\\"" >/dev/null; }',
         'role_privs() { pvesh get "/access/roles/$1" --output-format json 2>/dev/null | grep -o \'"[A-Za-z][A-Za-z.]*"\' | tr -d \'"\' | sort | tr "\\n" " "; }',
         "", "# 1. ACL entries"]
    for path, subj, role, prop in reversed(acl_entries(d)):
        flag = "--tokens" if "!" in subj else "--users"
        L.append(f'if acl_has {_sh(path)} {_sh(subj)} {_sh(role)}; then pveum acl delete {_sh(path)} --roles {_sh(role)} {flag} {_sh(subj)}; log "acl removed: {path} {subj} {role}"; fi')
    L.append("# 2. tokens")
    for name in d.tokens.values():
        L.append(f'if exists "/access/users/{d.userid}/token/{name}"; then pveum user token remove {_sh(d.userid)} {_sh(name)}; log "token removed: {d.userid}!{name}"; fi')
    L.append("# 3. service user (only if it is marked as created by Office Unbound)")
    L.append(f'if exists "/access/users/{d.userid}" && pvesh get "/access/users/{d.userid}" --output-format json | grep -q {_sh(MARK)}; then pveum user delete {_sh(d.userid)}; log "user removed: {d.userid}"; fi')
    L.append("# 4. roles (only if still exactly as generated)")
    for s in plan.steps:
        if s.kind == "role":
            want = " ".join(sorted(s.detail["privileges"]))
            L.append(f'if exists "/access/roles/{s.target}" && [ "$(role_privs {_sh(s.target)})" = "{want} " ]; then pveum role delete {_sh(s.target)}; log "role removed: {s.target}"; fi')
    pools = [s.target for s in plan.steps if s.kind == "pool" and s.op == "create"]
    if pools:
        L.append("# 5. pools created by the package (only if empty; Proxmox refuses to delete a non-empty pool)")
        for pl in pools:
            L.append(f'if exists "/pools/{pl}"; then pveum pool delete {_sh(pl)} || log "pool {pl} not removed (not empty)"; fi')
    L += _storage_rollback_lines(plan)
    L += ['log "rollback complete"', ""]
    return "\n".join(L)


def _storage_rollback_lines(plan: ProvisioningPlan) -> list[str]:
    return [f"pvesm set {_sh(s.target)} --content {_sh(','.join(s.detail['before']) or 'none')}   # restores the previous content types"
            for s in plan.steps if s.kind == "storage" and s.detail.get("change") == "content_add"]


def command_list(plan: ProvisioningPlan, d: Design, meta: dict | None = None) -> str:
    L = ["# Copy-paste alternative to provision.sh (run as root on one Proxmox VE node). No secrets in this file.",
         f"# plan_hash: {plan.hash()}", ""]
    for s in plan.steps:
        if s.kind == "pool":
            L.append(f"pveum pool add {_sh(s.target)} --comment {_sh(MARK)}")
    for s in plan.steps:
        if s.kind == "role":
            L.append(f"pveum role add {_sh(s.target)} --privs {_sh(' '.join(sorted(s.detail['privileges'])))}")
    L.append(f"pveum user add {_sh(d.userid)} --comment {_sh(MARK + ' Office Unbound service account')} --enable 1")
    for kind, name in d.tokens.items():
        L.append(f"pveum user token add {_sh(d.userid)} {_sh(name)} --privsep 1 --comment {_sh(MARK + ' ' + kind)}   # prints the secret ONCE: copy it now")
    for path, subj, role, prop in acl_entries(d):
        who = f"--tokens {_sh(subj)}" if "!" in subj else f"--users {_sh(subj)}"
        L.append(f"pveum acl modify {_sh(path)} --roles {_sh(role)} {who} --propagate {prop}")
    sc = (meta or {}).get("scope_change") or {}
    for path, subj, role, prop in sc.get("remove_acl") or []:
        L.append(f"pveum acl delete {_sh(path)} --roles {_sh(role)} {'--tokens' if '!' in subj else '--users'} {_sh(subj)}")
    for name, ru in (sc.get("role_updates") or {}).items():
        L.append(f"pveum role modify {_sh(name)} --privs {_sh(' '.join(ru['new']))}")
    for s in plan.steps:
        if s.kind == "storage" and s.detail.get("change") == "content_add":
            L.append(f"pvesm set {_sh(s.target)} --content {_sh(','.join(s.detail['after']))}   # adds `import`; existing content types unchanged")
    return "\n".join(L) + "\n"


def validation_commands(d: Design) -> str:
    L = ["# Run on the Proxmox node after provisioning (read-only)."]
    for kind, name in d.tokens.items():
        L.append(f"pveum user token list {_sh(d.userid)}")
        L.append(f"pveum user permissions {_sh(d.userid + '!' + name)}   # effective (token) permissions")
    L.append(f"pveum user permissions {_sh(d.userid)}")
    L.append("pveum acl list")
    L.append("pveum role list")
    return "\n".join(L) + "\n"


def report_markdown(plan: ProvisioningPlan, d: Design, meta: dict) -> str:
    p = plan.policy
    o = [f"# Office Unbound - Proxmox permissions report", "",
         f"- Plan hash: `{plan.hash()}`", f"- Capability profile: **{p['preset']}**", f"- Proxmox VE major version: {d.major}",
         f"- Service account: `{d.userid}` (realm @pve, no password, no OS account)",
         f"- API tokens (privilege separated): {', '.join('`' + d.userid + '!' + t + '`' for t in d.tokens.values())}", "", "## What will be created", ""]
    for s in plan.steps:
        o.append(f"- **{s.kind}** `{s.target}` - {s.op}" + (f" - {s.reason}" if s.reason else ""))
    o += ["", "## Roles and privileges", ""]
    for cap, (name, privs) in d.roles.items():
        o.append(f"- `{name}` ({cap}): {', '.join(sorted(privs))}")
    o += ["", "## Where (ACL paths)", ""]
    for path, subj, role, prop in acl_entries(d):
        o.append(f"- `{path}` - `{subj}` - `{role}`" + ("" if prop else " (no propagation)"))
    if plan.elevated:
        o += ["", "## Elevated privileges (explicit approval required)", ""]
        o += [f"- **{e['privilege']}** at `{e['path']}`: {e['why']}" for e in plan.elevated]
    if plan.consequences:
        o += ["", "## Consequences", ""] + [f"- {c}" for c in plan.consequences]
    if plan.conflicts or plan.warnings:
        o += ["", "## Conflicts and warnings", ""] + [f"- {c}" for c in plan.conflicts + plan.warnings]
    sc = (meta or {}).get("scope_change")
    if sc:
        o += ["", "## Scope change", "", f"- Direction: **{sc['direction']}**", f"- Before: {sc['old_scope']['mode']} - nodes {', '.join(sc['old_scope']['nodes']) or 'all'}",
              f"- After: {sc['new_scope']['mode']} - nodes {', '.join(sc['new_scope']['nodes']) or 'all'}",
              "- Permissions removed: " + (", ".join(f"`{p}` {r}" for p, _, r, _ in sc["remove_acl"]) or "none")]
    o += ["", "## Who enforces what", "", "| Control | Enforced by | Detail |", "|---|---|---|"]
    o += [f"| {e.control} | {e.enforced_by} | {e.detail} |" for e in plan.enforcement]
    o += ["", "## Never granted", "", "Permissions.Modify, User.Modify, Realm.*, Group.Allocate, Sys.Modify (unless listed above as elevated), the built-in Administrator and PVEAdmin roles.",
          "", "## Procedure", "", "1. Review this report. 2. Run `provision.sh` as root on one node (or the command list). 3. Copy the token secret(s) printed at the end.",
          "4. Hand them over through a secure channel and import them in Office Unbound. 5. To undo: `rollback.sh`."]
    return "\n".join(o) + "\n"


def report_html(md: str) -> str:
    body = []
    in_ul = in_tbl = False
    for line in md.splitlines():
        esc = html.escape(line)
        esc = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", esc)
        esc = re.sub(r"`(.+?)`", r"<code>\1</code>", esc)
        if line.startswith("|"):
            if set(line) <= set("|- "):
                continue
            cells = [c.strip() for c in esc.strip("|").split("|")]
            tag = "th" if not in_tbl else "td"
            if not in_tbl:
                body.append("<table>")
                in_tbl = True
            body.append("<tr>" + "".join(f"<{tag}>{c}</{tag}>" for c in cells) + "</tr>")
            continue
        if in_tbl:
            body.append("</table>")
            in_tbl = False
        if line.startswith("- "):
            if not in_ul:
                body.append("<ul>")
                in_ul = True
            body.append(f"<li>{esc[2:]}</li>")
            continue
        if in_ul:
            body.append("</ul>")
            in_ul = False
        if line.startswith("# "):
            body.append(f"<h1>{esc[2:]}</h1>")
        elif line.startswith("## "):
            body.append(f"<h2>{esc[3:]}</h2>")
        elif line.strip():
            body.append(f"<p>{esc}</p>")
    if in_ul:
        body.append("</ul>")
    if in_tbl:
        body.append("</table>")
    return ("<!doctype html><meta charset=utf-8><title>Office Unbound - Proxmox permissions report</title>"
            "<style>body{font:14px system-ui;max-width:60rem;margin:2rem auto;padding:0 1rem}table{border-collapse:collapse}td,th{border:1px solid #999;padding:.3rem .5rem;vertical-align:top}"
            "code{background:#eee;padding:0 .2rem}</style>" + "\n".join(body))


class ProxmoxPackageGenerator:
    def __init__(self, policy: Policy):
        self.policy = policy

    def generate(self, plan: ProvisioningPlan, meta: dict) -> dict[str, str]:
        if plan.blocked:
            raise PlanBuildError("the plan is blocked: " + "; ".join(plan.blocked))
        d = design_from_plan(plan, self.policy)
        md = report_markdown(plan, d, meta)
        pkg = {"schema": PKG_SCHEMA, "provider": "proxmox", "package_id": meta.get("package_id"), "plan_hash": plan.hash(), "pve_major": d.major,
               "service_user": d.userid, "tokens": [f"{d.userid}!{t}" for t in d.tokens.values()],
               "roles": {n: sorted(p) for _, (n, p) in d.roles.items()}, "acl": [{"path": a, "subject": b, "role": c, "propagate": e} for a, b, c, e in acl_entries(d)],
               "plan": plan.to_dict(), "files": ["provision.sh", "rollback.sh", "commands.txt", "validate.txt", "report.md", "report.html", "package.json"]}
        return {"provision.sh": generate_script(plan, d, meta), "rollback.sh": (generate_scope_rollback(plan, meta) if meta.get("scope_change") else generate_rollback(plan, d)),
                "commands.txt": command_list(plan, d, meta),
                "validate.txt": validation_commands(d), "report.md": md, "report.html": report_html(md),
                "package.json": json.dumps(pkg, indent=2, sort_keys=True, default=str)}
