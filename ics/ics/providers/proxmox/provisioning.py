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
from ...provisioning.model import Policy
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
    "Datastore.AllocateTemplate": (None, None, "upload ISOs/templates (full_admin only)", "pveum: privileges"),
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


# ---------------------------------------------------------------------------------------------------- design
CAP_ROLE_SUFFIX = {"monitor": "Monitor", "deploy": "Deploy", "storage": "Storage", "template_clone": "TemplateClone", "network": "Network",
                   "backup": "Backup", "custom": "Custom", "full_admin": "FullAdmin"}


def capabilities(policy: Policy) -> list[str]:
    if policy.preset == "monitoring":
        return ["monitor"]
    if policy.preset == "deploy":
        caps = ["monitor", "deploy", "storage"]
        if policy.scope.template_vmids:
            caps.append("template_clone")
        if policy.scope.networks:
            caps.append("network")
        return caps
    if policy.preset == "full_admin":
        return ["monitor", "full_admin"]
    return ["monitor"] + [c for c in policy.capabilities if c != "monitor"]


def role_privileges(cap: str, policy: Policy, major: int) -> set[str]:
    if major < MIN_MAJOR:
        raise PlanBuildError(f"Proxmox VE {major} is not supported (need 8 or 9)")
    if cap == "monitor":
        p = {"Sys.Audit", "VM.Audit", "Datastore.Audit", "Pool.Audit"}
        if policy.guest_agent:
            p.add("VM.GuestAgent.Audit" if major >= 9 else "VM.Monitor")
    elif cap == "deploy":
        p = {"VM.Allocate", "VM.Audit", "VM.PowerMgmt", "VM.Config.CPU", "VM.Config.Memory", "VM.Config.Disk", "VM.Config.Network",
             "VM.Config.Cloudinit", "VM.Config.Options", "VM.Config.HWType", "VM.Config.CDROM", "VM.Snapshot", "VM.Snapshot.Rollback", "VM.Clone", "Pool.Audit"}
        if policy.allow_migrate:
            p.add("VM.Migrate")
    elif cap == "storage":
        p = {"Datastore.AllocateSpace", "Datastore.Audit"}
    elif cap == "template_clone":
        p = {"VM.Clone", "VM.Audit"}
    elif cap == "network":
        p = {"SDN.Use"}
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


def role_name(policy: Policy, cap: str) -> str:
    return policy.role_names.get(cap) or policy.role_prefix + CAP_ROLE_SUFFIX[cap]


def design(policy: Policy, major: int, final_names: dict[str, str] | None = None, token_names: dict[str, str] | None = None,
           vnet_zones: dict[str, str] | None = None) -> Design:
    caps = capabilities(policy)
    s = policy.scope
    zones = vnet_zones or {}
    roles = {c: ((final_names or {}).get(c) or role_name(policy, c), frozenset(role_privileges(c, policy, major))) for c in caps}
    both, prov = ("inventory", "provision"), ("provision",)
    acl: list[AclSpec] = []
    if "full_admin" in caps:
        acl = [AclSpec("/", "monitor", 1, ("inventory",)), AclSpec("/", "full_admin", 1, prov)]
    else:
        acl += [AclSpec(f"/nodes/{n}", "monitor", 1, both) for n in s.nodes]
        acl += [AclSpec(f"/pool/{p}", "monitor", 1, both) for p in s.pools]
        acl += [AclSpec(f"/storage/{x}", "monitor", 1, both) for x in s.storages]
        acl += [AclSpec(f"/vms/{t}", "monitor", 0, both) for t in s.template_vmids]
        if "deploy" in caps:
            acl += [AclSpec(f"/pool/{p}", "deploy", 1, prov) for p in s.pools]
        if "storage" in caps:
            acl += [AclSpec(f"/storage/{x}", "storage", 1, prov) for x in s.storages]
        if "template_clone" in caps:
            acl += [AclSpec(f"/vms/{t}", "template_clone", 0, prov) for t in s.template_vmids]
        if "network" in caps:
            acl += [AclSpec(f"/sdn/zones/{zones.get(n, 'localnetwork')}/{n}", "network", 1, prov) for n in s.networks]
        if "backup" in caps:
            acl += [AclSpec(f"/pool/{p}", "backup", 1, prov) for p in s.pools]
            acl += [AclSpec(f"/storage/{x}", "backup", 1, prov) for x in s.backup_storages]
        if "custom" in caps:
            acl += [AclSpec(g.path, "custom", 1, prov) for g in policy.custom_grants]
            if policy.allow_cicustom:
                acl.append(AclSpec("/", "custom", 1, prov))
    kinds = ["inventory"] + (["provision"] if len(caps) > 1 else [])
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
    return Design(f"{policy.service_user}@{policy.realm}", roles, toks, uniq, major, list(s.pools))


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
    guests: dict[int, dict] = field(default_factory=dict)
    networks: dict[str, str] = field(default_factory=dict)         # bridge/vnet -> zone
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
                                    "nodes": [x for x in (s.get("nodes") or "").split(",") if x] or sorted(f.nodes)}
    for p in _opt(c, "/pools", f, "pools") or []:
        f.pools.add(p["poolid"])
    for r in _opt(c, "/cluster/resources?type=vm", f, "guests") or []:
        if "vmid" in r:
            f.guests[int(r["vmid"])] = {"node": r.get("node"), "name": r.get("name"), "pool": r.get("pool"), "template": bool(r.get("template")), "type": r.get("type")}
    for z in _opt(c, "/cluster/sdn/vnets", f, "SDN vnets") or []:
        f.networks[z["vnet"]] = z.get("zone", "localnetwork")
    for n, st in f.nodes.items():
        if st == "online":
            for i in _opt(c, f"/nodes/{n}/network", f, f"network of {n}") or []:
                if i.get("type") in ("bridge", "OVSBridge"):
                    f.networks.setdefault(i["iface"], "localnetwork")
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
          "The policy `scope.nodes` is persisted and checked by provisioning/enforce.py; broker wiring (EndpointScope.nodes) is done by the integration agent."),
        E("VMID ranges", "not_enforced" if s.vmid_ranges else "ics", "Proxmox ACLs cannot express VMID ranges. Policy guard implemented (provisioning/enforce.py); broker wiring pending."),
        E("Guest types (qemu/lxc)", "ics", "Not expressible in Proxmox ACLs. Policy guard implemented; broker wiring pending."),
        E("CPU / RAM / disk caps", "ics", "Proxmox has no per-user resource quota in ACLs. Policy guard implemented; broker wiring pending."),
    ]
    return out


def plan_for(policy: Policy, facts: Facts | None, *, pve_major: int | None = None, managed: dict | None = None, prune: bool = False,
             mode: str = "A") -> ProvisioningPlan:
    """Compute the plan. `facts=None` => offline plan (Mode B without connectivity): every object is a `create`, the script re-checks at run time."""
    major = facts.major if facts else pve_major
    if not major:
        raise PlanBuildError("the Proxmox VE major version (8 or 9) is required when no cluster is reachable")
    if policy.realm != "pve":
        raise PlanBuildError("the service account must live in the @pve realm")
    managed = managed or {}
    elevated = check_privileges(policy, major)
    for e in elevated:
        e["approved"] = e["privilege"] in policy.approve_elevated
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
        unauthorised = sorted(set(facts.nodes) - set(s.nodes)) if s.nodes else []
        if unauthorised:
            plan.facts["unauthorized_nodes"] = unauthorised
        unauth_st = sorted(set(facts.storages) - set(s.storages) - set(s.backup_storages))
        if unauth_st:
            plan.facts["unauthorized_storages"] = unauth_st
        if not facts.acl_readable:
            plan.warnings.append("the provisioning identity cannot read /access/acl: ACL conflicts cannot be fully checked")
        plan.warnings += facts.notes
    else:
        plan.warnings.append("offline plan: nothing was discovered; the script checks conflicts on the node at run time")
        for pname in policy.scope.pools:
            plan.steps.append(Step("pool", "create", pname, {}, "created only if it does not exist"))

    # --- roles (collision-safe)
    final: dict[str, str] = {}
    existing_roles = facts.roles if facts else {}
    taken = set(existing_roles)
    mroles = set(managed.get("roles", []))
    for cap, (name, privs) in d0.roles.items():
        if name in FORBIDDEN_ROLES:
            plan.blocked.append(f"role name {name} is reserved: Administrator/PVEAdmin are never used or generated")
        chosen = name
        ex = existing_roles.get(name)
        if ex is not None and (name in (facts.builtin_roles if facts else set()) or (ex != privs and name not in mroles)):
            n = 2
            while f"{name}-{n}" in taken:
                n += 1
            chosen = f"{name}-{n}"
            plan.conflicts.append(f"role {name} already exists with {'a built-in definition' if name in facts.builtin_roles else 'different privileges'}"
                                  f" ({', '.join(sorted(ex))}); it will NOT be touched, a new role {chosen} is created instead")
        taken.add(chosen)
        final[cap] = chosen
    d = design(policy, major, final, vnet_zones=zones)
    for cap, (name, privs) in d.roles.items():
        ex = existing_roles.get(name)
        det = {"privileges": sorted(privs), "capability": cap}
        if ex is None:
            plan.steps.append(Step("role", "create", name, det, f"capability '{cap}'"))
        elif ex == privs:
            plan.steps.append(Step("role", "noop", name, det, "already exists with exactly these privileges"))
        else:  # only reachable for a role this ICS manages (reconcile)
            plan.steps.append(Step("role", "modify", name, {**det, "was": sorted(ex)}, "restore the approved privilege set"))

    # --- user
    ex_u = facts.users.get(userid) if facts else None
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
        if ex_u is not None and tname in ex_u.get("tokens", {}):
            if full in managed.get("tokens", []):
                plan.steps.append(Step("token", "noop", full, {"kind": kind, "privsep": 1}, "existing ICS-managed token"))
            else:
                plan.steps.append(Step("token", "conflict", full, {"kind": kind}, "a token with this name exists and was not created by the ICS"))
                plan.blocked.append(f"token {full} already exists; choose a different token_base")
        else:
            plan.steps.append(Step("token", "create", full, {"kind": kind, "privsep": 1},
                                   "privilege-separated token; the secret is shown once and captured straight into the vault" if mode == "A"
                                   else "privilege-separated token; the secret is printed once on the customer's terminal"))
    if "provision" in d.tokens and not policy.scope.pools:
        plan.blocked.append("a provisioning (write) credential needs at least one authorised pool: add scope.pools")
    # --- ACL entries
    have = {(a["path"], a["ugid"], a["roleid"]) for a in (facts.acl if facts else [])}
    want = acl_entries(d)
    for path, subj, role, prop in want:
        key = f"{path}|{subj}|{role}"
        step_risk = "normal"
        if path == "/" and policy.preset != "full_admin" and role != d.roles.get("monitor", ("",))[0]:
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
    plan.facts["pve_major"] = major
    plan.facts["service_user"] = userid
    plan.facts["roles"] = {cap: n for cap, (n, _) in d.roles.items()}
    plan.facts["tokens"] = dict(d.tokens)
    return plan


def design_from_plan(plan: ProvisioningPlan, policy: Policy) -> Design:
    zones = {}
    for st in plan.steps:
        if st.kind == "acl" and st.detail["path"].startswith("/sdn/zones/"):
            _, _, _, zone, vnet = st.detail["path"].split("/")
            zones[vnet] = zone
    return design(policy, plan.facts["pve_major"], plan.facts["roles"], plan.facts["tokens"], zones)


def stored_design(plan: ProvisioningPlan) -> dict:
    """What must be remembered to recompute the design later (drift, rotate, revoke)."""
    d = design_from_plan(plan, Policy.model_validate(plan.policy))
    zones = {a.path.split("/")[4]: a.path.split("/")[3] for a in d.acl if a.path.startswith("/sdn/zones/")}
    return {"pve_major": d.major, "roles": plan.facts["roles"], "tokens": plan.facts["tokens"], "zones": zones}


def design_from_stored(policy: Policy, st: dict) -> Design:
    return design(policy, st["pve_major"], st["roles"], st["tokens"], st.get("zones") or {})


# ---------------------------------------------------------------------------------------------------- Mode A apply
@dataclass
class ApplyResult:
    secrets: dict[str, tuple[str, str]] = field(default_factory=dict)     # kind -> (full token id, secret)
    created: dict = field(default_factory=lambda: {"pools": [], "roles": [], "user": None, "tokens": [], "acl": []})
    log: list[str] = field(default_factory=list)


def apply_plan(admin: ProxmoxAdminClient, plan: ProvisioningPlan, d: Design) -> ApplyResult:
    """Executes create/modify/remove steps in dependency order. If a step fails, everything THIS RUN created is removed again
    (never touches pre-existing objects) and the original error is raised. Permissions are never widened to make a step pass."""
    res = ApplyResult()
    steps = [s for s in plan.steps if s.op in ("create", "modify", "remove")]
    order = {"pool": 0, "role": 1, "user": 2, "token": 3, "acl": 4}
    steps.sort(key=lambda s: (order[s.kind], s.op == "remove"))
    kinds = {v: k for k, v in d.tokens.items()}
    try:
        for s in steps:
            if s.kind == "pool":
                admin.pool_add(s.target, MARK)
                res.created["pools"].append(s.target)
            elif s.kind == "role" and s.op == "create":
                admin.role_add(s.target, s.detail["privileges"])
                res.created["roles"].append(s.target)
            elif s.kind == "role" and s.op == "modify":
                admin.role_set(s.target, s.detail["privileges"])
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


def rollback_created(admin: ProxmoxAdminClient, res: ApplyResult) -> list[str]:
    """Delete exactly what this run created (best effort, reverse order). Returns what could not be removed."""
    left = []
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
    probes += [f"/storage/{x}" for x in facts_storages if x not in s.storages and x not in s.backup_storages]
    if "full_admin" not in capabilities(policy):
        probes.append("/")
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
        if "template_clone" in caps:
            verbs.append(priv.evaluate("clone_template", [(f"/vms/{t}", ["VM.Clone", "VM.Audit"]) for t in s.template_vmids], perms_at))
    bad = [v for v in verbs if not v.ok]
    ok = rep.ok and not exposure and not bad
    return {"kind": kind, "ok": ok, "missing": rep.missing, "unexpected": rep.unexpected, "forbidden": rep.forbidden, "unauthorized_exposure": exposure,
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
         "}", ""]
    for s in plan.steps:
        if s.kind == "pool":
            L.append(f"ensure_pool {_sh(s.target)}")
    for s in plan.steps:
        if s.kind == "role":
            L.append(f"ensure_role {_sh(s.target)} {_sh(' '.join(sorted(s.detail['privileges'])))}")
    L.append(f"ensure_user {_sh(d.userid)}")
    for kind, name in d.tokens.items():
        L.append(f"ensure_token {_sh(d.userid)} {_sh(name)} {_sh(kind)}")
    for path, subj, role, prop in acl_entries(d):
        L.append(f"ensure_acl {_sh(path)} {_sh(subj)} {_sh(role)} {prop} {'token' if '!' in subj else 'user'}")
    L += ["", 'log "changes made: $CHANGES"',
          'if [ -n "$ISSUED" ]; then',
          '  printf "\\n==================== NEW API TOKEN SECRET(S) - SHOWN ONCE ====================\\n"',
          '  printf "%b" "$ISSUED"',
          '  printf "=================================================================================\\n"',
          '  printf "Hand these over securely (password manager / encrypted channel). Do NOT e-mail or paste into chat.\\n"',
          '  printf "Enter them in Office Unbound under Settings > Infrastructure > Import credential.\\n"',
          "fi", "exit 0", ""]
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
    L += ['log "rollback complete"', ""]
    return "\n".join(L)


def command_list(plan: ProvisioningPlan, d: Design) -> str:
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
        return {"provision.sh": generate_script(plan, d, meta), "rollback.sh": generate_rollback(plan, d), "commands.txt": command_list(plan, d),
                "validate.txt": validation_commands(d), "report.md": md, "report.html": report_html(md),
                "package.json": json.dumps(pkg, indent=2, sort_keys=True, default=str)}
