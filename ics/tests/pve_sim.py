"""STATEFUL PROXMOX VE API SIMULATOR -- A TEST DOUBLE. NOT A REAL ENDPOINT.

Used only by the test-suite to exercise the Proxmox provider end to end (HTTPS with a self-signed cert, token auth,
per-token permission enforcement, async tasks with UPIDs, failure injection). JSON shapes follow the PVE 8.x API.

Safety: it lives under tests/ (never installed), binds 127.0.0.1 only (the ICS SSRF guard refuses loopback endpoints unless
ICS_ALLOW_LOOPBACK_ENDPOINTS is set, which production does not do), and /version reports repoid "pve-sim-test-double";
the provider refuses to talk to anything advertising that marker unless loopback endpoints are explicitly allowed.
It is NOT a faithful model of PVE: privileges are simplified, storage/network behaviour is minimal, and passing
simulator tests is not evidence that the provider works against a real cluster (see docs/status/provider-proxmox.md).
"""
import hashlib
import http.server
import json
import re
import ssl
import tempfile
import threading
import time
import urllib.parse
from pathlib import Path

from .pve_mock import make_cert

SIM_MARKER = "pve-sim-test-double"

ROLES = {
    "PVEAuditor": {"Sys.Audit", "VM.Audit", "Datastore.Audit", "Pool.Audit", "SDN.Audit", "Mapping.Audit"},
    "PVEDatastoreUser": {"Datastore.AllocateSpace", "Datastore.Audit"},
    "PVESDNUser": {"SDN.Use", "SDN.Audit"},
    # docs/status/proxmox-setup.md (as updated by provider-proxmox analysis)
    "OULabProvisioner": {"VM.Allocate", "VM.Clone", "VM.Audit", "VM.PowerMgmt", "VM.Config.CDROM", "VM.Config.CPU",
                         "VM.Config.Cloudinit", "VM.Config.Disk", "VM.Config.HWType", "VM.Config.Memory", "VM.Config.Network",
                         "VM.Config.Options", "VM.Snapshot", "VM.Snapshot.Rollback", "VM.Migrate", "Pool.Audit"},
    "Administrator": {"*"},
}


# Every privilege name a PVE 8/9 node accepts in `pveum role add --privs` (the simulator validates role privs against this).
KNOWN_PRIVS = {"Datastore.Allocate", "Datastore.AllocateSpace", "Datastore.AllocateTemplate", "Datastore.Audit", "Group.Allocate",
               "Mapping.Audit", "Mapping.Modify", "Mapping.Use", "Permissions.Modify", "Pool.Allocate", "Pool.Audit", "Realm.Allocate",
               "Realm.AllocateUser", "SDN.Allocate", "SDN.Audit", "SDN.Use", "Sys.Audit", "Sys.Console", "Sys.Incoming", "Sys.Modify",
               "Sys.PowerMgmt", "Sys.Syslog", "User.Modify", "VM.Allocate", "VM.Audit", "VM.Backup", "VM.Clone", "VM.Config.CDROM",
               "VM.Config.CPU", "VM.Config.Cloudinit", "VM.Config.Disk", "VM.Config.HWType", "VM.Config.Memory", "VM.Config.Network",
               "VM.Config.Options", "VM.Console", "VM.GuestAgent.Audit", "VM.GuestAgent.FileRead", "VM.GuestAgent.FileSystemMgmt",
               "VM.GuestAgent.FileWrite", "VM.GuestAgent.Unrestricted", "VM.Migrate", "VM.Monitor", "VM.PowerMgmt", "VM.Snapshot",
               "VM.Snapshot.Rollback"}


class HTTPErr(Exception):
    def __init__(self, code, reason):
        self.code, self.reason = code, reason


def _kv(s):
    return dict(p.split("=", 1) for p in s.split(",") if "=" in p)


class PveSim:
    def __init__(self, task_delay=0.2, cluster="simcluster"):
        self.lock = threading.RLock()
        self.cluster = cluster
        self.task_delay = task_delay
        self.hang_tasks = False
        self.tokens: dict[str, dict] = {}
        self.roles = {k: set(v) for k, v in ROLES.items()}
        self.nodes = {}
        self.storages: dict[str, dict] = {}
        self.bridges: dict[str, dict] = {}
        self.sdn_zones: dict[str, dict] = {}
        self.sdn_vnets: dict[str, dict] = {}
        self.pools: set[str] = set()
        self.vms: dict[int, dict] = {}
        self.tasks: dict[str, dict] = {}
        self.failures: list[dict] = []
        self.fail_task_exit: str | None = None
        self.quorate = True
        self.version = {"version": "8.2.4", "release": "8.2", "repoid": SIM_MARKER}
        self.gzip = True
        self.seen: list[tuple[str, str]] = []
        self._pid = 1000
        # --- access control (users / API tokens / ACL entries / tickets); legacy `tokens[tid]["acl"]` lists keep working ---
        self.builtin_roles = set(ROLES)
        self.users: dict[str, dict] = {}
        self.acl_entries: list[dict] = []     # {"path","type":"user"|"token","ugid","roleid","propagate"}
        self.tickets: dict[str, str] = {}     # ticket -> userid
        self.changes: list[str] = []          # every REAL state change in the access-control model (idempotency tests)
        self.fw_cluster: dict = {}            # GET /cluster/firewall/options
        self.fw_nodes: dict = {}              # node -> {"options": {...}, "rules": [...]}
        self.write_calls: list[tuple[str, str]] = []   # every non-GET request that reached a route

    # ---------------- setup helpers ----------------
    def add_role(self, name, privs):
        self.roles[name] = set(privs)

    def add_token(self, tid, secret, acl):
        """acl = [(path, role)]"""
        self.tokens[tid] = {"secret": secret, "acl": list(acl)}

    def add_user(self, userid, password=None, comment="", enable=1, roles=()):
        """roles = [(path, role)] granted to the user directly (not to tokens)."""
        self.users[userid] = {"password": password, "comment": comment, "enable": enable, "tokens": {}}
        for path, role in roles:
            self.acl_entries.append({"path": path, "type": "user", "ugid": userid, "roleid": role, "propagate": 1})

    def add_node(self, name, status="online", cpus=8, mem=32 << 30):
        self.nodes[name] = {"node": name, "status": status, "maxcpu": cpus, "maxmem": mem, "maxdisk": 500 << 30,
                            "uptime": 100000, "ip": f"10.0.0.{len(self.nodes) + 10}"}

    def add_storage(self, name, type_="lvmthin", content="images,rootdir", shared=False, total=200 << 30, nodes=None):
        self.storages[name] = {"storage": name, "type": type_, "content": content, "shared": int(shared), "total": total,
                               "nodes": nodes or list(self.nodes)}

    def add_vm(self, vmid, node, name, kind="qemu", status="stopped", tags="", pool=None, template=False, disk_gb=8,
               storage="local-lvm", cores=2, memory=2048, bridge="vmbr0"):
        cfg = {"name": name, "cores": cores, "memory": memory, "net0": f"virtio=BC:24:11:00:00:{vmid % 256:02X},bridge={bridge},firewall=1"}
        if kind == "qemu":
            cfg["scsi0"] = f"{storage}:vm-{vmid}-disk-0,size={disk_gb}G"
        else:
            cfg["rootfs"] = f"{storage}:subvol-{vmid}-disk-0,size={disk_gb}G"
        if tags:
            cfg["tags"] = tags
        if template:
            cfg["template"] = 1
        self.vms[vmid] = {"vmid": vmid, "node": node, "kind": kind, "status": status, "pool": pool, "cfg": cfg, "snapshots": {},
                          "lock": None}
        if pool:
            self.pools.add(pool)

    def populate_default(self):
        self.add_node("pve1")
        self.add_node("pve2")
        self.add_storage("local", "dir", "iso,backup,vztmpl,snippets")
        self.add_storage("local-lvm", "lvmthin", "images,rootdir")
        self.add_storage("other-lvm", "lvmthin", "images,rootdir")
        self.bridges = {"vmbr0": {"vlan_aware": 0, "ports": "eno1", "cidr": "10.0.0.2/24"},
                        "vmbr1": {"vlan_aware": 1, "ports": "eno2", "cidr": None}}
        self.sdn_zones = {"zlab": {"zone": "zlab", "type": "vlan"}}
        self.sdn_vnets = {"vn1": {"vnet": "vn1", "zone": "zlab", "tag": 100}}
        self.pools |= {"ou-lab", "other"}
        self.add_vm(9000, "pve1", "debian12-tmpl", pool="ou-lab", template=True, tags="ou-template")
        self.add_vm(9100, "pve1", "foreign-tmpl", pool="other", template=True)
        self.add_vm(100, "pve1", "web01", status="running")                      # not in the pool, untagged
        self.add_vm(150, "pve1", "owned", pool="ou-lab", tags="ou-managed;ou-deployment-d1")
        self.add_vm(160, "pve1", "pool-but-untagged", pool="ou-lab")
        self.add_vm(170, "pve1", "other-deployment", pool="ou-lab", tags="ou-managed;ou-deployment-d2")
        self.add_vm(200, "pve2", "foreign", pool="other", tags="ou-managed;ou-deployment-d1")  # tagged but wrong pool
        self.add_token("ics-inv@pve!inventory", "invsecret0123456789", [("/", "PVEAuditor")])
        self.add_token("ics-lab@pve!lab", "labsecret0123456789", [
            ("/pool/ou-lab", "OULabProvisioner"), ("/storage/local-lvm", "PVEDatastoreUser"),
            ("/sdn/zones/localnetwork/vmbr1", "PVESDNUser"), ("/sdn/zones/zlab/vn1", "PVESDNUser")])
        self.add_token("ics-root@pam!root", "rootsecret0123456789", [("/", "Administrator")])

    def populate_realworld(self, fixed=False):
        """The owner's first real cluster as the lead observed it (PVE 9.2.21): 6 nodes but Sys.Audit only on pve06; one lvmthin storage
        with images,rootdir only; one pool; the ICS's own VM 126 (MAC BC:24:11:E7:F0:24) with mutating ACLs; no SDN.Use, no Pool.Audit."""
        self.version = {"version": "9.2.21", "release": "9.2", "repoid": "realworld0000"}
        self.cluster = "agit8or"
        for n in ("pve01", "pve2", "pve3", "pve04", "pve05", "pve06"):
            self.add_node(n, cpus=56, mem=251 << 30)
        self.add_storage("PVE06-Storage", "lvmthin", "images,rootdir", total=11140 << 30, nodes=["pve06"])
        self.bridges = {"vmbr0": {"vlan_aware": 0, "ports": "eno1", "cidr": "192.168.22.17/24"}}
        self.pools.add("officeunbound-pve06")
        self.add_vm(126, "pve06", "office-unbound", status="running", cores=24, memory=16384, bridge="vmbr0")
        self.vms[126]["cfg"]["net0"] = "virtio=BC:24:11:E7:F0:24,bridge=vmbr0,firewall=0"
        self.vms[126]["cfg"]["smbios1"] = "uuid=11111111-2222-3333-4444-555555555555"
        self.add_role("OUProv", {"VM.Allocate", "VM.Audit", "VM.Backup", "VM.Clone", "VM.Config.CDROM", "VM.Config.CPU", "VM.Config.Cloudinit",
                                 "VM.Config.Disk", "VM.Config.HWType", "VM.Config.Memory", "VM.Config.Network", "VM.Config.Options",
                                 "VM.Console", "VM.GuestAgent.Audit", "VM.PowerMgmt", "VM.Snapshot", "VM.Snapshot.Rollback"})
        self.add_role("NodeAudit", {"Sys.Audit"})
        self.add_token("officeunbound@pam!ics", "realsecret0123456789", [
            ("/nodes/pve06", "NodeAudit"), ("/pool/officeunbound-pve06", "OUProv"), ("/vms/126", "OUProv"),
            ("/storage/PVE06-Storage", "PVEDatastoreUser")])
        self.bridges["vmbr0"]["ports"] = "nic3"
        self.add_vm(131, "pve06", "ou-debian12-template", template=True, pool="officeunbound-pve06", disk_gb=8, storage="PVE06-Storage")
        if fixed:  # after the owner's ACL fixes: Pool.Audit + SDN.Use, VM.Console dropped, ICS VM is now a pool MEMBER
            self.roles["OUProv"] = (self.roles["OUProv"] | {"Pool.Audit"}) - {"VM.Console", "VM.Backup"}
            self.tokens["officeunbound@pam!ics"]["acl"] += [("/sdn/zones/localnetwork/vmbr0", "PVESDNUser")]
            self.vms[126]["pool"] = "officeunbound-pve06"

    ROOT_PW = "rootpw-sim-only-0123"

    def populate_owner_env(self, ics_vm_in_pool=False, pve_version="9.2.21"):
        """The owner's real environment (shape only): 6 nodes, ONLY pve06 is to be authorized; storages PVE06-Storage (lvmthin, pve06),
        ha-zfs (shared, must stay unauthorized) and PBS1 (backup, unauthorized); an existing officeunbound@pam user; template VMs 9612
        (Ubuntu 24.04) and 131 (Debian 12); the ICS's own VM 126 (protected). root@pam / ROOT_PW is the temporary provisioning identity."""
        self.version = {"version": pve_version, "release": ".".join(pve_version.split(".")[:2]), "repoid": SIM_MARKER}
        self.cluster = "agit8or"
        for n in ("pve01", "pve2", "pve3", "pve04", "pve05", "pve06"):
            self.add_node(n, cpus=56, mem=251 << 30)
        self.add_storage("PVE06-Storage", "lvmthin", "images,rootdir", total=11140 << 30, nodes=["pve06"])
        self.add_storage("ha-zfs", "zfspool", "images,rootdir", shared=True, total=4000 << 30)
        self.add_storage("PBS1", "pbs", "backup", shared=True, total=20000 << 30)
        self.bridges = {"vmbr0": {"vlan_aware": 0, "ports": "nic3", "cidr": "192.168.22.17/24"}}
        self.pools |= {"officeunbound-pve06", "other-team"}
        self.add_vm(126, "pve06", "office-unbound", status="running", cores=24, memory=16384, bridge="vmbr0", storage="PVE06-Storage",
                    pool="officeunbound-pve06" if ics_vm_in_pool else None)
        self.vms[126]["cfg"]["net0"] = "virtio=BC:24:11:E7:F0:24,bridge=vmbr0,firewall=0"
        self.add_vm(9612, "pve06", "ubuntu-2404-template", template=True, storage="PVE06-Storage", disk_gb=10)
        self.add_vm(131, "pve06", "debian-12-template", template=True, storage="PVE06-Storage", disk_gb=8)
        self.add_vm(300, "pve01", "customer-db", status="running", storage="ha-zfs", pool="other-team")
        self.add_user("root@pam", password=self.ROOT_PW, comment="provisioning (simulator)", roles=[("/", "Administrator")])
        self.add_user("officeunbound@pam", password=None, comment="pre-existing ICS user", roles=[("/pool/officeunbound-pve06", "PVEAuditor")])
        self.users["officeunbound@pam"]["tokens"]["ics"] = {"privsep": 1, "comment": "pre-existing", "expire": 0, "secret": "preexisting0123456789"}
        self.tokens["officeunbound@pam!ics"] = {"secret": "preexisting0123456789", "acl": [], "user": "officeunbound@pam", "privsep": 1}
        self.acl_entries.append({"path": "/pool/officeunbound-pve06", "type": "token", "ugid": "officeunbound@pam!ics",
                                 "roleid": "PVEAuditor", "propagate": 1})

    def fail(self, method, pattern, status=500, reason="injected failure", count=1):
        self.failures.append({"m": method, "re": re.compile(pattern), "s": status, "r": reason, "n": count})

    # ---------------- permissions ----------------
    def _chain(self, kind, ident=None):
        if kind == "root":
            return ["/"]
        if kind == "vm":
            vm = self.vms[ident]
            return [f"/vms/{ident}"] + ([f"/pool/{vm['pool']}"] if vm["pool"] else []) + ["/"]
        if kind == "pool":
            return [f"/pool/{ident}", "/"]
        if kind == "storage":
            return [f"/storage/{ident}", "/"]
        if kind == "node":
            return [f"/nodes/{ident}", "/"]
        if kind == "sdn":
            z = "localnetwork" if ident in self.bridges else self.sdn_vnets.get(ident, {}).get("zone", "localnetwork")
            return [f"/sdn/zones/{z}/{ident}", f"/sdn/zones/{z}", "/sdn/zones", "/sdn", "/"]
        if kind == "path":
            parts = ident.strip("/").split("/")
            return ["/" + "/".join(parts[:i]) for i in range(len(parts), 0, -1)] + ["/"]
        raise KeyError(kind)

    @staticmethod
    def _inter(a, b):
        if "*" in a:
            return set(b)
        if "*" in b:
            return set(a)
        return set(a) & set(b)

    def _acl_privs(self, typ, ugid, chain):
        out = set()
        for e in self.acl_entries:
            if e["type"] == typ and e["ugid"] == ugid and e["path"] in chain and (e["path"] == chain[0] or e["propagate"]):
                out |= self.roles.get(e["roleid"], set())
        return out

    def _user_ok(self, userid):
        u = self.users.get(userid)
        return bool(u and u.get("enable"))

    def privs(self, tid, chain):
        if "!" not in tid:                                  # a ticket-authenticated user
            return self._acl_privs("user", tid, chain) if self._user_ok(tid) else set()
        tok = self.tokens[tid]
        out = set()
        for path, role in tok["acl"]:
            if path in chain:
                out |= self.roles[role]
        if "user" in tok:                                   # API-created token: real PVE semantics
            if not self._user_ok(tok["user"]):
                return out
            userp = self._acl_privs("user", tok["user"], chain)
            tokp = self._acl_privs("token", tid, chain)
            out |= self._inter(tokp, userp) if tok.get("privsep") else userp
        return out

    def need(self, tid, kind, ident, priv):
        chain = self._chain(kind, ident)
        p = self.privs(tid, chain)
        if "*" not in p and priv not in p:
            raise HTTPErr(403, f"Permission check failed ({chain[0]}, {priv})")

    def can(self, tid, kind, ident, *privs):
        p = self.privs(tid, self._chain(kind, ident))
        return "*" in p or any(x in p for x in privs)

    # ---------------- tasks ----------------
    def _task(self, node, ttype, ident, tid, effect=None, exit_ok=True):
        self._pid += 1
        start = int(time.time())
        upid = f"UPID:{node}:{self._pid:08X}:{self._pid:08X}:{start:08X}:{ttype}:{ident}:{tid}:"
        done_at = float("inf") if self.hang_tasks else time.monotonic() + self.task_delay
        exit_ = "OK" if exit_ok else "command failed"
        if self.fail_task_exit:
            exit_, self.fail_task_exit = self.fail_task_exit, None
        self.tasks[upid] = {"node": node, "type": ttype, "id": ident, "user": tid, "start": start, "done_at": done_at,
                            "effect": effect, "exit": exit_, "finished": False,
                            "log": [f"starting task {ttype}", "TASK OK" if exit_ == "OK" else f"TASK ERROR: {exit_}"]}
        return upid

    def _settle(self):
        now = time.monotonic()
        for t in self.tasks.values():
            if not t["finished"] and now >= t["done_at"]:
                t["finished"] = True
                if t["effect"] and t["exit"] == "OK":
                    t["effect"]()

    # ---------------- guest views ----------------
    def _disk_used(self, storage):
        n = 0
        for vm in self.vms.values():
            for k, v in vm["cfg"].items():
                if isinstance(v, str) and v.startswith(storage + ":") and "size=" in v:
                    n += _size(_kv(v.split(",", 1)[1]).get("size", "0G"))
        return n

    def _res_vm(self, vm):
        c = vm["cfg"]
        run = vm["status"] == "running"
        lag = vm.get("res_lag", 0)   # real PVE 9.2: /cluster/resources is a cache; a fresh clone shows up WITHOUT its name for a few seconds
        if lag:
            vm["res_lag"] = lag - 1
        d = {"id": f"{vm['kind']}/{vm['vmid']}", "type": vm["kind"], "vmid": vm["vmid"], "node": vm["node"], "name": None if lag else c.get("name"),
             "status": vm.get("cached_status", vm["status"]), "maxcpu": c.get("cores", 1), "cpu": 0.03 if run else 0, "maxmem": c.get("memory", 512) << 20,
             "mem": (c.get("memory", 512) << 20) // 4 if run else 0, "maxdisk": self._vm_disk(vm), "disk": 0,
             "uptime": 5000 if run else 0, "netin": 1000, "netout": 500, "template": 1 if c.get("template") else 0}
        if c.get("tags"):
            d["tags"] = c["tags"]
        if vm["pool"]:
            d["pool"] = vm["pool"]
        return d

    def _vm_disk(self, vm):
        return sum(_size(_kv(v.split(",", 1)[1]).get("size", "0G")) for k, v in vm["cfg"].items()
                   if isinstance(v, str) and re.match(r"^(scsi|virtio|sata|ide)\d+$|^rootfs$", k) and "size=" in v)

    def _find(self, node, vmid, kind):
        vm = self.vms.get(vmid)
        if not vm or vm["kind"] != kind:
            raise HTTPErr(500, f"Configuration file 'nodes/{node}/{kind}/{vmid}.conf' does not exist")
        if vm["node"] != node:
            raise HTTPErr(500, f"Configuration file 'nodes/{node}/{kind}/{vmid}.conf' does not exist")
        return vm

    # ---------------- request handling ----------------
    def handle(self, method, rawpath, form, auth):
        with self.lock:
            self.seen.append((method, rawpath))
            self._settle()
            for f in list(self.failures):
                if f["m"] == method and f["re"].search(rawpath) and f["n"] > 0:
                    f["n"] -= 1
                    raise HTTPErr(f["s"], f["r"])
            u = urllib.parse.urlsplit(rawpath)
            path = u.path.removeprefix("/api2/json")
            q = dict(urllib.parse.parse_qsl(u.query))
            if method == "POST" and path == "/access/ticket":
                return self.r_ticket(form)
            tid = self._auth(auth)
            if method != "GET":
                self.write_calls.append((method, path))
                if auth.startswith("TICKET ") and auth.split(" ", 2)[2] != self._csrf(tid):
                    raise HTTPErr(401, "Invalid CSRF token")
            for m, rx, fn in self._routes():
                if m == method:
                    mt = rx.fullmatch(path)
                    if mt:
                        return fn(tid, q, form, *mt.groups())
            raise HTTPErr(501, f"Method '{method} {path}' not implemented")

    def _auth(self, auth):
        if auth and auth.startswith("TICKET "):
            _, ticket, csrf = (auth.split(" ", 2) + ["", ""])[:3]
            uid = self.tickets.get(ticket)
            if not uid or not self._user_ok(uid):
                raise HTTPErr(401, "invalid ticket")
            return uid
        m = re.fullmatch(r"PVEAPIToken=([^=]+)=(.+)", auth or "")
        if not m or m.group(1) not in self.tokens or self.tokens[m.group(1)]["secret"] != m.group(2):
            raise HTTPErr(401, "No ticket")
        return m.group(1)

    def _routes(self):
        R = lambda m, p, f: (m, re.compile(p), f)  # noqa: E731
        g = r"(qemu|lxc)"
        return [
            R("GET", r"/version", self.r_version), R("GET", r"/cluster/status", self.r_cluster_status),
            R("GET", r"/cluster/resources", self.r_resources), R("GET", r"/cluster/nextid", self.r_nextid), R("GET", r"/cluster/log", self.r_cluster_log),
            R("GET", r"/cluster/firewall/options", lambda *a: dict(self.fw_cluster)),
            R("GET", r"/nodes/([^/]+)/firewall/options", lambda tid, q, f, n: dict(self.fw_nodes.get(n, {}).get("options", {}))),
            R("GET", r"/nodes/([^/]+)/firewall/rules", lambda tid, q, f, n: list(self.fw_nodes.get(n, {}).get("rules", []))),
            R("GET", r"/nodes", self.r_nodes), R("GET", r"/pools/([^/]+)", self.r_pool), R("GET", r"/storage", self.r_storage_cfg),
            R("GET", r"/cluster/sdn/zones", self.r_zones), R("GET", r"/cluster/sdn/vnets", self.r_vnets),
            R("GET", r"/access/permissions", self.r_permissions),
            R("GET", r"/access/users", self.r_users), R("POST", r"/access/users", self.r_user_add),
            R("GET", r"/access/users/([^/]+)", self.r_user_get), R("PUT", r"/access/users/([^/]+)", self.r_user_set),
            R("DELETE", r"/access/users/([^/]+)", self.r_user_del),
            R("GET", r"/access/users/([^/]+)/token", self.r_tokens), R("GET", r"/access/users/([^/]+)/token/([^/]+)", self.r_token_get),
            R("POST", r"/access/users/([^/]+)/token/([^/]+)", self.r_token_add), R("PUT", r"/access/users/([^/]+)/token/([^/]+)", self.r_token_set),
            R("DELETE", r"/access/users/([^/]+)/token/([^/]+)", self.r_token_del),
            R("GET", r"/access/roles", self.r_roles), R("POST", r"/access/roles", self.r_role_add),
            R("GET", r"/access/roles/([^/]+)", self.r_role_get), R("PUT", r"/access/roles/([^/]+)", self.r_role_set),
            R("DELETE", r"/access/roles/([^/]+)", self.r_role_del),
            R("GET", r"/access/groups", lambda *a: []),
            R("GET", r"/access/acl", self.r_acl), R("PUT", r"/access/acl", self.r_acl_set),
            R("GET", r"/pools", self.r_pools), R("POST", r"/pools", self.r_pool_add), R("DELETE", r"/pools/([^/]+)", self.r_pool_del),
            R("GET", r"/nodes/([^/]+)/" + g, self.r_list_guests),
            R("GET", r"/nodes/([^/]+)/storage/([^/]+)/content", self.r_content),
            R("POST", r"/nodes/([^/]+)/storage/([^/]+)/upload", self.r_upload), R("POST", r"/nodes/([^/]+)/qemu", self.r_create),
            R("POST", r"/nodes/([^/]+)/qemu/(\d+)/template", self.r_template),
            R("GET", r"/nodes/([^/]+)/storage", self.r_node_storage), R("GET", r"/nodes/([^/]+)/network", self.r_network),
            R("GET", r"/nodes/([^/]+)/rrddata", self.r_rrd_node),
            R("GET", r"/nodes/([^/]+)/" + g + r"/(\d+)/rrddata", self.r_rrd_vm),
            R("GET", r"/nodes/([^/]+)/" + g + r"/(\d+)/config", self.r_get_config),
            R("GET", r"/nodes/([^/]+)/" + g + r"/(\d+)/status/current", self.r_status_current),
            R("PUT", r"/nodes/([^/]+)/" + g + r"/(\d+)/config", self.r_set_config),
            R("POST", r"/nodes/([^/]+)/" + g + r"/(\d+)/config", self.r_set_config),
            R("PUT", r"/nodes/([^/]+)/" + g + r"/(\d+)/resize", self.r_resize),
            R("POST", r"/nodes/([^/]+)/" + g + r"/(\d+)/clone", self.r_clone),
            R("POST", r"/nodes/([^/]+)/" + g + r"/(\d+)/status/(start|stop|shutdown|reboot)", self.r_power),
            R("POST", r"/nodes/([^/]+)/" + g + r"/(\d+)/snapshot", self.r_snapshot),
            R("POST", r"/nodes/([^/]+)/" + g + r"/(\d+)/snapshot/([^/]+)/rollback", self.r_rollback),
            R("POST", r"/nodes/([^/]+)/" + g + r"/(\d+)/migrate", self.r_migrate),
            R("DELETE", r"/nodes/([^/]+)/" + g + r"/(\d+)", self.r_destroy),
            R("GET", r"/nodes/([^/]+)/tasks/([^/]+)/status", self.r_task_status),
            R("GET", r"/nodes/([^/]+)/tasks/([^/]+)/log", self.r_task_log),
        ]

    def _node_up(self, node):
        if node not in self.nodes:
            raise HTTPErr(500, f"hostname lookup '{node}' failed - failed to get address info for: {node}")
        if self.nodes[node]["status"] != "online":
            raise HTTPErr(595, f"No route to host")

    # ---- reads
    def r_version(self, tid, q, f):
        return dict(self.version)

    def r_cluster_status(self, tid, q, f):
        out = [{"type": "cluster", "name": self.cluster, "version": 3, "nodes": len(self.nodes), "quorate": int(self.quorate), "id": "cluster"}]
        for n in self.nodes.values():
            out.append({"type": "node", "name": n["node"], "id": f"node/{n['node']}", "online": int(n["status"] == "online"),
                        "ip": n["ip"], "local": 1 if n["node"] == getattr(self, "local_node", None) else 0, "nodeid": 1, "level": ""})
        return out

    def r_nodes(self, tid, q, f):
        # like PVE: every node is listed; without Sys.Audit the usage figures are zero (NOT idle capacity)
        out = []
        for n in self.nodes.values():
            vis = self.can(tid, "node", n["node"], "Sys.Audit")
            out.append({"node": n["node"], "status": n["status"], "cpu": 0.05 if vis else 0, "maxcpu": n["maxcpu"] if vis else 0,
                        "mem": n["maxmem"] // 4 if vis else 0, "maxmem": n["maxmem"] if vis else 0, "disk": (1 << 30) if vis else 0,
                        "maxdisk": n["maxdisk"] if vis else 0, "uptime": n["uptime"] if vis else 0, "level": "", "id": f"node/{n['node']}"})
        return out

    def r_resources(self, tid, q, f):
        t = q.get("type")
        out = []
        if t in (None, "node"):
            for n in self.nodes.values():
                if self.can(tid, "node", n["node"], "Sys.Audit"):
                    out.append({"id": f"node/{n['node']}", "type": "node", "node": n["node"], "status": n["status"], "cpu": 0.05,
                                "maxcpu": n["maxcpu"], "mem": n["maxmem"] // 4, "maxmem": n["maxmem"], "disk": 1 << 30,
                                "maxdisk": n["maxdisk"], "uptime": n["uptime"], "level": ""})
        if t in (None, "vm"):
            out += [self._res_vm(v) for v in self.vms.values() if self.can(tid, "vm", v["vmid"], "VM.Audit")]
        if t in (None, "storage"):
            for s in self.storages.values():
                if self.can(tid, "storage", s["storage"], "Datastore.Audit", "Datastore.AllocateSpace"):
                    for n in s["nodes"]:
                        out.append({"id": f"storage/{n}/{s['storage']}", "type": "storage", "storage": s["storage"], "node": n,
                                    "status": "available", "content": s["content"], "shared": s["shared"], "plugintype": s["type"],
                                    "disk": self._disk_used(s["storage"]), "maxdisk": s["total"]})
        if t in (None, "sdn") and self.can(tid, "root", None, "SDN.Audit"):
            for z in self.sdn_zones:
                for n in self.nodes:
                    out.append({"id": f"sdn/{n}/{z}", "type": "sdn", "sdn": z, "node": n, "status": "ok"})
        return out

    def r_pool(self, tid, q, f, pool):
        self.need(tid, "pool", pool, "Pool.Audit")
        return {"poolid": pool, "members": [{"vmid": v["vmid"], "node": v["node"], "type": v["kind"]} for v in self.vms.values() if v["pool"] == pool]}

    def r_nextid(self, tid, q, f):
        n = 100
        while n in self.vms:
            n += 1
        return str(n)

    def r_storage_cfg(self, tid, q, f):
        return [{"storage": s["storage"], "type": s["type"], "content": s["content"], "shared": s["shared"],
                 "nodes": ",".join(s["nodes"]) if len(s["nodes"]) != len(self.nodes) else None,
                 **{k: s[k] for k in ("vgname", "thinpool", "pool") if k in s}}
                for s in self.storages.values() if self.can(tid, "storage", s["storage"], "Datastore.Audit", "Datastore.AllocateSpace")]

    def r_node_storage(self, tid, q, f, node):
        self._node_up(node)
        return [{"storage": s["storage"], "type": s["type"], "content": s["content"], "shared": s["shared"], "active": 1,
                 "enabled": 1, "total": s["total"], "used": self._disk_used(s["storage"]), "avail": s["total"] - self._disk_used(s["storage"])}
                for s in self.storages.values() if node in s["nodes"]
                and self.can(tid, "storage", s["storage"], "Datastore.Audit", "Datastore.AllocateSpace")]

    def r_content(self, tid, q, f, node, storage):
        if storage not in self.storages or node not in self.storages[storage]["nodes"]:
            raise HTTPErr(500, f"storage '{storage}' does not exist")
        self.need(tid, "storage", storage, "Datastore.Audit") if not self.can(tid, "storage", storage, "Datastore.AllocateSpace") else None
        out = []
        for vm in self.vms.values():
            for k, v in vm["cfg"].items():
                if isinstance(v, str) and v.startswith(storage + ":") and "size=" in v and self.can(tid, "vm", vm["vmid"], "VM.Audit"):
                    out.append({"volid": v.split(",")[0], "vmid": vm["vmid"], "size": _size(_kv(v.split(",", 1)[1]).get("size")),
                                "format": "raw", "content": "images"})
        out += [{"volid": f"{storage}:hidden", "vmid": 0, "size": h, "format": "raw", "content": "images"}
                for h in self.storages[storage].get("hidden_volumes", [])]
        return out

    def r_network(self, tid, q, f, node):
        self.need(tid, "node", node, "Sys.Audit")
        self._node_up(node)
        out = [{"iface": "eno1", "type": "eth", "active": 1}]
        for b, v in self.bridges.items():
            d = {"iface": b, "type": "bridge", "active": 1, "bridge_ports": v["ports"], "bridge_vlan_aware": v["vlan_aware"]}
            if v["cidr"]:
                d["cidr"] = v["cidr"]
            out.append(d)
        return out

    def r_zones(self, tid, q, f):
        self.need(tid, "root", None, "SDN.Audit")
        return list(self.sdn_zones.values())

    def r_vnets(self, tid, q, f):
        self.need(tid, "root", None, "SDN.Audit")
        return list(self.sdn_vnets.values())

    def _all_privs(self):
        return set().union(*(r for r in self.roles.values())) - {"*"}

    def r_permissions(self, tid, q, f):
        who = q.get("userid") or tid
        if who != tid and not self.can(tid, "path", "/access", "Permissions.Modify", "User.Modify", "Sys.Audit"):
            raise HTTPErr(403, "Permission check failed (/access, Permissions.Modify)")
        if ("!" in who and who not in self.tokens) or ("!" not in who and who not in self.users):
            raise HTTPErr(500, f"no such user '{who}'")
        if "path" in q:
            ps = [q["path"]]
        else:
            paths = {"/"} | {p for p, _ in self.tokens.get(who, {}).get("acl", [])} | {e["path"] for e in self.acl_entries
                                                                                      if e["ugid"] in (who, who.split("!")[0])}
            ps = sorted(paths)
        out = {}
        for p in ps:
            pr = self.privs(who, self._chain("path", p))
            if "*" in pr:
                pr = self._all_privs()
            if pr or "path" in q:
                out[p] = {x: 1 for x in sorted(pr)}
        return out

    # ---------------- access control ----------------
    def _csrf(self, uid):
        return "csrf-" + uid

    def r_ticket(self, f):
        uid, pw = f.get("username", ""), f.get("password", "")
        u = self.users.get(uid)
        if not u or not u.get("enable") or not u.get("password") or u["password"] != pw:
            raise HTTPErr(401, "authentication failure")
        ticket = f"PVE:{uid}:{len(self.tickets):08X}::sim"
        self.tickets[ticket] = uid
        return {"ticket": ticket, "CSRFPreventionToken": self._csrf(uid), "username": uid}

    def _read_access(self, tid):
        if not self.can(tid, "path", "/", "Sys.Audit", "Permissions.Modify", "User.Modify"):
            raise HTTPErr(403, "Permission check failed (/access, User.Modify)")

    def _need_at(self, tid, path, priv):
        if not self.can(tid, "path", path, priv):
            raise HTTPErr(403, f"Permission check failed ({path}, {priv})")

    def _log(self, what):
        self.changes.append(what)

    @staticmethod
    def _pub(d):
        return {k: v for k, v in d.items() if k != "secret"}

    def r_users(self, tid, q, f):
        self._read_access(tid)
        return [{"userid": k, "enable": v["enable"], "comment": v["comment"],
                 "tokens": [{"tokenid": t, **self._pub(d)} for t, d in v["tokens"].items()]} for k, v in self.users.items()]

    def r_user_add(self, tid, q, f):
        self._need_at(tid, "/access", "User.Modify")
        uid = f.get("userid", "")
        if not re.fullmatch(r"[^@\s!]+@[A-Za-z0-9._-]+", uid):
            raise HTTPErr(400, "Parameter verification failed: userid")
        if uid in self.users:
            raise HTTPErr(500, f"User '{uid}' already exists")
        self.users[uid] = {"password": f.get("password"), "comment": f.get("comment", ""), "enable": int(f.get("enable", 1)), "tokens": {}}
        self._log(f"user+{uid}")

    def _user(self, uid):
        if uid not in self.users:
            raise HTTPErr(500, f"no such user ('{uid}')")
        return self.users[uid]

    def r_user_get(self, tid, q, f, uid):
        self._read_access(tid)
        u = self._user(uid)
        return {"enable": u["enable"], "comment": u["comment"], "tokens": {t: self._pub(d) for t, d in u["tokens"].items()}}

    def r_user_set(self, tid, q, f, uid):
        self._need_at(tid, "/access", "User.Modify")
        u = self._user(uid)
        for k in ("comment", "enable"):
            if k in f:
                u[k] = int(f[k]) if k == "enable" else f[k]
        self._log(f"user~{uid}")

    def r_user_del(self, tid, q, f, uid):
        self._need_at(tid, "/access", "User.Modify")
        self._user(uid)
        for t in list(self.users[uid]["tokens"]):
            self._drop_token(uid, t)
        self.acl_entries = [e for e in self.acl_entries if not (e["type"] == "user" and e["ugid"] == uid)]
        del self.users[uid]
        self._log(f"user-{uid}")

    def r_tokens(self, tid, q, f, uid):
        self._read_access(tid)
        return [{"tokenid": t, **self._pub(d)} for t, d in self._user(uid)["tokens"].items()]

    def r_token_get(self, tid, q, f, uid, t):
        self._read_access(tid)
        d = self._user(uid)["tokens"].get(t)
        if d is None:
            raise HTTPErr(500, f"no such token '{t}'")
        return self._pub(d)

    def r_token_add(self, tid, q, f, uid, t):
        self._need_at(tid, "/access", "User.Modify")
        u = self._user(uid)
        if t in u["tokens"]:
            raise HTTPErr(500, f"Token already exists: {uid}!{t}")
        import secrets as _s
        secret = _s.token_urlsafe(24)
        ps = int(f.get("privsep", 1))
        u["tokens"][t] = {"privsep": ps, "comment": f.get("comment", ""), "expire": int(f.get("expire", 0)), "secret": secret}
        self.tokens[f"{uid}!{t}"] = {"secret": secret, "acl": [], "user": uid, "privsep": ps}
        self._log(f"token+{uid}!{t}")
        return {"full-tokenid": f"{uid}!{t}", "info": {"privsep": str(ps), "comment": f.get("comment", "")}, "value": secret}

    def r_token_set(self, tid, q, f, uid, t):
        self._need_at(tid, "/access", "User.Modify")
        d = self._user(uid)["tokens"].get(t)
        if d is None:
            raise HTTPErr(500, f"no such token '{t}'")
        if "privsep" in f:
            d["privsep"] = int(f["privsep"])
            self.tokens[f"{uid}!{t}"]["privsep"] = d["privsep"]
        if "comment" in f:
            d["comment"] = f["comment"]
        self._log(f"token~{uid}!{t}")

    def _drop_token(self, uid, t):
        self.users[uid]["tokens"].pop(t, None)
        self.tokens.pop(f"{uid}!{t}", None)
        self.acl_entries = [e for e in self.acl_entries if not (e["type"] == "token" and e["ugid"] == f"{uid}!{t}")]

    def r_token_del(self, tid, q, f, uid, t):
        self._need_at(tid, "/access", "User.Modify")
        if t not in self._user(uid)["tokens"]:
            raise HTTPErr(500, f"no such token '{t}'")
        self._drop_token(uid, t)
        self._log(f"token-{uid}!{t}")

    def r_roles(self, tid, q, f):
        return [{"roleid": k, "privs": ",".join(sorted(v)), "special": int(k in self.builtin_roles)} for k, v in self.roles.items()]

    def r_role_get(self, tid, q, f, r):
        if r not in self.roles:
            raise HTTPErr(500, f"role '{r}' does not exist")
        return {p: 1 for p in sorted(self.roles[r])}

    @staticmethod
    def _privlist(s):
        return {p for p in re.split(r"[,\s;]+", s or "") if p}

    def _known_priv(self, ps):
        bad = sorted(p for p in ps if p not in KNOWN_PRIVS and p != "*")
        if bad:
            raise HTTPErr(400, f"Parameter verification failed: privs: invalid privilege '{bad[0]}'")

    def r_role_add(self, tid, q, f):
        self._need_at(tid, "/access", "Permissions.Modify")
        r = f.get("roleid", "")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", r):
            raise HTTPErr(400, "Parameter verification failed: roleid")
        if r in self.roles:
            raise HTTPErr(500, f"role '{r}' already exists")
        ps = self._privlist(f.get("privs"))
        self._known_priv(ps)
        self.roles[r] = ps
        self._log(f"role+{r}")

    def r_role_set(self, tid, q, f, r):
        self._need_at(tid, "/access", "Permissions.Modify")
        if r in self.builtin_roles:
            raise HTTPErr(500, f"role '{r}' is built-in and cannot be modified")
        if r not in self.roles:
            raise HTTPErr(500, f"role '{r}' does not exist")
        ps = self._privlist(f.get("privs"))
        self._known_priv(ps)
        new = (self.roles[r] | ps) if f.get("append") in ("1", 1, True) else ps
        if new != self.roles[r]:
            self.roles[r] = new
            self._log(f"role~{r}")

    def r_role_del(self, tid, q, f, r):
        self._need_at(tid, "/access", "Permissions.Modify")
        if r in self.builtin_roles:
            raise HTTPErr(500, f"role '{r}' is built-in and cannot be deleted")
        if r not in self.roles:
            raise HTTPErr(500, f"role '{r}' does not exist")
        del self.roles[r]
        self.acl_entries = [e for e in self.acl_entries if e["roleid"] != r]
        self._log(f"role-{r}")

    def r_acl(self, tid, q, f):
        self._read_access(tid)
        out = [{"path": e["path"], "type": e["type"], "ugid": e["ugid"], "roleid": e["roleid"], "propagate": e["propagate"]} for e in self.acl_entries]
        for t, d in self.tokens.items():
            out += [{"path": p, "type": "token", "ugid": t, "roleid": r, "propagate": 1} for p, r in d["acl"]]
        return out

    def r_acl_set(self, tid, q, f):
        path = f.get("path", "")
        if not re.fullmatch(r"/[A-Za-z0-9/._:@+-]*", path):
            raise HTTPErr(400, "Parameter verification failed: path")
        self._need_at(tid, path, "Permissions.Modify")
        roles = [x for x in re.split(r"[,\s]+", f.get("roles", "")) if x]
        subj = ([("user", x) for x in re.split(r"[,\s]+", f.get("users", "")) if x]
                + [("token", x) for x in re.split(r"[,\s]+", f.get("tokens", "")) if x])
        if not roles or not subj:
            raise HTTPErr(400, "Parameter verification failed: need roles and one of users/tokens")
        for r in roles:
            if r not in self.roles:
                raise HTTPErr(500, f"role '{r}' does not exist")
        for typ, ugid in subj:
            if typ == "user" and ugid not in self.users:
                raise HTTPErr(500, f"no such user ('{ugid}')")
            if typ == "token" and ugid not in self.tokens:
                raise HTTPErr(500, f"no such token '{ugid}'")
        prop = int(f.get("propagate", 1))
        delete = f.get("delete") in ("1", 1, True)
        for typ, ugid in subj:
            for r in roles:
                cur = [e for e in self.acl_entries if (e["path"], e["type"], e["ugid"], e["roleid"]) == (path, typ, ugid, r)]
                if delete:
                    if cur:
                        self.acl_entries.remove(cur[0])
                        self._log(f"acl-{path}|{ugid}|{r}")
                elif not cur:
                    self.acl_entries.append({"path": path, "type": typ, "ugid": ugid, "roleid": r, "propagate": prop})
                    self._log(f"acl+{path}|{ugid}|{r}")
                elif cur[0]["propagate"] != prop:
                    cur[0]["propagate"] = prop
                    self._log(f"acl~{path}|{ugid}|{r}")

    def r_pools(self, tid, q, f):
        return [{"poolid": p} for p in sorted(self.pools) if self.can(tid, "pool", p, "Pool.Audit", "Pool.Allocate")]

    def r_pool_add(self, tid, q, f):
        self._need_at(tid, "/pool", "Pool.Allocate")
        p = f.get("poolid", "")
        if p in self.pools:
            raise HTTPErr(500, f"pool '{p}' already exists")
        self.pools.add(p)
        self._log(f"pool+{p}")

    def r_pool_del(self, tid, q, f, p):
        self._need_at(tid, "/pool", "Pool.Allocate")
        if any(v["pool"] == p for v in self.vms.values()):
            raise HTTPErr(500, f"pool '{p}' is not empty")
        self.pools.discard(p)
        self._log(f"pool-{p}")

    def r_list_guests(self, tid, q, f, node, kind):
        self._node_up(node)
        return [{"vmid": v["vmid"], "name": v["cfg"].get("name"), "status": v["status"]} for v in self.vms.values()
                if v["node"] == node and v["kind"] == kind and self.can(tid, "vm", v["vmid"], "VM.Audit")]

    def r_status_current(self, tid, q, f, node, kind, vmid):
        vm = self._find(node, int(vmid), kind)
        self.need(tid, "vm", vm["vmid"], "VM.Audit")
        return {"vmid": vm["vmid"], "status": vm["status"], "name": vm["cfg"].get("name")}

    def r_get_config(self, tid, q, f, node, kind, vmid):
        vm = self._find(node, int(vmid), kind)
        self.need(tid, "vm", vm["vmid"], "VM.Audit")
        if str(q.get("current", "0")) in ("1", "true"):
            return {**vm["cfg"], "digest": "d" * 40}          # the ACTIVE config
        eff = dict(vm["cfg"])                                   # real PVE default: pending changes applied
        for k, v in vm.get("pending", {}).items():
            if v is None:
                eff.pop(k, None)
            else:
                eff[k] = v
        return {**eff, "digest": "d" * 40}

    def r_cluster_log(self, tid, q, f):
        """Real PVE: any user reads its OWN entries (Sys.Syslog on / reads all). Entries are written by update_vm (see r_set_config)."""
        return [e for e in getattr(self, "cluster_log", []) if e["user"] == tid][-int(q.get("max", 50) or 50):]

    def _series(self, timeframe, seed):
        n = {"hour": 60, "day": 288, "week": 168, "month": 240, "year": 366}.get(timeframe, 60)
        step = {"hour": 60, "day": 300, "week": 3600, "month": 7200, "year": 86400}.get(timeframe, 60)
        end = int(time.time()) // step * step
        return end, step, n

    def r_rrd_node(self, tid, q, f, node):
        self.need(tid, "node", node, "Sys.Audit")
        end, step, n = self._series(q.get("timeframe", "hour"), node)
        return [{"time": end - (n - i) * step, "cpu": 0.1 + 0.001 * i, "memused": (8 << 30) + i, "memtotal": 32 << 30,
                 "netin": 1000.0 + i, "netout": 500.0, "loadavg": 0.5, "iowait": 0.01, "roottotal": 100 << 30, "rootused": 10 << 30}
                for i in range(n)] + [{"time": end}]  # PVE appends a trailing sample with no data

    def r_rrd_vm(self, tid, q, f, node, kind, vmid):
        vm = self._find(node, int(vmid), kind)
        self.need(tid, "vm", vm["vmid"], "VM.Audit")
        end, step, n = self._series(q.get("timeframe", "hour"), vmid)
        return [{"time": end - (n - i) * step, "cpu": 0.02 + 0.0001 * i, "mem": 1 << 30, "maxmem": 2 << 30, "maxcpu": 2,
                 "netin": 200.0, "netout": 100.0, "diskread": 0.0, "diskwrite": 50.0, "disk": 0, "maxdisk": 8 << 30} for i in range(n)]

    def r_task_status(self, tid, q, f, node, upid):
        t = self.tasks.get(urllib.parse.unquote(upid))
        if not t or t["node"] != node:
            raise HTTPErr(500, "no such task")
        if t["user"] != tid:
            self.need(tid, "node", node, "Sys.Audit")
        d = {"upid": urllib.parse.unquote(upid), "node": node, "type": t["type"], "id": t["id"], "user": t["user"],
             "pid": 1, "pstart": 1, "starttime": t["start"], "status": "stopped" if t["finished"] else "running"}
        if t["finished"]:
            d["exitstatus"] = t["exit"]
        return d

    def r_task_log(self, tid, q, f, node, upid):
        t = self.tasks.get(urllib.parse.unquote(upid))
        if not t:
            raise HTTPErr(500, "no such task")
        return [{"n": i + 1, "t": line} for i, line in enumerate(t["log"] if t["finished"] else t["log"][:1])]

    # ---- writes
    def _unlocked(self, vm):
        if vm["lock"]:
            raise HTTPErr(500, f"VM is locked ({vm['lock']})")

    def r_clone(self, tid, q, f, node, kind, vmid):
        src = self._find(node, int(vmid), kind)
        self.need(tid, "vm", src["vmid"], "VM.Clone")
        newid = int(f.get("newid") or self.r_nextid(tid, {}, {}))
        pool, full = f.get("pool"), f.get("full", "0") == "1"
        if newid in self.vms:
            raise HTTPErr(500, f"unable to create VM {newid}: config file already exists")
        if pool:
            if pool not in self.pools:
                raise HTTPErr(500, f"pool '{pool}' does not exist")
            self.need(tid, "pool", pool, "VM.Allocate")
        else:
            self.need(tid, "root", None, "VM.Allocate")
        st = f.get("storage")
        if st:
            if st not in self.storages:
                raise HTTPErr(500, f"storage '{st}' does not exist")
            self.need(tid, "storage", st, "Datastore.AllocateSpace")
        if not full and not src["cfg"].get("template"):
            raise HTTPErr(500, "Linked clone feature is not available (source is not a template)")
        target = f.get("target") or node
        cfg = {k: v for k, v in src["cfg"].items() if k not in ("template", "tags")}
        cfg["name"] = f.get("name") or f"Copy-of-VM-{src['cfg'].get('name')}"
        if st and full:
            for k, v in list(cfg.items()):
                if isinstance(v, str) and re.match(r"^(scsi|virtio|sata|ide)\d+$|^rootfs$", k):
                    cfg[k] = f"{st}:" + v.split(":", 1)[1].replace(f"-{src['vmid']}-", f"-{newid}-")
        self.vms[newid] = {"vmid": newid, "node": target, "kind": kind, "status": "stopped", "pool": pool, "cfg": cfg,
                           "snapshots": {}, "lock": "clone"}

        def done():
            self.vms[newid]["lock"] = None
            self.vms[newid]["res_lag"] = getattr(self, "clone_res_lag", 0)
        return self._task(node, "qmclone" if kind == "qemu" else "vzclone", str(src["vmid"]), tid, done)  # PVE 9: source vmid, not the new one

    _CFG_PRIV = [(r"cores|sockets|vcpus|cpu", "VM.Config.CPU"), (r"memory|balloon", "VM.Config.Memory"),
                 (r"net\d+", "VM.Config.Network"), (r"(scsi|virtio|sata|ide)\d+|rootfs", "VM.Config.Disk"),
                 (r"ciuser|cipassword|sshkeys|ipconfig\d+|nameserver|searchdomain|citype|ciupgrade", "VM.Config.Cloudinit"),
                 (r"smbios1", "VM.Config.HWType"),
                 (r"name|description|tags|onboot", "VM.Config.Options")]

    def r_set_config(self, tid, q, f, node, kind, vmid):
        vm = self._find(node, int(vmid), kind)
        self._unlocked(vm)
        # real PVE (qemu-server update_vm_api): the parameter values are written to the cluster log and syslog, only cipassword is masked
        if not hasattr(self, "cluster_log"):
            self.cluster_log = []
        self.cluster_log.append({"user": tid, "pri": 6, "node": node, "tag": "pvedaemon",
                                 "msg": f"update VM {vm['vmid']}: " + " ".join(f"-{k} {'<hidden>' if k == 'cipassword' else v}" for k, v in sorted(f.items()))})
        running = vm["status"] == "running"
        for k, v in f.items():
            if k == "delete":
                for dk in str(v).split(","):
                    for rx, pr in self._CFG_PRIV:
                        if re.fullmatch(rx, dk):
                            self.need(tid, "vm", vm["vmid"], pr)
                            break
                    if running and dk == "smbios1":     # not hot-pluggable: stays in the active section until the VM restarts
                        vm.setdefault("pending", {})[dk] = None
                    else:
                        vm["cfg"].pop(dk, None)
                continue
            if k == "cicustom":
                self.need(tid, "root", None, "Sys.Modify")  # PVE restricts cicustom to highly privileged users
                continue
            for rx, pr in self._CFG_PRIV:
                if re.fullmatch(rx, k):
                    self.need(tid, "vm", vm["vmid"], pr)
                    break
            else:
                raise HTTPErr(400, f"Parameter verification failed. {k}: property is not defined in schema")
            if re.fullmatch(r"net\d+", k):
                br = _kv(v.split(",", 1)[1] if "," in v else "").get("bridge") or _kv(v).get("bridge")
                if br not in self.bridges and br not in self.sdn_vnets:
                    raise HTTPErr(500, f"unable to find bridge '{br}'")
                self.need(tid, "sdn", br, "SDN.Use")
            if re.fullmatch(r"(scsi|virtio|sata|ide)\d+", k) and ":" in v and not v.startswith("none"):
                st = v.split(":", 1)[0]
                if st not in self.storages:
                    raise HTTPErr(500, f"storage '{st}' does not exist")
                self.need(tid, "storage", st, "Datastore.AllocateSpace")
                if v.split(":", 1)[1].split(",")[0].isdigit():  # "storage:SIZE" -> allocate
                    sz = v.split(":", 1)[1].split(",")[0]
                    v = f"{st}:vm-{vm['vmid']}-disk-{k}" + f",size={sz}G"
                elif v.endswith("cloudinit"):
                    if any(isinstance(x, str) and "cloudinit" in x for kk, x in vm["cfg"].items() if re.match(r"^(ide|sata|scsi)\d+$", kk)):
                        # real PVE: a template made from a cloud image already carries its drive; asking for another one fails
                        raise HTTPErr(500, f"lvcreate '{st}/vm-{vm['vmid']}-cloudinit' error: Logical Volume \"vm-{vm['vmid']}-cloudinit\" already exists")
                    v = f"{st}:vm-{vm['vmid']}-cloudinit,media=cdrom"
            if running and k == "smbios1":
                vm.setdefault("pending", {})[k] = _num(v)
            else:
                vm["cfg"][k] = _num(v)
        return None

    def r_resize(self, tid, q, f, node, kind, vmid):
        vm = self._find(node, int(vmid), kind)
        self.need(tid, "vm", vm["vmid"], "VM.Config.Disk")
        d, size = f.get("disk"), f.get("size", "")
        if d not in vm["cfg"] or "size=" not in str(vm["cfg"][d]):
            raise HTTPErr(500, f"disk '{d}' does not exist")
        opts = vm["cfg"][d].split(",", 1)
        cur = _size(_kv(opts[1]).get("size"))
        new = cur + _size(size[1:]) if size.startswith("+") else _size(size)
        if new < cur:
            raise HTTPErr(500, "shrinking disks is not supported")
        vm["cfg"][d] = re.sub(r"size=\w+", f"size={new >> 30}G", vm["cfg"][d])
        return None

    def r_power(self, tid, q, f, node, kind, vmid, op):
        vm = self._find(node, int(vmid), kind)
        self.need(tid, "vm", vm["vmid"], "VM.PowerMgmt")
        self._unlocked(vm)
        if op == "start" and vm["status"] == "running":
            raise HTTPErr(500, "VM is already running")
        if op in ("stop", "shutdown") and vm["status"] != "running":
            raise HTTPErr(500, "VM is not running")

        def done():
            if op in ("start", "reboot", "stop", "shutdown"):      # real PVE applies pending changes on (re)start
                for pk, pv in vm.pop("pending", {}).items():
                    vm["cfg"].pop(pk, None) if pv is None else vm["cfg"].__setitem__(pk, pv)
            vm["status"] = "running" if op in ("start", "reboot") else "stopped"
        return self._task(node, {"start": "qmstart", "stop": "qmstop", "shutdown": "qmshutdown", "reboot": "qmreboot"}[op], str(vm["vmid"]), tid, done)

    def r_snapshot(self, tid, q, f, node, kind, vmid):
        vm = self._find(node, int(vmid), kind)
        self.need(tid, "vm", vm["vmid"], "VM.Snapshot")
        n = f.get("snapname", "")
        if n in vm["snapshots"]:
            raise HTTPErr(500, f"snapshot '{n}' already exists")

        def done():
            vm["snapshots"][n] = dict(vm["cfg"])
        return self._task(node, "qmsnapshot", str(vm["vmid"]), tid, done)

    def r_rollback(self, tid, q, f, node, kind, vmid, name):
        vm = self._find(node, int(vmid), kind)
        self.need(tid, "vm", vm["vmid"], "VM.Snapshot.Rollback")
        if name not in vm["snapshots"]:
            raise HTTPErr(500, f"snapshot '{name}' does not exist")

        def done():
            vm["cfg"] = dict(vm["snapshots"][name])
            vm["status"] = "stopped"
        return self._task(node, "qmrollback", str(vm["vmid"]), tid, done)

    def r_migrate(self, tid, q, f, node, kind, vmid):
        vm = self._find(node, int(vmid), kind)
        self.need(tid, "vm", vm["vmid"], "VM.Migrate")
        tgt = f.get("target")
        if tgt not in self.nodes:
            raise HTTPErr(500, f"no such cluster node '{tgt}'")
        if tgt == node:
            raise HTTPErr(500, "target is local node")

        def done():
            vm["node"] = tgt
        return self._task(node, "qmigrate", str(vm["vmid"]), tid, done)

    def r_upload(self, tid, q, f, node, storage):
        """PVE 8.4+/9: POST /nodes/<n>/storage/<s>/upload (multipart; content=import|iso|vztmpl). Models the privilege, the content check and the checksum."""
        self._node_up(node)
        if storage not in self.storages or node not in self.storages[storage]["nodes"]:
            raise HTTPErr(500, f"storage '{storage}' does not exist")
        self.need(tid, "storage", storage, "Datastore.AllocateTemplate")
        content = f.get("content")
        if content not in ("import", "iso", "vztmpl") or content not in self.storages[storage]["content"].split(","):
            raise HTTPErr(500, f"storage '{storage}' does not support content type '{content}'")
        data, fname = f.get("__file__") or b"", f.get("__filename__") or ""
        if content == "import" and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*\.(qcow2|raw|vmdk)", fname):
            raise HTTPErr(400, "Parameter verification failed. filename: import content needs a .qcow2/.raw/.vmdk file")
        if f.get("checksum") and hashlib.sha256(data).hexdigest() != f["checksum"]:
            raise HTTPErr(500, "checksum mismatch")
        self.uploaded_bytes = getattr(self, "uploaded_bytes", 0) + len(data)

        def done():
            self.storages[storage].setdefault("files", {})[f"{content}/{fname}"] = len(data)
        return self._task(node, "imgcopy", "", tid, done)

    def r_create(self, tid, q, f, node):
        self._node_up(node)
        vmid = int(f.get("vmid") or 0)
        if vmid in self.vms or vmid < 100:
            raise HTTPErr(500, f"unable to create VM {vmid}: config file already exists")
        pool = f.get("pool")
        if pool:
            if pool not in self.pools:
                raise HTTPErr(500, f"pool '{pool}' does not exist")
            self.need(tid, "pool", pool, "VM.Allocate")
        else:
            self.need(tid, "root", None, "VM.Allocate")
        cfg = {"name": f.get("name"), "cores": int(f.get("cores", 1)), "memory": int(f.get("memory", 512)), "tags": f.get("tags", "")}
        for k, v in f.items():
            if re.fullmatch(r"scsi\d+", k):
                m = re.fullmatch(r"([^:]+):0,import-from=([^:]+):(import/[^,]+)", v)
                if not m:
                    raise HTTPErr(400, "Parameter verification failed. scsi0: invalid format")
                tgt, src, rel = m.groups()
                if tgt not in self.storages or "images" not in self.storages[tgt]["content"].split(","):
                    raise HTTPErr(500, f"storage '{tgt}' does not support images")
                self.need(tid, "storage", tgt, "Datastore.AllocateSpace")
                self.need(tid, "storage", src, "Datastore.Audit") if not self.can(tid, "storage", src, "Datastore.AllocateSpace") else None
                fsz = self.storages.get(src, {}).get("files", {}).get(rel)
                if fsz is None:
                    raise HTTPErr(500, f"volume '{src}:{rel}' does not exist")
                cfg[k] = f"{tgt}:vm-{vmid}-disk-0,size=3G"
            elif k in ("net0", "boot", "serial0", "agent", "ostype", "scsihw", "description"):
                cfg[k] = v
        self.vms[vmid] = {"vmid": vmid, "node": node, "kind": "qemu", "status": "stopped", "pool": pool, "cfg": cfg, "snapshots": {}, "lock": None}
        return self._task(node, "qmcreate", str(vmid), tid)

    def r_template(self, tid, q, f, node, vmid):
        vm = self._find(node, int(vmid), "qemu")
        self.need(tid, "vm", vm["vmid"], "VM.Allocate")
        self._unlocked(vm)
        if vm["status"] == "running":
            raise HTTPErr(500, "VM is running")

        def done():
            vm["cfg"]["template"] = 1
        return self._task(node, "qmtemplate", str(vm["vmid"]), tid, done)

    def r_destroy(self, tid, q, f, node, kind, vmid):
        vm = self._find(node, int(vmid), kind)
        self.need(tid, "vm", vm["vmid"], "VM.Allocate")
        if vm["status"] == "running":
            raise HTTPErr(500, "VM is running - destroy failed")
        self._unlocked(vm)

        def done():
            self.vms.pop(vm["vmid"], None)
        return self._task(node, "qmdestroy", str(vm["vmid"]), tid, done)


def _size(s):
    m = re.fullmatch(r"(\d+)([KMGT]?)", str(s or "0"))
    if not m:
        return 0
    return int(m.group(1)) * {"": 1, "K": 1 << 10, "M": 1 << 20, "G": 1 << 30, "T": 1 << 40}[m.group(2)]


def _num(v):
    return int(v) if isinstance(v, str) and v.isdigit() else v


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _do(self):
        form = {}
        n = int(self.headers.get("Content-Length") or 0)
        if n and (self.headers.get("Content-Type") or "").startswith("multipart/form-data"):
            import email.parser
            import email.policy
            raw = self.rfile.read(n)
            msg = email.parser.BytesParser(policy=email.policy.HTTP).parsebytes(b"Content-Type: " + self.headers["Content-Type"].encode() + b"\r\n\r\n" + raw)
            for part in msg.iter_parts():
                nm = part.get_param("name", header="content-disposition")
                if part.get_filename():
                    form["__file__"], form["__filename__"] = part.get_payload(decode=True), part.get_filename()
                elif nm:
                    form[nm] = part.get_content()
        elif n:
            form = dict(urllib.parse.parse_qsl(self.rfile.read(n).decode()))
        sim: PveSim = self.server.sim
        try:
            auth = self.headers.get("Authorization")
            ck = re.search(r"PVEAuthCookie=([^;]+)", self.headers.get("Cookie") or "")
            if auth is None and ck:
                auth = f"TICKET {urllib.parse.unquote(ck.group(1))} {self.headers.get('CSRFPreventionToken') or ''}"
            data = sim.handle(self.command, self.path, form, auth)
            code, reason, body = 200, "OK", {"data": data}
        except HTTPErr as e:
            code, reason, body = e.code, e.reason, {"data": None, "message": e.reason}
        b = json.dumps(body).encode()
        gz = sim.gzip and len(b) > 200 and "gzip" in (self.headers.get("Accept-Encoding") or "")
        if gz:
            import gzip
            b = gzip.compress(b)
        self.send_response(code, reason)
        self.send_header("Content-Type", "application/json")
        if gz:
            self.send_header("Content-Encoding", "gzip")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    do_GET = do_POST = do_PUT = do_DELETE = _do


class SimServer:
    """HTTPS server around a PveSim (127.0.0.1, ephemeral port, self-signed cert)."""

    def __init__(self, sim: PveSim | None = None):
        self.sim = sim or PveSim()
        self.cert_pem, key_pem, self.fingerprint = make_cert()
        d = tempfile.mkdtemp()
        cf, kf = Path(d, "c.pem"), Path(d, "k.pem")
        cf.write_text(self.cert_pem)
        kf.write_text(key_pem)
        kf.chmod(0o600)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cf, kf)
        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.srv.sim = self.sim
        self.srv.socket = ctx.wrap_socket(self.srv.socket, server_side=True)
        self.url = f"https://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()
