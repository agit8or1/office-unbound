"""STATEFUL PROXMOX VE API SIMULATOR -- A TEST DOUBLE. NOT A REAL ENDPOINT.

Used only by the test-suite to exercise the Proxmox provider end to end (HTTPS with a self-signed cert, token auth,
per-token permission enforcement, async tasks with UPIDs, failure injection). JSON shapes follow the PVE 8.x API.

Safety: it lives under tests/ (never installed), binds 127.0.0.1 only (the ICS SSRF guard refuses loopback endpoints unless
ICS_ALLOW_LOOPBACK_ENDPOINTS is set, which production does not do), and /version reports repoid "pve-sim-test-double";
the provider refuses to talk to anything advertising that marker unless loopback endpoints are explicitly allowed.
It is NOT a faithful model of PVE: privileges are simplified, storage/network behaviour is minimal, and passing
simulator tests is not evidence that the provider works against a real cluster (see docs/status/provider-proxmox.md).
"""
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
        self.seen: list[tuple[str, str]] = []
        self._pid = 1000

    # ---------------- setup helpers ----------------
    def add_role(self, name, privs):
        self.roles[name] = set(privs)

    def add_token(self, tid, secret, acl):
        """acl = [(path, role)]"""
        self.tokens[tid] = {"secret": secret, "acl": list(acl)}

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

    def privs(self, tid, chain):
        out = set()
        for path, role in self.tokens[tid]["acl"]:
            if path in chain:
                out |= self.roles[role]
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
        d = {"id": f"{vm['kind']}/{vm['vmid']}", "type": vm["kind"], "vmid": vm["vmid"], "node": vm["node"], "name": c.get("name"),
             "status": vm["status"], "maxcpu": c.get("cores", 1), "cpu": 0.03 if run else 0, "maxmem": c.get("memory", 512) << 20,
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
            tid = self._auth(auth)
            u = urllib.parse.urlsplit(rawpath)
            path = u.path.removeprefix("/api2/json")
            q = dict(urllib.parse.parse_qsl(u.query))
            for m, rx, fn in self._routes():
                if m == method:
                    mt = rx.fullmatch(path)
                    if mt:
                        return fn(tid, q, form, *mt.groups())
            raise HTTPErr(501, f"Method '{method} {path}' not implemented")

    def _auth(self, auth):
        m = re.fullmatch(r"PVEAPIToken=([^=]+)=(.+)", auth or "")
        if not m or m.group(1) not in self.tokens or self.tokens[m.group(1)]["secret"] != m.group(2):
            raise HTTPErr(401, "No ticket")
        return m.group(1)

    def _routes(self):
        R = lambda m, p, f: (m, re.compile(p), f)  # noqa: E731
        g = r"(qemu|lxc)"
        return [
            R("GET", r"/version", self.r_version), R("GET", r"/cluster/status", self.r_cluster_status),
            R("GET", r"/cluster/resources", self.r_resources), R("GET", r"/cluster/nextid", self.r_nextid),
            R("GET", r"/nodes", self.r_nodes), R("GET", r"/storage", self.r_storage_cfg),
            R("GET", r"/cluster/sdn/zones", self.r_zones), R("GET", r"/cluster/sdn/vnets", self.r_vnets),
            R("GET", r"/access/permissions", self.r_permissions),
            R("GET", r"/nodes/([^/]+)/" + g, self.r_list_guests),
            R("GET", r"/nodes/([^/]+)/storage", self.r_node_storage), R("GET", r"/nodes/([^/]+)/network", self.r_network),
            R("GET", r"/nodes/([^/]+)/rrddata", self.r_rrd_node),
            R("GET", r"/nodes/([^/]+)/" + g + r"/(\d+)/rrddata", self.r_rrd_vm),
            R("GET", r"/nodes/([^/]+)/" + g + r"/(\d+)/config", self.r_get_config),
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
        return {"version": "8.2.4", "release": "8.2", "repoid": SIM_MARKER}

    def r_cluster_status(self, tid, q, f):
        out = [{"type": "cluster", "name": self.cluster, "version": 3, "nodes": len(self.nodes), "quorate": int(self.quorate), "id": "cluster"}]
        for n in self.nodes.values():
            out.append({"type": "node", "name": n["node"], "id": f"node/{n['node']}", "online": int(n["status"] == "online"),
                        "ip": n["ip"], "local": 0, "nodeid": 1, "level": ""})
        return out

    def r_nodes(self, tid, q, f):
        return [{"node": n["node"], "status": n["status"], "cpu": 0.05, "maxcpu": n["maxcpu"], "mem": n["maxmem"] // 4,
                 "maxmem": n["maxmem"], "disk": 1 << 30, "maxdisk": n["maxdisk"], "uptime": n["uptime"], "level": "", "id": f"node/{n['node']}"}
                for n in self.nodes.values() if self.can(tid, "node", n["node"], "Sys.Audit")]

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

    def r_nextid(self, tid, q, f):
        n = 100
        while n in self.vms:
            n += 1
        return str(n)

    def r_storage_cfg(self, tid, q, f):
        return [{"storage": s["storage"], "type": s["type"], "content": s["content"], "shared": s["shared"],
                 "nodes": ",".join(s["nodes"]) if len(s["nodes"]) != len(self.nodes) else None}
                for s in self.storages.values() if self.can(tid, "storage", s["storage"], "Datastore.Audit", "Datastore.AllocateSpace")]

    def r_node_storage(self, tid, q, f, node):
        self._node_up(node)
        return [{"storage": s["storage"], "type": s["type"], "content": s["content"], "shared": s["shared"], "active": 1,
                 "enabled": 1, "total": s["total"], "used": self._disk_used(s["storage"]), "avail": s["total"] - self._disk_used(s["storage"])}
                for s in self.storages.values() if node in s["nodes"]
                and self.can(tid, "storage", s["storage"], "Datastore.Audit", "Datastore.AllocateSpace")]

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

    def r_permissions(self, tid, q, f):
        if "path" in q:
            ps = [q["path"]]
        else:
            ps = sorted({"/"} | {p for p, _ in self.tokens[tid]["acl"]})
        out = {}
        for p in ps:
            pr = self.privs(tid, self._chain("path", p))
            if "*" in pr:
                allp = set().union(*(r for r in self.roles.values())) - {"*"}
                pr = allp
            out[p] = {x: 1 for x in sorted(pr)}
        return out

    def r_list_guests(self, tid, q, f, node, kind):
        self._node_up(node)
        return [{"vmid": v["vmid"], "name": v["cfg"].get("name"), "status": v["status"]} for v in self.vms.values()
                if v["node"] == node and v["kind"] == kind and self.can(tid, "vm", v["vmid"], "VM.Audit")]

    def r_get_config(self, tid, q, f, node, kind, vmid):
        vm = self._find(node, int(vmid), kind)
        self.need(tid, "vm", vm["vmid"], "VM.Audit")
        return {**vm["cfg"], "digest": "d" * 40}

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
        return self._task(node, "qmclone" if kind == "qemu" else "vzclone", str(newid), tid, done)

    _CFG_PRIV = [(r"cores|sockets|vcpus|cpu", "VM.Config.CPU"), (r"memory|balloon", "VM.Config.Memory"),
                 (r"net\d+", "VM.Config.Network"), (r"(scsi|virtio|sata|ide)\d+|rootfs", "VM.Config.Disk"),
                 (r"ciuser|cipassword|sshkeys|ipconfig\d+|nameserver|searchdomain|citype", "VM.Config.Cloudinit"),
                 (r"name|description|tags|onboot", "VM.Config.Options")]

    def r_set_config(self, tid, q, f, node, kind, vmid):
        vm = self._find(node, int(vmid), kind)
        self._unlocked(vm)
        for k, v in f.items():
            if k == "delete":
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
                    v = f"{st}:vm-{vm['vmid']}-cloudinit,media=cdrom"
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
        if n:
            form = dict(urllib.parse.parse_qsl(self.rfile.read(n).decode()))
        sim: PveSim = self.server.sim
        try:
            data = sim.handle(self.command, self.path, form, self.headers.get("Authorization"))
            code, reason, body = 200, "OK", {"data": data}
        except HTTPErr as e:
            code, reason, body = e.code, e.reason, {"data": None, "message": e.reason}
        b = json.dumps(body).encode()
        self.send_response(code, reason)
        self.send_header("Content-Type", "application/json")
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
