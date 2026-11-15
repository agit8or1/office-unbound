"""Proxmox VE provider (ADR-0009 section 2).

`ProxmoxProvider` is read-only (probe/discover/metrics/task_status); it only ever holds a ProxmoxReadClient.
`ProxmoxMutations` adds the mutation verbs, only exists with a `provision` credential, and can only be constructed inside
`providers.base.job_execution()`. Every mutation re-resolves its target from the live cluster (never from the DB cache) and
re-checks scope: pool / storage / bridge(+VLAN) allowlists and the ownership tags `ou-managed` + `ou-deployment-<id>`.
"""
from __future__ import annotations

import ipaddress
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Literal

from ...proxmox import ProxmoxError, ProxmoxHTTPError, ProxmoxReadClient, ProxmoxWriteClient
from ..base import (Discovery, MutationNotAllowed, ProbeResult, ProviderError, ProviderTimeout, Sample, Scope, ScopeViolation,
                    TaskRef, TaskStatus, VerbCheck, VmCloneSpec, VmConfigSpec, VmRef, require_job_execution)
from . import privileges as priv

SIM_MARKER = "pve-sim-test-double"
THIN_TYPES = ("lvmthin", "zfspool", "rbd", "cephfs")
OWNED_TAG = "ou-managed"
DEP_PREFIX = "ou-deployment-"
_UPID = re.compile(r"^UPID:([A-Za-z0-9.-]+):[0-9A-Fa-f]{8}:[0-9A-Fa-f]{8,}:[0-9A-Fa-f]{8}:([a-z0-9]+):([^:]*):([^:]+):$")
_DEP_ID = re.compile(r"^[a-z0-9][a-z0-9_.+-]{0,60}$")
_NAME = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_SNAP = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,39}$")
_DISK = re.compile(r"^(scsi|virtio|sata|ide)\d{1,2}$|^rootfs$")
_NEWDISK = re.compile(r"^(scsi|virtio|sata)\d{1,2}$")
_CIUSER = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_SSHKEY = re.compile(r"^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com) [A-Za-z0-9+/=]{20,2000}( [\x21-\x7e ]{0,100})?$")
_CICUSTOM = re.compile(r"^(user|network|meta|vendor)=([A-Za-z0-9._-]{1,40}):snippets/[A-Za-z0-9._-]{1,100}$")
_DOMAIN = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_KIND_PATH = {"vm": "qemu", "lxc": "lxc"}


@dataclass(frozen=True)
class EndpointScope:
    pools: tuple[str, ...] = ()
    storage: tuple[str, ...] = ()
    networks: tuple[str, ...] = ()          # "vmbr1" (any VLAN) or "vmbr1/20" (that VLAN only)
    templates: tuple[int, ...] = ()         # extra template vmids allowed outside the pools (explicit operator choice)
    allow_cicustom: bool = False
    protected: tuple[int, ...] = ()         # guests that are never mutated, whatever the ACLs say

    def network_ok(self, bridge: str, vlan: int | None) -> bool:
        for n in self.networks:
            b, _, v = n.partition("/")
            if b == bridge and (not v or (vlan is not None and int(v) == vlan)):
                return True
        return False


_MAC = re.compile(r"(?<![0-9A-Fa-f:])([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})(?![0-9A-Fa-f:])")
_UUID = re.compile(r"uuid=([0-9a-fA-F-]{32,36})")
MUTATING_PRIVS = ("VM.Allocate", "VM.Clone", "VM.PowerMgmt", "VM.Config.CPU", "VM.Config.Memory", "VM.Config.Disk", "VM.Config.Network",
                  "VM.Config.Options", "VM.Config.Cloudinit", "VM.Config.HWType", "VM.Config.CDROM", "VM.Snapshot", "VM.Snapshot.Rollback",
                  "VM.Migrate", "VM.Backup")


@dataclass(frozen=True)
class SelfIdentity:
    """How to recognise the VM this ICS runs in: its NIC MAC addresses and SMBIOS/product UUID. Mutations of a guest that
    matches are refused regardless of ACLs (an ICS must never be able to power off/destroy itself)."""
    macs: frozenset[str] = frozenset()
    uuids: frozenset[str] = frozenset()

    def matches(self, cfg: dict) -> bool:
        blob = " ".join(str(v) for k, v in cfg.items() if re.match(r"^(net\d+|smbios1)$", k))
        macs = {m.lower() for m in _MAC.findall(blob)}
        uu = {u.lower() for u in _UUID.findall(blob)}
        return bool(macs & self.macs) or bool(uu & self.uuids)

    def __bool__(self) -> bool:
        return bool(self.macs or self.uuids)


_LOCAL: SelfIdentity | None = None


def local_identity() -> SelfIdentity:
    """Identity of the machine the ICS runs on (read once from /sys; unreadable pieces are skipped, never guessed)."""
    global _LOCAL
    if _LOCAL is None:
        import glob
        macs, uuids = set(), set()
        for f in glob.glob("/sys/class/net/*/address"):
            try:
                m = open(f).read().strip().lower()
            except OSError:
                continue
            if _MAC.fullmatch(m) and m != "00:00:00:00:00:00":
                macs.add(m)
        try:
            u = open("/sys/class/dmi/id/product_uuid").read().strip().lower()
            if re.fullmatch(r"[0-9a-f-]{32,36}", u):
                uuids.add(u)
        except OSError:
            pass
        _LOCAL = SelfIdentity(frozenset(macs), frozenset(uuids))
    return _LOCAL


def tags_of(s: str | None) -> list[str]:
    return [t.strip().lower() for t in re.split(r"[;,]", s or "") if t.strip()]


def _clean(s: str | None, n: int = 300) -> str:
    return re.sub(r"[^\x20-\x7e]", "", s or "")[:n]


def map_error(e: Exception, what: str = "request") -> ProviderError:
    """Translate transport/PVE errors into operator-readable provider errors (no secrets: ProxmoxError text is already scrubbed)."""
    if isinstance(e, ProviderError):
        return e
    if isinstance(e, ProxmoxHTTPError):
        r = e.reason or ""
        if e.status == 401:
            return ProviderError("auth", "Proxmox rejected the API token (HTTP 401): wrong token id/secret, or the token or user is disabled/expired.")
        if e.status == 403:
            return ProviderError("permission", f"Proxmox denied the request: {r or 'permission check failed'}. Grant that privilege to the "
                                               "ICS token (run the probe in Settings > Infrastructure for the exact command).")
        if e.status == 595 or e.status >= 502:
            return ProviderError("node_unreachable", f"The Proxmox node is unreachable or down (HTTP {e.status}): {r}")
        if e.status == 400:
            return ProviderError("invalid_request", f"Proxmox rejected the parameters: {r}")
        if "locked" in r.lower():
            return ProviderError("locked", f"The guest is locked by another operation ({r}); retry later.")
        if "already exists" in r.lower():
            return ProviderError("exists", f"Already exists on Proxmox: {r}")
        return ProviderError("pve_error", f"Proxmox refused the {what}: {r or 'HTTP ' + str(e.status)}")
    m = str(e)
    if "pinned" in m:
        return ProviderError("tls", "The server certificate does not match the pinned SHA-256 fingerprint. If the node certificate was "
                                    "renewed, verify the new fingerprint out of band and update the endpoint.")
    if "CERTIFICATE_VERIFY_FAILED" in m or "SSLError" in m or "certificate" in m.lower():
        return ProviderError("tls", "TLS verification against the configured CA bundle failed (unknown CA, expired certificate or hostname mismatch).")
    if "deadline" in m or "Timeout" in m:
        return ProviderError("timeout", "Proxmox did not answer in time.")
    if "ConnectError" in m or "failed" in m:
        return ProviderError("unreachable", "Could not connect to Proxmox (network unreachable, refused or DNS failure).")
    return ProviderError("pve_error", f"Proxmox {what} failed: {_clean(m, 200)}")


class ProxmoxProvider:
    kind = "proxmox"

    def __init__(self, inventory: ProxmoxReadClient | None, *, scope: EndpointScope | None = None, trust: str = "fingerprint",
                 inventory_token_id: str | None = None, provision_probe: ProxmoxReadClient | None = None,
                 provision_token_id: str | None = None, allow_simulator: bool = False, sleep: Callable[[float], None] = time.sleep,
                 self_identity: SelfIdentity | None = None):
        self.self_identity = self_identity or SelfIdentity()
        self._inv, self._prov_ro = inventory, provision_probe
        self.scope = scope or EndpointScope()
        self.trust, self._inv_tid, self._prov_tid = trust, inventory_token_id, provision_token_id
        self._allow_sim, self._sleep = allow_simulator, sleep

    # ---- plumbing
    def _c(self, client=None) -> ProxmoxReadClient:
        c = client or self._inv or self._prov_ro
        if c is None:
            raise ProviderError("no_credential", "no credential configured for this endpoint")
        return c

    def _get(self, path: str, client=None):
        try:
            return self._c(client)._get(path)
        except ProxmoxError as e:
            raise map_error(e, "read") from None

    def _vnet_zones(self, client=None) -> dict[str, str]:
        try:
            return {v["vnet"]: v.get("zone", "localnetwork") for v in self._c(client)._get("/cluster/sdn/vnets")}
        except ProxmoxError:
            return {}

    def _check_sim(self, version: dict) -> None:
        if isinstance(version, dict) and version.get("repoid") == SIM_MARKER and not self._allow_sim:
            raise ProviderError("simulator", "this address answers as the Proxmox test double; it can not be used as a real endpoint")

    # ---- probe
    def probe(self) -> ProbeResult:
        res = ProbeResult(ok=False, tls={"trust": self.trust, "ok": False})
        main = self._inv or self._prov_ro
        try:
            v = main._get("/version")
        except ProxmoxError as e:
            pe = map_error(e, "connection")
            res.errors.append(pe.message)
            if isinstance(e, ProxmoxHTTPError):
                res.tls["ok"] = True
                res.credentials["inventory" if self._inv else "provision"] = {"authenticated": False}
            elif pe.code == "tls":
                res.tls["error"] = pe.message
            return res
        res.tls["ok"] = True
        try:
            self._check_sim(v)
        except ProviderError as e:
            res.errors.append(e.message)
            res.simulator = True
            return res
        res.simulator = isinstance(v, dict) and v.get("repoid") == SIM_MARKER
        res.version, res.release = v.get("version"), v.get("release")
        try:
            st = main._get("/cluster/status")
            cl = next((x for x in st if x.get("type") == "cluster"), None)
            res.cluster_name = cl["name"] if cl else next((x["name"] for x in st if x.get("type") == "node"), None)
            res.quorate = bool(cl.get("quorate")) if cl else True
            res.nodes = sum(1 for x in st if x.get("type") == "node")
        except (ProxmoxError, KeyError, TypeError):
            res.errors.append("could not read cluster status (needs Sys.Audit)")
        if self._inv:
            res.credentials["inventory"] = {"authenticated": True, "token_id": self._inv_tid}
            res.verbs += self._inventory_verbs(self._inv, self._inv_tid, res)
        if self._prov_ro:
            try:
                self._prov_ro._get("/version")
                authed = True
            except ProxmoxError as e:
                authed = False
                res.errors.append("provision credential: " + map_error(e, "connection").message)
            res.credentials["provision"] = {"authenticated": authed, "token_id": self._prov_tid}
            if authed:
                res.verbs += self._verbs(self._prov_ro, priv.PROVISION_VERBS, self._prov_tid)
                res.warnings += self._extra_warnings(self._prov_ro)
            else:
                res.verbs += [VerbCheck(v_, False, note="provision credential rejected") for v_ in priv.PROVISION_VERBS]
        else:
            res.credentials["provision"] = {"authenticated": False, "configured": False}
            res.verbs += [VerbCheck(v_, False, note="no provision credential configured") for v_ in priv.PROVISION_VERBS]
        try:
            res.capabilities = self._capabilities(main)
        except ProxmoxError:
            res.warnings.append("could not read storage configuration (needs Datastore.Audit): capabilities unknown")
        self._find_self(res, main)
        res.ok = bool(res.credentials.get("inventory", {}).get("authenticated")) and all(
            x.ok for x in res.verbs if x.verb in priv.INVENTORY_VERBS)
        return res

    def _perms_fn(self, client):
        cache: dict[str, set[str]] = {}

        def at(path: str) -> set[str]:
            if path not in cache:
                try:
                    d = client._get("/access/permissions?path=" + urllib.parse.quote(path, safe="/"))
                    cache[path] = {k for k, v in (d.get(path) or {}).items() if v}
                except ProxmoxError:
                    cache[path] = set()
            return cache[path]
        return at

    def _verbs(self, client, verbs, token_id) -> list[VerbCheck]:
        at = self._perms_fn(client)
        zones = self._vnet_zones(client)
        out = []
        for verb in verbs:
            if verb in priv.PROVISION_VERBS and not self.scope.pools:
                out.append(VerbCheck(verb, False, note="no allowed pool configured"))
                continue
            if verb in ("configure_vm", "clone_vm", "resize_disk", "migrate") and not self.scope.storage:
                out.append(VerbCheck(verb, False, note="no allowed storage configured"))
                continue
            nets = tuple(sorted({n.partition("/")[0] for n in self.scope.networks}))
            reqs = priv.required(verb, self.scope.pools, self.scope.storage, nets, zones, self.scope.allow_cicustom)
            out.append(priv.evaluate(verb, reqs, at, token_id))
        return out

    def _inventory_verbs(self, client, token_id, res: ProbeResult) -> list[VerbCheck]:
        """Inventory credentials may be scoped (Sys.Audit per node, VM.Audit per pool): require *some* visibility, report coverage."""
        at = self._perms_fn(client)
        try:
            nodes = [n["node"] for n in client._get("/nodes")]
        except ProxmoxError:
            nodes = []
        audited = [n for n in nodes if "Sys.Audit" in at(f"/nodes/{n}")]
        root = at("/")
        sys_ok = "Sys.Audit" in root or bool(audited)
        try:
            vm_ok = "VM.Audit" in root or bool(client._get("/cluster/resources?type=vm"))
            ds_ok = "Datastore.Audit" in root or bool(client._get("/storage"))
        except ProxmoxError:
            vm_ok = ds_ok = False
        miss = []
        if not sys_ok:
            miss.append({"path": "/nodes/<node>", "privileges": ["Sys.Audit"], "fix": priv.fix_hint("/", ["Sys.Audit"], token_id)})
        if not vm_ok:
            miss.append({"path": "/", "privileges": ["VM.Audit"], "fix": priv.fix_hint("/", ["VM.Audit"], token_id)})
        if not ds_ok:
            miss.append({"path": "/storage/<id>", "privileges": ["Datastore.Audit"], "fix": priv.fix_hint("/storage/<id>", [], token_id)})
        if nodes and len(audited) < len(nodes) and "Sys.Audit" not in root:
            res.warnings.append(f"Sys.Audit on {len(audited)} of {len(nodes)} cluster nodes: the others are not managed "
                                f"(no visibility; not counted as capacity): {', '.join(n for n in nodes if n not in audited)}")
        return [VerbCheck("discover", sys_ok and vm_ok and ds_ok, miss), VerbCheck("metrics", sys_ok and vm_ok, [m for m in miss if m["privileges"] != ["Datastore.Audit"]])]

    def _capabilities(self, client) -> list[dict]:
        cfg = client._get("/storage")
        want = set(self.scope.storage)
        cands = [s for s in cfg if not want or s.get("storage") in want]
        have = {c for s in cands for c in (s.get("content") or "").split(",") if c}
        scope = f"storage {', '.join(sorted(want))}" if want else "any visible storage"
        vlan = self._vlan_capability(client)
        return [vlan,
            {"name": "vm_disks", "ok": "images" in have, "blocking": True,
             "detail": f"{scope} " + ("offers" if "images" in have else "has NO") + " content type `images` (VM disks)"},
            {"name": "cloudinit_snippets", "ok": "snippets" in have, "blocking": False,
             "detail": ("cicustom snippets possible" if "snippets" in have else
                        "no `snippets` content: cloud-init is limited to ciuser/sshkeys/ipconfig/nameserver/searchdomain; agent enrollment "
                        "must not depend on snippets (bake a first-boot unit into the template, or add a directory storage with snippets)")},
            {"name": "template_import", "ok": "import" in have, "blocking": False,
             "detail": ("image import available (template build possible)" if "import" in have else
                        "no `import` content: ICS cannot build templates itself; provide a cloud-init template inside the allowed pool, "
                        "or a directory storage with content `import`")},
        ]

    def _vlan_capability(self, client) -> dict:
        try:
            nodes = [n["node"] for n in client._get("/nodes")]
            bridges: dict[str, bool] = {}
            for n in nodes:
                if "Sys.Audit" not in self._perms_fn(client)(f"/nodes/{n}"):
                    continue
                for i in client._get(f"/nodes/{_seg(n)}/network"):
                    if i.get("type") in ("bridge", "OVSBridge"):
                        bridges[i["iface"]] = bridges.get(i["iface"], False) or bool(i.get("bridge_vlan_aware"))
        except ProxmoxError:
            return {"name": "vlan_tagging", "ok": False, "blocking": False, "detail": "could not read bridges (needs Sys.Audit)"}
        want = {n.partition("/")[0] for n in self.scope.networks}
        cand = {b: v for b, v in bridges.items() if not want or b in want}
        wants_vlan = any("/" in n for n in self.scope.networks)
        ok = any(cand.values())
        detail = ("VLAN-aware bridge available: " + ", ".join(sorted(b for b, v in cand.items() if v))) if ok else (
            "no VLAN-aware bridge in scope (" + (", ".join(sorted(cand)) or "none") + "): VLAN tagging unavailable; "
            "enable `bridge-vlan-aware yes` on the bridge or use untagged/SDN vnets")
        return {"name": "vlan_tagging", "ok": ok, "blocking": wants_vlan and not ok, "detail": detail}

    def _find_self(self, res: ProbeResult, client) -> None:
        """Locate the ICS's own VM (and explicitly protected guests) and warn loudly when a token could mutate it."""
        if not (self.self_identity or self.scope.protected):
            return
        try:
            vms = [r for r in client._get("/cluster/resources?type=vm") if r.get("type") in ("qemu", "lxc")][:150]
        except ProxmoxError:
            return
        for r in vms:
            is_self = r["vmid"] in self.scope.protected
            if not is_self and self.self_identity and r.get("type") == "qemu":
                try:
                    is_self = self.self_identity.matches(client._get(f"/nodes/{_seg(r['node'])}/qemu/{int(r['vmid'])}/config"))
                except (ProxmoxError, ProviderError):
                    continue
            if not is_self:
                continue
            if r.get("pool") in self.scope.pools:
                res.warnings.append(
                    f"ICS VM {r['vmid']} '{r.get('name')}' is inside the managed pool {r['pool']}: pool-scoped rights propagate onto it. "
                    "Pool membership is never treated as ownership; only guests carrying ou-managed + ou-deployment-<id> tags that the ICS "
                    "created are mutable, and the ICS's own VM is refused by identity regardless. Consider moving it out of the pool.")
            res.self_vm = {"vmid": r["vmid"], "node": r.get("node"), "name": r.get("name"), "mutable": False, "privileges": [],
                           "protected_reason": "explicit protected_vmids" if r["vmid"] in self.scope.protected else "matches this ICS host's NIC MAC / SMBIOS UUID"}
            for label, c, tid in (("provision", self._prov_ro, self._prov_tid), ("inventory", self._inv, self._inv_tid)):
                if c is None:
                    continue
                p = f"/vms/{int(r['vmid'])}"
                try:
                    d = c._get("/access/permissions?path=" + p).get(p) or {}
                except ProxmoxError:
                    continue
                bad = [x for x in MUTATING_PRIVS if d.get(x)]
                if bad:
                    res.self_vm["mutable"] = True
                    res.self_vm["privileges"] = sorted(set(res.self_vm["privileges"]) | set(bad))
                    res.warnings.append(
                        f"DANGER: the {label} token ({tid}) holds mutating privileges ({', '.join(bad)}) on VM {r['vmid']} "
                        f"'{r.get('name')}', which is THIS ICS host. The ICS refuses to mutate its own VM regardless, but remove the grant: "
                        f"pveum acl delete {p} --tokens '{tid}' --roles <role>   (keep at most PVEAuditor there)")

    def _extra_warnings(self, client) -> list[str]:
        at = self._perms_fn(client)
        w = []
        for p in self.scope.pools:
            if "Pool.Audit" not in at(f"/pool/{p}"):
                w.append(f"warning: Pool.Audit missing on /pool/{p}: pool membership is derived from /cluster/resources instead of GET /pools/{p} "
                         f"(fix: pveum acl modify /pool/{p} --tokens '{self._prov_tid}' --roles PVEPoolUser)")
            extra = [x for x in priv.UNNECESSARY if x in at(f"/pool/{p}")]
            if extra:
                w.append(f"warning: the provision token has privileges ICS does not use on /pool/{p}: {', '.join(extra)} (consider removing)")
        return w

    # ---- discovery
    def discover(self) -> Discovery:
        d = Discovery()
        now = datetime.now(timezone.utc)
        v = self._get("/version")
        self._check_sim(v)
        ver = v.get("version") if isinstance(v, dict) else None
        try:
            st = self._get("/cluster/status")
            cl = next((x for x in st if x.get("type") == "cluster"), None)
            ips = {x["name"]: x.get("ip") for x in st if x.get("type") == "node"}
            nodes_in = [x for x in st if x.get("type") == "node"]
            name = cl["name"] if cl else (nodes_in[0]["name"] if nodes_in else "standalone")
            d.clusters.append({"name": name, "quorate": bool(cl.get("quorate")) if cl else True, "nodes_total": len(nodes_in),
                               "nodes_online": sum(1 for x in nodes_in if x.get("online")), "version": ver})
            d.complete.add("clusters")
        except ProviderError as e:
            ips = {}
            d.warnings.append(f"cluster status: {e.message}")
        nodes: list[dict] = []
        try:
            for n in self._get("/nodes"):
                managed = self._node_audit(n["node"])
                if managed is None:
                    managed = bool(n.get("maxcpu"))
                if not managed:
                    d.warnings.append(f"node {n['node']} is listed by the cluster but the token has no Sys.Audit on it: not managed "
                                      "(its capacity is unknown and is not counted)")
                n["_managed"] = managed
                nodes.append(n)
                keep = (lambda v: v) if managed else (lambda v: None)  # no visibility is NOT idle capacity
                d.nodes.append({"name": n["node"], "status": n.get("status", "unknown"), "cpu_total": keep(n.get("maxcpu")),
                                "mem_total": keep(n.get("maxmem")), "mem_used": keep(n.get("mem")),
                                "cpu_pct": keep((n.get("cpu") or 0) * 100 if n.get("cpu") is not None else None),
                                "disk_total": keep(n.get("maxdisk")), "disk_used": keep(n.get("disk")), "uptime": keep(n.get("uptime")),
                                "ip": ips.get(n["node"]), "managed": managed})
            d.complete.add("nodes")
        except ProviderError as e:
            d.warnings.append(f"nodes: {e.message}")
        online = [n["node"] for n in nodes if n.get("status") == "online" and n["_managed"]]
        stor_ok = net_ok = True
        for n in online:
            try:
                for s in self._get(f"/nodes/{_seg(n)}/storage"):
                    d.storage.append({"name": s["storage"], "node": n, "type": s.get("type"), "thin": s.get("type") in THIN_TYPES,
                                      "provisioned_bytes": self._provisioned(n, s),
                                      "content": [c for c in (s.get("content") or "").split(",") if c], "shared": bool(s.get("shared")),
                                      "enabled": bool(s.get("enabled", 1)), "active": bool(s.get("active", 1)),
                                      "total": s.get("total"), "used": s.get("used")})
            except ProviderError as e:
                stor_ok = False
                d.warnings.append(f"storage on {n}: {e.message}")
            try:
                for i in self._get(f"/nodes/{_seg(n)}/network"):
                    if i.get("type") in ("bridge", "OVSBridge"):
                        d.networks.append({"name": i["iface"], "node": n, "kind": "bridge", "vlan_aware": bool(i.get("bridge_vlan_aware")),
                                           "ports": i.get("bridge_ports"), "cidr": i.get("cidr"), "zone": None, "tag": None})
            except ProviderError as e:
                net_ok = False
                d.warnings.append(f"network on {n}: {e.message}")
        if len(online) == sum(1 for n in nodes if n["_managed"] and n.get("status") == "online"):
            if stor_ok:
                d.complete.add("storage")
            if net_ok:
                d.complete.add("networks")
        try:
            for z in self._get("/cluster/sdn/zones"):
                d.networks.append({"name": z["zone"], "node": "", "kind": "sdn_zone", "vlan_aware": None, "ports": None, "cidr": None,
                                   "zone": z["zone"], "tag": None})
            for vn in self._get("/cluster/sdn/vnets"):
                d.networks.append({"name": vn["vnet"], "node": "", "kind": "sdn_vnet", "vlan_aware": None, "ports": None, "cidr": None,
                                   "zone": vn.get("zone"), "tag": vn.get("tag")})
        except ProviderError as e:
            net_ok = False
            d.complete.discard("networks")
            d.warnings.append(f"SDN: {e.message} (needs SDN.Audit; bridges are still listed)")
        try:
            for r in self._get("/cluster/resources?type=vm"):
                if r.get("type") not in ("qemu", "lxc"):
                    continue
                tags = tags_of(r.get("tags"))
                dep = next((t[len(DEP_PREFIX):] for t in tags if t.startswith(DEP_PREFIX)), None)
                kind = "vm" if r["type"] == "qemu" else "lxc"
                base = {"vmid": r["vmid"], "kind": kind, "node": r.get("node", ""), "name": r.get("name"), "tags": tags, "pool": r.get("pool"),
                        "disk_max": r.get("maxdisk")}
                if r.get("template"):
                    d.templates.append(base)
                else:
                    d.guests.append({**base, "status": r.get("status", "unknown"), "ou_managed": OWNED_TAG in tags,
                                     "ou_deployment_id": dep if OWNED_TAG in tags else None, "cpus": r.get("maxcpu"),
                                     "mem_max": r.get("maxmem"), "uptime": r.get("uptime"),
                                     "cpu_pct": (r.get("cpu") or 0) * 100, "mem_used": r.get("mem")})
            d.complete |= {"guests", "templates"}
        except ProviderError as e:
            d.warnings.append(f"guests: {e.message}")
        d.observed_at = now  # type: ignore[attr-defined]
        return d

    def _provisioned(self, node: str, s: dict) -> int | None:
        """Sum of the sizes of the VISIBLE volumes on a storage (virtual size). Incomplete if the token cannot see every guest, so
        it is only ever shown next to PVE's own physical used/total, never as capacity on its own."""
        if not {"images", "rootdir"} & set((s.get("content") or "").split(",")) or not s.get("active", 1):
            return None
        try:
            vols = self._c()._get(f"/nodes/{_seg(node)}/storage/{urllib.parse.quote(s['storage'], safe='')}/content")
        except ProxmoxError:
            return None
        return sum(int(v.get("size") or 0) for v in vols if isinstance(v, dict))

    def _node_audit(self, node: str) -> bool | None:
        path = f"/nodes/{_seg(node)}"
        try:
            d = self._c()._get("/access/permissions?path=" + path)
        except ProxmoxError:
            return None
        return bool((d.get(path) or {}).get("Sys.Audit"))

    # ---- metrics
    _NODE_M = {"cpu": ("cpu_pct", 100.0), "memused": ("mem_used_bytes", 1), "memtotal": ("mem_total_bytes", 1), "netin": ("net_in_bps", 1),
               "netout": ("net_out_bps", 1), "loadavg": ("load1", 1), "iowait": ("iowait_pct", 100.0), "rootused": ("disk_used_bytes", 1),
               "roottotal": ("disk_total_bytes", 1)}
    _GUEST_M = {"cpu": ("cpu_pct", 100.0), "mem": ("mem_used_bytes", 1), "maxmem": ("mem_total_bytes", 1), "netin": ("net_in_bps", 1),
                "netout": ("net_out_bps", 1), "diskread": ("disk_read_bps", 1), "diskwrite": ("disk_write_bps", 1),
                "disk": ("disk_used_bytes", 1), "maxdisk": ("disk_total_bytes", 1)}

    def metrics(self, scope: Scope, since: datetime, step: int = 60) -> list[Sample]:
        age = (datetime.now(timezone.utc) - since).total_seconds()
        tf = "hour" if age <= 3600 else "day" if age <= 86400 else "week" if age <= 7 * 86400 else "month"
        if scope.type == "node":
            path, mp, key = f"/nodes/{_seg(scope.node)}/rrddata?timeframe={tf}&cf=AVERAGE", self._NODE_M, scope.node
        elif scope.type == "guest":
            path = f"/nodes/{_seg(scope.node)}/{_KIND_PATH[scope.kind]}/{int(scope.vmid)}/rrddata?timeframe={tf}&cf=AVERAGE"
            mp, key = self._GUEST_M, str(int(scope.vmid))
        else:
            raise ProviderError("unsupported", "storage metrics come from discovery snapshots, not rrddata")
        rows = self._get(path)
        out: list[Sample] = []
        for r in rows:
            t = r.get("time")
            if not isinstance(t, (int, float)):
                continue
            ts = datetime.fromtimestamp(t, timezone.utc)
            if ts < since:
                continue
            for src, (metric, mult) in mp.items():
                v = r.get(src)
                if isinstance(v, (int, float)) and not isinstance(v, bool) and v == v and abs(v) != float("inf"):
                    out.append(Sample(scope.type, key, metric, ts, float(v) * mult))
        return out

    # ---- tasks
    def _upid(self, task: TaskRef) -> tuple[str, str]:
        m = _UPID.match(task.upid or "")
        if not m or m.group(1) != task.node:
            raise ProviderError("bad_task", "malformed task reference")
        return m.group(1), urllib.parse.quote(task.upid, safe=":@!")

    def task_status(self, task: TaskRef) -> TaskStatus:
        if task.upid is None:
            return TaskStatus("ok", "OK", "completed synchronously")
        node, q = self._upid(task)
        d = self._get(f"/nodes/{_seg(node)}/tasks/{q}/status", self._task_client())
        if d.get("status") != "stopped":
            return TaskStatus("running")
        ex = d.get("exitstatus") or "unknown"
        if ex == "OK" or ex.startswith("WARNINGS"):
            return TaskStatus("ok", ex)
        tail = ""
        try:
            log = self._get(f"/nodes/{_seg(node)}/tasks/{q}/log?limit=20&start=0", self._task_client())
            tail = " | ".join(_clean(x.get("t"), 160) for x in log[-4:])
        except ProviderError:
            pass
        return TaskStatus("error", ex, _clean(f"{ex}" + (f" ({tail})" if tail else ""), 600))

    def _task_client(self):
        return None

    def wait(self, task: TaskRef, timeout: float = 300.0, interval: float = 1.0) -> TaskStatus:
        """Poll until done. Raises ProviderTimeout (the task may still finish on Proxmox: check its log) or ProviderError on failure."""
        end = time.monotonic() + timeout
        while True:
            st = self.task_status(task)
            if st.state == "ok":
                return st
            if st.state == "error":
                raise ProviderError("task_failed", f"Proxmox task {task.kind} failed: {st.message}")
            if time.monotonic() >= end:
                raise ProviderTimeout(f"Proxmox task {task.kind} was still running after {timeout:g}s; it may complete on its own - "
                                      "check the task log in Proxmox before retrying.")
            self._sleep(min(interval, max(0.0, end - time.monotonic())))


class ProxmoxMutations(ProxmoxProvider):
    """Mutation verbs. Only constructible inside job execution and only with a provision credential."""

    def __init__(self, write: ProxmoxWriteClient, *, scope: EndpointScope, token_id: str, allow_simulator: bool = False,
                 sleep: Callable[[float], None] = time.sleep, self_identity: SelfIdentity | None = None):
        require_job_execution()
        if not scope.pools:
            raise MutationNotAllowed("endpoint has no allowed pool; mutations refused")
        super().__init__(write, scope=scope, inventory_token_id=token_id, provision_token_id=token_id, allow_simulator=allow_simulator, sleep=sleep,
                         self_identity=self_identity)
        self._w, self._tid = write, token_id
        self._prov_ro = write
        self._inv = write  # reads (task polling, guest resolution) use the provision token: it only sees its own pools

    def _task_client(self):
        return self._w

    def _do(self, method: str, path: str, data: dict | None = None):
        require_job_execution()
        try:
            return getattr(self._w, method)(path, data) if method in ("post", "put") else getattr(self._w, method)(path)
        except ProxmoxError as e:
            raise map_error(e, "operation") from None

    # ---- scope helpers
    def _resources(self) -> list[dict]:
        return self._get("/cluster/resources?type=vm", self._w)

    def _guest(self, ref: VmRef, *, allow_untagged: bool = False) -> dict:
        if not ref.deployment_id or not _DEP_ID.match(ref.deployment_id):
            raise ScopeViolation("a valid deployment id is required to modify a guest")
        self._refuse_self(ref.vmid, ref.node, ref.kind)
        r = next((x for x in self._resources() if x.get("vmid") == ref.vmid), None)
        if r is None:
            raise ScopeViolation(f"guest {ref.vmid} is not visible to the provisioning token (not in an allowed pool)")
        if r.get("node") != ref.node or r.get("type") != _KIND_PATH[ref.kind]:
            raise ScopeViolation(f"guest {ref.vmid} is not a {ref.kind} on node {ref.node}")
        if r.get("pool") not in self.scope.pools:
            raise ScopeViolation(f"guest {ref.vmid} is in pool {r.get('pool')!r}, not in the endpoint's allowed pools")
        if r.get("template"):
            raise ScopeViolation(f"guest {ref.vmid} is a template")
        tags = tags_of(r.get("tags"))
        if not allow_untagged and (OWNED_TAG not in tags or DEP_PREFIX + ref.deployment_id.lower() not in tags):
            raise ScopeViolation(f"guest {ref.vmid} does not carry the ownership tags {OWNED_TAG} + {DEP_PREFIX}{ref.deployment_id}")
        return r

    def _refuse_self(self, vmid: int, node: str, kind: str = "vm") -> None:
        """HARD RULE: never touch the ICS's own VM or a protected guest, whatever the token is allowed to do. Fails closed."""
        if vmid in self.scope.protected:
            raise ScopeViolation(f"guest {vmid} is protected (protected_vmids); refusing to modify it")
        if self.self_identity:
            try:
                cfg = self._get(f"/nodes/{_seg(node)}/{_KIND_PATH[kind]}/{int(vmid)}/config", self._w)
            except ProviderError:
                raise ScopeViolation(f"cannot verify that guest {vmid} is not the ICS host itself; refusing") from None
            if self.self_identity.matches(cfg):
                raise ScopeViolation(f"guest {vmid} is the ICS host itself (NIC MAC / SMBIOS UUID match); refusing every mutation of it")

    def _cfg(self, ref: VmRef) -> dict:
        return self._get(f"/nodes/{_seg(ref.node)}/{_KIND_PATH[ref.kind]}/{int(ref.vmid)}/config", self._w)

    def _storage_of(self, value: str) -> str:
        return str(value).split(":", 1)[0]

    def _need_storage(self, st: str) -> None:
        if st not in self.scope.storage:
            raise ScopeViolation(f"storage {st!r} is not in the endpoint's allowed storage")

    def _node_names(self) -> set[str]:
        return {n["node"] for n in self._get("/nodes", self._w)}

    def _task(self, node: str, upid, vmid=None, kind="task", dep=None) -> TaskRef:
        if isinstance(upid, str) and upid.startswith("UPID:"):
            return TaskRef(node, upid, vmid, kind, dep)
        return TaskRef(node, None, vmid, kind, dep)

    # ---- verbs
    def clone_vm(self, spec: VmCloneSpec) -> TaskRef:
        require_job_execution()
        if not _DEP_ID.match(spec.deployment_id.lower()):
            raise ScopeViolation("invalid deployment id")
        if not _NAME.match(spec.name):
            raise ProviderError("invalid_request", "VM name must be a valid DNS label")
        if spec.pool not in self.scope.pools:
            raise ScopeViolation(f"pool {spec.pool!r} is not in the endpoint's allowed pools")
        if spec.new_vmid is not None and spec.new_vmid in self.scope.protected:
            raise ScopeViolation(f"vmid {spec.new_vmid} is protected; refusing to clone into it")
        if spec.template_vmid in self.scope.protected:
            raise ScopeViolation(f"vmid {spec.template_vmid} is protected and cannot be used as a template")
        res = self._resources()
        t = next((x for x in res if x.get("vmid") == spec.template_vmid), None)
        if t is None or not t.get("template") or t.get("node") != spec.template_node:
            raise ScopeViolation(f"template {spec.template_vmid} not found on node {spec.template_node}")
        if t.get("pool") not in self.scope.pools and spec.template_vmid not in self.scope.templates:
            raise ScopeViolation(f"template {spec.template_vmid} is not in an allowed pool and was not explicitly approved")
        if spec.full:
            self._need_storage(spec.storage)
        else:
            tcfg = self._get(f"/nodes/{_seg(spec.template_node)}/qemu/{spec.template_vmid}/config", self._w)
            for k, v in tcfg.items():
                if _DISK.match(k) and isinstance(v, str) and ":" in v:
                    self._need_storage(self._storage_of(v))
        if spec.target_node and spec.target_node not in self._node_names():
            raise ScopeViolation(f"target node {spec.target_node!r} is not part of this cluster")
        newid = spec.new_vmid
        if newid is None:
            newid = int(self._get("/cluster/nextid", self._w))
        if not 100 <= newid <= 999_999_999:
            raise ProviderError("invalid_request", "vmid out of range")
        data = {"newid": newid, "name": spec.name, "pool": spec.pool, "full": 1 if spec.full else 0}
        if spec.full:
            data["storage"] = spec.storage
        if spec.target_node and spec.target_node != spec.template_node:
            data["target"] = spec.target_node
        upid = self._do("post", f"/nodes/{_seg(spec.template_node)}/qemu/{spec.template_vmid}/clone", data)
        return self._task(spec.template_node, upid, newid, "qmclone", spec.deployment_id)

    def finalize_clone(self, task: TaskRef) -> TaskRef:
        """Apply the ownership tags to a VM created by a clone task of this token. MUST be called by the executor once the clone task
        succeeded (PVE clone cannot set tags). Refuses anything that is not that exact, successful clone task."""
        require_job_execution()
        m = _UPID.match(task.upid or "")
        if (not m or m.group(2) != "qmclone" or m.group(3) != str(task.vmid) or m.group(4) != self._tid
                or not task.deployment_id or not _DEP_ID.match(task.deployment_id.lower())):
            raise ScopeViolation("finalize_clone needs the UPID of a qmclone task started by this credential")
        if self.task_status(task).state != "ok":
            raise ProviderError("task_not_done", "the clone task has not completed successfully")
        r = next((x for x in self._resources() if x.get("vmid") == task.vmid), None)
        if r is None or r.get("pool") not in self.scope.pools:
            raise ScopeViolation("cloned guest is not in an allowed pool")
        keep = [t for t in tags_of(r.get("tags")) if t != OWNED_TAG and not t.startswith(DEP_PREFIX)]
        tags = ";".join(keep + [OWNED_TAG, DEP_PREFIX + task.deployment_id.lower()])
        node = r["node"]
        up = self._do("put", f"/nodes/{_seg(node)}/qemu/{int(task.vmid)}/config", {"tags": tags})
        return self._task(node, up, task.vmid, "tag", task.deployment_id)

    def configure_vm(self, ref: VmRef, spec: VmConfigSpec) -> TaskRef:
        require_job_execution()
        self._guest(ref)
        d: dict = {}
        if spec.cores is not None:
            if not 1 <= spec.cores <= 256:
                raise ProviderError("invalid_request", "cores must be 1..256")
            d["cores"] = spec.cores
        if spec.memory_mb is not None:
            if not 128 <= spec.memory_mb <= 4_194_304:
                raise ProviderError("invalid_request", "memory must be 128 MB..4 TB")
            d["memory"] = spec.memory_mb
        for n in spec.nics:
            if not 0 <= n.index <= 31 or not re.fullmatch(r"[A-Za-z0-9_.-]{1,10}", n.bridge) or (n.vlan is not None and not 1 <= n.vlan <= 4094):
                raise ProviderError("invalid_request", "invalid NIC specification")
            if not self.scope.network_ok(n.bridge, n.vlan):
                raise ScopeViolation(f"bridge/VLAN {n.bridge}{'/' + str(n.vlan) if n.vlan else ''} is not in the endpoint's allowed networks")
            d[f"net{n.index}"] = f"{n.model},bridge={n.bridge}" + (f",tag={n.vlan}" if n.vlan else "") + f",firewall={int(n.firewall)}"
        for key, st, size in spec.new_disks:
            if not _NEWDISK.match(key) or not 1 <= size <= 65536:
                raise ProviderError("invalid_request", "invalid disk specification")
            self._need_storage(st)
            d[key] = f"{st}:{size}"
        if spec.cloudinit_storage:
            self._need_storage(spec.cloudinit_storage)
            d["ide2"] = f"{spec.cloudinit_storage}:cloudinit"
        if spec.ciuser is not None:
            if not _CIUSER.match(spec.ciuser):
                raise ProviderError("invalid_request", "invalid cloud-init user name")
            d["ciuser"] = spec.ciuser
        if spec.sshkeys:
            for k in spec.sshkeys:
                if not _SSHKEY.match(k):
                    raise ProviderError("invalid_request", "an SSH public key is malformed or of an unsupported type")
            d["sshkeys"] = urllib.parse.quote("\n".join(spec.sshkeys) + "\n", safe="")  # PVE's `urlencoded` format
        for ic in spec.ipconfigs:
            try:
                if ic.ip != "dhcp":
                    ipaddress.ip_interface(ic.ip)
                if ic.gw:
                    ipaddress.ip_address(ic.gw)
            except ValueError:
                raise ProviderError("invalid_request", "invalid ipconfig address") from None
            if not 0 <= ic.index <= 31:
                raise ProviderError("invalid_request", "invalid ipconfig index")
            d[f"ipconfig{ic.index}"] = f"ip={ic.ip}" + (f",gw={ic.gw}" if ic.gw else "")
        if spec.nameserver:
            try:
                ipaddress.ip_address(spec.nameserver)
            except ValueError:
                raise ProviderError("invalid_request", "invalid nameserver") from None
            d["nameserver"] = spec.nameserver
        if spec.searchdomain:
            if not _DOMAIN.match(spec.searchdomain):
                raise ProviderError("invalid_request", "invalid search domain")
            d["searchdomain"] = spec.searchdomain
        if spec.cicustom:
            if not self.scope.allow_cicustom:
                raise ScopeViolation("cicustom snippets are not enabled for this endpoint")
            m = _CICUSTOM.match(spec.cicustom)
            if not m:
                raise ProviderError("invalid_request", "cicustom must be <user|network|meta|vendor>=<storage>:snippets/<file>")
            self._need_storage(m.group(2))
            d["cicustom"] = spec.cicustom
        if spec.description is not None:
            d["description"] = _clean(spec.description, 200)
        if not d:
            raise ProviderError("invalid_request", "nothing to configure")
        up = self._do("put", f"/nodes/{_seg(ref.node)}/{_KIND_PATH[ref.kind]}/{int(ref.vmid)}/config", d)
        return self._task(ref.node, up, ref.vmid, "config", ref.deployment_id)

    def resize_disk(self, ref: VmRef, disk: str, new_size_gb: int) -> TaskRef:
        require_job_execution()
        self._guest(ref)
        if not _DISK.match(disk) or not 1 <= new_size_gb <= 65536:
            raise ProviderError("invalid_request", "invalid disk or size")
        cfg = self._cfg(ref)
        cur = cfg.get(disk)
        if not isinstance(cur, str) or "size=" not in cur:
            raise ProviderError("invalid_request", f"guest has no sized disk {disk}")
        self._need_storage(self._storage_of(cur))
        m = re.search(r"size=(\d+)([KMGT]?)", cur)
        cur_gb = int(m.group(1)) * {"": 1 / (1 << 30), "K": 1 / (1 << 20), "M": 1 / (1 << 10), "G": 1, "T": 1024}[m.group(2)]
        if new_size_gb <= cur_gb:
            raise ProviderError("invalid_request", f"disks can only grow (current {cur_gb:g} GB, requested {new_size_gb} GB)")
        up = self._do("put", f"/nodes/{_seg(ref.node)}/{_KIND_PATH[ref.kind]}/{int(ref.vmid)}/resize", {"disk": disk, "size": f"{new_size_gb}G"})
        return self._task(ref.node, up, ref.vmid, "resize", ref.deployment_id)

    def power(self, ref: VmRef, op: Literal["start", "shutdown", "stop", "reboot"]) -> TaskRef:
        require_job_execution()
        if op not in ("start", "shutdown", "stop", "reboot"):
            raise ProviderError("invalid_request", "unknown power operation")
        self._guest(ref)
        up = self._do("post", f"/nodes/{_seg(ref.node)}/{_KIND_PATH[ref.kind]}/{int(ref.vmid)}/status/{op}", {})
        return self._task(ref.node, up, ref.vmid, "power-" + op, ref.deployment_id)

    def snapshot(self, ref: VmRef, name: str) -> TaskRef:
        require_job_execution()
        if not _SNAP.match(name):
            raise ProviderError("invalid_request", "snapshot name must match [A-Za-z][A-Za-z0-9_-]{0,39}")
        self._guest(ref)
        up = self._do("post", f"/nodes/{_seg(ref.node)}/{_KIND_PATH[ref.kind]}/{int(ref.vmid)}/snapshot", {"snapname": name})
        return self._task(ref.node, up, ref.vmid, "snapshot", ref.deployment_id)

    def rollback(self, ref: VmRef, name: str) -> TaskRef:
        require_job_execution()
        if not _SNAP.match(name):
            raise ProviderError("invalid_request", "invalid snapshot name")
        self._guest(ref)
        up = self._do("post", f"/nodes/{_seg(ref.node)}/{_KIND_PATH[ref.kind]}/{int(ref.vmid)}/snapshot/{name}/rollback", {})
        return self._task(ref.node, up, ref.vmid, "rollback", ref.deployment_id)

    def migrate(self, ref: VmRef, target_node: str, online: bool) -> TaskRef:
        require_job_execution()
        g = self._guest(ref)
        if target_node not in self._node_names() or target_node == ref.node:
            raise ScopeViolation(f"target node {target_node!r} is not another node of this cluster")
        for k, v in self._cfg(ref).items():
            if _DISK.match(k) and isinstance(v, str) and ":" in v and "media=cdrom" not in v:
                self._need_storage(self._storage_of(v))
        data = {"target": target_node}
        if online and g.get("status") == "running":
            data["online"] = 1
            if ref.kind == "vm":
                data["with-local-disks"] = 1
        up = self._do("post", f"/nodes/{_seg(ref.node)}/{_KIND_PATH[ref.kind]}/{int(ref.vmid)}/migrate", data)
        return self._task(ref.node, up, ref.vmid, "migrate", ref.deployment_id)

    def destroy_vm(self, ref: VmRef) -> TaskRef:
        require_job_execution()
        g = self._guest(ref)
        if g.get("status") == "running":
            raise ProviderError("invalid_state", f"guest {ref.vmid} is running; stop it before destroying it")
        up = self._do("delete", f"/nodes/{_seg(ref.node)}/{_KIND_PATH[ref.kind]}/{int(ref.vmid)}?purge=1&destroy-unreferenced-disks=1")
        return self._task(ref.node, up, ref.vmid, "destroy", ref.deployment_id)


def _seg(node: str) -> str:
    if not isinstance(node, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,62}", node):
        raise ProviderError("invalid_request", "invalid node name")
    return node
