"""Per-customer network model (agent BY, Stage 4/5 prep): which SDN VNet/subnet a customer's deployments live on.

Pure data + pure functions, no I/O except `load_network_model()` (a JSON/YAML file named by `OU_NETWORK_MODEL`). Planning stays a pure
function: `generate_plan(..., networks=model, scope_networks=endpoint.allowed_networks)`.

What this module guarantees at PLAN time (the hypervisor enforces the same thing again at run time, see docs/admin/proxmox-sdn-isolation.md):
  * a customer's NICs attach ONLY to the VNet assigned to that customer on that endpoint (never the shared bridge, never another customer's VNet);
  * the VNet must be inside the endpoint's `allowed_networks` (the same `EndpointScope.networks` the provider enforces on every NIC call);
  * subnets of different customers never overlap, and no service address (ICS, repo, DNS ...) lies inside a customer subnet;
  * every VM gets a deterministic static address (.10 + index, sorted by VM name) and the subnet's gateway;
  * the plan carries the exact flow list the PVE firewall must allow (everything else is DROP): `plan["network"]["flows"]`.
App-level controls are NOT part of this: the plan only describes network facts the hypervisor must enforce.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SLUG = r"^[a-z0-9][a-z0-9-]{1,30}$"
PVE_ID = r"^[a-z][a-z0-9]{0,7}$"          # SDN zone / vnet ids: max 8 chars, lowercase alphanumeric
FIRST_HOST_OFFSET = 10                     # .1 gateway, .2-.9 reserved (future gateway/HA addresses), VMs from .10
_HOSTPORT = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$")


class _M(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _net(s: str) -> ipaddress.IPv4Network:
    try:
        n = ipaddress.IPv4Network(s, strict=True)
    except ValueError as e:
        raise ValueError(f"not a valid IPv4 network: {s!r} ({e})") from None
    return n


def _hostport(s: str) -> tuple[ipaddress.IPv4Address, int]:
    m = _HOSTPORT.match(s)
    if not m:
        raise ValueError(f"expected <ipv4>:<port>, got {s!r}")
    try:
        ip, port = ipaddress.IPv4Address(m.group(1)), int(m.group(2))
    except ValueError:
        raise ValueError(f"bad address in {s!r}") from None
    if not 1 <= port <= 65535:
        raise ValueError(f"bad port in {s!r}")
    return ip, port


class NetworkAssignment(_M):
    """One customer on one endpoint -> one VNet and one subnet."""
    customer_id: str = Field(pattern=SLUG)
    endpoint: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,62}$")
    zone: str = Field(pattern=PVE_ID)
    vnet: str = Field(pattern=PVE_ID)
    subnet: str
    gateway: str | None = None

    @field_validator("subnet")
    @classmethod
    def _subnet(cls, v: str) -> str:
        n = _net(v)
        if not n.is_private:
            raise ValueError("customer subnets must be private (RFC 1918) addresses")
        if not 16 <= n.prefixlen <= 28:
            raise ValueError("customer subnet prefix must be between /16 and /28")
        return str(n)

    @model_validator(mode="after")
    def _gw(self):
        n = _net(self.subnet)
        gw = ipaddress.IPv4Address(self.gateway) if self.gateway else next(n.hosts())
        if gw not in n or gw == n.network_address or gw == n.broadcast_address:
            raise ValueError(f"gateway {gw} is not a host address of {n}")
        self.gateway = str(gw)
        return self

    @property
    def net(self) -> ipaddress.IPv4Network:
        return ipaddress.IPv4Network(self.subnet)


class ServiceFlows(_M):
    """Addresses outside the customer subnets that guests/management legitimately talk to (site-wide, one set per endpoint)."""
    mgmt_sources: list[str] = Field(min_length=1, max_length=8, description="CIDRs (normally the ICS /32) allowed to reach the node-agent port")
    agent_port: int = Field(default=8443, ge=1, le=65535)
    ics_callback: str = Field(description="<ip>:<port> of the dedicated guest-bootstrap callback listener on the ICS")
    repo: list[str] = Field(min_length=1, max_length=8, description="<ip>:<port> of the signed apt repository / OCI registry mirror")
    backup: list[str] = Field(default_factory=list, max_length=8, description="<ip>:<port> of the backup target (restic repository)")
    dns: list[str] = Field(min_length=1, max_length=4, description="resolver addresses (UDP+TCP 53)")
    ntp: list[str] = Field(default_factory=list, max_length=4, description="NTP server addresses (UDP 123)")
    edge_sources: list[str] = Field(default_factory=list, max_length=8, description="CIDRs of the edge/reverse proxy that may open inbound service ports")

    @field_validator("mgmt_sources", "edge_sources")
    @classmethod
    def _cidrs(cls, v: list[str]) -> list[str]:
        return [str(_net(x)) for x in v]

    @field_validator("ics_callback")
    @classmethod
    def _cb(cls, v: str) -> str:
        _hostport(v)
        return v

    @field_validator("repo", "backup")
    @classmethod
    def _hp(cls, v: list[str]) -> list[str]:
        for x in v:
            _hostport(x)
        return v

    @field_validator("dns", "ntp")
    @classmethod
    def _ips(cls, v: list[str]) -> list[str]:
        for x in v:
            ipaddress.IPv4Address(x)
        return v

    def addresses(self) -> list[ipaddress.IPv4Network]:
        out = [_net(x) for x in self.mgmt_sources + self.edge_sources]
        out += [ipaddress.IPv4Network(f"{_hostport(x)[0]}/32") for x in [self.ics_callback, *self.repo, *self.backup]]
        out += [ipaddress.IPv4Network(f"{ipaddress.IPv4Address(x)}/32") for x in [*self.dns, *self.ntp]]
        return out


class NetworkModel(_M):
    version: int = Field(default=1, ge=1, le=1)
    assignments: list[NetworkAssignment] = Field(default_factory=list, max_length=500)
    flows: dict[str, ServiceFlows] = Field(default_factory=dict, description="endpoint name -> service flows")

    @model_validator(mode="after")
    def _consistent(self):
        seen_v: dict[tuple[str, str], str] = {}
        seen_c: set[tuple[str, str]] = set()
        for a in self.assignments:
            if (a.customer_id, a.endpoint) in seen_c:
                raise ValueError(f"customer {a.customer_id!r} has two assignments on endpoint {a.endpoint!r}")
            seen_c.add((a.customer_id, a.endpoint))
            k = (a.endpoint, a.vnet)
            if k in seen_v:
                raise ValueError(f"vnet {a.vnet!r} on {a.endpoint!r} is assigned to both {seen_v[k]!r} and {a.customer_id!r}")
            seen_v[k] = a.customer_id
            if a.endpoint not in self.flows:
                raise ValueError(f"endpoint {a.endpoint!r} has assignments but no `flows` entry")
        for i, a in enumerate(self.assignments):
            for b in self.assignments[i + 1:]:
                if a.endpoint == b.endpoint and a.net.overlaps(b.net):
                    raise ValueError(f"subnets of {a.customer_id!r} ({a.subnet}) and {b.customer_id!r} ({b.subnet}) overlap on {a.endpoint!r}")
            for s in self.flows[a.endpoint].addresses():
                if s.overlaps(a.net):
                    raise ValueError(f"service address {s} lies inside the customer subnet {a.subnet} of {a.customer_id!r}")
        return self

    def for_customer(self, customer_id: str, endpoint: str) -> NetworkAssignment | None:
        return next((a for a in self.assignments if a.customer_id == customer_id and a.endpoint == endpoint), None)

    def digest_input(self) -> dict:
        return self.model_dump(mode="json")


def load_network_model(path: str | os.PathLike | None = None) -> NetworkModel | None:
    """`OU_NETWORK_MODEL` (or `path`): JSON or YAML file. Unset = no model (legacy single-bridge planning, with the `no_vlan_isolation` warning).
    A set-but-broken file raises: a typo must not silently turn isolation off."""
    p = path or os.environ.get("OU_NETWORK_MODEL")
    if not p:
        return None
    text = Path(p).read_text(encoding="utf-8")
    if str(p).endswith((".yaml", ".yml")):
        import yaml
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    return NetworkModel.model_validate(data)


# ---- plan-time resolution ----------------------------------------------------------------------------------------------

def _err(code: str, msg: str, **d) -> dict:
    return {"code": code, "message": msg, **d}


def resolve(model: NetworkModel, customer_id: str, endpoint: str, requested_bridge: str, scope_networks: tuple[str, ...] | None,
            vm_names: list[str], default_bridge: str = "vmbr0") -> tuple[dict | None, list[dict], list[dict]]:
    """-> (network section for the plan or None, errors, warnings). `scope_networks` None = scope unknown (not checked)."""
    errors: list[dict] = []
    warnings: list[dict] = []
    a = model.for_customer(customer_id, endpoint)
    if a is None:
        errors.append(_err("network_unassigned", f"customer {customer_id!r} has no VNet assigned on endpoint {endpoint!r}; production plans never fall back "
                                                 "to a shared bridge. Assign a VNet in the network model (docs/admin/proxmox-sdn-isolation.md)."))
        return None, errors, warnings
    if requested_bridge not in (a.vnet, default_bridge):
        owner = next((x.customer_id for x in model.assignments if x.endpoint == endpoint and x.vnet == requested_bridge), None)
        errors.append(_err("network_not_assigned",
                           f"bridge/VNet {requested_bridge!r} is not the network of customer {customer_id!r} (assigned: {a.vnet!r})"
                           + (f"; it belongs to customer {owner!r}" if owner else ""), vnet=a.vnet))
    if scope_networks is not None:
        from ..providers.proxmox.provider import EndpointScope
        if not EndpointScope(networks=tuple(scope_networks)).network_ok(a.vnet, None):
            errors.append(_err("network_out_of_scope", f"VNet {a.vnet!r} is not in the endpoint's allowed networks; the provider would refuse every NIC on it. "
                                                       "Add it to the endpoint scope (and grant SDN.Use on /sdn/zones/{zone}/{vnet} in Proxmox)".format(zone=a.zone, vnet=a.vnet)))
    hosts = list(a.net.hosts())
    first = ipaddress.IPv4Address(int(a.net.network_address) + FIRST_HOST_OFFSET)
    free = [h for h in hosts if h >= first and str(h) != a.gateway]
    names = sorted(vm_names)
    if len(names) > len(free):
        errors.append(_err("subnet_too_small", f"{len(names)} VMs need addresses but {a.subnet} offers {len(free)} from .{FIRST_HOST_OFFSET}", subnet=a.subnet))
        addrs: dict[str, str] = {}
    else:
        addrs = {n: f"{free[i]}/{a.net.prefixlen}" for i, n in enumerate(names)}
    sf = model.flows[endpoint]
    net = {"zone": a.zone, "vnet": a.vnet, "subnet": a.subnet, "gateway": a.gateway, "addresses": addrs, "dns": list(sf.dns),
           "isolation": {"default": "drop", "cross_customer": "drop", "other_customer_subnets": sorted(
               x.subnet for x in model.assignments if x.endpoint == endpoint and x.customer_id != customer_id)},
           "flows": _flows(a, sf)}
    return net, errors, warnings


def _flows(a: NetworkAssignment, sf: ServiceFlows) -> list[dict]:
    """The complete allow-list, in a stable order. Anything not listed (in particular any other customer's subnet) is dropped."""
    f: list[dict] = []

    def add(fid, direction, src, dst, proto, port, purpose):
        f.append({"id": fid, "direction": direction, "from": src, "to": dst, "proto": proto, "port": port, "purpose": purpose})

    for s in sf.mgmt_sources:
        add("mgmt-agent", "in", s, a.subnet, "tcp", sf.agent_port, "ICS -> node agent (mTLS)")
    ip, port = _hostport(sf.ics_callback)
    add("bootstrap-callback", "out", a.subnet, f"{ip}/32", "tcp", port, "guest -> ICS bootstrap callback listener (pinned TLS)")
    for r in sf.repo:
        ip, port = _hostport(r)
        add("repo", "out", a.subnet, f"{ip}/32", "tcp", port, "guest -> signed apt repository / OCI registry")
    for r in sf.backup:
        ip, port = _hostport(r)
        add("backup", "out", a.subnet, f"{ip}/32", "tcp", port, "guest -> backup target")
    for d in sf.dns:
        add("dns-udp", "out", a.subnet, f"{d}/32", "udp", 53, "DNS")
        add("dns-tcp", "out", a.subnet, f"{d}/32", "tcp", 53, "DNS")
    for n in sf.ntp:
        add("ntp", "out", a.subnet, f"{n}/32", "udp", 123, "time")
    for e in sf.edge_sources:
        add("edge-inbound", "in", e, a.subnet, "tcp+udp", "per plan.firewall (exposure edge/public)", "edge/reverse proxy -> published service ports only")
    add("intra-customer", "internal", a.subnet, a.subnet, "tcp+udp", "per plan.firewall", "VM <-> VM inside this customer, component ports only")
    return f
