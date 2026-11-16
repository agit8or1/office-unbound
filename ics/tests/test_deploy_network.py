"""Per-customer VNet assignment in plans (agent BY). Pure: no database."""
import json

import pytest
from pydantic import ValidationError

from ics.deploy.executor import _ipconfigs, _nameserver
from ics.deploy.netmodel import NetworkModel, load_network_model
from ics.deploy.plan import generate_plan
from ics.providers.proxmox import EndpointScope
from tests.test_deploy_plan import cap, codes, inp, pinned

FLOWS = {"mgmt_sources": ["192.168.22.167/32"], "ics_callback": "192.168.22.167:8445", "repo": ["192.168.22.167:443"],
         "backup": ["192.168.22.50:8000"], "dns": ["192.168.22.1"], "ntp": ["192.168.22.1"], "edge_sources": ["192.168.22.20/32"]}


def model(**kw):
    d = {"assignments": [
        {"customer_id": "acme", "endpoint": "lab", "zone": "oucust", "vnet": "ouc01", "subnet": "10.64.1.0/24"},
        {"customer_id": "globex", "endpoint": "lab", "zone": "oucust", "vnet": "ouc02", "subnet": "10.64.2.0/24"}],
        "flows": {"lab": FLOWS}}
    d.update(kw)
    return NetworkModel.model_validate(d)


def plan(customer="acme", scope=("ouc01", "ouc02"), **kw):
    return generate_plan(inp(customer_id=customer, endpoint="lab", **kw), cap(), pinned(), networks=model(), scope_networks=scope)


def test_plan_binds_customer_to_its_vnet_with_static_addresses():
    p = plan()
    assert not [e for e in p["errors"] if e["code"].startswith("network")]
    net = p["network"]
    assert net["vnet"] == "ouc01" and net["gateway"] == "10.64.1.1" and net["isolation"]["other_customer_subnets"] == ["10.64.2.0/24"]
    ips = [v["nics"][0]["ip"] for v in p["vms"]]
    assert len(set(ips)) == len(ips) and all(i.startswith("10.64.1.") for i in ips)
    assert {v["nics"][0]["bridge"] for v in p["vms"]} == {"ouc01"}
    assert "no_vlan_isolation" not in codes(p["warnings"])
    ids = {f["id"] for f in net["flows"]}
    assert {"mgmt-agent", "bootstrap-callback", "repo", "backup", "dns-udp", "ntp", "edge-inbound", "intra-customer"} <= ids
    assert plan()["plan_hash"] == p["plan_hash"]
    assert plan("globex")["network"]["vnet"] == "ouc02"


def test_other_customers_vnet_and_shared_bridge_are_refused():
    e = plan(bridge="ouc02")["errors"]
    assert "network_not_assigned" in codes(e) and "globex" in next(x["message"] for x in e if x["code"] == "network_not_assigned")
    assert "network_not_assigned" in codes(plan(bridge="vmbr1")["errors"])
    assert "network_vlan_with_model" in codes(plan(vlan=20)["errors"])


def test_unassigned_customer_never_falls_back_to_shared_bridge():
    p = generate_plan(inp(customer_id="initech", endpoint="lab"), cap(), pinned(), networks=model(), scope_networks=("ouc01",))
    assert "network_unassigned" in codes(p["errors"]) and not p["executable"]


def test_vnet_must_be_inside_endpoint_scope():
    assert "network_out_of_scope" in codes(plan(scope=("ouc02",))["errors"])
    assert "network_out_of_scope" in codes(plan(scope=())["errors"])           # deny by default
    assert "network_out_of_scope" not in codes(plan(scope=None)["errors"])     # unknown scope: not checked here (provider still enforces)
    s = EndpointScope(networks=("ouc01",))
    assert s.network_ok("ouc01", None) and not s.network_ok("ouc02", None) and not s.network_ok("vmbr0", None)


def test_model_validation_rejects_overlap_duplicates_and_service_inside_subnet():
    a = model().assignments
    with pytest.raises(ValidationError, match="overlap"):
        model(assignments=[a[0].model_dump(), {**{k: v for k, v in a[1].model_dump().items() if k != "gateway"}, "subnet": "10.64.1.128/25"}])
    with pytest.raises(ValidationError, match="assigned to both"):
        model(assignments=[a[0].model_dump(), {**a[1].model_dump(), "vnet": "ouc01"}])
    with pytest.raises(ValidationError, match="inside the customer subnet"):
        model(flows={"lab": {**FLOWS, "dns": ["10.64.1.5"]}})
    with pytest.raises(ValidationError, match="private"):
        model(assignments=[{**{k: v for k, v in a[0].model_dump().items() if k != "gateway"}, "subnet": "8.8.8.0/24"}])
    with pytest.raises(ValidationError):
        model(assignments=[{**a[0].model_dump(), "vnet": "toolongvnet"}])


def test_subnet_too_small_and_no_model_is_legacy():
    from ics.deploy.netmodel import resolve
    m = model(assignments=[{"customer_id": "acme", "endpoint": "lab", "zone": "oucust", "vnet": "ouc01", "subnet": "10.64.1.0/28"}])
    net, errs, _ = resolve(m, "acme", "lab", "ouc01", None, [f"vm{i}" for i in range(6)])
    assert "subnet_too_small" in codes(errs) and net["addresses"] == {}
    legacy = generate_plan(inp(), cap(), pinned())
    assert "network" not in legacy and "no_vlan_isolation" in codes(legacy["warnings"])


def test_executor_uses_static_ip_and_plan_dns():
    p = plan()
    nic = p["vms"][0]["nics"][0]
    ic = _ipconfigs({"nics": [nic]}, True)[0]
    assert ic.ip == nic["ip"] and ic.gw == "10.64.1.1"
    assert _ipconfigs({"nics": [{"bridge": "vmbr0", "vlan": None}]}, True)[0].ip == "dhcp"

    class C:
        plan = p
    assert _nameserver(C) == "192.168.22.1"


def test_loader(tmp_path, monkeypatch):
    f = tmp_path / "n.json"
    f.write_text(json.dumps(model().model_dump(mode="json")))
    monkeypatch.setenv("OU_NETWORK_MODEL", str(f))
    assert load_network_model().for_customer("acme", "lab").vnet == "ouc01"
    f.write_text("{not json")
    with pytest.raises(Exception):
        load_network_model()
    monkeypatch.delenv("OU_NETWORK_MODEL")
    assert load_network_model() is None
