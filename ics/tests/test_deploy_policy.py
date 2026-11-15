"""Real-cluster policies: audited nodes only, thin-pool overcommit, no-VLAN warning (pure)."""
from ics.deploy.plan import capacity_from_inventory, generate_plan

from .test_deploy_plan import codes, inp, pinned

TiB, GiB = 1024 ** 4, 1024 ** 3


def snap(avail=2 * TiB, prov=int(15.17 * TiB)):
    return {"nodes": [
        {"node": "pve06", "status": "online", "info": {"maxcpu": 56, "maxmem": 251 * GiB}, "qemu": [], "lxc": [],
         "network": [{"iface": "vmbr0", "type": "bridge"}],
         "storage": [{"storage": "PVE06-Storage", "type": "lvmthin", "content": "images,rootdir", "total": int(10.91 * TiB),
                      "avail": avail, "provisioned": prov, "active": 1}]},
        {"node": "pve01", "status": "online", "info": {}, "error": "permission denied (not audited)"}]}


def test_thin_pool_uses_physical_space_and_refuses_to_grow_overcommit():
    c = pinned()
    cap = capacity_from_inventory(snap())
    assert [n.name for n in cap.nodes if n.online] == ["pve06"]          # unaudited node is never a placement target
    s = cap.storages[0]
    assert s.thin and s.provisioned_gb > s.total_gb and s.avail_gb == 2048
    p = generate_plan(inp(profile="lab", users=10), cap, c)
    assert "thin_overcommit" in codes(p["errors"]) and not p["executable"]
    ok = generate_plan(inp(profile="lab", users=10), capacity_from_inventory(snap(prov=4 * TiB)), c)
    assert ok["errors"] == [] and "no_vlan_isolation" in codes(ok["warnings"])
    assert {v["node"] for v in ok["vms"]} == {"pve06"}
    small = generate_plan(inp(profile="lab", users=10), capacity_from_inventory(snap(avail=50 * GiB, prov=4 * TiB)), c)
    assert "insufficient_capacity" in codes(small["errors"])
    assert "no_vlan_isolation" not in codes(generate_plan(inp(profile="lab", users=10, vlan=20), capacity_from_inventory(snap(prov=4 * TiB)), c)["warnings"])
