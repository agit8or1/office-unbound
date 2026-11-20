"""Owner per-VM floor (catalog meta.vm_minimum; owner 2026-11-20: "vms are being sized too small. min 8 cpu, 8gb, etc")."""
from ics.deploy.catalog import load_catalog
from ics.deploy.plan import PlanInput, generate_plan
from ics.deploy.sizing import SizingSpec, VmOverride, Workload

from .test_deploy_plan import cap, inp, pinned


def test_the_catalog_sets_8_vcpu_8_gb_and_a_40_gb_root_disk():
    m = load_catalog().meta.vm_minimum
    assert (m.cores, m.memory_mb, m.root_disk_gb) == (8, 8192, 40)


def _vms(p):
    assert p["executable"], p["errors"]
    return p["vms"]


def test_every_vm_gets_at_least_the_floor_in_both_sizing_modes():
    for spec in (inp(users=5), inp(users=5, sizing=SizingSpec(workload=Workload()))):
        for v in _vms(generate_plan(spec, cap(), pinned())):
            root = next(d for d in v["disks"] if d["name"] == "root")
            assert v["cores"] >= 8 and v["memory_mb"] >= 8192 and root["size_gb"] >= 40, v["name"]


def test_a_larger_sized_vm_keeps_its_size():
    big = max(_vms(generate_plan(inp(profile="large", users=1000), cap(nodes=4, cores=256, mem=2_000_000, sto=40000), pinned())), key=lambda v: v["memory_mb"])
    assert big["memory_mb"] > 8192


def test_an_override_below_the_floor_is_refused():
    p0 = generate_plan(inp(users=5, sizing=SizingSpec(workload=Workload())), cap(), pinned())
    name = p0["vms"][0]["name"]
    p = generate_plan(inp(users=5, sizing=SizingSpec(workload=Workload(), vm_overrides={name: VmOverride(cores=4, memory_mb=4096)})),
                      cap(), pinned())
    assert not p["executable"] and {e["code"] for e in p["errors"]} >= {"override_below_minimum"}
