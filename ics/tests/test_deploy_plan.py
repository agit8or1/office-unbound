"""Catalog validation, sizing, deterministic plan generation, capacity refusal, anti-affinity, DAG, change diff, drift (pure; no DB)."""
import copy
import re

import pytest
import yaml

from ics.deploy import catalog as catmod
from ics.deploy.catalog import CatalogError, Formula, build_catalog, load_catalog
from ics.deploy.plan import (Capacity, ExistingVm, NodeCap, PlanInput, StorageCap, capacity_from_inventory, generate_plan, order_steps,
                             plan_hash)
from ics.deploy.state import diff_plans, drift_findings, plan_resources

DIGEST = "sha256:" + "a" * 64


def pinned(cat=None):
    """The real catalog with every OCI placeholder replaced by a pinned digest (so plans are executable)."""
    c = cat or load_catalog()
    for comp in c.components.values():
        for a in comp.artifacts:
            if a.kind == "oci":
                a.digest = DIGEST
    return c


def cap(nodes=2, cores=64, mem=262144, sto=4000, shared=False):
    ns = [NodeCap(f"pve{i + 1}", cores, mem) for i in range(nodes)]
    st = [StorageCap("shared", sto, [])] if shared else [StorageCap("local-lvm", sto, [n.name]) for n in ns]
    return Capacity(ns, st, ["vmbr0"])


def inp(**kw):
    d = dict(customer_id="acme", deployment_id="prod", profile="small", users=40, domain="acme.example", endpoint="lab", pool="acme")
    d.update(kw)
    return PlanInput(**d)


def codes(items):
    return [e["code"] for e in items]


# ---- catalog -----------------------------------------------------------------------------------------------------

def test_real_catalog_loads_and_is_complete():
    c = load_catalog()
    assert set(c.profiles) == {"lab", "small", "medium", "large", "ha", "msp-multi", "dedicated", "custom"}
    assert set(c.components) == {"identity", "groupware", "files", "office", "edge", "monitoring-agent"}
    assert re.fullmatch(r"[0-9a-f]{64}", c.digest)
    for comp in c.components.values():  # every formula cites its evidence
        for f in (comp.resources.cores, comp.resources.memory_mb, comp.resources.disk_gb, *(v.size_gb for v in comp.volumes)):
            assert f.source
    # OCI artifacts are placeholders until the build pipeline pins them; plans must refuse to execute meanwhile.
    # `office` is pinned to the LAB-signed Office Unbound Docs image (2026-11-15); `files` is still a placeholder.
    assert not c.components["office"].unpinned and c.components["files"].unpinned


def test_every_stock_profile_generates_a_plan_without_structural_errors():
    c = pinned()
    for name in ("lab", "small", "medium", "large", "ha", "msp-multi", "dedicated"):
        p = generate_plan(inp(profile=name, users=20, tenants=2 if name == "msp-multi" else 1), cap(3), c)
        assert p["errors"] == [], (name, p["errors"])
        assert p["executable"] and p["steps"]
        ports = [(v["name"]) for v in p["vms"]]
        assert len(ports) == len(set(ports))


def _raw():
    d = load_catalog()
    return d  # for structure only


def test_catalog_validation_rejects_bad_definitions(tmp_path):
    base = catmod.default_dir()
    meta = yaml.safe_load((base / "catalog.yaml").read_text())
    comps = [yaml.safe_load(f.read_text()) for f in sorted((base / "components").glob("*.yaml"))]
    profs = [yaml.safe_load(f.read_text()) for f in sorted((base / "profiles").glob("*.yaml"))]
    build_catalog(meta, comps, profs)  # baseline valid

    def bad(mut, msg):
        c, p = copy.deepcopy(comps), copy.deepcopy(profs)
        mut(c, p)
        with pytest.raises(CatalogError, match=msg):
            build_catalog(meta, c, p)

    idx = {x["name"]: x for x in comps}
    bad(lambda c, p: next(x for x in c if x["name"] == "files")["artifacts"][0].pop("digest"), "digest")                      # digest REQUIRED
    bad(lambda c, p: next(x for x in c if x["name"] == "files")["artifacts"][0].update(digest="sha256:xyz"), "digest")        # malformed
    bad(lambda c, p: next(x for x in c if x["name"] == "edge")["artifacts"][0].update(version="latest"), "pin")
    bad(lambda c, p: next(x for x in c if x["name"] == "office").update(depends_on=["nope"]), "unknown dependency")
    bad(lambda c, p: (next(x for x in c if x["name"] == "identity").update(depends_on=["office"])), "cycle")
    bad(lambda c, p: next(x for x in c if x["name"] == "files")["resources"]["cores"].pop("source"), "source")               # evidence required
    bad(lambda c, p: next(x for x in c if x["name"] == "files")["health_checks"][0].update(port=1), "does not declare")
    bad(lambda c, p: next(x for x in p if x["name"] == "small")["vms"][0]["components"].append("nope"), "unknown component")
    bad(lambda c, p: next(x for x in p if x["name"] == "small")["vms"][1]["components"].append("identity"), "more than one")
    bad(lambda c, p: next(x for x in p if x["name"] == "small")["vms"][0]["components"].append("monitoring-agent"), "every VM")
    bad(lambda c, p: next(x for x in p if x["name"] == "ha")["vms"][0].update(replicas=1), "replicas")
    bad(lambda c, p: next(x for x in c if x["name"] == "files").update(extra=1), "extra")
    assert idx  # silence unused


def test_formula_ceil_is_exact_decimal():
    assert Formula(base=2, per_user=0.004, source="test x").at(250) == 3        # not 4 from float error
    assert Formula(base=2, per_user=0.004, source="test x").at(251) == 4
    assert Formula(base=0, per_user=0.25, source="test x").at(1) == 1


# ---- plan generation ---------------------------------------------------------------------------------------------

def test_plan_is_deterministic_and_hash_covers_everything():
    c = pinned()
    a, b = generate_plan(inp(), cap(), c), generate_plan(inp(), cap(), c)
    assert a == b and a["plan_hash"] == b["plan_hash"] == plan_hash(a)
    assert generate_plan(inp(users=41), cap(), c)["plan_hash"] != a["plan_hash"]
    assert generate_plan(inp(), cap(sto=3999), c)["plan_hash"] != a["plan_hash"]          # capacity is part of the plan
    assert generate_plan(inp(domain="other.example"), cap(), c)["plan_hash"] != a["plan_hash"]
    import json
    json.dumps(a, allow_nan=False)  # plain JSON data, ints only
    assert not [x for x in re.findall(r"\d+\.\d+", json.dumps(a["consumption"]))]


def test_plan_contents_small_profile():
    p = generate_plan(inp(), cap(), pinned())
    assert p["executable"] and codes(p["errors"]) == []
    names = [v["name"] for v in p["vms"]]
    assert names == ["acme-prod-files", "acme-prod-groupware", "acme-prod-id"]
    idv = next(v for v in p["vms"] if v["logical"] == "id")
    assert set(idv["components"]) == {"identity", "edge", "monitoring-agent"}
    assert idv["os_image"]["id"] == "ubuntu-24.04" and idv["nics"] == [{"bridge": "vmbr0", "vlan": None}]
    assert {"ou-managed", "ou-deployment-prod"} <= set(idv["tags"])
    assert all(d["storage"] for v in p["vms"] for d in v["disks"])
    # sizing = overhead + components (formula at 40 users): identity mem 2048+80, edge 512+10, agent 64, overhead 512
    assert idv["memory_mb"] == 512 + 2048 + 80 + 512 + 10 + 64
    cons = p["consumption"]
    assert cons["vms"] == 3 and cons["cores"] == sum(v["cores"] for v in p["vms"]) and cons["disk_gb"] == sum(d["size_gb"] for v in p["vms"] for d in v["disks"])
    assert {c["name"] for c in p["containers"]} >= {"acme-prod-files-opencloud", "acme-prod-files-collabora"}
    assert any(s["package"] == "ou-gromox" for s in p["services"])
    # firewall: public mail ports, edge -> backends, ics -> agents; DNS and checks and backups
    fw = {(r["vm"], r["port"], r["from"]) for r in p["firewall"]}
    assert ("acme-prod-groupware", 25, "any") in fw and ("acme-prod-groupware", 8447, "acme-prod-id") in fw
    assert ("acme-prod-groupware", 636, "acme-prod-id") not in fw and ("acme-prod-id", 636, "acme-prod-groupware") in fw  # groupware needs LDAP
    assert all(("acme-prod-" + n, 8443, "ics-control") in fw for n in ("id", "groupware", "files"))
    dns = {(r["name"], r["type"]) for r in p["dns"]}
    assert ("acme.example", "MX") in dns and ("cloud.acme.example", "A") in dns and ("mail.acme.example", "A") in dns
    assert any(c["kind"] == "smtp_banner" for c in p["checks"]) and any(c["kind"] == "http" for c in p["checks"])
    assert {b["component"] for b in p["backups"]} == {"identity", "groupware", "files", "edge"} and all(b["retention_days"] == 14 for b in p["backups"])
    # capacity remaining reported per node and storage
    assert {n["name"] for n in p["capacity"]["nodes"]} == {"pve1", "pve2"} and all(n["memory_free_mb"] > 0 for n in p["capacity"]["nodes"])
    assert {w["code"] for w in p["warnings"]} >= {"sizing_assumptions", "os_image_unpinned"}


def test_unpinned_artifacts_block_execution_with_explanation():
    p = generate_plan(inp(), cap(), load_catalog())        # real catalog: OCI digests are placeholders
    assert not p["executable"] and "artifact_unpinned" in codes(p["errors"])
    assert p["vms"] and p["steps"]                        # still previewable


def test_optional_component_toggle():
    c = pinned()
    on = generate_plan(inp(), cap(), c)
    off = generate_plan(inp(optional={"office": False}), cap(), c)
    assert "office" not in {x["component"] for x in off["containers"]} and off["consumption"]["memory_mb"] < on["consumption"]["memory_mb"]
    assert "unknown_optional" in codes(generate_plan(inp(optional={"identity": False}), cap(), c)["errors"])
    # lab: disabling office keeps the single VM
    assert len(generate_plan(inp(profile="lab", users=5, optional={"office": False}), cap(), c)["vms"]) == 1


def test_profile_and_input_errors():
    c = pinned()
    assert "users_exceed_profile" in codes(generate_plan(inp(users=51), cap(), c)["errors"])
    assert "near_profile_limit" in codes(generate_plan(inp(users=47), cap(), c)["warnings"])
    assert "unknown_profile" in codes(generate_plan(inp(profile="nope"), cap(), c)["errors"])
    assert "unknown_bridge" in codes(generate_plan(inp(bridge="vmbr9"), cap(), c)["errors"])
    assert "no_inventory" in codes(generate_plan(inp(), Capacity(), c)["errors"])
    assert "tenants_not_supported" in codes(generate_plan(inp(tenants=2), cap(), c)["errors"])
    assert "custom_layout_not_allowed" in codes(generate_plan(inp(custom_layout=[{"name": "x", "components": ["edge"]}]), cap(), c)["errors"])
    assert "custom_layout_missing" in codes(generate_plan(inp(profile="custom"), cap(), c)["errors"])
    assert "name_too_long" in codes(generate_plan(inp(customer_id="c" * 30, deployment_id="d" * 30), cap(), c)["errors"])
    assert "unknown_node" in codes(generate_plan(inp(allowed_nodes=["ghost"]), cap(), c)["errors"])
    assert "unknown_storage" in codes(generate_plan(inp(storage="nope"), cap(), c)["errors"])
    assert "unknown_os_image" in codes(generate_plan(inp(os_image="win95"), cap(), c)["errors"])


def test_custom_layout_and_port_conflicts():
    c = pinned()
    ok = generate_plan(inp(profile="custom", custom_layout=[{"name": "a", "components": ["identity", "edge"]},
                                                             {"name": "b", "components": ["groupware"]}]), cap(), c)
    assert ok["errors"] == []
    # edge + a second listener on 443 would clash; here: two components with the same port on one VM (identity and a clone of it is impossible),
    # so use the stock conflict: none of the stock components clash on one VM (lab all-in-one is clean)
    assert generate_plan(inp(profile="lab", users=5), cap(), c)["errors"] == []
    missing = generate_plan(inp(profile="custom", custom_layout=[{"name": "a", "components": ["groupware"]}]), cap(), c)
    assert "missing_dependency" in codes(missing["errors"])


def test_multi_tenant_isolation_layout():
    p = generate_plan(inp(profile="msp-multi", users=30, tenants=3), cap(3), pinned())
    assert p["errors"] == []
    t = lambda tid: {v["logical"] for v in p["vms"] if v["tenant"] == tid}  # noqa: E731
    assert t("t01") == t("t02") == t("t03") == {"identity", "groupware", "files"} and t(None) == {"edge"}
    assert len({v["name"] for v in p["vms"]}) == 10
    # tenants never share a VM and DNS is per tenant domain
    assert all(len({v["tenant"]}) == 1 for v in p["vms"])
    assert any(r["name"] == "mail.t02.acme.example" for r in p["dns"])
    # a tenant's identity VM is reachable only from its own tenant's VMs (and the shared edge), never from another tenant
    src = {r["from"] for r in p["firewall"] if r["port"] == 636 and r["vm"] == "acme-prod-t02-identity"}
    assert "acme-prod-t02-groupware" in src and not any(x.startswith(("acme-prod-t01", "acme-prod-t03")) for x in src)


# ---- capacity, placement, anti-affinity ---------------------------------------------------------------------------

def test_capacity_refusal_reports_shortfall():
    c = pinned()
    p = generate_plan(inp(profile="medium", users=200), cap(1, cores=8, mem=16384), c)
    assert not p["executable"]
    e = next(x for x in p["errors"] if x["code"] == "insufficient_capacity")
    assert "RAM short" in e["message"] or "vCPU short" in e["message"]
    p2 = generate_plan(inp(), cap(2, sto=100), c)
    assert any(x["code"] == "insufficient_capacity" and "storage short" in x["message"] for x in p2["errors"])
    off = Capacity([NodeCap("pve1", 64, 262144, online=False)], [StorageCap("s", 5000, [])], ["vmbr0"])
    assert {"insufficient_nodes", "insufficient_capacity"} <= set(codes(generate_plan(inp(), off, c)["errors"]))
    # shared storage reserve (10%) is never allocated
    tight = generate_plan(inp(profile="lab", users=5), Capacity([NodeCap("a", 64, 262144)], [StorageCap("s", 100, [])], ["vmbr0"]), c)
    assert not tight["executable"]


def test_existing_load_reduces_capacity():
    c = pinned()
    free = Capacity([NodeCap("a", 16, 32768)], [StorageCap("s", 2000, [])], ["vmbr0"])
    busy = Capacity([NodeCap("a", 16, 32768, used_memory_mb=30000)], [StorageCap("s", 2000, [])], ["vmbr0"])
    assert generate_plan(inp(profile="lab", users=10), free, c)["executable"]
    assert not generate_plan(inp(profile="lab", users=10), busy, c)["executable"]


def test_ha_anti_affinity_distinct_nodes():
    c = pinned()
    p = generate_plan(inp(profile="ha", users=30), cap(2), c)
    assert p["errors"] == []
    by_group = {}
    for v in p["vms"]:
        by_group.setdefault(v["group"], []).append(v["node"])
    assert len(by_group) == 5 and all(len(n) == 2 and len(set(n)) == 2 for n in by_group.values())
    # one node only -> refused with a clear reason (never silently co-located)
    one = generate_plan(inp(profile="ha", users=30), cap(1), c)
    assert "anti_affinity_unsatisfiable" in codes(one["errors"]) and "insufficient_nodes" in codes(one["errors"])
    # three nodes: still distinct per group, load spreads
    three = generate_plan(inp(profile="ha", users=30), cap(3), c)
    assert all(len(set(v["node"] for v in three["vms"] if v["group"] == g)) == 2 for g in by_group)
    assert "ha_replication_unvalidated" in codes(p["warnings"])


def test_non_ha_replicas_prefer_but_do_not_require_distinct_nodes():
    p = generate_plan(inp(profile="large", users=100), cap(2), pinned())
    assert p["errors"] == []
    offices = [v for v in p["vms"] if v["logical"] == "office"]
    assert len(offices) == 2 and offices[0]["node"] != offices[1]["node"]
    single = generate_plan(inp(profile="large", users=100), cap(1), pinned())
    assert single["errors"] == [] and len({v["node"] for v in single["vms"]}) == 1


def test_dedicated_profile_excludes_nodes_with_foreign_guests():
    c = pinned()
    n = [NodeCap("a", 64, 262144, foreign_guests=2), NodeCap("b", 64, 262144)]
    p = generate_plan(inp(profile="dedicated", users=20), Capacity(n, [StorageCap("s", 4000, [])], ["vmbr0"]), c)
    assert p["errors"] == [] and {v["node"] for v in p["vms"]} == {"b"} and "node_not_dedicated" in codes(p["warnings"])
    only = generate_plan(inp(profile="dedicated", users=20), Capacity(n[:1], [StorageCap("s", 4000, [])], ["vmbr0"]), c)
    assert not only["executable"]


def test_storage_choice_and_node_local_pools():
    c = pinned()
    capc = Capacity([NodeCap("a", 64, 262144), NodeCap("b", 64, 262144)],
                    [StorageCap("fast", 3000, ["a"]), StorageCap("fast", 100, ["b"]), StorageCap("slow", 9000, [])], ["vmbr0"])
    p = generate_plan(inp(storage="fast", profile="lab", users=10), capc, c)
    assert p["errors"] == [] and p["vms"][0]["node"] == "a" and {d["storage"] for d in p["vms"][0]["disks"]} == {"fast"}
    assert {s["name"] for s in p["capacity"]["storage"]} == {"fast@a", "fast@b", "slow"}


# ---- DAG / steps ---------------------------------------------------------------------------------------------------

def test_steps_form_a_valid_dependency_order():
    p = generate_plan(inp(), cap(), pinned())
    pos = {s["key"]: s["seq"] for s in p["steps"]}
    assert [s["seq"] for s in p["steps"]] == list(range(len(p["steps"])))
    for s in p["steps"]:
        assert all(pos[d] < s["seq"] for d in s["depends_on"]), s["key"]
    # chain per VM and component ordering across VMs
    assert pos["vm.clone:acme-prod-id"] < pos["vm.configure:acme-prod-id"] < pos["vm.resize:acme-prod-id"] < pos["vm.start:acme-prod-id"] < pos["agent.enroll:acme-prod-id"]
    assert pos["health.verify:acme-prod-id:identity"] < pos["comp.install:acme-prod-groupware:groupware"]      # groupware needs identity healthy
    assert pos["health.verify:acme-prod-files:files"] < pos["comp.install:acme-prod-files:office"]
    assert pos["health.verify:acme-prod-groupware:groupware"] < pos["comp.install:acme-prod-id:edge"]           # edge routes to what exists
    kinds = {s["kind"] for s in p["steps"]}
    assert kinds == {"provider_task", "wait_agent_enrollment", "agent_runbook", "register_checks", "verify_health"}
    inst = next(s for s in p["steps"] if s["key"] == "comp.install:acme-prod-files:files")
    assert [r["runbook"] for r in inst["params"]["runbooks"]] == ["podman.pull_verified", "podman.deploy_unit"]
    assert inst["params"]["runbooks"][0]["params"]["image"].endswith("@" + DIGEST)   # the exact shape the node agent accepts
    assert inst["params"]["runbooks"][1]["params"]["type"] == "container" and inst["params"]["runbooks"][1]["params"]["component"] == "files"
    inst = next(s for s in p["steps"] if s["key"] == "comp.install:acme-prod-groupware:groupware")
    assert {r["runbook"] for r in inst["params"]["runbooks"]} == {"pkg.install_pinned"}


def test_order_steps_rejects_cycles_and_unknown_deps():
    s = lambda k, d: {"key": k, "depends_on": d}  # noqa: E731
    assert [x["key"] for x in order_steps([s("b", ["a"]), s("a", [])])] == ["a", "b"]
    with pytest.raises(ValueError, match="cycle"):
        order_steps([s("a", ["b"]), s("b", ["a"])])
    with pytest.raises(ValueError, match="unknown"):
        order_steps([s("a", ["zz"])])


# ---- capacity from inventory -----------------------------------------------------------------------------------------

def test_capacity_from_proxmox_inventory_snapshot():
    GiB = 1024 ** 3
    data = {"nodes": [
        {"node": "pve1", "status": "online", "info": {"maxcpu": 16, "maxmem": 64 * GiB},
         "qemu": [{"vmid": 100, "name": "x", "cpus": 4, "maxmem": 8 * GiB, "tags": "ou-managed;ou-deployment-prod"},
                  {"vmid": 101, "name": "y", "cpus": 2, "maxmem": 4 * GiB, "tags": ""}], "lxc": [],
         "storage": [{"storage": "local-lvm", "content": "images,rootdir", "avail": 500 * GiB, "active": 1},
                     {"storage": "iso", "content": "iso", "avail": 900 * GiB, "active": 1},
                     {"storage": "nfs", "content": "images", "avail": 700 * GiB, "shared": 1, "active": 1}],
         "network": [{"iface": "vmbr0", "type": "bridge"}, {"iface": "eno1", "type": "eth"}]},
        {"node": "pve2", "status": "offline", "info": {}},
        {"node": "pve3", "status": "online", "info": {"maxcpu": 8, "maxmem": 32 * GiB}, "error": "x"}]}
    c = capacity_from_inventory(data, "prod")
    n1 = next(n for n in c.nodes if n.name == "pve1")
    assert (n1.cores, n1.memory_mb, n1.used_memory_mb, n1.used_vcpus, n1.foreign_guests) == (16, 65536, 12288, 6, 1)
    assert not next(n for n in c.nodes if n.name == "pve2").online and not next(n for n in c.nodes if n.name == "pve3").online
    assert {(s.name, tuple(s.nodes), s.avail_gb) for s in c.storages} == {("local-lvm", ("pve1",), 500), ("nfs", (), 700)}
    assert c.bridges == ["vmbr0"]


# ---- change diff -----------------------------------------------------------------------------------------------------

def _existing(plan):
    return {v["name"]: ExistingVm(v["node"], v["cores"], v["memory_mb"], {d["name"]: (d["size_gb"], d["storage"]) for d in v["disks"]})
            for v in plan["vms"]}


def test_change_diff_grow_users_is_normal_risk_with_downtime_and_snapshot():
    c = pinned()
    old = generate_plan(inp(users=40), cap(), c)
    new = generate_plan(inp(users=50), cap(), c, _existing(old))
    d = diff_plans(old, new, c)
    assert not d["empty"] and d["added"] == [] and d["removed"] == [] and d["risk"] == "normal"
    assert {x["name"] for x in d["changed"] if x["kind"] == "vm"} == {"acme-prod-files", "acme-prod-groupware", "acme-prod-id"}
    assert d["capacity_impact"]["memory_mb"] > 0 and d["capacity_impact"]["disk_gb"] > 0 and d["capacity_impact"]["vms"] == 0
    assert d["snapshot_required"] and set(d["snapshot_vms"]) == {"acme-prod-files", "acme-prod-groupware", "acme-prod-id"}
    assert d["requires_maintenance"] and d["downtime_seconds"] > 0 and any(k.startswith("vm.stop:") for k in d["disruptive_steps"])
    keys = [s["key"] for s in d["steps"]]
    f = "acme-prod-files"
    assert keys.index(f"vm.snapshot:{f}") < keys.index(f"vm.stop:{f}") < keys.index(f"vm.configure:{f}") < keys.index(f"vm.start:{f}")
    assert any(k.startswith(f"vm.resize:{f}:") for k in keys)
    # pinned placement: the VMs stay where they are
    assert {v["name"]: v["node"] for v in new["vms"]} == {v["name"]: v["node"] for v in old["vms"]}


def test_change_diff_add_and_remove_resources():
    c = pinned()
    old = generate_plan(inp(profile="medium", users=100), cap(), c)
    new = generate_plan(inp(profile="medium", users=100, optional={"office": False}), cap(), c, _existing(old))
    d = diff_plans(old, new, c)
    assert {"kind": "vm", "name": "acme-prod-office"} in d["removed"] and d["risk"] == "high" and "resources are removed" in d["risk_reasons"]
    assert any(s["key"] == "vm.destroy:acme-prod-office" for s in d["steps"]) and d["capacity_impact"]["vms"] == -1
    back = diff_plans(new, generate_plan(inp(profile="medium", users=100), cap(), c, _existing(new)), c)
    assert {"kind": "vm", "name": "acme-prod-office"} in back["added"] and back["risk"] == "normal"
    assert any(s["key"] == "vm.clone:acme-prod-office" for s in back["steps"]) and back["capacity_impact"]["vms"] == 1
    assert diff_plans(old, old, c)["empty"]


def test_change_capacity_check_credits_existing_allocation_and_blocks_shrink():
    c = pinned()
    one = Capacity([NodeCap("a", 16, 32768)], [StorageCap("s", 3000, [])], ["vmbr0"])
    old = generate_plan(inp(profile="lab", users=10), one, c)
    assert old["executable"]
    # the deployment's own VM is already counted as used by the node; growing it must credit the old allocation
    v = old["vms"][0]
    used = Capacity([NodeCap("a", 16, 32768, used_memory_mb=v["memory_mb"], used_vcpus=v["cores"])], [StorageCap("s", 3000 - v["disks"][0]["size_gb"], [])], ["vmbr0"])
    grown = generate_plan(inp(profile="lab", users=20), used, c, _existing(old))
    assert grown["errors"] == [], grown["errors"]
    shrunk = generate_plan(inp(profile="lab", users=5), used, c, _existing(old))
    assert "disk_shrink" in codes(shrunk["errors"])
    too_big = generate_plan(inp(profile="lab", users=25), Capacity([NodeCap("a", 16, 32768, used_memory_mb=v["memory_mb"], used_vcpus=v["cores"])],
                                                                  [StorageCap("s", 10, [])], ["vmbr0"]), c, _existing(old))
    assert not too_big["executable"]


# ---- drift -------------------------------------------------------------------------------------------------------------

def test_drift_findings_report_only():
    c = pinned()
    plan = generate_plan(inp(profile="lab", users=10), cap(), c)
    v = plan["vms"][0]
    res = []
    for (k, n), desired in plan_resources(plan).items():
        r = {"kind": k, "name": n, "desired": desired, "actual": None, "state": "present", "provider_ref": None}
        if k == "vm":
            r["provider_ref"] = {"node": v["node"], "vmid": 100}
        if k in ("container", "service"):
            r["actual"] = {"version": desired["version"], "digest": desired.get("digest")}
        res.append(r)
    GiB, MiB = 1024 ** 3, 1048576
    good = [{"vmid": 100, "name": v["name"], "status": "running", "cpus": v["cores"], "maxmem": v["memory_mb"] * MiB,
             "maxdisk": v["disks"][0]["size_gb"] * GiB, "tags": "ou-managed;ou-deployment-prod"}]
    assert drift_findings([r for r in res if r["kind"] in ("vm", "container", "service")], good, "prod") == []
    bad = [{**good[0], "cpus": v["cores"] + 2, "status": "stopped", "tags": ""}, {"vmid": 200, "name": "rogue", "tags": "ou-deployment-prod"}]
    f = drift_findings([r for r in res if r["kind"] == "vm"], bad, "prod")
    types = {(x["name"], x["type"]) for x in f}
    assert (v["name"], "changed") in types and (v["name"], "not_running") in types and ("rogue", "unexpected") in types
    ch = next(x for x in f if x["type"] == "changed")
    assert ch["fields"]["cores"] == {"desired": v["cores"], "actual": v["cores"] + 2} and "tags" in ch["fields"]
    assert [x["type"] for x in drift_findings([r for r in res if r["kind"] == "vm"], [], "prod")] == ["missing"]
    sv = [dict(r, actual={"version": "0.0.1"}) for r in res if r["kind"] == "service"][:1]
    assert drift_findings(sv, [], "prod")[0]["type"] == "changed"
