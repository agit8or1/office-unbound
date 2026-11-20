"""Sizing engine: catalog sizing data, derived profile counts, service-driven sizing, dependency closure, placement within the approved
scope, HA/dedicated qualification, capacity analysis vs inventory, estimates labelling, overrides, resize proposals; API dry runs write
nothing and the produced plan_input still goes through POST /plans + approvals."""
import copy
import json
import re

import pytest
from sqlalchemy import text

from ics.deploy import sizer
from ics.deploy.catalog import CatalogError, HaStrategy, build_catalog, default_dir, describe_profile, load_catalog
from ics.deploy.plan import Capacity, NodeCap, PlanInput, StorageCap, capacity_from_inventory, generate_plan
from ics.deploy.sizing import services_to_components

from .test_deploy_exec import H, GiB, actors, create, env, seed_inventory, submit  # noqa: F401  (fixtures)
from .test_deploy_plan import inp, pinned

CORE = ["mail", "calendar", "contacts", "files"]
ALL = [*CORE, "office", "chat", "meetings", "telephony"]


def cap(nodes=2, cores=32, mem=131072, sto=4000, shared=False, used_mem=0, used_vcpu=0, foreign=0):
    ns = [NodeCap(f"pve{i + 1}", cores, mem, used_mem, used_vcpu, True, foreign) for i in range(nodes)]
    st = [StorageCap("shared", sto, [], sto, False, None, "rbd")] if shared else [StorageCap("local-lvm", sto, [n.name], sto, True, None, "lvmthin") for n in ns]
    return Capacity(ns, st, ["vmbr0"])


def req(**kw):
    d = dict(deployment_type="production", customer_id="acme", deployment_id="prod", domain="acme.example", endpoint="lab",
             workload={"users": 100}, services=CORE, backup={"destination": "pbs"})
    d.update(kw)
    return sizer.SizeRequest(**d)


SCOPE = sizer.Scope(backup_storages=[{"name": "pbs", "avail_gb": 100000, "shared": True, "type": "pbs"}])


def run(r, c, cat=None, scope=SCOPE):
    cat = cat or pinned()
    return sizer.size(r, c, cat, lambda i: generate_plan(i, c, cat), scope)


def codes(xs):
    return [x["code"] for x in xs]


# ---- catalog data -----------------------------------------------------------------------------------------------------

def test_every_component_has_sizing_with_evidence():
    c = load_catalog()
    for comp in c.components.values():
        s = comp.sizing
        assert s is not None, comp.name
        assert {v.volume for v in s.volumes} == {v.name for v in comp.volumes}
        for m in (s.cores, s.memory_mb, s.disk_gb, *s.volumes):
            assert m.base_evidence in ("measured", "estimate") and m.source
            if m.base_evidence == "measured":
                assert "results.md" in m.source, (comp.name, m.source)   # a measurement cites the lab document
            for f in m.factors:
                assert f.evidence in ("measured", "estimate") and f.source
                if f.evidence == "measured":
                    assert "results.md" in f.source
        assert s.validated.reference
        # no component claims application HA today; VM restart is recovery, not HA
        assert not s.ha.capable, comp.name


def test_sizing_schema_rejects_inconsistent_data(tmp_path):
    import yaml
    d = default_dir()
    meta = yaml.safe_load((d / "catalog.yaml").read_text())
    comps = [yaml.safe_load(p.read_text()) for p in sorted((d / "components").glob("*.yaml"))]
    profs = [yaml.safe_load(p.read_text()) for p in sorted((d / "profiles").glob("*.yaml"))]

    def bad(mut, msg):
        c2 = copy.deepcopy(comps)
        mut(next(x for x in c2 if x["name"] == "groupware")["sizing"])
        with pytest.raises(CatalogError, match=msg):
            build_catalog(meta, c2, profs)
    bad(lambda s: s["volumes"].pop(), "sizing.volumes")
    bad(lambda s: s["minimum"].update(memory_mb=999999), "recommended must be")
    bad(lambda s: s["memory_mb"].update(base_evidence="guess"), "base_evidence")
    bad(lambda s: s["consolidation"].update(never_with=["nope"]), "never_with")


def test_profile_vm_counts_are_derived_and_match_generated_plans():
    """The contradictory hand-written counts (Small 3 vs 6, Medium 5 vs 8, Large 6 vs 8) are gone: titles carry no count, and the
    displayed counts are computed from the layout and equal the generated plan's VM count."""
    c = pinned()
    for name, p in c.profiles.items():
        assert not re.search(r"\d+ VMs", p.title), p.title
        if p.custom:
            continue
        counts = describe_profile(p)["vm_counts"]
        t = 2 if p.tenancy == "multi" else 1
        default = generate_plan(inp(profile=name, users=20, tenants=t), cap(3), c)
        allopt = generate_plan(inp(profile=name, users=20, tenants=t, optional={o: True for o in p.optional_components}), cap(3), c)
        none = generate_plan(inp(profile=name, users=20, tenants=t, optional={o: False for o in p.optional_components}), cap(3), c)
        if p.tenancy == "multi":
            shared = sum(v.replicas for v in p.vms if not v.per_tenant)
            assert len(default["vms"]) == shared + (counts["default"] - shared) * t
        else:
            assert (len(default["vms"]), len(allopt["vms"]), len(none["vms"])) == (counts["default"], counts["all_optional"], counts["minimum"]), name
        assert p.sizing_preset is not None


# ---- engine: services, closure, sizing --------------------------------------------------------------------------------

def test_dependency_closure_and_disabled_components_consume_nothing():
    c = load_catalog()
    assert services_to_components(c, ["office"])[0] == {"identity", "edge", "files", "office"}
    assert services_to_components(c, ["telephony"])[0] == {"identity", "edge", "telephony"}
    assert services_to_components(c, ["mail"])[0] == {"identity", "edge", "groupware"}
    assert services_to_components(c, ["nope"])[1] == ["nope"]
    r = run(req(services=["files"]), cap())
    comps = {x for v in r["vms"] for x in v["components"]}
    assert "groupware" not in comps and "office" not in comps and "chat" not in comps
    assert all(not any(d["name"].startswith("groupware") for d in v["disks"]) for v in r["vms"])
    full = run(req(services=CORE), cap())
    assert r["totals"]["memory_mb"] < full["totals"]["memory_mb"] and r["totals"]["disk_gb"] < full["totals"]["disk_gb"]


@pytest.mark.usefixtures("no_vm_floor")
def test_sizing_changes_with_services_and_workload():
    light = run(req(services=["mail", "calendar", "files"]), cap())
    heavy = run(req(services=["mail", "calendar", "files", "office", "meetings"]), cap())
    assert heavy["totals"]["memory_mb"] > light["totals"]["memory_mb"] and heavy["totals"]["cores"] > light["totals"]["cores"]
    busy = run(req(services=CORE + ["office"], workload={"users": 100, "concurrent_users": 100, "office_editor_pct": 50}), cap())
    calm = run(req(services=CORE + ["office"], workload={"users": 100, "concurrent_users": 10}), cap())
    assert busy["totals"]["memory_mb"] > calm["totals"]["memory_mb"]
    big_mail = run(req(workload={"users": 100, "mailbox_gb_per_user": 20}), cap())
    assert big_mail["totals"]["disk_gb"] > run(req(), cap())["totals"]["disk_gb"]
    grown = run(req(workload={"users": 100, "growth_pct": 50}), cap())
    assert grown["totals"]["disk_gb"] > run(req(), cap())["totals"]["disk_gb"] and grown["capacity"]["growth"]["fits_today"]


def test_estimates_are_flagged_and_margin_applies_only_to_estimates():
    r = run(req(services=CORE + ["office"]), cap())
    assert r["estimates_flags"] and "groupware.cores" in r["estimates_flags"]
    assert "office.memory_mb" not in r["estimates_flags"]   # office memory = measured base + measured per-document factor
    p = generate_plan(PlanInput(**r["plan_input"]), cap(), pinned())
    assert "sizing_estimates" in codes(p["warnings"]) and "sizing_assumptions" not in codes(p["warnings"])
    lo = run(req(services=CORE + ["office"], workload={"users": 400}, overrides={"estimate_margin_pct": 0}), cap(sto=20000))
    hi = run(req(services=CORE + ["office"], workload={"users": 400}, overrides={"estimate_margin_pct": 100}), cap(sto=20000))
    office = lambda x: next(v for v in x["vms"] if "office" in v["components"])["sizing"]["components"]["office"]  # noqa: E731
    assert office(lo)["memory_mb"] == office(hi)["memory_mb"]           # measured: no margin
    assert office(lo)["cores"] < office(hi)["cores"]                    # estimate: margin applies
    assert r["estimated_supported_workload"]["estimate"] is True and r["validated"] is False
    assert any(e["exceeds"] for e in r["evidence"])                    # 100 users > 8 tested mailboxes: never claimed as validated


def test_displayed_counts_equal_plan_and_recommendation_text():
    c = cap()
    for t, svc in (("evaluation", CORE), ("production", CORE + ["office"]), ("production", ALL)):
        r = run(req(deployment_type=t, services=svc), c)
        p = generate_plan(PlanInput(**r["plan_input"]), c, pinned())
        assert r["recommended"]["vms"] == r["totals"]["vms"] == len(r["vms"]) == len(p["vms"]) == p["consumption"]["vms"]
        assert p["plan_hash"] == r["plan_hash"]
        assert f"Recommended: {len(p['vms'])} VMs" in r["recommended"]["text"]
        for a in r["architectures"]:
            if a["available"]:
                assert a["vms"] == len(generate_plan(sizer.plan_input_for(req(deployment_type=t, services=svc), a["id"],
                                                                          services_to_components(pinned(), svc)[0], pinned(), c, SCOPE), c, pinned())["vms"])
    assert run(req(deployment_type="evaluation"), c)["recommended"]["architecture"] == "consolidated"
    assert run(req(deployment_type="evaluation"), c)["production_ready"] is False


def test_consolidation_rules_respect_port_conflicts():
    r = run(req(deployment_type="evaluation", services=ALL, architecture="consolidated"), cap())
    by = {v["logical"]: v["components"] for v in r["vms"]}
    for a, b in (("edge", "chat"), ("edge", "meetings"), ("meetings", "telephony")):
        assert not any(a in cs and b in cs for cs in by.values())
    assert "port_conflict" not in codes(generate_plan(PlanInput(**r["plan_input"]), cap(), pinned())["errors"])


# ---- placement, capacity, qualification -------------------------------------------------------------------------------

def test_placement_respects_allowed_nodes_and_free_capacity():
    c = cap(3)
    r = run(req(placement={"allowed_nodes": ["pve2"]}), c)
    assert {v["node"] for v in r["vms"]} == {"pve2"} and r["plan_input"]["allowed_nodes"] == ["pve2"]
    # pve1 is full: nothing goes there
    c2 = Capacity([NodeCap("pve1", 32, 131072, used_memory_mb=117000), NodeCap("pve2", 32, 131072)],
                  [StorageCap("shared", 4000, [], 4000, False, None, "rbd")], ["vmbr0"])
    assert {v["node"] for v in run(req(), c2)["vms"]} == {"pve2"}
    # not enough anywhere: no recommendation, shortfall explains and offers alternatives
    tiny = Capacity([NodeCap("pve1", 4, 8192)], [StorageCap("s", 100, [], 100, False, None, "dir")], ["vmbr0"])
    r3 = run(req(services=ALL, workload={"users": 500}), tiny)
    assert r3["recommended"] is None and r3["selected"] is None
    kinds = {a["kind"] for a in r3["shortfall"]["alternatives"]}
    assert "add_capacity" in kinds
    assert all(not a.get("fits") for a in r3["architectures"])
    # an explicitly requested layout that does not fit is reported, never silently accepted as production-ready
    r4 = run(req(services=ALL, workload={"users": 500}, architecture="isolated"), tiny)
    assert r4["fits"] is False and r4["production_ready"] is False and "does not fit the permitted capacity" in r4["production_ready_blockers"]


def test_storage_choice_stays_in_approved_scope():
    c = Capacity([NodeCap("pve1", 32, 131072)], [StorageCap("big", 9000, [], 9000), StorageCap("ok", 3000, [], 3000)], ["vmbr0"])
    r = run(req(), c, scope=sizer.Scope(allowed_storage=["ok"], allowed_pools=["acme-pool"], allowed_networks=["vmbr1/42"],
                                        backup_storages=SCOPE.backup_storages))
    assert r["plan_input"]["storage"] == "ok" and r["plan_input"]["pool"] == "acme-pool"
    assert (r["plan_input"]["bridge"], r["plan_input"]["vlan"]) == ("vmbr1", 42)
    assert {d["storage"] for v in r["vms"] for d in v["disks"]} == {"ok"}
    assert [s["name"] for s in r["capacity"]["storage"]] == ["ok"]


def test_ha_not_offered_without_qualifying_components_or_infrastructure():
    r = run(req(), cap(3))
    ha = next(a for a in r["architectures"] if a["id"] == "ha")
    assert not ha["available"] and "not implemented" in ha["why_not"] and "VM restart is recovery, not HA" in ha["why_not"]
    assert r["recommended"]["architecture"] != "ha"
    assert any(s["kind"] == "ha_unavailable" for s in r["scaling_recommendations"])
    # a catalog where every component had implemented replication: still refused on one node, offered on two
    cat = pinned()
    for comp in cat.components.values():
        comp.sizing.ha.strategies = [HaStrategy(id="primary_replica", status="implemented", note="test")]
    one = run(req(), cap(1), cat)
    ha1 = next(a for a in one["architectures"] if a["id"] == "ha")
    assert not ha1["available"] and "at least 2" in ha1["why_not"]
    two = run(req(architecture="ha"), cap(2), cat)
    assert two["selected"] == "ha" and two["fits"]
    groups: dict[str, set] = {}
    for v in two["vms"]:
        groups.setdefault(v["logical"], set()).add(v["node"])
    assert groups and all(len(n) == 2 for n in groups.values())
    assert two["recovery"]["application_ha"] is True


def test_dedicated_needs_an_empty_approved_node():
    r = run(req(), cap(2, foreign=3))
    d = next(a for a in r["architectures"] if a["id"] == "dedicated")
    assert not d["available"] and "outside this deployment" in d["why_not"]
    c = Capacity([NodeCap("pve1", 32, 131072, foreign_guests=2), NodeCap("pve2", 32, 131072)],
                 [StorageCap("shared", 4000, [], 4000)], ["vmbr0"])
    r2 = run(req(architecture="dedicated"), c)
    assert r2["fits"] and {v["node"] for v in r2["vms"]} == {"pve2"} and r2["plan_input"]["sizing"]["dedicated_nodes"] is True


def test_capacity_analysis_matches_inventory():
    data = {"nodes": [{"node": "pve1", "status": "online", "info": {"maxcpu": 8, "maxmem": 64 * GiB},
                       "qemu": [{"vmid": 101, "name": "other", "maxmem": 16 * GiB, "cpus": 8, "tags": ""}], "lxc": [],
                       "storage": [{"storage": "local-lvm", "content": "images", "type": "lvmthin", "avail": 3000 * GiB, "total": 4000 * GiB, "active": 1}]}]}
    c = capacity_from_inventory(data, "prod")
    r = run(req(services=CORE + ["office"]), c)
    n = r["capacity"]["nodes"][0]
    assert n["existing_vcpus"] == 8 and n["existing_memory_mb"] == 16384 and n["foreign_guests"] == 1
    assert n["available"] == {"vcpu": 8 * 4 - 8, "memory_mb": 65536 * 90 // 100 - 16384}
    assert n["requested"]["vcpu"] == r["totals"]["cores"] and n["headroom"]["memory_mb"] == n["available"]["memory_mb"] - r["totals"]["memory_mb"]
    assert r["capacity"]["storage"][0] == {"name": "local-lvm", "key": "local-lvm@pve1", "shared": False, "nodes": ["pve1"], "thin": True,
                                           "type": "lvmthin", "available_gb": 2700,"requested_gb_all_pools_of_name": r["totals"]["disk_gb"]}
    w = codes(r["capacity"]["warnings"])
    assert {"single_failure_domain", "local_storage_no_redundancy", "thin_storage"} <= set(w)
    assert "cpu_contention_high" in w   # 8 existing + new vCPUs on 8 physical cores
    assert r["production_ready"] is False and "heavy CPU over-allocation" in r["production_ready_blockers"]


def test_backup_validation():
    r = run(req(backup={"destination": None}), cap())
    assert not r["backup"]["valid"] and "no_backup_destination" in codes(r["backup"]["issues"]) and not r["production_ready"]
    r2 = run(req(backup={"destination": "pbs", "rpo_hours": 1, "retention_days": 30}), cap(),
             scope=sizer.Scope(backup_storages=[{"name": "pbs", "avail_gb": 10, "shared": True, "type": "pbs"}]))
    assert {"rpo_not_achievable", "backup_space_insufficient"} <= set(codes(r2["backup"]["issues"]))
    assert r2["backup"]["estimate"] is True and r2["plan_input"]["backup_retention_days"] == 30


def test_msp_layout_shares_edge_and_isolates_tenants():
    r = run(req(deployment_type="msp", workload={"users": 20, "tenants": 3}), cap(3))
    edge = [v for v in r["vms"] if "edge" in v["components"]]
    assert len(edge) == 1 and edge[0]["tenant"] is None
    others = [v for v in r["vms"] if v not in edge]
    assert {v["tenant"] for v in others} == {"t01", "t02", "t03"} and len(others) % 3 == 0
    p = generate_plan(PlanInput(**r["plan_input"]), cap(3), pinned())
    assert p["errors"] == [] and len(p["vms"]) == r["totals"]["vms"]
    assert "tenants_need_msp" in codes(run(req(workload={"users": 20, "tenants": 2}), cap())["errors"])


def test_operator_overrides():
    base = run(req(architecture="balanced"), cap())
    gw = next(v for v in base["vms"] if "groupware" in v["components"])
    up = run(req(architecture="balanced", overrides={"vm": {"groupware": {"memory_mb": gw["memory_mb"] + 4096}}}), cap())
    assert next(v for v in up["vms"] if v["logical"] == "groupware")["memory_mb"] == gw["memory_mb"] + 4096
    low = run(req(architecture="balanced", overrides={"vm": {"groupware": {"memory_mb": 512}}}), cap())
    p = generate_plan(PlanInput(**low["plan_input"]), cap(), pinned())
    assert "override_below_minimum" in codes(p["errors"]) and not p["executable"]


def test_legacy_profile_plans_are_unchanged():
    p = generate_plan(inp(profile="small", users=40), cap(), pinned())
    assert "sizing" not in p["input"] and "sizing" not in p
    assert "sizing_assumptions" in codes(p["warnings"])


def test_resize_recommendations_pure():
    vms = [{"name": "a", "cores": 2, "memory_mb": 4096}, {"name": "b", "cores": 4, "memory_mb": 8192}, {"name": "c", "cores": 2, "memory_mb": 2048}]
    usage = {"a": {"samples": 100, "cpu_avg_pct": 80, "cpu_peak_pct": 99, "mem_peak_mb": 3900},
             "b": {"samples": 100, "cpu_avg_pct": 2, "cpu_peak_pct": 5, "mem_peak_mb": 1000}, "c": {"samples": 0}}
    recs, ovr = sizer.resize_recommendations(vms, usage)
    by = {(r["kind"], r["vm"]) for r in recs}
    assert ("increase_resources", "a") in by and ("decrease_resources", "b") in by and ("no_data", "c") in by
    assert set(ovr) == {"a"} and ovr["a"].memory_mb >= 3900 * 100 // 70 and ovr["a"].cores > 2
    assert all(r["automatic"] is False for r in recs)
    assert next(r for r in recs if r["kind"] == "increase_resources")["requires_downtime"] is True


# ---- API (real DB) ----------------------------------------------------------------------------------------------------

TABLES = ("deployments", "deployment_revisions", "deployment_resources", "plans", "jobs", "job_steps", "approvals", "audit_log")


def _counts(rt):
    with rt.session() as db:
        return {t: db.execute(text(f"SELECT count(*) FROM {t}")).scalar() for t in TABLES
                if db.execute(text("SELECT to_regclass(:t)"), {"t": t}).scalar()}


def body(**kw):
    return json.loads(req(**kw).model_dump_json())


def test_size_api_is_a_dry_run_and_feeds_the_plan_endpoint(client, actors, rt, env, mk_user, login):
    seed_inventory(rt)
    (o, oh) = actors[0]
    before = _counts(rt)
    r = o.post(f"{H}/deployments/size", json=body(services=CORE + ["office"]), headers=oh)
    assert r.status_code == 200, r.text
    s = r.json()
    assert s["writes"] == "none" and s["recommended"]["vms"] == len(s["vms"])
    p = o.post(f"{H}/deployments/plan", json=s["plan_input"], headers=oh)
    assert p.status_code == 200, p.text
    assert len(p.json()["vms"]) == len(s["vms"]) and p.json()["plan_hash"] == s["plan_hash"]
    assert {v["name"]: (v["cores"], v["memory_mb"], v["node"]) for v in p.json()["vms"]} == {v["name"]: (v["cores"], v["memory_mb"], v["node"]) for v in s["vms"]}
    # regeneration with other services / architectures still writes nothing
    for kw in ({"services": ALL}, {"architecture": "isolated"}, {"deployment_type": "evaluation"}):
        assert o.post(f"{H}/deployments/size", json=body(**kw), headers=oh).status_code == 200
    assert _counts(rt) == before
    assert o.post(f"{H}/deployments/size", json=body(endpoint="nope"), headers=oh).status_code == 404
    assert o.post(f"{H}/deployments/size", json={**body(), "extra": 1}, headers=oh).status_code == 422
    viewer = login(mk_user("vw", "viewer"))
    assert viewer[0].post(f"{H}/deployments/size", json=body(), headers=viewer[1]).status_code == 403


def test_sized_plan_still_requires_approval(client, actors, rt, env):
    seed_inventory(rt)
    (o, oh) = actors[0]
    s = o.post(f"{H}/deployments/size", json=body(), headers=oh).json()
    assert s["plan_executable"], s["plan_blocking"]
    r = o.post(f"{H}/plans", json={"action": "deployment.create", "params": {"spec": s["plan_input"], "plan_hash": s["plan_hash"]}}, headers=oh)
    assert r.status_code == 201, r.text
    with rt.session() as db:
        assert db.execute(text("SELECT count(*) FROM jobs")).scalar() == 0          # nothing runs before approval
        assert db.execute(text("SELECT status FROM plans WHERE id = :p"), {"p": r.json()["plan_id"]}).scalar() != "approved"
    assert env.provider.calls == []
    _, a1, a2 = actors
    first = a1[0].post(f"{H}/plans/{r.json()['plan_id']}/approve", headers=a1[1])
    assert first.status_code == 200 and not first.json().get("job_id")             # high risk: one approval is not enough
    with rt.session() as db:
        assert db.execute(text("SELECT count(*) FROM jobs")).scalar() == 0


def test_resize_plan_from_metrics_writes_nothing(client, actors, rt, env):
    eid = seed_inventory(rt)
    (o, oh) = actors[0]
    s = o.post(f"{H}/deployments/size", json=body(architecture="balanced"), headers=oh).json()
    submit(actors, rt, "deployment.create", {"spec": s["plan_input"], "plan_hash": s["plan_hash"]})
    with rt.session() as db:
        refs = {r.logical_name: r.provider_ref for r in db.execute(text("SELECT logical_name, provider_ref FROM deployment_resources WHERE kind = 'vm'"))}
        assert refs and all(r and r.get("vmid") for r in refs.values())
        gw = next(v for v in s["vms"] if "groupware" in v["components"])
        for i in range(30):
            for metric, val in (("cpu_pct", 85.0), ("mem_used_bytes", gw["memory_mb"] * 0.95 * 1048576)):
                db.execute(text("INSERT INTO metric_samples (endpoint_id, scope_type, scope_id, metric, resolution, ts, value, vmax) "
                                "VALUES (:e, 'guest', :s, :m, '1m', now() - make_interval(mins => :i), :v, :v)"),
                           {"e": eid, "s": str(refs[gw["name"]]["vmid"]), "m": metric, "i": i, "v": val})
        db.commit()
    before = _counts(rt)
    r = o.post(f"{H}/deployments/prod/resize-plan", json={"window": "24h"}, headers=oh)
    assert r.status_code == 200, r.text
    out = r.json()
    assert _counts(rt) == before and out["writes"] == "none"
    inc = [x for x in out["recommendations"] if x["kind"] == "increase_resources"]
    assert [x["vm"] for x in inc] == [gw["name"]] and inc[0]["requires_downtime"] is True
    assert any(x["kind"] == "no_data" for x in out["recommendations"])
    ha = next(x for x in out["recommendations"] if x["kind"] == "upgrade_ha")
    assert ha["available"] is False and ha["requires_data_migration"] is True
    pc = out["proposed_change"]
    assert pc["submit_as"]["action"] == "deployment.change" and pc["diff"]["changed"]
    assert pc["changes"]["sizing"]["vm_overrides"][gw["name"]]["memory_mb"] > gw["memory_mb"]
    assert pc["requires_downtime"] is True and pc["requires_data_migration"] is False
    assert out["model_drift"]["differs"] is False
    assert o.post(f"{H}/deployments/nope/resize-plan", headers=oh).status_code == 404
