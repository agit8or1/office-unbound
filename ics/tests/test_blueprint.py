from ics.blueprint import preview

GOOD = """
deployment_id: dep-001
customer_id: acme
target: {endpoint: lab-pve, pool: acme-pool}
components:
  - {name: db, version: 16.4.0, vm: {cores: 2, memory_mb: 4096, disk_gb: 40}}
  - {name: app, version: 1.2.3, vm: {cores: 4, memory_mb: 8192, disk_gb: 60}, depends_on: [db]}
  - {name: proxy, version: 2.0.1, vm: {cores: 1, memory_mb: 1024, disk_gb: 10}, depends_on: [app]}
"""


def test_valid_plan_ordering_and_totals():
    out = preview(GOOD, {"lab-pve"})
    assert out["valid"] and out["dry_run"]
    assert [s["component"] for s in out["plan"]["steps"]] == ["db", "app", "proxy"]
    assert out["plan"]["steps"][1]["vm_name"] == "acme-dep-001-app"
    assert out["plan"]["totals"] == {"vms": 3, "cores": 7, "memory_mb": 13312, "disk_gb": 110}


def test_errors():
    assert not preview(GOOD.replace("16.4.0", "latest"), {"lab-pve"})["valid"]
    assert not preview(GOOD.replace("16.4.0", "^16"), {"lab-pve"})["valid"]
    assert "not registered" in preview(GOOD, set())["errors"][0]["msg"]
    assert not preview(GOOD.replace("depends_on: [db]", "depends_on: [nope]"), {"lab-pve"})["valid"]
    cyc = GOOD.replace("name: db, version: 16.4.0,", "name: db, depends_on: [proxy], version: 16.4.0,")
    assert "cycle" in preview(cyc, {"lab-pve"})["errors"][0]["msg"]
    assert not preview("a: [", {"lab-pve"})["valid"]
    assert not preview(GOOD + "  - {name: x, version: 1.0.0, image: evil, vm: {cores: 1, memory_mb: 1024, disk_gb: 10}}", {"lab-pve"})["valid"]


def test_preview_api(client, mk_user, login):
    o, oh = login(mk_user("op", "operator"))
    r = o.post("/api/v1/plans/preview", json={"blueprint_yaml": GOOD}, headers=oh)
    assert r.status_code == 200 and r.json()["valid"] is False  # endpoint not registered
    r = o.post("/api/v1/plans/preview", json={"blueprint_yaml": "deployment_id: 1"}, headers=oh)
    assert r.json()["valid"] is False and r.json()["errors"]
