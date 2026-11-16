"""Check kind `infra`: alert rules evaluated from the recorded inventory (no Proxmox call): offline nodes, stopped guests, CPU / memory / storage
thresholds, stale data reported as stale (never as a reading), tenancy-bound endpoint reference, and the full check -> incident path."""
import pytest
from pydantic import ValidationError
from sqlalchemy import text

from ics import checks, monitor
from ics.inventory import infra_checks

H = "/api/v1"
GiB = 1 << 30


def _ep(rt):
    with rt.session() as db:
        eid = str(db.execute(text("INSERT INTO endpoints (name, type, base_url, token_id, token_secret_enc, fingerprint_sha256) VALUES "
                                  "('c1', 'proxmox', 'https://pve.test:8006', 'u@pve!t', :s, :f) RETURNING id"), {"s": b"x", "f": "ab" * 32}).scalar())
        db.execute(text("DELETE FROM infra_nodes WHERE endpoint_id = :e"), {"e": eid})
        for n, st, cpu, used, age in (("pve01", "online", 20.0, 10, 0), ("pve02", "offline", None, None, 0), ("pve03", "online", 97.0, 60, 0),
                                      ("pve04", "online", 50.0, 10, 3600)):
            db.execute(text("INSERT INTO infra_nodes (endpoint_id, name, status, cpu_pct, mem_used, mem_total, observed_at) VALUES "
                            "(:e, :n, :s, :c, :u, :t, now() - make_interval(secs => :a))"),
                       {"e": eid, "n": n, "s": st, "c": cpu, "u": None if used is None else used * GiB, "t": 64 * GiB, "a": age})
        for v, st in ((101, "running"), (102, "stopped")):
            db.execute(text("INSERT INTO infra_guests (endpoint_id, vmid, kind, node, name, status, observed_at) VALUES (:e, :v, 'vm', 'pve01', :n, :s, now())"),
                       {"e": eid, "v": v, "n": f"app{v}", "s": st})
        for name, used, total, active in (("local-lvm", 90, 100, True), ("nfs", 10, 100, False)):
            db.execute(text("INSERT INTO infra_storage (endpoint_id, name, node, type, active, enabled, used, total, observed_at) VALUES "
                            "(:e, :n, 'pve01', 'lvmthin', :a, true, :u, :t, now())"), {"e": eid, "n": name, "u": used * GiB, "t": total * GiB, "a": active})
        db.commit()
    return eid


def ev(rt, eid, **kw):
    return infra_checks.evaluate(rt, {"endpoint_id": eid, **kw})


def test_rules_report_real_readings_and_stale_data_as_stale(rt):
    eid = _ep(rt)
    o = ev(rt, eid, rule="node_offline")
    assert o.status == "critical" and "pve02 is offline" in o.message and "pve04" in " ".join(o.details["stale"])   # 1 h old data: stale, not "online"
    assert ev(rt, eid, rule="node_offline", target="pve01").status == "ok"
    o = ev(rt, eid, rule="node_cpu")
    assert o.status == "critical" and "pve03 97.0% >= 95%" in o.message
    assert ev(rt, eid, rule="node_cpu", target="pve02").status == "warning"                                         # offline node: no CPU value, never invented
    o = ev(rt, eid, rule="node_memory", target="pve03", warn_pct=80, crit_pct=99)
    assert o.status == "warning" and "93.8%" in o.message
    o = ev(rt, eid, rule="guest_stopped")
    assert o.status == "critical" and "102" in o.message and "101" not in o.message
    assert ev(rt, eid, rule="guest_stopped", target="101").status == "ok"
    o = ev(rt, eid, rule="storage_used")
    assert o.status == "critical" and "nfs@pve01 is inactive" in o.message
    assert ev(rt, eid, rule="storage_used", target="local-lvm").status == "warning"
    o = ev(rt, eid, rule="node_offline", target="nope")
    assert o.status == "warning" and o.details["cause"] == "no_data"


def test_config_is_closed_and_validated():
    for bad in ({"rule": "rm_rf"}, {"rule": "node_cpu", "warn_pct": 99, "crit_pct": 50}, {"rule": "guest_stopped", "target": "pve01"},
                {"rule": "node_cpu", "target": "a b"}, {"rule": "node_cpu", "extra": 1}):
        with pytest.raises(ValidationError):
            infra_checks.InfraCheckConfig.model_validate({"endpoint_id": "00000000-0000-0000-0000-000000000001", **bad})
    assert checks.config_host("infra", {}) is None and "infra" in checks.KINDS


def test_infra_check_through_the_plan_and_the_incident_path(rt, client, mk_user, login):
    eid = _ep(rt)
    op, oh = login(mk_user("op", "operator"))
    body = {"action": "check.create", "params": {"name": "nodes-offline", "kind": "infra", "interval_seconds": 60, "fail_threshold": 1,
                                                 "config": {"endpoint_id": eid, "rule": "node_offline"}}}
    r = op.post(f"{H}/plans", json=body, headers=oh)
    assert r.status_code == 201, r.text
    bad = op.post(f"{H}/plans", json={**body, "params": {**body["params"], "name": "x2", "config": {"endpoint_id": "00000000-0000-0000-0000-000000000009",
                                                                                                       "rule": "node_offline"}}}, headers=oh)
    assert bad.status_code == 404
    from ics import worker
    if r.json()["status"] != "approved":
        ad, adh = login(mk_user("ad", "admin"))
        ap, aph = login(mk_user("ap", "approver"))
        ap.post(f"{H}/plans/{r.json()['plan_id']}/approve", headers=aph)
    while worker.run_once(rt):
        pass
    with rt.session() as db:
        db.execute(text("UPDATE checks SET next_run_at = now() - interval '1 second'"))
        db.commit()
    assert monitor.run_due_checks(rt) >= 1
    with rt.session() as db:
        st = db.execute(text("SELECT state FROM checks WHERE name = 'nodes-offline'")).scalar()
        inc = db.execute(text("SELECT count(*) FROM incidents")).scalar()
    assert st == "critical" and inc == 1
