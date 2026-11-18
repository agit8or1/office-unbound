"""HA / backup visibility (read-only) and the consolidated overview: collected through the READ token only, reported as "no data" when the
token cannot see it (never as "no backup"), alert rules on top, capacity projection only with enough recorded history."""
import time

from sqlalchemy import text

from ics.inventory import collector, infra_checks
from ics.inventory.overview import overview, projection
from .test_admin_session import w  # noqa: F401  (fixture)
from .test_manage_access import _connect_policy
from .test_provisioning import owner  # noqa: F401  (fixture)

H = "/api/v1"
POOLED = {"preset": "deploy", "scope_mode": "single_node",
          "scope": {"nodes": ["pve06"], "pools": ["office-unbound"], "storages": ["PVE06-Storage"], "networks": ["vmbr0"], "protected_vmids": [126]}}


def _discover(rt, eid):
    with rt.session() as db:
        r = collector.collect_discovery(rt, db, eid)
    assert r["ok"], r
    return r


def _seed(sim):
    sim.add_storage("bk-nfs", type_="nfs", content="backup", shared=True)
    now = int(time.time())
    sim.add_vm(105, "pve06", "app-a", status="running", storage="PVE06-Storage")
    sim.add_vm(106, "pve06", "app-b", status="running", storage="PVE06-Storage")
    sim.backup_vols += [{"storage": "bk-nfs", "vmid": 105, "ctime": now - 3600}, {"storage": "bk-nfs", "vmid": 105, "ctime": now - 90000},
                        {"storage": "bk-nfs", "vmid": 106, "ctime": now - 5 * 86400}]
    sim.ha += [{"id": "service:vm:105", "type": "service", "sid": "vm:105", "node": "pve06", "state": "started", "request_state": "started"},
               {"id": "service:vm:106", "type": "service", "sid": "vm:106", "node": "pve06", "state": "error", "request_state": "started"},
               {"id": "lrm:pve06", "type": "lrm", "node": "pve06", "status": "active"}]
    sim.vzdump_tasks += [{"upid": "UPID:pve06:1:1:1:vzdump:106:root@pam:", "type": "vzdump", "node": "pve06", "id": "106", "status": "job errors",
                          "starttime": now - 7200, "endtime": now - 7000},
                         {"upid": "UPID:pve06:2:2:2:vzdump:105:root@pam:", "type": "vzdump", "node": "pve06", "id": "105", "status": "OK",
                          "starttime": now - 3700, "endtime": now - 3600}]


def ev(rt, eid, **kw):
    return infra_checks.evaluate(rt, {"endpoint_id": eid, **kw})


def test_whole_cluster_monitoring_collects_ha_and_backups_and_rules_fire(w, owner, rt):  # noqa: F811
    _seed(owner.sim)
    _, eid = _connect_policy(w, owner, {**POOLED, "monitor_cluster": True})
    before = list(owner.sim.write_calls)
    r = _discover(rt, eid)
    assert owner.sim.write_calls == before                                  # discovery is read-only
    assert not [x for x in r["warnings"] if "HA" in x or "backup" in x], r["warnings"]
    with rt.session() as db:
        comp = db.execute(text("SELECT complete FROM infra_collect_state WHERE endpoint_id = :e"), {"e": eid}).scalar()
        bk = {x.vmid: x for x in db.execute(text("SELECT vmid, copies, last_at FROM infra_backups WHERE endpoint_id = :e"), {"e": eid})}
    assert {"ha", "backups", "backup_tasks"} <= set(comp)
    assert bk[105].copies == 2 and bk[106].copies == 1
    o = ev(rt, eid, rule="ha_state")
    assert o.status == "critical" and "vm:106" in o.message and "vm:105" not in o.message
    assert ev(rt, eid, rule="ha_state", target="105").status == "ok"
    o = ev(rt, eid, rule="backup_age")
    assert o.status == "critical" and "106" in o.message and "105 " not in o.message
    assert ev(rt, eid, rule="backup_age", target="105").status == "ok"
    assert ev(rt, eid, rule="backup_age", target="106", max_age_hours=200).status == "ok"
    o = ev(rt, eid, rule="backup_failed")
    assert o.status == "critical" and "job errors" in o.message
    assert ev(rt, eid, rule="backup_failed", target="105").status == "ok"
    assert ev(rt, eid, rule="cluster_quorum").status == "ok"
    owner.sim.quorate = False
    _discover(rt, eid)
    assert ev(rt, eid, rule="cluster_quorum").status == "critical"
    r = w.ad.get(f"{H}/infra/overview", headers=w.adh)
    assert r.status_code == 200, r.text
    c = [x for x in r.json()["clusters"] if x["endpoint_id"] == eid][0]
    assert c["quorate"] is False and c["ha"] == {"services": 2, "problems": 1}
    assert c["backups"]["failed_tasks"] == 1 and c["backups"]["never"] >= 0 and c["freshness"]["stale"] is False
    assert all(s["projection"]["days_to_full"] is None and "insufficient" in s["projection"]["note"] for s in c["storage"])


def test_selected_nodes_only_reports_no_data_not_no_backup(w, owner, rt):  # noqa: F811
    _seed(owner.sim)
    _, eid = _connect_policy(w, owner, POOLED)
    r = _discover(rt, eid)
    assert not [x for x in r["warnings"] if "HA" in x], r["warnings"]     # not granted is a choice, not a fault: no warning noise
    o = ev(rt, eid, rule="backup_age")                                    # no read access to the backup storage
    assert o.status == "warning" and o.details["cause"] == "no_data", o
    o = ev(rt, eid, rule="ha_state")                                      # HA is cluster-wide: outside a node-scoped token by the admin's choice
    assert o.status == "ok" and o.details["cause"] == "not_monitored" and "not monitored" in o.message, o
    for rule in ("node_cpu", "node_memory"):                              # nodes outside the scope are not monitored, never STALE
        o = ev(rt, eid, rule=rule)
        assert o.status == "ok" and "STALE" not in o.message, (rule, o)
    assert ev(rt, eid, rule="backup_failed").status == "critical"          # tasks on the monitored node ARE visible (Sys.Audit on /nodes/pve06)
    owner.sim.cluster_tasks_hidden = True                                 # the real cluster: /cluster/tasks is empty for this token
    _discover(rt, eid)
    o = ev(rt, eid, rule="backup_failed")
    assert o.status == "critical", o                                      # still found through the node's own task list
    c = [x for x in w.ad.get(f"{H}/infra/overview", headers=w.adh).json()["clusters"] if x["endpoint_id"] == eid][0]
    assert c["ha"] is None


def test_projection_needs_history_and_never_invents_a_date(rt):
    with rt.session() as db:
        eid = str(db.execute(text("INSERT INTO endpoints (name, type, base_url, token_id, token_secret_enc, fingerprint_sha256) VALUES "
                                  "('p1', 'proxmox', 'https://pve.test:8006', 'u@pve!t', :s, :f) RETURNING id"), {"s": b"x", "f": "cd" * 32}).scalar())
        sid = "00000000-0000-0000-0000-0000000000aa"
        assert projection(db, eid, sid, 10, 100)["days_to_full"] is None
        for i in range(48):        # 2 days of hourly samples growing 1 GiB / hour
            db.execute(text("INSERT INTO metric_samples VALUES (:e, 'storage', :s, 'used_bytes', '1h', now() - make_interval(hours => :h), :v, :v)"),
                       {"e": eid, "s": sid, "h": 48 - i, "v": float(i << 30)})
        p = projection(db, eid, sid, 48 << 30, 72 << 30)
        assert p["days_to_full"] == 1.0 and p["growth_bytes_per_day"] == 24 << 30
        db.execute(text("UPDATE metric_samples SET value = 5 WHERE scope_id = :s"), {"s": sid})
        assert projection(db, eid, sid, 5, 100)["note"] == "not growing"
        assert overview(db, "e.id = '" + eid + "'", 900)[0]["freshness"]["stale"] is True
        db.rollback()


def test_summary_reports_guest_visibility_from_the_approved_policy(w, owner, rt):  # noqa: F811
    """GET /infra/summary says whether 0/0 guests means "none exist" or "only Office Unbound's pool is visible" (from the policy, never guessed)."""
    s = w.v.get(f"{H}/infra/summary").json()
    assert s["guest_visibility"] == "none" and s["guest_visibility_limited"] == []
    _, eid = _connect_policy(w, owner, POOLED)                             # "selected nodes": the read token only sees its own pool
    s = w.v.get(f"{H}/infra/summary").json()
    assert s["guest_visibility"] == "own_only" and [x["endpoint_id"] for x in s["guest_visibility_limited"]] == [eid]
    with rt.session() as db:
        db.execute(text("UPDATE endpoint_policy SET policy = jsonb_set(policy, '{monitor_cluster}', 'true') WHERE endpoint_id = :e"), {"e": eid})
        db.commit()
    s = w.v.get(f"{H}/infra/summary").json()
    assert s["guest_visibility"] == "cluster" and s["guest_visibility_limited"] == []
    with rt.session() as db:                                               # a hand-registered token: no policy to read -> unknown, not "cluster"
        db.execute(text("DELETE FROM endpoint_policy WHERE endpoint_id = :e"), {"e": eid})
        db.commit()
    assert w.v.get(f"{H}/infra/summary").json()["guest_visibility"] == "unknown"


def test_a_later_successful_backup_clears_an_earlier_failure_of_the_same_guest(w, owner, rt):  # noqa: F811
    """Real cluster (2026-11-18): VM 113 failed three times (PBS1 fingerprint), then backed up OK; only the latest result per guest counts."""
    _seed(owner.sim)
    _, eid = _connect_policy(w, owner, POOLED)
    _discover(rt, eid)
    assert ev(rt, eid, rule="backup_failed").status == "critical"          # 106's only task failed
    now = int(time.time())
    owner.sim.vzdump_tasks.append({"upid": "UPID:pve06:3:3:3:vzdump:106:root@pam:", "type": "vzdump", "node": "pve06", "id": "106", "status": "OK",
                                   "starttime": now - 600, "endtime": now - 500})
    _discover(rt, eid)
    o = ev(rt, eid, rule="backup_failed")
    assert o.status == "ok", o
