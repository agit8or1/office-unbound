"""Endpoints as settings, inventory collectors, metrics, health, setup API. Proxmox is the STATEFUL SIMULATOR (test double)."""
import json
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text

from ics import worker
from ics.inventory import collector
from ics.providers import base
from ics.providers.base import MutationNotAllowed, VmRef
from ics.providers.proxmox import open_mutations, open_read_provider
from .infra_fixtures import H, INV, LAB, job, real_sim, sim  # noqa: F401

SCOPE_P = {"allowed_nodes": ["pve1", "pve2"], "allowed_pools": ["ou-lab"], "allowed_storage": ["local-lvm"], "allowed_networks": ["vmbr1"]}


class World:
    def __init__(self, rt, mk_user, login):
        self.rt = rt
        self.o, self.oh = login(mk_user("op", "operator"))
        self.a1, self.a1h = login(mk_user("ap1", "approver"))
        self.a2, self.a2h = login(mk_user("ap2", "approver"))
        self.ad, self.adh = login(mk_user("adm", "admin"))
        self.v, self.vh = login(mk_user("view", "viewer"))

    def plan(self, action, params, expect=201):
        r = self.o.post(f"{H}/plans", json={"action": action, "params": params}, headers=self.oh)
        assert r.status_code == expect, r.text
        return r.json()

    def run(self, action, params):
        """plan -> approvals by risk -> execute. Returns (plan, job)."""
        p = self.plan(action, params)
        if p["status"] != "approved":
            need = 2 if p["risk"] == "high" else 1
            for c, h in ((self.a1, self.a1h), (self.a2, self.a2h))[:need]:
                r = c.post(f"{H}/plans/{p['plan_id']}/approve", headers=h)
                assert r.status_code == 200, r.text
            jid = r.json()["job_id"]
        else:
            jid = p["job_id"]
        while worker.run_once(self.rt):
            pass
        return p, self.o.get(f"{H}/jobs/{jid}").json()


@pytest.fixture()
def w(rt, mk_user, login):
    return World(rt, mk_user, login)


def reg(sim, **over):
    p = {"name": "lab", "type": "proxmox", "base_url": sim.url, "token_id": INV[0], "token_secret": INV[1],
         "fingerprint_sha256": sim.fingerprint, "provision_token_id": LAB[0], "provision_token_secret": LAB[1], **SCOPE_P,
         "defaults": {"storage": "local-lvm", "bridge": "vmbr1", "vlan": 20, "ip_mode": "dhcp", "dns_servers": ["10.0.0.1"],
                      "search_domain": "lab.example", "resource_policy": "balanced"}}
    p.update(over)
    return p


def registered(w, sim, **over):
    p, j = w.run("endpoint.register", reg(sim, **over))
    assert j["status"] == "succeeded", j
    return j["result"]["endpoint_id"]


def dump_everything(rt, w):
    with rt.session() as db:
        d = json.dumps([[str(c) for c in r] for r in db.execute(text("SELECT details FROM audit_events")).all()])
        d += json.dumps([[str(c) for c in r] for r in db.execute(text("SELECT params, risk FROM plans")).all()])
        d += json.dumps([[str(c) for c in r] for r in db.execute(text("SELECT result, error FROM jobs")).all()])
        d += json.dumps([[str(c) for c in r] for r in db.execute(text("SELECT last_probe FROM endpoints")).all()])
    for path in ("/endpoints", "/plans", "/jobs", "/infra/summary"):
        d += w.o.get(f"{H}{path}").text
    return d


# ------------------------------------------------------------------------------ register (extended)
def test_register_two_credential_roles_scope_defaults_and_no_secret_leak(w, sim, rt):
    eid = registered(w, sim)
    ep = w.v.get(f"{H}/endpoints/{eid}").json()
    assert ep["credentials"] == {"inventory": {"present": True, "token_id": INV[0]}, "provision": {"present": True, "token_id": LAB[0]}}
    assert ep["scope"]["allowed_pools"] == ["ou-lab"] and ep["scope"]["allowed_networks"] == ["vmbr1"]
    assert ep["defaults"]["vlan"] == 20 and ep["trust"] == "fingerprint" and ep["enabled"] is True
    assert ep["last_probe"]["ok"] is True and ep["last_probe"]["verbs"]["clone_vm"] is True
    blob = dump_everything(rt, w)
    for s in (INV[1], LAB[1]):
        assert s not in blob
    with rt.session() as db:
        row = db.execute(text("SELECT token_secret_enc, provision_secret_enc FROM endpoints")).first()
        encs = [bytes(r[0]) for r in db.execute(text("SELECT secret_enc FROM credentials")).all()]
    assert row[0] is None and len(encs) == 2 and all(INV[1].encode() not in e and LAB[1].encode() not in e for e in encs)
    assert w.a1.get(f"{H}/audit/verify").json()["ok"] is True


def test_register_validation_for_new_fields(w, sim):
    for over in ({"provision_token_secret": None}, {"allowed_pools": []}, {"allowed_networks": ["vmbr1/0"]}, {"allowed_pools": ["a b"]},
                 {"provision_token_id": "root"}, {"defaults": {"bridge": "x;y"}}, {"defaults": {"nope": 1}}, {"protected_vmids": [0]}):
        w.plan("endpoint.register", reg(sim, **over), expect=422)


def test_register_fails_without_persisting_when_provision_token_is_wrong(w, sim, rt):
    p, j = w.run("endpoint.register", reg(sim, provision_token_secret="wrongsecret0123456789"))
    assert j["status"] == "failed" and "provision credential" in j["error"]["message"]
    with rt.session() as db:
        assert db.execute(text("SELECT count(*) FROM endpoints")).scalar() == 0
    assert "wrongsecret0123456789" not in json.dumps(j)


def test_register_refuses_wrong_pin(w, sim, rt):
    p, j = w.run("endpoint.register", reg(sim, fingerprint_sha256="ab" * 32))
    assert j["status"] == "failed" and "pinned" in j["error"]["message"]


# ------------------------------------------------------------------------------ discovery + API + health
def refresh(w, eid):
    p, j = w.run("inventory.refresh", {"endpoint_id": eid})
    assert j["status"] == "succeeded", j
    return j["result"]


def test_discovery_via_refresh_fills_infra_tables_and_api_filters(w, sim, rt):
    eid = registered(w, sim)
    res = refresh(w, eid)
    assert res["discovery"]["ok"] and res["discovery"]["counts"]["nodes"] == 2
    g = w.v.get(f"{H}/infra/guests").json()
    assert {x["vmid"] for x in g} == {100, 150, 160, 170, 200}
    assert [x["vmid"] for x in w.v.get(f"{H}/infra/guests?deployment=d1").json()] == [150, 200]
    assert {x["vmid"] for x in w.v.get(f"{H}/infra/guests?node=pve2").json()} == {200}
    assert w.v.get(f"{H}/infra/guests?kind=lxc").json() == []
    assert {x["name"] for x in w.v.get(f"{H}/infra/nodes").json()} == {"pve1", "pve2"}
    assert len(w.v.get(f"{H}/infra/clusters").json()) == 1
    assert {x["vmid"] for x in w.v.get(f"{H}/infra/templates").json()} == {9000, 9100}
    st = w.v.get(f"{H}/infra/storage?node=pve1").json()
    assert {x["name"] for x in st} == {"local", "local-lvm", "other-lvm"} and all("health" in x for x in st)
    nets = w.v.get(f"{H}/infra/networks").json()
    assert {x["kind"] for x in nets} == {"bridge", "sdn_zone", "sdn_vnet"}
    s = w.v.get(f"{H}/infra/summary").json()
    assert s["nodes"] == {"total": 2, "online": 2, "managed": 2} and s["guests"]["vms"] == 5 and s["guests"]["running"] == 1
    assert s["templates"] == 2 and s["health"]["status"] == "ok" and s["clusters"] == 1 and s["storage"]["bytes_total"] > 0
    ep = w.v.get(f"{H}/endpoints/{eid}").json()
    assert ep["last_discovery"]["ok"] is True and ep["health"]["status"] == "ok" and ep["last_discovery"]["counts"]["guests"] == 5
    assert w.v.get(f"{H}/infra/summary").status_code == 200
    # unauthenticated
    from fastapi.testclient import TestClient
    anon = TestClient(w.o.app, base_url="https://testserver")
    assert anon.get(f"{H}/infra/summary").status_code == 401 and anon.get(f"{H}/endpoints").status_code == 401


def test_rediscovery_prunes_vanished_guests_and_keeps_rows_of_unmanaged_failures(w, sim, rt):
    eid = registered(w, sim)
    refresh(w, eid)
    del sim.sim.vms[160]
    refresh(w, eid)
    assert 160 not in {x["vmid"] for x in w.v.get(f"{H}/infra/guests").json()}
    # a storage read failure on one node must not delete that kind's rows
    sim.sim.fail("GET", r"/nodes/pve2/storage$", 500, "boom", count=2)  # the legacy raw snapshot consumes the first
    refresh(w, eid)
    assert {x["node"] for x in w.v.get(f"{H}/infra/storage").json()} >= {"pve1", "pve2"}
    ep = w.v.get(f"{H}/endpoints/{eid}").json()
    assert ep["health"]["status"] == "warning" and any("storage on pve2" in x for x in ep["last_discovery"]["warnings"])


def test_health_rollup_rules(w, sim, rt):
    eid = registered(w, sim)
    refresh(w, eid)
    sim.sim.nodes["pve2"]["status"] = "offline"
    refresh(w, eid)
    s = w.v.get(f"{H}/infra/summary").json()
    assert s["health"]["status"] == "critical" and any(r["resource"] == "node" and r["name"] == "pve2" for r in s["health"]["reasons"])
    sim.sim.nodes["pve2"]["status"] = "online"
    sim.sim.storages["other-lvm"]["total"] = 10 << 30
    sim.sim.add_vm(900, "pve1", "big", disk_gb=9, storage="other-lvm", pool="ou-lab")
    sim.sim.storages["other-lvm"]["total"] = int(9.2 * (1 << 30))
    refresh(w, eid)
    s = w.v.get(f"{H}/infra/summary").json()
    assert s["health"]["status"] == "critical" and any("% full" in (r["reason"] or "") for r in s["health"]["reasons"])
    sim.sim.storages["other-lvm"]["total"] = 12 << 30     # 75% used but thin-provisioned beyond physical capacity
    sim.sim.storages["other-lvm"]["hidden_volumes"] = [10 << 30]
    sim.sim.storages["other-lvm"]["type"] = "lvmthin"
    refresh(w, eid)
    st = [x for x in w.v.get(f"{H}/infra/storage?node=pve1").json() if x["name"] == "other-lvm"][0]
    assert st["thin"] is True and st["provisioned_bytes"] > st["total"] and st["health"]["status"] == "warning"
    assert "overcommitted" in st["health"]["reason"]
    # stale observation -> unknown, never ok
    with rt.session() as db:
        db.execute(text("UPDATE infra_nodes SET observed_at = now() - interval '2 hours'"))
        db.commit()
    nodes = w.v.get(f"{H}/infra/nodes").json()
    assert all(n["health"]["status"] == "unknown" for n in nodes)


def test_discovery_failure_is_recorded_and_critical(w, sim, rt):
    eid = registered(w, sim)
    refresh(w, eid)
    sim.sim.fail("GET", r"/version", 401, "No ticket", count=5)
    with rt.session() as db:
        r = collector.collect_discovery(rt, db, eid)
    assert r["ok"] is False and "401" in r["error"]
    ep = w.v.get(f"{H}/endpoints/{eid}").json()
    assert ep["health"]["status"] == "critical" and ep["last_discovery"]["ok"] is False
    assert w.v.get(f"{H}/infra/summary").json()["health"]["status"] == "critical"
    assert len(w.v.get(f"{H}/infra/nodes").json()) == 2   # last known rows kept


def test_unmanaged_nodes_never_count_as_capacity(w, rt, real_sim):
    real = ("officeunbound@pam!ics", "realsecret0123456789")
    p = reg(real_sim, name="pve06", token_id=real[0], token_secret=real[1], provision_token_id=None, provision_token_secret=None,
            allowed_nodes=["pve06"], allowed_pools=["officeunbound-pve06"], allowed_storage=["PVE06-Storage"], allowed_networks=["vmbr0"], defaults=None)
    pl, j = w.run("endpoint.register", p)
    assert j["status"] == "succeeded", j
    refresh(w, j["result"]["endpoint_id"])
    s = w.v.get(f"{H}/infra/summary").json()
    assert s["nodes"] == {"total": 6, "online": 6, "managed": 1}
    assert s["capacity"]["cpu_total"] == 56 and s["health"]["status"] in ("ok", "warning")
    nodes = {n["name"]: n for n in w.v.get(f"{H}/infra/nodes").json()}
    assert nodes["pve01"]["managed"] is False and nodes["pve01"]["cpu_total"] is None and nodes["pve01"]["health"]["status"] == "unmanaged"


# ------------------------------------------------------------------------------ metrics
def _seed(rt, eid, scope_id, metric="cpu_pct", minutes=130, start_value=0):
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    rows = [{"e": eid, "t": "node", "s": scope_id, "m": metric, "ts": now - timedelta(minutes=i), "v": float(start_value + i)} for i in range(minutes)]
    with rt.session() as db:
        collector._insert_samples(db, rows)
        db.commit()


def test_metrics_collector_pulls_rrddata_idempotently(w, sim, rt):
    eid = registered(w, sim)
    refresh(w, eid)
    with rt.session() as db:
        r1 = collector.collect_metrics(rt, db, eid)
        n1 = db.execute(text("SELECT count(*) FROM metric_samples WHERE resolution='1m'")).scalar()
        r2 = collector.collect_metrics(rt, db, eid)
        n2 = db.execute(text("SELECT count(*) FROM metric_samples WHERE resolution='1m'")).scalar()
        nid = str(db.execute(text("SELECT id FROM infra_nodes WHERE name='pve1'")).scalar())
    assert r1["ok"] and r1["samples"] > 100 and n1 > 100 and n2 >= n1 and n2 - n1 < 40   # second pull adds at most the newest minute(s)
    out = w.v.get(f"{H}/infra/metrics?scope=node&id={nid}&metric=cpu_pct&range=1h").json()
    assert out["bucket_seconds"] == 60 and 40 < len(out["points"]) <= 62
    assert w.v.get(f"{H}/infra/summary").json()["health"]["status"] == "ok"
    ep = w.v.get(f"{H}/endpoints/{eid}").json()
    assert ep["last_metrics"]["at"] is not None


def test_metrics_bucketing_rollup_retention(w, sim, rt):
    eid = registered(w, sim)
    sid = "00000000-0000-0000-0000-000000000001"
    _seed(rt, eid, sid, minutes=130)
    with rt.session() as db:
        collector.rollup_and_prune(db)
        assert db.execute(text("SELECT count(*) FROM metric_samples WHERE resolution='5m'")).scalar() >= 20
        assert db.execute(text("SELECT count(*) FROM metric_samples WHERE resolution='1h'")).scalar() >= 1
        # idempotent
        before = db.execute(text("SELECT count(*), sum(value) FROM metric_samples WHERE resolution='5m'")).first()
        collector.rollup_and_prune(db)
        assert db.execute(text("SELECT count(*), sum(value) FROM metric_samples WHERE resolution='5m'")).first() == before
    q = lambda rng: w.v.get(f"{H}/infra/metrics?scope=node&id={sid}&metric=cpu_pct&range={rng}").json()   # noqa: E731
    h1, d1 = q("1h"), q("24h")
    assert h1["source_resolution"] == "1m" and h1["bucket_seconds"] == 60 and 59 <= len(h1["points"]) <= 62
    assert d1["source_resolution"] == "1m" and d1["bucket_seconds"] == 300
    # 5-minute buckets of consecutive minute values: avg of 5 consecutive integers, max = the largest
    full = [p for p in d1["points"] if p["max"] - p["avg"] == 2.0]
    assert len(full) >= 20
    assert all(p["avg"] == pytest.approx(p["max"] - 2.0) for p in full)
    assert q("7d")["source_resolution"] == "5m" and q("7d")["bucket_seconds"] == 3600 and len(q("7d")["points"]) <= 4
    assert q("30d")["source_resolution"] == "1h"
    # retention: 1m 48 h, 5m 7 d, 1h 30 d
    with rt.session() as db:
        for res, age in (("1m", "3 days"), ("5m", "8 days"), ("1h", "31 days"), ("1h", "29 days")):
            db.execute(text("INSERT INTO metric_samples (endpoint_id, scope_type, scope_id, metric, resolution, ts, value, vmax) "
                            f"VALUES (:e,'node',:s,'old_{res}_{age[:2]}',:r, now() - interval '{age}', 1, 1)"), {"e": eid, "s": sid, "r": res})
        db.commit()
        collector.rollup_and_prune(db)
        left = {r[0] for r in db.execute(text("SELECT metric FROM metric_samples WHERE metric LIKE 'old_%'"))}
    assert left == {"old_1h_29"}
    assert w.v.get(f"{H}/infra/metrics?scope=node&id={sid}&metric=cpu_pct&range=2h").status_code == 422
    assert w.v.get(f"{H}/infra/metrics?scope=bogus&id={sid}&metric=cpu_pct").status_code == 422
    assert w.v.get(f"{H}/infra/metrics?scope=node&id=notauuid&metric=cpu_pct").status_code == 422


# ------------------------------------------------------------------------------ setup API
def probe_body(sim, **over):
    b = {"base_url": sim.url, "token_id": INV[0], "token_secret": INV[1], "fingerprint_sha256": sim.fingerprint,
         "provision_token_id": LAB[0], "provision_token_secret": LAB[1], **SCOPE_P}
    b.update(over)
    return b


def test_setup_probe_is_admin_only_persists_nothing_and_never_echoes_secrets(w, sim, rt):
    assert w.o.post(f"{H}/setup/probe", json=probe_body(sim), headers=w.oh).status_code == 403
    r = w.ad.post(f"{H}/setup/probe", json=probe_body(sim), headers=w.adh)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["ok"] and out["version"] == "8.2.4" and out["tls"]["ok"] and out["tls"]["verified_by"] == "fingerprint"
    assert out["permissions"]["inventory"]["ok"] and out["permissions"]["provision"]["ok"]
    assert out["discovery"]["nodes"][0]["name"] == "pve1" and {"pve1", "pve2"} == {n["name"] for n in out["discovery"]["nodes"]}
    assert any(g["template"] for g in out["discovery"]["guests"]) and "ou-lab" in out["discovery"]["pools"]
    assert INV[1] not in r.text and LAB[1] not in r.text
    with rt.session() as db:
        assert db.execute(text("SELECT count(*) FROM endpoints")).scalar() == 0
        assert db.execute(text("SELECT count(*) FROM plans")).scalar() == 0
    assert INV[1] not in dump_everything(rt, w)


def test_setup_probe_reports_missing_and_unnecessary_privileges_with_fix_commands(w, sim):
    out = w.ad.post(f"{H}/setup/probe", json=probe_body(sim, allowed_networks=["vmbr0"], allowed_pools=["ou-lab", "other"]), headers=w.adh).json()
    prov = out["permissions"]["provision"]
    assert prov["ok"] is False
    assert {"path": "/sdn/zones/localnetwork/vmbr0", "privilege": "SDN.Use"} in prov["missing"]
    assert any("PVESDNUser" in c for c in prov["fix_commands"])


def test_setup_probe_real_scenario_flags_unnecessary_and_self_vm(w, real_sim, monkeypatch):
    from ics.providers.proxmox import provider as pp
    monkeypatch.setattr(pp, "_LOCAL", pp.SelfIdentity(macs=frozenset({"bc:24:11:e7:f0:24"})))
    real = ("officeunbound@pam!ics", "realsecret0123456789")
    b = probe_body(real_sim, token_id=real[0], token_secret=real[1], provision_token_id=real[0], provision_token_secret=real[1],
                   allowed_nodes=["pve06"], allowed_pools=["officeunbound-pve06"], allowed_storage=["PVE06-Storage"], allowed_networks=["vmbr0"])
    out = w.ad.post(f"{H}/setup/probe", json=b, headers=w.adh).json()
    un = {u["privilege"] for u in out["permissions"]["provision"]["unnecessary"]}
    assert {"VM.Console", "VM.Backup"} <= un
    assert out["self_vm"]["vmid"] == 126 and out["self_vm"]["mutable"] is True and any("DANGER" in x for x in out["warnings"])
    assert {c["name"]: c["ok"] for c in out["capabilities"]}["cloudinit_snippets"] is False


def test_setup_probe_tls_stage_sends_no_token_and_shows_presented_fingerprint(w, sim):
    seen = len(sim.sim.seen)
    r = w.ad.post(f"{H}/setup/probe", json={"stage": "tls", "base_url": sim.url, "fingerprint_sha256": sim.fingerprint}, headers=w.adh)
    t = r.json()["tls"]
    assert r.status_code == 200 and t["ok"] and t["presented_fingerprint_sha256"] == sim.fingerprint and t["verified_by"] == "fingerprint"
    bad = w.ad.post(f"{H}/setup/probe", json={"stage": "tls", "base_url": sim.url, "fingerprint_sha256": "ab" * 32}, headers=w.adh).json()["tls"]
    assert bad["ok"] is False and bad["presented_fingerprint_sha256"] == sim.fingerprint and "does not match" in bad["error"]
    none = w.ad.post(f"{H}/setup/probe", json={"stage": "tls", "base_url": sim.url}, headers=w.adh).json()["tls"]
    assert none["ok"] is False and none["presented_fingerprint_sha256"] == sim.fingerprint
    ca = w.ad.post(f"{H}/setup/probe", json={"stage": "tls", "base_url": sim.url, "ca_pem": sim.cert_pem}, headers=w.adh).json()["tls"]
    assert ca["ok"] is True and ca["verified_by"] == "ca"
    assert len(sim.sim.seen) == seen                      # not a single HTTP request: no credential could have been sent
    assert w.ad.post(f"{H}/setup/probe", json={"stage": "tls", "base_url": sim.url, "token_secret": "x" * 12}, headers=w.adh).status_code == 422


def test_setup_probe_bad_input_and_pin_mismatch(w, sim):
    assert w.ad.post(f"{H}/setup/probe", json=probe_body(sim, token_secret="bad secret"), headers=w.adh).status_code == 422
    r = w.ad.post(f"{H}/setup/probe", json=probe_body(sim, token_secret="bad secret"), headers=w.adh)
    assert "bad secret" not in r.text
    assert w.ad.post(f"{H}/setup/probe", json=probe_body(sim, base_url="http://x"), headers=w.adh).status_code == 422
    out = w.ad.post(f"{H}/setup/probe", json=probe_body(sim, fingerprint_sha256="cd" * 32), headers=w.adh).json()
    assert out["ok"] is False and out["tls"]["ok"] is False and "pinned" in out["error"]
    w.ad.post(f"{H}/setup/probe", json=probe_body(sim, base_url="https://169.254.169.254"), headers=w.adh).status_code == 422


def test_setup_state_progression(w, sim, rt):
    s = w.v.get(f"{H}/setup/state").json()
    assert s == {"has_endpoint": False, "has_endpoints": False, "endpoints": 0, "discovery_done": False, "defaults_saved": False,
                 "provision_configured": False, "next_step": "register_endpoint"}
    eid = registered(w, sim)
    assert w.v.get(f"{H}/setup/state").json()["next_step"] == "discover"
    refresh(w, eid)
    s = w.v.get(f"{H}/setup/state").json()
    assert s["discovery_done"] and s["defaults_saved"] and s["provision_configured"] and s["next_step"] == "done"


# ------------------------------------------------------------------------------ update / disable / remove
def test_update_rename_is_normal_risk_and_scope_or_secret_changes_are_high(w, sim, rt):
    eid = registered(w, sim)
    p = w.plan("endpoint.update", {"endpoint_id": eid, "display_name": "Lab cluster"})
    assert p["risk"] == "normal"
    pl, j = w.run("endpoint.update", {"endpoint_id": eid, "display_name": "Lab cluster 2"})
    assert j["status"] == "succeeded" and j["result"]["reprobed"] is False
    assert w.v.get(f"{H}/endpoints/{eid}").json()["display_name"] == "Lab cluster 2"
    for params in ({"allowed_storage": ["local-lvm", "other-lvm"]}, {"token_id": INV[0], "token_secret": "newsecret0123456789"},
                   {"base_url": sim.url}, {"fingerprint_sha256": sim.fingerprint}, {"remove_provision": True}, {"protected_vmids": [150]},
                   {"provision_token_id": LAB[0], "provision_token_secret": "newsecret0123456789"}, {"defaults": {"vlan": 30}}):
        assert w.plan("endpoint.update", {"endpoint_id": eid, **params})["risk"] == "high", params
    w.plan("endpoint.update", {"endpoint_id": eid}, expect=422)                       # no change
    w.plan("endpoint.update", {"endpoint_id": eid, "token_id": INV[0]}, expect=422)    # id without secret
    w.plan("endpoint.update", {"endpoint_id": eid, "ca_pem": sim.cert_pem, "fingerprint_sha256": sim.fingerprint}, expect=422)
    w.plan("endpoint.update", {"endpoint_id": "00000000-0000-0000-0000-000000000000", "display_name": "x"}, expect=404)


def test_update_secret_rotation_reprobes_and_rejects_bad_credentials(w, sim, rt):
    eid = registered(w, sim)
    sim.sim.add_token(INV[0], "rotated-secret-0123456789", [("/", "PVEAuditor")])
    bad = w.run("endpoint.update", {"endpoint_id": eid, "token_id": INV[0], "token_secret": "not-the-new-secret-01234"})[1]
    assert bad["status"] == "failed" and "401" in bad["error"]["message"] and "not-the-new-secret-01234" not in json.dumps(bad)
    j = w.run("endpoint.update", {"endpoint_id": eid, "token_id": INV[0], "token_secret": "rotated-secret-0123456789"})[1]
    assert j["status"] == "succeeded" and j["result"]["reprobed"] is True
    assert refresh(w, eid)["discovery"]["ok"]             # the new secret decrypts and works
    blob = dump_everything(rt, w)
    assert "rotated-secret-0123456789" not in blob and "not-the-new-secret-01234" not in blob and INV[1] not in blob
    with rt.session() as db:
        enc = b"".join(bytes(r[0]) for r in db.execute(text("SELECT secret_enc FROM credentials")).all())
    assert b"rotated-secret" not in enc


def test_update_trust_change_reprobes_and_failure_persists_nothing(w, sim, rt):
    eid = registered(w, sim)
    j = w.run("endpoint.update", {"endpoint_id": eid, "fingerprint_sha256": "ab" * 32})[1]
    assert j["status"] == "failed" and "pinned" in j["error"]["message"]
    assert w.v.get(f"{H}/endpoints/{eid}").json()["fingerprint_sha256"] == sim.fingerprint
    # switching to CA trust works (and re-encrypts secrets under the new binding)
    j = w.run("endpoint.update", {"endpoint_id": eid, "ca_pem": sim.cert_pem})[1]
    assert j["status"] == "succeeded"
    ep = w.v.get(f"{H}/endpoints/{eid}").json()
    assert ep["trust"] == "ca_bundle" and ep["fingerprint_sha256"] is None
    assert refresh(w, eid)["discovery"]["ok"]
    with rt.session() as db:
        with base.job_execution("t"):
            assert open_mutations(rt, db.execute(text("SELECT * FROM endpoints")).first()).scope.pools == ("ou-lab",)


def test_update_changes_scope_and_provision_and_base_url_requires_ssrf_guard(w, sim, rt):
    eid = registered(w, sim)
    j = w.run("endpoint.update", {"endpoint_id": eid, "allowed_storage": ["local-lvm", "other-lvm"], "allowed_networks": ["vmbr1/20"]})[1]
    assert j["status"] == "succeeded"
    sc = w.v.get(f"{H}/endpoints/{eid}").json()["scope"]
    assert sc["allowed_storage"] == ["local-lvm", "other-lvm"] and sc["allowed_networks"] == ["vmbr1/20"]
    j = w.run("endpoint.update", {"endpoint_id": eid, "remove_provision": True})[1]
    assert j["status"] == "succeeded"
    ep = w.v.get(f"{H}/endpoints/{eid}").json()
    assert ep["credentials"]["provision"]["present"] is False
    with rt.session() as db, base.job_execution("t"):
        with pytest.raises(MutationNotAllowed, match="only an inventory credential"):
            open_mutations(rt, db.execute(text("SELECT * FROM endpoints")).first())
    w.plan("endpoint.update", {"endpoint_id": eid, "base_url": "https://169.254.169.254"}, expect=422)
    w.plan("endpoint.update", {"endpoint_id": eid, "base_url": "http://plain.example"}, expect=422)


def test_plan_hash_binds_edits_to_the_endpoint_trust_anchors(w, sim, rt):
    eid = registered(w, sim)
    p = w.plan("endpoint.update", {"endpoint_id": eid, "display_name": "bound"})
    with rt.session() as db:   # someone swaps the trust anchor between planning and approval
        db.execute(text("UPDATE endpoints SET fingerprint_sha256 = :f"), {"f": "ee" * 32})
        db.commit()
    r = w.a1.post(f"{H}/plans/{p['plan_id']}/approve", headers=w.a1h)
    jid = r.json()["job_id"]
    while worker.run_once(rt):
        pass
    j = w.o.get(f"{H}/jobs/{jid}").json()
    assert j["status"] == "failed" and "changed after approval" in j["error"]["message"]


def test_disable_enable_stop_collection_and_refuse_mutations(w, sim, rt):
    eid = registered(w, sim)
    assert w.plan("endpoint.disable", {"endpoint_id": eid})["risk"] == "normal"
    j = w.run("endpoint.disable", {"endpoint_id": eid})[1]
    assert j["status"] == "succeeded" or j["status"] == "failed"   # the first plan above is still pending; the second may race on state
    ep = w.v.get(f"{H}/endpoints/{eid}").json()
    assert ep["enabled"] is False and ep["health"]["status"] == "disabled"
    collector._next.clear()
    seen = len(sim.sim.seen)
    collector.tick(rt)
    assert len(sim.sim.seen) == seen                         # a disabled endpoint is not contacted
    with rt.session() as db, base.job_execution("t"):
        with pytest.raises(MutationNotAllowed, match="disabled"):
            open_mutations(rt, db.execute(text("SELECT * FROM endpoints")).first())
    w.plan("endpoint.disable", {"endpoint_id": eid}, expect=409)
    assert w.run("endpoint.enable", {"endpoint_id": eid})[1]["status"] == "succeeded"
    collector.tick(rt)
    assert len(sim.sim.seen) > seen
    assert w.v.get(f"{H}/endpoints/{eid}").json()["enabled"] is True


def test_remove_requires_confirmation_force_when_referenced_and_keeps_history(w, sim, rt, owner_engine):
    eid = registered(w, sim)
    refresh(w, eid)
    w.plan("endpoint.remove", {"endpoint_id": eid, "confirm_name": "wrong"}, expect=422)
    p = w.plan("endpoint.remove", {"endpoint_id": eid, "confirm_name": "lab"})
    assert p["risk"] == "high"
    with rt.session() as db:    # the deployment engine's real table
        db.execute(text("INSERT INTO deployments (slug, customer_id, profile, profile_version, endpoint_id, status, desired_spec) "
                        "VALUES ('dep-ref', 'c1', 'lab', '1.0.0', :e, 'active', '{}'::jsonb)"), {"e": eid})
        db.commit()
    try:
        w.plan("endpoint.remove", {"endpoint_id": eid, "confirm_name": "lab"}, expect=409)
        pl, j = w.run("endpoint.remove", {"endpoint_id": eid, "confirm_name": "lab", "force_detach": True})
        assert j["status"] == "succeeded" and j["result"]["referencing_deployments"] == 1
    finally:
        with rt.session() as db:
            db.execute(text("DELETE FROM deployments WHERE slug = 'dep-ref'"))
            db.commit()
    assert w.v.get(f"{H}/endpoints").json() == []
    det = w.v.get(f"{H}/endpoints?include_detached=true").json()
    assert len(det) == 1 and det[0]["health"]["status"] == "detached" and det[0]["credentials"]["provision"]["present"] is False
    assert det[0]["detached_at"] and det[0]["name"].startswith("lab~detached-")
    with rt.session() as db:
        row = db.execute(text("SELECT token_secret_enc, provision_secret_enc, allowed_pools FROM endpoints")).first()
        assert bytes(row[0]) == b"" and row[1] is None and row[2] == []
        assert db.execute(text("SELECT count(*) FROM infra_guests")).scalar() == 5            # history kept
        assert db.execute(text("SELECT count(*) FROM inventory_snapshots")).scalar() >= 1
    assert w.v.get(f"{H}/infra/guests").json() == []                                           # but not shown as live inventory
    assert w.v.get(f"{H}/infra/summary").json()["endpoints"] == {"active": 0, "total": 1}
    assert registered(w, sim)                                                                   # the name can be reused
    w.plan("endpoint.update", {"endpoint_id": eid, "display_name": "x"}, expect=409)


# ------------------------------------------------------------------------------ factory guard + end to end mutation
def test_open_mutations_only_in_job_and_end_to_end_with_vault_credentials(w, sim, rt):
    eid = registered(w, sim)
    with rt.session() as db:
        ep = db.execute(text("SELECT * FROM endpoints WHERE id = :i"), {"i": eid}).first()
        with pytest.raises(MutationNotAllowed):
            open_mutations(rt, ep)                                   # request-handler context
        assert not hasattr(open_read_provider(rt, ep), "power")
        known: list[str] = []
        with base.job_execution("job-1"):
            m = open_mutations(rt, ep, known)
            assert LAB[1] in known
            t = m.power(VmRef("pve1", 150, "vm", "d1"), "start")
            assert m.wait(t, timeout=5).state == "ok"
            from ics.providers.base import ScopeViolation
            with pytest.raises(ScopeViolation):
                m.power(VmRef("pve1", 160, "vm", "d1"), "start")
    assert sim.sim.vms[150]["status"] == "running"


def test_job_runner_enters_job_execution_context(w, sim, rt, monkeypatch):
    from ics import actions
    seen = []
    orig = actions._EXEC[actions.ActionType.endpoint_disable]
    monkeypatch.setitem(actions._EXEC, actions.ActionType.endpoint_disable,
                        lambda *a, **k: (seen.append(base.current_job()), orig(*a, **k))[1])
    eid = registered(w, sim)
    w.run("endpoint.disable", {"endpoint_id": eid})
    assert seen and seen[0] is not None and base.current_job() is None
