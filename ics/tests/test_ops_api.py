"""Part A: backend follow-ups for the UI (users list, richer plans, me.id, audit pagination, jobs filter, refresh state)."""
from ics import worker
from .pve_mock import SEC, TID

H = "/api/v1"


def _register(o, oh, ap, aph, ap2, aph2, pve, rt):
    body = {"action": "endpoint.register", "params": {"name": "lab-pve", "type": "proxmox", "base_url": pve.url, "token_id": TID,
                                                       "token_secret": SEC, "fingerprint_sha256": pve.fingerprint}}
    pid = o.post(f"{H}/plans", json=body, headers=oh).json()["plan_id"]
    ap.post(f"{H}/plans/{pid}/approve", headers=aph)
    ap2.post(f"{H}/plans/{pid}/approve", headers=aph2)
    worker.run_once(rt)
    return o.get(f"{H}/endpoints").json()[0]["id"]


def test_users_list_is_viewer_readable_ip_admin_only_and_has_no_secrets(client, mk_user, login):
    mk_user("viewer1", "viewer")
    o, oh = login(mk_user("op", "operator"))
    ad, adh = login(mk_user("adm", "admin"))
    assert o.get(f"{H}/users").status_code == 200 and "last_login_ip" not in o.get(f"{H}/users").json()[0]
    r = ad.get(f"{H}/users")
    assert r.status_code == 200
    names = {u["username"]: u for u in r.json()}
    assert set(names) == {"viewer1", "op", "adm"}
    assert "last_login_ip" in names["op"]
    forbidden = ("password", "totp", "token", "secret", "hash")
    assert not any(f in k for k in names["op"] for f in forbidden)
    assert names["op"]["status"] == "active" and names["op"]["role"] == "operator"


def test_auth_me_and_login_include_id(client, mk_user, login):
    u = mk_user("op", "operator")
    o, oh = login(u)
    assert o.get(f"{H}/auth/me").json()["id"] == u["id"]


def test_plans_list_has_hash_requester_and_approvals(client, mk_user, login, pve, rt):
    o, oh = login(mk_user("op", "operator"))
    ap, aph = login(mk_user("ap", "approver"))
    ap2, aph2 = login(mk_user("ap2", "approver"))
    body = {"action": "endpoint.register", "params": {"name": "p1", "type": "proxmox", "base_url": pve.url, "token_id": TID,
                                                       "token_secret": SEC, "fingerprint_sha256": pve.fingerprint}}
    created = o.post(f"{H}/plans", json=body, headers=oh).json()
    p = o.get(f"{H}/plans").json()[0]
    assert p["params_hash"] == created["params_hash"] and len(p["params_hash"]) == 64
    assert p["requested_by_username"] == "op" and p["approval_count"] == 0 and p["approvers"] == [] and p["approvals_required"] == 2
    assert "token_secret" not in p["params"]
    ap.post(f"{H}/plans/{created['plan_id']}/approve", headers=aph)
    ap2.post(f"{H}/plans/{created['plan_id']}/approve", headers=aph2)
    p = o.get(f"{H}/plans").json()[0]
    assert p["approval_count"] == 2 and p["approvers"] == ["ap", "ap2"] and p["status"] == "approved"
    assert p["decided_by_username"] == "ap2"
    assert len(o.get(f"{H}/plans?status=pending_approval").json()) == 0
    assert len(o.get(f"{H}/plans?status=approved").json()) == 1
    assert o.get(f"{H}/plans?status=bogus").status_code == 422


def test_audit_pagination_before_seq(client, mk_user, login):
    ap, aph = login(mk_user("ap", "approver"))
    first = ap.get(f"{H}/audit?limit=3").json()
    assert len(first) == 3 and first[0]["seq"] > first[1]["seq"] > first[2]["seq"]
    older = ap.get(f"{H}/audit?limit=3&before_seq={first[-1]['seq']}").json()
    assert older and all(e["seq"] < first[-1]["seq"] for e in older)
    assert {e["seq"] for e in older}.isdisjoint({e["seq"] for e in first})
    assert ap.get(f"{H}/audit?before_seq=1").json() == []
    assert ap.get(f"{H}/audit?before_seq=abc").status_code == 422


def test_jobs_filter_and_limit(client, mk_user, login, pve, rt):
    o, oh = login(mk_user("op", "operator"))
    ap, aph = login(mk_user("ap", "approver"))
    ap2, aph2 = login(mk_user("ap2", "approver"))
    eid = _register(o, oh, ap, aph, ap2, aph2, pve, rt)
    for _ in range(2):
        o.post(f"{H}/plans", json={"action": "inventory.refresh", "params": {"endpoint_id": eid}}, headers=oh)
    assert len(o.get(f"{H}/jobs").json()) == 3
    assert len(o.get(f"{H}/jobs?status=queued").json()) == 2
    assert len(o.get(f"{H}/jobs?status=succeeded").json()) == 1
    assert len(o.get(f"{H}/jobs?limit=1").json()) == 1
    assert o.get(f"{H}/jobs?status=nope").status_code == 422
    assert len(o.get(f"{H}/jobs?limit=0").json()) == 1  # clamped to [1, 500]


def test_inventory_refresh_state(client, mk_user, login, pve, rt):
    o, oh = login(mk_user("op", "operator"))
    ap, aph = login(mk_user("ap", "approver"))
    ap2, aph2 = login(mk_user("ap2", "approver"))
    eid = _register(o, oh, ap, aph, ap2, aph2, pve, rt)
    st = o.get(f"{H}/endpoints/{eid}/inventory/refresh-state").json()
    assert st["state"] == "none" and st["last_snapshot_at"] is None
    r = o.post(f"{H}/plans", json={"action": "inventory.refresh", "params": {"endpoint_id": eid}}, headers=oh).json()
    st = o.get(f"{H}/endpoints/{eid}/inventory/refresh-state").json()
    assert st["state"] == "queued" and st["job_id"] == r["job_id"]
    worker.run_once(rt)
    st = o.get(f"{H}/endpoints/{eid}/inventory/refresh-state").json()
    assert st["state"] == "succeeded" and st["finished_at"] and st["last_snapshot_at"] and st["error"] is None
    assert o.get(f"{H}/endpoints/00000000-0000-0000-0000-000000000000/inventory/refresh-state").status_code == 404
