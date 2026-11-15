import json
import threading
import uuid

from sqlalchemy import text

from ics import worker
from ics.actions import claim_job
from .pve_mock import TID, SEC

H = "/api/v1"


def reg_body(pve, **over):
    p = {"name": "lab-pve", "type": "proxmox", "base_url": pve.url, "token_id": TID, "token_secret": SEC,
         "fingerprint_sha256": pve.fingerprint}
    p.update(over)
    return {"action": "endpoint.register", "params": p}


def test_register_validation(client, mk_user, login, pve):
    o, oh = login(mk_user("op", "operator"))
    for over in ({"base_url": "http://x.example"}, {"fingerprint_sha256": None}, {"ca_pem": "-----BEGIN CERTIFICATE-----\nx"},
                 {"fingerprint_sha256": "zz"}, {"token_id": "root"}, {"extra": 1}, {"base_url": "https://u:p@h/"}):
        r = o.post(f"{H}/plans", json=reg_body(pve, **over), headers=oh)
        assert r.status_code == 422, (over, r.text)
    assert o.post(f"{H}/plans", json={"action": "shell.exec", "params": {}}, headers=oh).status_code == 422


def test_self_approval_rejected_and_full_flow(client, mk_user, login, pve, rt):
    o, oh = login(mk_user("op", "operator"))
    ap, aph = login(mk_user("ap", "approver"))
    ad, adh = login(mk_user("adm", "admin"))
    r = o.post(f"{H}/plans", json=reg_body(pve), headers=oh)
    assert r.status_code == 201 and r.json()["status"] == "pending_approval" and r.json()["job_id"] is None
    pid = r.json()["plan_id"]
    assert o.post(f"{H}/plans/{pid}/approve", headers=oh).status_code == 403          # operator role
    # an approver who is also the requester
    r2 = ad.post(f"{H}/plans", json=reg_body(pve, name="other"), headers=adh)
    pid2 = r2.json()["plan_id"]
    assert ad.post(f"{H}/plans/{pid2}/approve", headers=adh).status_code == 403       # self approval
    assert ad.post(f"{H}/plans/{pid2}/reject", headers=adh).status_code == 403
    with rt.session() as db:
        assert db.execute(text("SELECT count(*) FROM audit_events WHERE action='plan.self_decision_rejected'")).scalar() == 2
        assert db.execute(text("SELECT count(*) FROM jobs")).scalar() == 0
    # a different approver succeeds, exactly once
    a = ap.post(f"{H}/plans/{pid}/approve", headers=aph)
    assert a.status_code == 200 and a.json()["job_id"]
    assert ap.post(f"{H}/plans/{pid}/approve", headers=aph).status_code == 409
    assert worker.run_once(rt) is True and worker.run_once(rt) is False
    job = o.get(f"{H}/jobs/{a.json()['job_id']}").json()
    assert job["status"] == "succeeded" and job["started_at"] and job["finished_at"], job
    eid = job["result"]["endpoint_id"]
    eps = o.get(f"{H}/endpoints").json()
    assert eps[0]["id"] == eid and "token_secret" not in eps[0] and SEC not in json.dumps(eps)
    # refresh: auto-approved low risk
    rr = o.post(f"{H}/plans", json={"action": "inventory.refresh", "params": {"endpoint_id": eid}}, headers=oh)
    assert rr.json()["status"] == "approved" and rr.json()["job_id"]
    assert worker.run_once(rt)
    assert o.get(f"{H}/jobs/{rr.json()['job_id']}").json()["status"] == "succeeded"
    inv = o.get(f"{H}/endpoints/{eid}/inventory").json()
    assert inv["data"]["version"]["version"] == "8.2.4" and len(inv["data"]["nodes"]) == 2
    assert len(o.get(f"{H}/endpoints/{eid}/inventory/snapshots").json()) == 1
    # secrets nowhere in plans, audit, jobs, API
    with rt.session() as db:
        dump = json.dumps([[str(c) for c in r] for r in db.execute(text("SELECT details FROM audit_events")).all()])
        dump += json.dumps(o.get(f"{H}/plans").json()) + json.dumps(o.get(f"{H}/jobs").json())
        assert db.execute(text("SELECT count(*) FROM plans WHERE secret_enc IS NOT NULL")).scalar() == 1  # only the unapproved 'other'
        enc = db.execute(text("SELECT token_secret_enc FROM endpoints")).scalar()
    assert SEC not in dump and SEC.encode() not in bytes(enc)
    assert ap.get(f"{H}/audit/verify").json()["ok"] is True


def test_job_fails_on_wrong_pin_with_structured_error(client, mk_user, login, pve, rt):
    o, oh = login(mk_user("op", "operator"))
    ap, aph = login(mk_user("ap", "approver"))
    pid = o.post(f"{H}/plans", json=reg_body(pve, fingerprint_sha256="cd" * 32), headers=oh).json()["plan_id"]
    jid = ap.post(f"{H}/plans/{pid}/approve", headers=aph).json()["job_id"]
    worker.run_once(rt)
    job = o.get(f"{H}/jobs/{jid}").json()
    assert job["status"] == "failed" and job["error"]["type"] == "ProxmoxError" and "pinned" in job["error"]["message"]
    assert o.get(f"{H}/endpoints").json() == []


def _queue_jobs(rt, n):
    with rt.session() as db:
        uid = db.execute(text("INSERT INTO users (username,password_hash,totp_secret_enc,role) VALUES ('u','x','\\x00','admin') RETURNING id")).scalar()
        for _ in range(n):
            pid = db.execute(text("INSERT INTO plans (action,params,risk,status,requested_by) VALUES "
                                  "('inventory.refresh','{}','low','approved',:u) RETURNING id"), {"u": uid}).scalar()
            db.execute(text("INSERT INTO jobs (plan_id,action,status) VALUES (:p,'inventory.refresh','queued')"), {"p": pid})
        db.commit()


def _race(rt, threads):
    got, barrier = [], threading.Barrier(threads)

    def go():
        barrier.wait()
        while (j := claim_job(rt)) is not None:
            got.append(j["id"])
    ts = [threading.Thread(target=go) for _ in range(threads)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    return got


def test_single_job_claimed_exactly_once(rt):
    _queue_jobs(rt, 1)
    assert len(_race(rt, 8)) == 1


def test_many_jobs_each_claimed_once(rt):
    _queue_jobs(rt, 40)
    got = _race(rt, 8)
    assert len(got) == 40 and len(set(got)) == 40
    with rt.session() as db:
        assert db.execute(text("SELECT count(*) FROM jobs WHERE status='running' AND started_at IS NOT NULL")).scalar() == 40
        assert db.execute(text("SELECT count(*) FROM audit_events WHERE action='job.started'")).scalar() == 40


def test_plan_has_at_most_one_job(rt):
    _queue_jobs(rt, 1)
    import pytest
    from sqlalchemy.exc import IntegrityError
    with rt.session() as db:
        pid = db.execute(text("SELECT plan_id FROM jobs")).scalar()
        with pytest.raises(IntegrityError):
            db.execute(text("INSERT INTO jobs (plan_id,action,status) VALUES (:p,'inventory.refresh','queued')"), {"p": pid})


def test_health(client, rt):
    assert client.get("/healthz").json() == {"status": "ok"}
    r = client.get("/readyz")
    assert r.status_code == 503 and r.json()["checks"]["worker"]["ok"] is False and r.json()["checks"]["database"]["ok"]
    worker.heartbeat(rt)
    r = client.get("/readyz")
    assert r.status_code == 200 and r.json()["checks"]["audit_chain"]["ok"] and r.json()["ready"]
