"""ADR-0017 single-admin approval mode: an install with one administrator approves its own plans (one approval each);
the plan -> approval -> job flow, the digest binding and the audit trail stay. Default (two_person) is unchanged."""
import dataclasses

import pytest
from sqlalchemy import text

from ics import worker
from ics.config import Settings
from .pve_mock import SEC
from .test_flow import reg_body

H = "/api/v1"


@pytest.fixture()
def solo(rt, monkeypatch):
    monkeypatch.setattr(rt, "settings", dataclasses.replace(rt.settings, approval_mode="single_admin"))
    return rt


def test_mode_is_validated_and_forces_one_approval(base_settings):
    s = dataclasses.replace(base_settings, approval_mode="single_admin")
    assert s.required_approvals_high == 1
    assert dataclasses.replace(base_settings).required_approvals_high == 2 and base_settings.approval_mode == "two_person"
    with pytest.raises(RuntimeError):
        dataclasses.replace(base_settings, approval_mode="nobody")
    assert Settings.__dataclass_fields__["approval_mode"].default == "two_person"


def test_the_only_admin_approves_their_own_high_risk_plan_once(solo, client, mk_user, login, pve):
    ad, adh = login(mk_user("owner", "admin"))
    assert ad.get(f"{H}/approvals/policy").json() == {"normal": 1, "high": 1, "mode": "single_admin", "self_approval": True,
                                                      "note": "single-admin mode: an admin approves their own plans"}
    r = ad.post(f"{H}/plans", json=reg_body(pve), headers=adh)
    assert r.status_code == 201, r.text
    c = r.json()
    assert c["status"] == "pending_approval" and c["risk"] == "high" and c["approvals_required"] == 1 and c["self_approval"] is True
    listed = [p for p in ad.get(f"{H}/plans").json() if p["id"] == c["plan_id"]][0]
    assert listed["self_approval"] is True and listed["approvals_required"] == 1
    a = ad.post(f"{H}/plans/{c['plan_id']}/approve", headers=adh)
    assert a.status_code == 200 and a.json()["status"] == "approved" and a.json()["job_id"], a.text
    assert ad.post(f"{H}/plans/{c['plan_id']}/approve", headers=adh).status_code == 409        # still exactly once
    assert worker.run_once(solo) is True
    job = ad.get(f"{H}/jobs/{a.json()['job_id']}").json()
    assert job["status"] == "succeeded", job
    assert SEC not in str(ad.get(f"{H}/endpoints").json())
    with solo.session() as db:
        d = db.execute(text("SELECT details FROM audit_events WHERE action = 'plan.approve'")).scalar()
        assert d["self_approval"] is True and d["approval_mode"] == "single_admin"


def test_other_roles_still_need_someone_else_and_an_admin_can_reject_own(solo, client, mk_user, login, pve):
    ap, aph = login(mk_user("ap", "approver"))
    r = ap.post(f"{H}/plans", json=reg_body(pve), headers=aph)
    pid = r.json()["plan_id"]
    assert r.json()["self_approval"] is False
    assert ap.post(f"{H}/plans/{pid}/approve", headers=aph).status_code == 403               # an approver is never self-approving
    ad, adh = login(mk_user("owner", "admin"))
    assert ad.post(f"{H}/plans/{pid}/approve", headers=adh).json()["status"] == "approved"   # the admin approves it: one approval
    r2 = ad.post(f"{H}/plans", json=reg_body(pve, name="other"), headers=adh)
    assert ad.post(f"{H}/plans/{r2.json()['plan_id']}/reject", headers=adh).json()["status"] == "rejected"


def test_two_person_default_is_unchanged(client, mk_user, login, pve):
    ad, adh = login(mk_user("owner", "admin"))
    assert ad.get(f"{H}/approvals/policy").json()["self_approval"] is False
    r = ad.post(f"{H}/plans", json=reg_body(pve), headers=adh)
    assert r.json()["approvals_required"] == 2 and r.json()["self_approval"] is False
    assert ad.post(f"{H}/plans/{r.json()['plan_id']}/approve", headers=adh).status_code == 403
