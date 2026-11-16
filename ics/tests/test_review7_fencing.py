"""Security review 7 H-5: a fenced / superseded controller stops ALL side effects, not only signed agent requests (resurrected-primary simulation)."""
import pytest
from sqlalchemy import text

from ics import agentclient, alerts, egress, epoch, worker
from ics.actions import claim_job
from ics.epoch import NotActive
from ics.proxmox import ProxmoxReadClient

from .test_review5 import H, world  # noqa: F401


@pytest.fixture()
def primary(rt, owner_engine):
    """the controller as a running primary: process epoch fixed from the database; the controller_state row is restored afterwards"""
    with rt.session() as db:
        saved = dict(db.execute(text("SELECT epoch, role, note FROM controller_state WHERE id = 1")).mappings().first())
    rt.own_epoch, rt.fenced_reason = None, None
    assert rt.assert_active() == saved["epoch"]
    yield rt
    unfence(owner_engine, saved["role"], saved["note"])
    rt.own_epoch, rt.fenced_reason = None, None


def unfence(owner_engine, role="primary", note=None):
    """restore the row through the OWNER with the guard trigger off: the application role can no longer un-fence (migration 0012)"""
    with owner_engine.connect() as c:
        c.execute(text("ALTER TABLE controller_state DISABLE TRIGGER controller_state_guard"))
        c.execute(text("UPDATE controller_state SET role = :r, note = :n WHERE id = 1"), {"r": role, "n": note})
        c.execute(text("ALTER TABLE controller_state ENABLE TRIGGER controller_state_guard"))


def queue_job(world):
    c, h = world["sessions"]["all"]
    r = c.post(f"{H}/plans", json={"action": "maintenance.create", "params": {"name": "w", "check_id": world["ids"]["check_a"], "duration_minutes": 5}}, headers=h)
    assert r.status_code == 201, r.text
    assert r.json()["job_id"]


def supersede(rt, how):
    """what the resurrected primary sees: the other controller's promotion reached its database (replicated / pg_rewind / --fence-old-dsn-file)"""
    if how == "epoch":
        rt.own_epoch -= 1          # the database is one epoch ahead of what this process started with (the epoch column itself can only go up)
        return
    with rt.session() as db:
        db.execute(text("UPDATE controller_state SET role = 'fenced' WHERE id = 1"))
        db.commit()


@pytest.mark.parametrize("how", ["epoch", "fenced"])
def test_h5_fenced_controller_claims_no_job_and_runs_nothing(primary, world, how, owner_engine):
    rt = primary
    queue_job(world)
    supersede(rt, how)
    assert claim_job(rt) is None
    assert worker.run_once(rt) is False
    with rt.session() as db:
        assert db.execute(text("SELECT count(*) FROM jobs WHERE status = 'queued'")).scalar() >= 1      # still queued: nothing ran it
        assert db.execute(text("SELECT count(*) FROM jobs WHERE status = 'running'")).scalar() == 0
    assert worker.Worker(rt).active() is False and worker.Worker(rt).healthy() is False                # heartbeat is withheld too
    # sticky: even if the row looked healthy again, this process stays fenced until it is restarted
    unfence(owner_engine)
    assert claim_job(rt) is None


def test_h5_unfenced_controller_still_claims_jobs(primary, world):
    """control: the same flow works when nothing superseded the controller (the tests above are not vacuous)"""
    queue_job(world)
    assert claim_job(primary) is not None


def test_h5_no_provider_agent_notification_or_enrollment_call_leaves_the_process(primary, monkeypatch):
    rt = primary
    supersede(rt, "epoch")
    with pytest.raises(NotActive):
        rt.assert_active()
    sent = []
    import httpx
    monkeypatch.setattr(httpx.Client, "stream", lambda *a, **k: sent.append(a) or (_ for _ in ()).throw(AssertionError("network touched")))
    monkeypatch.setattr(httpx.Client, "post", lambda *a, **k: sent.append(a) or (_ for _ in ()).throw(AssertionError("network touched")))
    pve = ProxmoxReadClient("https://127.0.0.1:8006", "ics@pve!t", "0123456789abcdef0123456789abcdef", fingerprint_sha256="ab" * 32, allow_loopback=True)
    with pytest.raises(NotActive):
        pve._get("/version")                                                              # provider (Proxmox) call
    with pytest.raises(NotActive):
        alerts.send("webhook", {"url": "https://127.0.0.1/x"}, None, alerts.Message("e", "s", "b", {}), allow_loopback=True)      # notification
    with pytest.raises(NotActive):
        agentclient.identity("127.0.0.1", 8443, "ab" * 32, allow_loopback=True)         # enrollment probe
    with pytest.raises(NotActive):
        agentclient.enroll("127.0.0.1", 8443, "ab" * 32, token="x" * 20, ics_pubkey_b64="A" * 44, node_id="n", expect_agent_pubkey_b64="A" * 44, allow_loopback=True)
    with pytest.raises(NotActive):
        egress.require()
    assert sent == []


def test_h5_console_and_api_mutations_return_503_but_reads_work(primary, world):
    rt = primary
    c, h = world["sessions"]["all"]
    supersede(rt, "fenced")
    r = c.post(f"{H}/plans", json={"action": "maintenance.create", "params": {"name": "w", "check_id": world["ids"]["check_a"], "duration_minutes": 5}}, headers=h)
    assert r.status_code == 503 and r.headers.get("x-ou-role") == "fenced"
    assert c.post(f"{H}/plans/{world['ids']['check_a']}/approve", headers=h).status_code == 503
    assert c.get(f"{H}/version").status_code == 200                                      # an operator can still read why


def test_h5_agent_learned_fence_stops_everything_at_once(primary, world):
    """an agent that has seen a higher epoch refuses us (stale_epoch): the hook fences this process immediately, even before/without the DB write"""
    rt = primary
    queue_job(world)
    agentclient.stale_epoch_hook(rt.own_epoch + 5)
    assert rt.fenced_reason and "self-fenced" in rt.fenced_reason
    assert claim_job(rt) is None
    with pytest.raises(NotActive):
        egress.require()


def test_h5_standby_never_has_side_effects(rt, monkeypatch):
    import dataclasses
    real = rt.settings
    rt.settings = dataclasses.replace(real, role="standby")
    rt.own_epoch, rt.fenced_reason = None, None
    try:
        with pytest.raises(NotActive):
            epoch.assert_active(rt)
    finally:
        rt.settings = real
        rt.own_epoch, rt.fenced_reason = None, None


def test_h5_a_fenced_row_cannot_be_flipped_back_by_the_application_role(primary):
    rt = primary
    supersede(rt, "fenced")
    from sqlalchemy.exc import DBAPIError
    with pytest.raises(DBAPIError, match="only through a promotion"):
        with rt.session() as db:
            db.execute(text("UPDATE controller_state SET role = 'primary' WHERE id = 1"))
            db.commit()
