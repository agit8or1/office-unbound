"""Security review 7 H-5 follow-up: the controller lease with an external witness. A primary isolated by a partition (it still believes its own database) fences
itself when its lease runs out; promotion needs the witness to have stopped granting for T + margin. Fake clock + simulated partition."""
import threading

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import text

from ics import agentclient, egress, lease as L
from ics.actions import claim_job
from ics.epoch import NotActive

from .test_review5 import H, world  # noqa: F401
from .test_review7_fencing import queue_job

T, RENEW, MARGIN = 30.0, 5.0, 10.0


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def wall(self):
        return 1_800_000_000.0 + self.t

    def advance(self, s):
        self.t += s


class Net:
    """the path controller -> witness; `down` = partition"""

    def __init__(self, witness):
        self.w, self.down, self.log = witness, False, []

    def __call__(self, req):
        if self.down:
            raise ConnectionError("partition")
        resp = self.w.handle(req)
        self.log.append(resp)
        return resp


@pytest.fixture()
def keys():
    return Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()      # (controller signing key, witness key)


@pytest.fixture()
def clock():
    return Clock()


@pytest.fixture()
def witness(keys, clock, tmp_path):
    return L.Witness(keys[1], keys[0].public_key(), lease_seconds=T, state_path=str(tmp_path / "witness.json"), clock=clock, wall=clock.wall)


def make_lease(keys, clock, net, epoch_fn, **kw):
    return L.Lease(signing_key=keys[0], witness_pub=keys[1].public_key(), transport=net, epoch_fn=epoch_fn, lease_seconds=T, renew_seconds=RENEW, clock=clock, wall=clock.wall, **kw)


@pytest.fixture()
def primary(rt):
    with rt.session() as db:
        saved = dict(db.execute(text("SELECT role, note FROM controller_state WHERE id = 1")).mappings().first())
    rt.own_epoch, rt.fenced_reason, rt.lease = None, None, None
    ep = rt.assert_active()
    yield rt, ep
    rt.lease, rt.own_epoch, rt.fenced_reason = None, None, None


# ------------------------------------------------------------------------------------------------------------------------ the partition
def test_a_partitioned_primary_fences_itself_when_the_lease_runs_out(primary, world, keys, clock, witness):  # noqa: F811
    rt, ep = primary
    net = Net(witness)
    rt.lease = make_lease(keys, clock, net, lambda: ep)
    with pytest.raises(NotActive, match="lease expired"):          # lease mode: nothing happens before the first grant
        rt.assert_active()
    assert claim_job(rt) is None
    assert rt.lease.renew_once() is True
    queue_job(world)
    queue_job(world)
    assert rt.assert_active() == ep and claim_job(rt) is not None   # active while the lease is valid ...
    net.down = True                                                # ... partition: the witness can no longer be reached, the DB still says "primary"
    for _ in range(5):                                             # renewals fail, the lease keeps running down
        clock.advance(RENEW)
        assert rt.lease.renew_once() is False
    assert rt.assert_active() == ep                                # 25 s: still inside T
    clock.advance(6)                                               # 31 s > T
    with pytest.raises(NotActive, match="lease expired"):
        rt.assert_active()
    assert claim_job(rt) is None                                   # no job claim (one queued job is still waiting)
    with pytest.raises(NotActive):
        egress.require()                                           # no provider / agent / notification / enrollment / ssh call
    c, h = world["sessions"]["all"]
    r = c.post(f"{H}/plans", json={"action": "maintenance.create", "params": {"name": "w", "check_id": world["ids"]["check_a"], "duration_minutes": 5}}, headers=h)
    assert r.status_code == 503 and r.headers.get("x-ou-role") == "fenced"      # API mutations
    net.down = False                                               # the partition heals and nobody promoted: the controller recovers by itself
    assert rt.lease.renew_once() is True
    assert rt.assert_active() == ep


def test_lease_is_measured_from_before_the_request_so_delay_only_shortens_it(keys, clock, witness):
    slow = Net(witness)

    def delayed(req):
        r = slow(req)
        clock.advance(8)                 # the answer took 8 s to come back
        return r
    ls = make_lease(keys, clock, delayed, lambda: 1)
    t0 = clock()
    assert ls.renew_once()
    assert ls.valid_until == t0 + T
    clock.advance(T - 8 - 0.5)
    assert ls.valid()
    clock.advance(1)
    assert not ls.valid()                # the controller's view ended at t0 + T, never later than the witness's


# ------------------------------------------------------------------------------------------------------------------------ promotion proof
def test_promotion_waits_until_no_lease_can_be_valid_and_the_old_primary_is_then_superseded(primary, keys, clock, witness):
    rt, ep = primary
    net = Net(witness)
    rt.lease = make_lease(keys, clock, net, lambda: ep, on_superseded=lambda: setattr(rt, "fenced_reason", "superseded"))
    assert rt.lease.renew_once()
    t_grant = clock()
    net.down = True                                                # partition: the old primary keeps running on its remaining lease
    clock.advance(12)
    with pytest.raises(RuntimeError, match="revoke"):
        witness.wait_proven(MARGIN)                                # waiting without revoking first is refused: the witness would still grant
    assert witness.revoke() == ep                                  # promotion CLI step 1: the witness stops granting
    assert witness.seconds_until_proven(MARGIN) == pytest.approx(T + MARGIN - 12)
    slept = []
    witness.wait_proven(MARGIN, sleep=lambda s: (slept.append(s), clock.advance(s)), progress=None)    # step 2: wait (fake clock)
    assert clock() - t_grant >= T + MARGIN                         # epoch may be bumped only now ...
    assert not rt.lease.valid()                                    # ... and by then the isolated primary's lease is over, whatever its database says
    with pytest.raises(NotActive):
        rt.assert_active()
    net.down = False
    assert rt.lease.renew_once() is False and rt.lease.superseded  # healed: the witness answers "superseded": fenced for good
    assert rt.fenced_reason == "superseded"
    clock.advance(1)
    assert not rt.lease.valid()


def test_witness_refuses_to_grant_for_a_revoked_epoch_even_with_a_valid_signature(keys, clock, witness):
    ls = make_lease(keys, clock, Net(witness), lambda: 4)
    assert ls.renew_once()
    witness.revoke()
    assert ls.renew_once() is False and ls.superseded
    higher = make_lease(keys, clock, Net(witness), lambda: 5)      # the NEW primary (epoch 5) is granted
    assert higher.renew_once()


def test_revoke_by_another_process_reaches_the_serving_witness_and_survives_restart(keys, clock, tmp_path):
    path = str(tmp_path / "w.json")
    server = L.Witness(keys[1], keys[0].public_key(), lease_seconds=T, state_path=path, clock=clock, wall=clock.wall)
    ls = make_lease(keys, clock, Net(server), lambda: 7)
    assert ls.renew_once()
    cli = L.Witness(None, None, lease_seconds=T, state_path=path, clock=clock, wall=clock.wall)       # `ics.witness revoke` in its own process
    cli.revoke()
    assert ls.renew_once() is False and ls.superseded              # the serving process picked the revocation up from the state file
    clock.advance(3)
    restarted = L.Witness(None, None, lease_seconds=T, state_path=path, clock=lambda: 50.0, wall=clock.wall)   # a fresh monotonic clock after a restart
    assert restarted.seconds_until_proven(MARGIN) == pytest.approx(T + MARGIN - 3)                       # the persisted grant still counts


# ------------------------------------------------------------------------------------------------------------------------ authenticity
def test_forged_replayed_and_wrong_nonce_replies_grant_nothing(keys, clock, witness):
    attacker = Ed25519PrivateKey.generate()
    evil = L.Witness(attacker, keys[0].public_key(), lease_seconds=T, clock=clock, wall=clock.wall)      # a rogue witness: answers, but with another key
    assert make_lease(keys, clock, Net(evil), lambda: 1).renew_once() is False
    good = Net(witness)
    ls = make_lease(keys, clock, good, lambda: 1)
    assert ls.renew_once()
    old = good.log[-1]
    clock.advance(40)
    assert not ls.valid()
    assert make_lease(keys, clock, lambda req: old, lambda: 1).renew_once() is False                     # a recorded (valid!) answer replayed: wrong nonce
    ls2 = make_lease(keys, clock, lambda req: {**old, "resp": {**old["resp"], "lease_s": 9999, "nonce": req["req"]["nonce"]}}, lambda: 1)
    assert ls2.renew_once() is False and not ls2.valid()                                                  # tampered answer: signature fails


def test_witness_rejects_requests_that_are_not_the_controllers(keys, clock, witness):
    other = Ed25519PrivateKey.generate()
    ls = L.Lease(signing_key=other, witness_pub=keys[1].public_key(), transport=Net(witness), epoch_fn=lambda: 1, clock=clock, wall=clock.wall)
    assert ls.renew_once() is False                                  # signed by a key the witness does not know
    good = make_lease(keys, clock, Net(witness), lambda: 1)
    body = {"v": 1, "op": "grant", "epoch": 1, "nonce": "n" * 16, "issued_at": int(clock.wall())}
    req = {"req": body, "sig": agentclient.sign(keys[0], L.REQ_PREFIX, body)}
    witness.handle(req)
    with pytest.raises(ValueError, match="replayed"):
        witness.handle(req)
    old = {**body, "nonce": "m" * 16, "issued_at": int(clock.wall()) - 3600}
    with pytest.raises(ValueError, match="stale"):
        witness.handle({"req": old, "sig": agentclient.sign(keys[0], L.REQ_PREFIX, old)})
    assert good.renew_once()


# ------------------------------------------------------------------------------------------------------------------------ modes
def test_standalone_override_runs_without_a_witness(keys, clock):
    def boom(req):
        raise AssertionError("no witness is contacted in standalone mode")
    ls = make_lease(keys, clock, boom, lambda: 1, standalone=True)
    ls.start()
    clock.advance(10_000)
    assert ls.valid()
    ls.require()


def test_lease_off_by_default_single_controller_keeps_working(rt, world):  # noqa: F811
    assert rt.lease is None and rt.settings.lease_witness_url is None
    rt.own_epoch, rt.fenced_reason = None, None
    rt.assert_active()
    queue_job(world)
    assert claim_job(rt) is not None


def test_witness_and_lease_over_real_http(keys, clock, tmp_path):
    from http.server import ThreadingHTTPServer
    from ics.witness import make_handler
    w = L.Witness(keys[1], keys[0].public_key(), lease_seconds=T, state_path=str(tmp_path / "w.json"))
    srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(w))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{srv.server_address[1]}"
        ls = L.Lease(signing_key=keys[0], witness_pub=keys[1].public_key(), transport=L.http_transport(url), epoch_fn=lambda: 3, lease_seconds=T)
        assert ls.renew_once() and ls.valid()
        w.revoke()
        assert ls.renew_once() is False and ls.superseded
        import httpx
        assert httpx.post(url + "/witness/v1/grant", content=b"{}", timeout=3).status_code == 400
    finally:
        srv.shutdown()
