"""Controller epoch / fencing on the agent protocol (ADR-0012): backward compatible, persistent, refuses a lower epoch."""
import time
import uuid

import pytest

from ics import agentclient

from .test_agent import NODE, enrolled  # noqa: F401  (fixture)


def _req(enrolled, epoch, action="service.status", params=None):
    fa, priv, node = enrolled
    body = agentclient.build_request(priv, action=action, params=params or {"unit": "gromox-imap"}, node_id=NODE, job_id=str(uuid.uuid4()), epoch=epoch)
    return agentclient.call(node, priv, action="", params={}, job_id="", req_override=body, allow_loopback=True)[1]


def test_epochless_requests_keep_working_until_an_epoch_is_seen(enrolled):
    assert _req(enrolled, None)["status"] == "ok"             # pre-epoch controller (backward compatible)
    r = _req(enrolled, 1)
    assert r["status"] == "ok" and r["agent_epoch"] == 1
    r = _req(enrolled, None)                                  # once an epoch was seen, an epoch-less request is refused
    assert r["status"] == "rejected" and r["code"] == "epoch_required"


def test_agent_refuses_a_lower_epoch_and_learns_a_higher_one(enrolled):
    fa = enrolled[0]
    assert _req(enrolled, 1)["status"] == "ok"
    assert _req(enrolled, 2)["agent_epoch"] == 2              # promotion: first request of the new primary raises the mark
    n = len(fa.calls())
    old = _req(enrolled, 1, action="service.restart")         # resurrected old primary (same signing key, valid signature)
    assert old["status"] == "rejected" and old["code"] == "stale_epoch" and old["agent_epoch"] == 2
    assert len(fa.calls()) == n                               # nothing executed
    assert _req(enrolled, 2)["status"] == "ok"                # the legitimate primary is unaffected


def test_epoch_mark_survives_agent_restart(tmp_path):
    from ou_agent import proto
    g = proto.EpochGate(str(tmp_path / "epoch.json"))
    assert g.admit(None) == 0 and g.admit(3) == 3
    g2 = proto.EpochGate(str(tmp_path / "epoch.json"))
    assert g2.max_epoch == 3
    with pytest.raises(proto.Reject) as e:
        g2.admit(2)
    assert e.value.code == "stale_epoch"
    with pytest.raises(proto.Reject) as e:
        g2.admit(None)
    assert e.value.code == "epoch_required"


@pytest.mark.parametrize("bad", [True, -1, "2", 2.0, 2**70])
def test_malformed_epoch_is_bad_format(bad):
    from ou_agent import proto
    now = int(time.time())
    req = {"v": 1, "action": "service.status", "params": {"unit": "x"}, "node_id": NODE, "job_id": str(uuid.uuid4()), "issued_at": now,
           "expires_at": now + 60, "nonce": "n" * 24, "epoch": bad}
    with pytest.raises(proto.Reject) as e:
        proto.check_envelope(req, now=now, node_id=NODE)
    assert e.value.code == "bad_format"


def test_stale_epoch_refusal_reaches_the_fencing_hook(enrolled, monkeypatch):
    seen = []
    monkeypatch.setattr(agentclient, "stale_epoch_hook", seen.append)
    assert _req(enrolled, 5)["status"] == "ok"
    assert _req(enrolled, 4)["code"] == "stale_epoch"
    assert seen == [5]
