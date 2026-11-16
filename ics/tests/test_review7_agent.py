"""Security review 7 (review-6 L7 / review 7 L-2): the agent's epoch mark fails CLOSED when its file is corrupt or empty, is stored twice and atomically,
and is re-seeded only by an operator with a document signed by the current controller."""
import json
import os
import sys
import time

import pytest

from ics import agentclient

AGENT_DIR = os.path.join(os.path.dirname(__file__), "..", "agent")
sys.path.insert(0, AGENT_DIR)
from ou_agent import cli, proto  # noqa: E402


def test_corrupt_or_empty_epoch_file_fails_closed_not_to_zero(tmp_path):
    p = str(tmp_path / "epoch.json")
    g = proto.EpochGate(p)
    assert g.admit(5) == 5 and os.path.exists(p) and os.path.exists(p + ".bak")
    for junk in ("", "{", '{"max_epoch": -1}', '{"max_epoch": "x"}', "null", '{"max_epoch": 5, "sum": "bad"}'):
        for f in (p, p + ".bak"):
            open(f, "w").write(junk)
        g2 = proto.EpochGate(p)
        assert g2.corrupt, junk
        for e in (None, 1, 5, 99):             # review-6 L7: epoch-less AND old-primary requests used to be accepted after a reset
            with pytest.raises(proto.Reject) as ex:
                g2.admit(e)
            assert ex.value.code == "epoch_state_corrupt"
        assert g2.max_epoch == 0 and not os.path.exists(p + ".tmp")


def test_one_good_copy_is_enough_and_heals_the_other(tmp_path):
    p = str(tmp_path / "epoch.json")
    proto.EpochGate(p).admit(7)
    open(p, "w").write("")                                    # primary destroyed, backup intact
    g = proto.EpochGate(p)
    assert not g.corrupt and g.max_epoch == 7
    assert proto._read_mark(p) == ("ok", 7)                    # healed
    os.unlink(p)
    assert proto.EpochGate(p).max_epoch == 7                   # primary missing but backup present: still 7, never 0
    with pytest.raises(proto.Reject) as ex:
        proto.EpochGate(p).admit(3)
    assert ex.value.code == "stale_epoch"


def test_no_file_at_all_is_a_node_that_never_saw_an_epoch(tmp_path):
    g = proto.EpochGate(str(tmp_path / "epoch.json"))
    assert not g.corrupt and g.admit(None) == 0


def test_reseed_needs_a_doc_signed_by_the_current_controller(tmp_path):
    state = str(tmp_path)
    ics = agentclient.Ed25519PrivateKey.generate()
    node = "11111111-1111-1111-1111-111111111111"
    json.dump({"ics_pubkey": agentclient.pub_b64(ics.public_key()), "node_id": node}, open(os.path.join(state, "trust.json"), "w"))
    p = os.path.join(state, "epoch.json")
    open(p, "w").write("")                                    # corrupt
    gate = proto.EpochGate(p)
    assert gate.corrupt

    def doc(**kw):
        body = {"v": 1, "node_id": node, "epoch": 4, "issued_at": int(time.time())}
        body.update(kw)
        fn = os.path.join(state, "doc.json")
        json.dump({"attest": body, "sig": agentclient.sign(kw.pop("_key", ics), proto.RESEED_PREFIX, body)}, open(fn, "w"))
        return fn
    other = agentclient.Ed25519PrivateKey.generate()
    body = {"v": 1, "node_id": node, "epoch": 4, "issued_at": int(time.time())}
    json.dump({"attest": body, "sig": agentclient.sign(other, proto.RESEED_PREFIX, body)}, open(os.path.join(state, "forged.json"), "w"))
    with pytest.raises(SystemExit):
        cli.reseed_epoch(state, os.path.join(state, "forged.json"))        # not the pinned ICS key
    with pytest.raises(SystemExit):
        cli.reseed_epoch(state, doc(node_id="22222222-2222-2222-2222-222222222222"))
    with pytest.raises(SystemExit):
        cli.reseed_epoch(state, doc(issued_at=int(time.time()) - 7200))    # too old
    with pytest.raises(proto.Reject):
        gate.admit(4)                                                     # still closed
    assert cli.reseed_epoch(state, doc()) == 0
    assert gate.admit(4) == 4                                             # the RUNNING gate re-reads the state: no restart needed
    with pytest.raises(proto.Reject):
        gate.admit(3)
