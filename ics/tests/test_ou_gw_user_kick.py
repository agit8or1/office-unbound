"""M3 regression: kick_sent is reported only when a listener (patched gromox-imap) acknowledged the USER-KICK."""
import importlib.machinery
import importlib.util
import os

P = os.path.join(os.path.dirname(__file__), "..", "agent", "deploy", "runbooks", "ou-gw-user")


def load():
    loader = importlib.machinery.SourceFileLoader("ou_gw_user", P)
    spec = importlib.util.spec_from_loader("ou_gw_user", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


def test_ack_when_patched_imap_logs_the_kick():
    m = load()
    assert m.kick_acknowledged("bob@lab", "now", timeout=1, runner=lambda: "x\nimap: USER-KICK received for bob@lab\n") is True


def test_no_ack_when_imap_is_unpatched_or_silent():
    m = load()
    assert m.kick_acknowledged("bob@lab", "now", timeout=0.3, runner=lambda: "imap: login ok for bob@lab\n") is False


def test_ack_is_per_user():
    m = load()
    assert m.kick_acknowledged("bob@lab", "now", timeout=0.3, runner=lambda: "imap: USER-KICK received for alice@lab\n") is False
