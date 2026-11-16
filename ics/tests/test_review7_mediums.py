"""Security review 7 mediums and partials: M-1 (scoped admin cannot create an all-customers / wider account), M-2 (NIC binding re-verified at connect time),
L-4 (dedicated promotion key), L5 (/system for all-customers admins only)."""
import pytest
from sqlalchemy import text

from ics import agentclient, auth
from ics.deploy import agentport
from ics.deploy.ports import StepFailed
from ics.guest import bootsecrets, callback
from .test_guest_callback import GUEST_IP, post, report
from .test_lab_ssh_bootstrap import _audit_actions, _port
from .test_review5 import H, world  # noqa: F401
from .test_review5_bootstrap import _fresh_limiter  # noqa: F401


# ---------------------------------------------------------------------------------------------------------------------------- M-1
def test_m1_a_scoped_admin_cannot_invite_an_all_customers_account(rt, mk_user, login, world):  # noqa: F811
    adm = mk_user("scoped-admin", "admin")
    with rt.session() as db:
        db.execute(text("UPDATE users SET all_customers = false WHERE id = :u"), {"u": adm["id"]})
        db.execute(text("INSERT INTO operator_customers (user_id, customer_id) VALUES (:u, :c)"), {"u": adm["id"], "c": world["ca"]})
        db.commit()
    c, h = login(adm)
    r = c.post(f"{H}/users", json={"username": "invitee-op", "role": "operator"}, headers=h)
    assert r.status_code == 201, r.text
    with rt.session() as db:
        row = db.execute(text("SELECT id, all_customers FROM users WHERE username = 'invitee-op'")).first()
        assert row.all_customers is False                                       # was true (column default): the invitee would see EVERY customer
        scope = {str(x.customer_id) for x in db.execute(text("SELECT customer_id FROM operator_customers WHERE user_id = :u"), {"u": row.id}).all()}
        assert scope == {world["ca"]}                                           # exactly the creator's customers
        ev = db.execute(text("SELECT details FROM audit_events WHERE action = 'user.invite' AND resource_id = :i"), {"i": str(row.id)}).scalar()
        assert ev["all_customers"] is False and ev["customer_ids"] == [world["ca"]]


def test_m1_an_all_customers_admin_still_creates_all_customers_accounts_and_nobody_creates_a_wider_role(rt, mk_user, world):  # noqa: F811
    admin = mk_user("all-admin", "admin")
    op = mk_user("lowly-op", "operator")
    with rt.session() as db:
        auth.create_invite(db, rt, "from-all-admin", "operator", created_by=admin["id"], actor="t")
        assert db.execute(text("SELECT all_customers FROM users WHERE username = 'from-all-admin'")).scalar() is True
        with pytest.raises(ValueError, match="higher than your own"):
            auth.create_invite(db, rt, "wider", "admin", created_by=op["id"], actor="t")          # an account wider than the creator's own role


# ---------------------------------------------------------------------------------------------------------------------------- M-2
class MacSeq:
    """the ICS host's neighbour table as the attacker of review 7 M-2 manipulates it: the VM's MAC at first, then another one"""

    def __init__(self, *macs):
        self.macs, self.n = list(macs), 0

    def __call__(self, addr):
        m = self.macs[min(self.n, len(self.macs) - 1)]
        self.n += 1
        return m


VM_MAC = "bc:24:11:44:38:7d"          # FakeProv.guest_mac
EVIL = "de:ad:be:ef:00:01"


def test_m2_a_neighbour_entry_that_flips_before_the_connect_is_refused(rt, client, tmp_path, monkeypatch):
    port = _port(rt, tmp_path, monkeypatch)
    port.bootstrap_config("vm1")
    rec = bootsecrets.find(rt, port.dep["id"], "vm1", 140, "callback")
    assert post(client, report(rec)).status_code == 200
    seq = MacSeq(VM_MAC, EVIL)                                      # passes the first check, is re-ARPed to the attacker before the connection
    monkeypatch.setattr(agentport, "neighbour_mac", seq)
    monkeypatch.setattr(agentport.agentclient, "identity", lambda *a, **k: pytest.fail("the ICS connected although the MAC changed"))
    with pytest.raises(StepFailed, match="hardware address"):
        port.wait_enrollment("vm1", 600)
    assert seq.n >= 2 and "guest.bootstrap_nic_mismatch" in _audit_actions(rt)


@pytest.mark.parametrize("good_calls", [2, 3])      # flips before the token is sent (2) / after the agent answered the enrollment (3)
def test_m2_a_flip_between_the_probe_and_the_token_or_after_the_enrollment_is_refused(rt, client, tmp_path, monkeypatch, good_calls):
    port = _port(rt, tmp_path, monkeypatch)
    port.bootstrap_config("vm1")
    rec = bootsecrets.find(rt, port.dep["id"], "vm1", 140, "callback")
    assert post(client, report(rec, agent_key_fingerprint_sha256=agentclient.key_fingerprint(PUB))).status_code == 200
    monkeypatch.setattr(agentport, "neighbour_mac", MacSeq(*([VM_MAC] * good_calls), EVIL))
    sent = []
    monkeypatch.setattr(agentport.agentclient, "identity", lambda *a, **k: {"agent_pubkey": PUB, "enrolled": False})
    monkeypatch.setattr(agentport.agentclient, "enroll", lambda *a, **k: sent.append(1) or {"capabilities": {}, "agent_version": "1"})
    with pytest.raises(StepFailed, match="hardware address"):
        port.wait_enrollment("vm1", 600)
    with rt.session() as db:
        assert db.execute(text("SELECT count(*) FROM nodes WHERE name = :n"), {"n": port.node_name("vm1")}).scalar() == 0   # no node is recorded
    assert bool(sent) == (good_calls == 3)              # before the token left the ICS (2) / the token was spent but the node is NOT recorded (3)


def _pub():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return agentclient.pub_b64(Ed25519PrivateKey.generate().public_key())


PUB = _pub()


# ---------------------------------------------------------------------------------------------------------------------------- L-4
# ---------------------------------------------------------------------------------------------------------------------------- L5
def test_l5_system_detail_is_for_all_customers_admins_only(rt, mk_user, login, world):  # noqa: F811
    adm = mk_user("scoped-admin2", "admin")
    with rt.session() as db:
        db.execute(text("UPDATE users SET all_customers = false WHERE id = :u"), {"u": adm["id"]})
        db.execute(text("INSERT INTO operator_customers (user_id, customer_id) VALUES (:u, :c)"), {"u": adm["id"], "c": world["ca"]})
        db.commit()
    c, h = login(adm)
    assert c.get(f"{H}/system").status_code == 404
    full = mk_user("all-admin2", "admin")
    c2, h2 = login(full)
    assert c2.get(f"{H}/system").status_code == 200
