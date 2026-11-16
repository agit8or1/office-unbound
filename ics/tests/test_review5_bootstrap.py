"""Security review 5 bootstrap findings M1, M2, L2, L3 (callback rate limits, guest retry, NIC binding, replay stop, body cap, constant-time path)."""
import os

import pytest
from sqlalchemy import text

from ics.deploy import agentport
from ics.deploy.ports import StepFailed
from ics.guest import bootsecrets, callback
from ou_agent import firstboot
from .infra_fixtures import job, mutations, sim  # noqa: F401
from .test_guest_callback import GUEST_IP, Runner, guest, guest_post, issue, post, report, smbios_dir
from .test_lab_ssh_bootstrap import _audit_actions, _port


@pytest.fixture(autouse=True)
def _fresh_limiter(monkeypatch):
    callback.LIMITER.reset()
    monkeypatch.setattr(callback, "source_ip", lambda request, rt: request.headers.get("x-test-src", GUEST_IP))
    monkeypatch.setattr(callback, "_ics_address_towards", lambda a: "192.168.22.167")
    yield
    callback.LIMITER.reset()


def test_m1_an_unknown_id_flood_from_many_sources_cannot_starve_a_known_vm(rt, client):
    rec = issue(rt)
    codes = []
    for i in range(callback.UNKNOWN_LIMIT + 30):
        codes.append(post(client, {**report(rec), "bid": f"{i:016x}"}, src=f"10.3.{i // 250}.{i % 250 + 1}").status_code)
    assert 429 in codes                                                             # the flood itself is bounded ...
    r = post(client, report(rec))                                                   # ... but the genuine VM still gets through (was 429: one global bucket)
    assert r.status_code == 200, r.text


def test_m1_the_guest_backs_off_on_429_and_503_instead_of_failing_closed(rt, client, tmp_path):
    rec = issue(rt)
    d = smbios_dir(tmp_path, rec)
    g = guest(tmp_path, Runner())
    real = guest_post(client)
    n, sleeps = [], []

    def busy_twice(c, body):
        n.append(1)
        if len(n) <= 2:
            raise firstboot.Busy("the ICS is busy (HTTP 429)", 7)
        return real(c, body)
    conf = firstboot.bootstrap(g, d, post=busy_twice, retry_seconds=600, sleep=sleeps.append, clock=lambda: 0.0)
    assert len(n) == 3 and conf["agent_port"] == 8443 and sleeps and max(sleeps) <= 120 and sleeps[0] >= 7
    assert os.path.exists(g.p("/var/lib/ou-bootstrap/done")) and not os.path.exists(g.p("/var/lib/ou-bootstrap/failed"))


def test_m1_busy_retries_are_bounded(rt, tmp_path):
    rec = issue(rt)
    g = guest(tmp_path, Runner())
    clock = iter(range(0, 100000, 40))
    n = []

    def always_busy(c, body):
        n.append(1)
        raise firstboot.Busy("the ICS is busy (HTTP 503)")
    with pytest.raises(firstboot.Refused):
        firstboot.bootstrap(g, smbios_dir(tmp_path, rec), post=always_busy, retry_seconds=200, sleep=lambda s: None, clock=lambda: next(clock))
    assert 3 <= len(n) <= 12 and os.path.exists(g.p("/var/lib/ou-bootstrap/failed"))


def test_m1_post_pinned_turns_429_into_busy_not_into_a_final_refusal():
    src = open(firstboot.__file__).read().split("def post_pinned")[1].split("def verify_response")[0]
    assert "Busy(" in src and "429" in src and "503" in src


def test_l2_the_body_cap_is_enforced(client):
    assert client.post(callback.PATH, content=b"x" * 5000, headers={"content-type": "application/json"}).status_code == 413
    assert client.post(callback.PATH, content=b"{" + b" " * 5000 + b"}", headers={"content-type": "application/json"}).status_code == 413


def test_l3_unknown_ids_cost_the_same_work(rt, client, monkeypatch):
    rec = issue(rt)
    calls = []
    monkeypatch.setattr(callback, "_dummy_work", lambda rt_: calls.append(1))
    post(client, {**report(rec), "bid": "ff" * 8})
    assert calls == [1]
    post(client, report(rec))
    assert calls == [1]


def test_m2_a_replay_before_enrollment_stops_the_deployment(rt, client, tmp_path, monkeypatch):
    port = _port(rt, tmp_path, monkeypatch)
    port.bootstrap_config("vm1")
    rec = bootsecrets.find(rt, port.dep["id"], "vm1", 140, "callback")
    assert post(client, report(rec)).status_code == 200                              # the genuine guest
    r = post(client, report(rec, nonce="cd" * 16, tls_fingerprint_sha256="33" * 32))  # someone else with the secret
    assert r.status_code == 401
    assert bootsecrets.secrets_wiped(rt, rec.id)
    with rt.session() as db:
        assert db.execute(text("SELECT state FROM guest_bootstrap WHERE id = :i"), {"i": rec.id}).scalar() == "failed"
    assert {"guest.bootstrap_replay_alarm", "guest.bootstrap_failed_by_replay"} <= set(_audit_actions(rt))
    with pytest.raises(StepFailed):
        port.wait_enrollment("vm1", 600)                                              # enrollment is refused ...
    assert port.provider.status == "stopped" and port.provider.cfg == {}               # ... the VM is stopped and its material cleared


def test_m2_the_reporting_host_must_be_the_vms_nic(rt, client, tmp_path, monkeypatch):
    port = _port(rt, tmp_path, monkeypatch)
    port.bootstrap_config("vm1")
    rec = bootsecrets.find(rt, port.dep["id"], "vm1", 140, "callback")
    assert post(client, report(rec)).status_code == 200
    monkeypatch.setattr(agentport, "neighbour_mac", lambda a: "de:ad:be:ef:00:01")      # an impostor's hardware address answers for that IP
    with pytest.raises(StepFailed, match="hardware address"):
        port.wait_enrollment("vm1", 600)
    assert "guest.bootstrap_nic_mismatch" in _audit_actions(rt) and port.provider.status == "stopped" and port.provider.cfg == {}
    assert bootsecrets.secrets_wiped(rt, rec.id)


def test_m2_no_neighbour_entry_fails_closed(rt, client, tmp_path, monkeypatch):
    port = _port(rt, tmp_path, monkeypatch)
    port.bootstrap_config("vm1")
    rec = bootsecrets.find(rt, port.dep["id"], "vm1", 140, "callback")
    assert post(client, report(rec)).status_code == 200
    monkeypatch.setattr(agentport, "neighbour_mac", lambda a: None)
    with pytest.raises(StepFailed, match="neighbour"):
        port.wait_enrollment("vm1", 600)
    assert "guest.bootstrap_nic_unverified" in _audit_actions(rt)


def test_m2_neighbour_table_parser(tmp_path):
    from ics.guest import neigh
    f = tmp_path / "arp"
    f.write_text("IP address       HW type     Flags       HW address            Mask     Device\n"
                 "192.168.22.50    0x1         0x2         BC:24:11:44:38:7D     *        eth0\n192.168.22.51    0x1         0x0         00:00:00:00:00:00     *        eth0\n")
    assert neigh._lookup("192.168.22.50", str(f)) == "bc:24:11:44:38:7d"
    assert neigh._lookup("192.168.22.51", str(f)) is None and neigh._lookup("10.0.0.1", str(f)) is None


def test_m2_task_log_check_reports_but_never_returns_log_text():
    from ics.providers.base import TaskRef
    from ics.providers.proxmox.provider import ProxmoxProvider
    p = ProxmoxProvider.__new__(ProxmoxProvider)
    p._upid = lambda t: ("pve1", "q")
    p._task_client = lambda: None
    p._get = lambda path, client=None: [{"t": "update VM 140: -smbios1 uuid=x,serial=SECRETVALUE"}]
    t = TaskRef("pve1", "UPID:pve1:0:0:0:qmconfig:140:u@pam:", 140, "config", "d", None, None)
    assert p.task_log_mentions(t, ["SECRETVALUE"]) is True and p.task_log_mentions(t, ["other"]) is False
    assert p.task_log_mentions(TaskRef("pve1", None, 140, "config", "d", None, None), ["SECRETVALUE"]) is False
