"""Node agent: Ed25519 signing, replay protection, allowlist, argv-only execution, enrollment, polkit rendering; ICS <-> agent interop."""
import json
import os
import subprocess
import sys
import time
import uuid
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ics import agentclient

NODE = str(uuid.uuid4())


@pytest.fixture()
def enrolled(fake_agent):
    """An agent enrolled by an ICS key (via the real HTTPS enrollment path). Returns (fake_agent, ics_priv, node)."""
    priv = Ed25519PrivateKey.generate()
    ident = agentclient.identity("127.0.0.1", fake_agent.port, fake_agent.tls_fp, allow_loopback=True)
    assert ident["enrolled"] is False
    agentclient.enroll("127.0.0.1", fake_agent.port, fake_agent.tls_fp, token=fake_agent.token, ics_pubkey_b64=agentclient.pub_b64(priv.public_key()),
                       node_id=NODE, expect_agent_pubkey_b64=ident["agent_pubkey"], allow_loopback=True)
    node = SimpleNamespace(id=NODE, address="127.0.0.1", port=fake_agent.port, tls_fingerprint_sha256=fake_agent.tls_fp,
                           agent_pubkey=ident["agent_pubkey"])
    return fake_agent, priv, node


def call(enrolled, action="service.restart", params=None, **kw):
    fa, priv, node = enrolled
    return agentclient.call(node, priv, action=action, params={"unit": "gromox-imap"} if params is None else params, job_id=kw.pop("job_id", str(uuid.uuid4())),
                            allow_loopback=True, **kw)[1]


def test_enrollment_is_single_use_and_pins(fake_agent):
    priv = Ed25519PrivateKey.generate()
    pub = agentclient.pub_b64(priv.public_key())
    ident = agentclient.identity("127.0.0.1", fake_agent.port, fake_agent.tls_fp, allow_loopback=True)
    assert agentclient.key_fingerprint(ident["agent_pubkey"]) == fake_agent.key_fp
    with pytest.raises(agentclient.AgentError, match="untrusted|unreachable"):  # wrong TLS pin: nothing is sent
        agentclient.identity("127.0.0.1", fake_agent.port, "ab" * 32, allow_loopback=True)
    with pytest.raises(agentclient.AgentError, match="refused"):  # wrong token
        agentclient.enroll("127.0.0.1", fake_agent.port, fake_agent.tls_fp, token="x" * 43, ics_pubkey_b64=pub, node_id=NODE,
                           expect_agent_pubkey_b64=ident["agent_pubkey"], allow_loopback=True)
    agentclient.enroll("127.0.0.1", fake_agent.port, fake_agent.tls_fp, token=fake_agent.token, ics_pubkey_b64=pub, node_id=NODE,
                       expect_agent_pubkey_b64=ident["agent_pubkey"], allow_loopback=True)
    with pytest.raises(agentclient.AgentError, match="refused"):  # token consumed; agent now enrolled
        agentclient.enroll("127.0.0.1", fake_agent.port, fake_agent.tls_fp, token=fake_agent.token, ics_pubkey_b64=pub, node_id=NODE,
                           expect_agent_pubkey_b64=ident["agent_pubkey"], allow_loopback=True)
    assert not os.path.exists(os.path.join(fake_agent.state, "enroll.json"))


def test_enrollment_token_burns_after_repeated_failures(fake_agent):
    priv = Ed25519PrivateKey.generate()
    ident = agentclient.identity("127.0.0.1", fake_agent.port, fake_agent.tls_fp, allow_loopback=True)
    for _ in range(5):
        with pytest.raises(agentclient.AgentError):
            agentclient.enroll("127.0.0.1", fake_agent.port, fake_agent.tls_fp, token="y" * 43, ics_pubkey_b64=agentclient.pub_b64(priv.public_key()),
                               node_id=NODE, expect_agent_pubkey_b64=ident["agent_pubkey"], allow_loopback=True)
    with pytest.raises(agentclient.AgentError, match="refused"):  # even the right token no longer works
        agentclient.enroll("127.0.0.1", fake_agent.port, fake_agent.tls_fp, token=fake_agent.token,
                           ics_pubkey_b64=agentclient.pub_b64(priv.public_key()), node_id=NODE,
                           expect_agent_pubkey_b64=ident["agent_pubkey"], allow_loopback=True)


def test_unenrolled_agent_executes_nothing(fake_agent):
    code, d = agentclient._post("127.0.0.1", fake_agent.port, fake_agent.tls_fp, "/v1/exec", {"req": {}, "sig": "AAAA"},
                                allow_loopback=True, deadline=5)
    assert code == 403 and d["resp"]["code"] == "not_enrolled" and fake_agent.calls() == []


def test_signed_restart_runs_systemctl_with_argv_only(enrolled):
    fa = enrolled[0]
    r = call(enrolled)
    assert r["status"] == "ok" and r["result"]["unit"] == "gromox-imap" and r["result"]["active_state"] == "active"
    first = fa.calls()[0]
    assert first == "--no-ask-password restart gromox-imap.service"  # exact argv, no shell


def test_replayed_request_is_rejected(enrolled):
    fa, priv, node = enrolled
    body = agentclient.build_request(priv, action="service.restart", params={"unit": "nginx"}, node_id=NODE, job_id=str(uuid.uuid4()))
    ok = agentclient.call(node, priv, action="", params={}, job_id="", req_override=body, allow_loopback=True)[1]
    assert ok["status"] == "ok"
    n = len(fa.calls())
    rep = agentclient.call(node, priv, action="", params={}, job_id="", req_override=body, allow_loopback=True)[1]  # identical bytes again
    assert rep["status"] == "rejected" and rep["code"] == "replay_nonce"
    assert len(fa.calls()) == n  # nothing executed the second time


def test_job_id_is_single_use_even_with_fresh_nonce(enrolled):
    jid = str(uuid.uuid4())
    assert call(enrolled, job_id=jid)["status"] == "ok"
    r = call(enrolled, job_id=jid)
    assert r["status"] == "rejected" and r["code"] == "replay_job"


def test_replay_survives_agent_restart(enrolled, tmp_path):
    from ou_agent import server
    fa, priv, node = enrolled
    body = agentclient.build_request(priv, action="service.status", params={"unit": "nginx"}, node_id=NODE, job_id=str(uuid.uuid4()))
    assert agentclient.call(node, priv, action="", params={}, job_id="", req_override=body, allow_loopback=True)[1]["status"] == "ok"
    fresh = server.Agent(fa.cfg, fa.state)  # new process state, same journal directory
    code, resp = fresh.exec(body)
    assert code == 403 and resp["resp"]["code"] == "replay_nonce"


@pytest.mark.parametrize("delta,window,code", [(-200, 60, "expired"), (500, 60, "not_yet_valid"), (0, 600, "window_too_long")])
def test_expired_future_and_long_window_requests_rejected(enrolled, delta, window, code):
    fa, priv, node = enrolled
    body = agentclient.build_request(priv, action="service.restart", params={"unit": "nginx"}, node_id=NODE, job_id=str(uuid.uuid4()),
                                     now=int(time.time()) + delta, ttl=window)
    r = agentclient.call(node, priv, action="", params={}, job_id="", req_override=body, allow_loopback=True)[1]
    assert r["status"] == "rejected" and r["code"] == code
    assert fa.calls() == []


@pytest.mark.parametrize("action,params,code", [
    ("service.restart", {"unit": "sshd"}, "not_allowed"),
    ("service.restart", {"unit": "nginx.service"}, "not_allowed"),           # must match exactly
    ("service.restart", {"unit": "nginx;id"}, "not_allowed"),
    ("service.restart", {"unit": "../../etc/passwd"}, "not_allowed"),
    ("service.restart", {"unit": "nginx", "extra": "--now"}, "bad_params"),
    ("service.restart", {}, "bad_params"),
    ("service.stop", {"unit": "nginx"}, "not_allowed"),                        # not in the closed runbook list
    ("shell.exec", {"cmd": "id"}, "not_allowed"),
    ("disk.usage", {"path": "/etc"}, "not_allowed"),
    ("disk.usage", {"unit": "nginx"}, "bad_params"),
])
def test_non_allowlisted_requests_rejected_by_agent(enrolled, action, params, code):
    fa = enrolled[0]
    r = call(enrolled, action, params)
    assert r["status"] == "rejected" and r["code"] == code, r
    assert fa.calls() == []


def test_tampered_or_foreign_signature_rejected(enrolled):
    fa, priv, node = enrolled
    body = agentclient.build_request(priv, action="service.status", params={"unit": "nginx"}, node_id=NODE, job_id=str(uuid.uuid4()))
    body["req"]["params"]["unit"] = "mariadb"   # tamper after signing
    r = agentclient.call(node, priv, action="", params={}, job_id="", req_override=body, allow_loopback=True)[1]
    assert r["code"] == "bad_signature"
    other = Ed25519PrivateKey.generate()        # signed by a key the agent never enrolled
    r = agentclient.call(node, other, action="service.status", params={"unit": "nginx"}, job_id=str(uuid.uuid4()), allow_loopback=True)[1]
    assert r["code"] == "bad_signature" and fa.calls() == []


def test_request_for_another_node_rejected(enrolled):
    fa, priv, node = enrolled
    body = agentclient.build_request(priv, action="service.status", params={"unit": "nginx"}, node_id=str(uuid.uuid4()), job_id=str(uuid.uuid4()))
    r = agentclient.call(node, priv, action="", params={}, job_id="", req_override=body, allow_loopback=True)
    assert r[1]["code"] == "wrong_node"


def test_unknown_envelope_fields_and_floats_rejected(enrolled):
    fa, priv, node = enrolled
    from ou_agent import proto
    req = agentclient.build_request(priv, action="service.status", params={"unit": "nginx"}, node_id=NODE, job_id=str(uuid.uuid4()))["req"]
    req["extra"] = 1
    body = {"req": req, "sig": agentclient.sign(priv, agentclient.REQ_PREFIX, req)}
    assert agentclient.call(node, priv, action="", params={}, job_id="", req_override=body, allow_loopback=True)[1]["code"] == "bad_format"
    req = agentclient.build_request(priv, action="disk.usage", params={"path": "/"}, node_id=NODE, job_id=str(uuid.uuid4()))["req"]
    req["params"] = {"path": "/", "x": 1.5}
    with pytest.raises(ValueError):
        agentclient.sign(priv, agentclient.REQ_PREFIX, {"x": float("nan")})
    with pytest.raises(proto.Reject):
        proto.check_envelope({**req, "params": {"a": 1.5}}, now=req["issued_at"], node_id=NODE)


def test_ics_rejects_forged_or_mismatched_responses(enrolled):
    """A man in the middle without the agent key cannot fake success: signature, nonce, job id and node id are all checked."""
    fa, priv, node = enrolled
    forged = SimpleNamespace(**{**node.__dict__, "agent_pubkey": agentclient.pub_b64(Ed25519PrivateKey.generate().public_key())})
    with pytest.raises(agentclient.AgentError, match="signature invalid"):
        agentclient.call(forged, priv, action="service.status", params={"unit": "nginx"}, job_id=str(uuid.uuid4()), allow_loopback=True)


def test_service_status_and_disk_usage(enrolled):
    r = call(enrolled, "service.status", {"unit": "gromox-imap"})
    assert r["status"] == "ok" and r["result"]["active_state"] == "active"
    d = call(enrolled, "disk.usage", {"path": "/"})
    assert d["status"] == "ok" and 0 <= d["result"]["used_percent"] <= 100 and d["result"]["total_bytes"] > 0


def test_config_must_be_root_owned_and_not_writable(tmp_path):
    from ou_agent import server
    p = tmp_path / "agent.json"
    p.write_text(json.dumps({"listen": {"address": "127.0.0.1", "port": 1}, "runbooks": {"service.restart": {"units": ["nginx"]}}}))
    if os.getuid() != 0:
        with pytest.raises(SystemExit, match="owned by root"):
            server.load_config(str(p))
    with pytest.raises(ValueError):
        from ou_agent import runbooks
        runbooks.validate_config({"runbooks": {"service.restart": {"units": ["a b"]}}})
    with pytest.raises(ValueError):
        from ou_agent import runbooks
        runbooks.validate_config({"runbooks": {"shell.exec": {}}})


def test_polkit_rule_allows_only_listed_units_for_restart(tmp_path):
    cfg = tmp_path / "a.json"
    cfg.write_text(json.dumps({"runbooks": {"service.restart": {"units": ["gromox-imap", "nginx"]}, "service.status": {"units": ["sshd"]}}}))
    script = os.path.join(os.path.dirname(__file__), "..", "agent", "deploy", "render_polkit.py")
    out = subprocess.run([sys.executable, script, str(cfg)], capture_output=True, text=True, check=True).stdout
    assert '["gromox-imap.service", "nginx.service"]' in out and "sshd" not in out   # status needs no privilege, so it is not granted
    assert 'subject.user != "ou-agent"' in out and "polkit.Result.NO" in out and 'verb") == "restart"' in out
    bad = tmp_path / "b.json"
    bad.write_text(json.dumps({"runbooks": {"service.restart": {"units": ["x\"; evil"]}}}))
    assert subprocess.run([sys.executable, script, str(bad)], capture_output=True).returncode != 0


def test_agent_unit_and_installer_are_hardened():
    d = os.path.join(os.path.dirname(__file__), "..", "agent", "deploy")
    unit = open(os.path.join(d, "ou-agent.service")).read()
    for s in ("User=ou-agent", "NoNewPrivileges=true", "ProtectSystem=strict", "CapabilityBoundingSet=", "MemoryDenyWriteExecute=true"):
        assert s in unit
    assert "User=root" not in unit
    src = "".join(open(os.path.join(os.path.dirname(__file__), "..", "agent", "ou_agent", f)).read() for f in ("runbooks.py", "server.py"))
    assert "shell=True" not in src and "os.system" not in src and "sudo" not in src


def test_idle_tcp_connection_does_not_block_agent(fake_agent):
    """Review H1: one idle connection (no TLS ClientHello) must not stall other requests."""
    import socket, time as _t
    idle = [socket.create_connection(("127.0.0.1", fake_agent.port), timeout=5) for _ in range(3)]
    try:
        t0 = _t.monotonic()
        ident = agentclient.identity("127.0.0.1", fake_agent.port, fake_agent.tls_fp, allow_loopback=True)
        assert ident["agent_pubkey"] and _t.monotonic() - t0 < 3.0
    finally:
        for s in idle:
            s.close()


def test_agent_handshake_deadline_closes_silent_connection(fake_agent, monkeypatch):
    """A silent client is disconnected after the handshake deadline instead of holding a thread forever."""
    import socket, time as _t
    from ou_agent import server as srvmod
    monkeypatch.setattr(srvmod._Server, "handshake_timeout", 1.0)
    s = socket.create_connection(("127.0.0.1", fake_agent.port), timeout=10)
    try:
        t0 = _t.monotonic()
        s.settimeout(10)
        data = s.recv(1)          # server closes (b"") once its handshake deadline passes
        assert data == b"" and _t.monotonic() - t0 < 12.0
    finally:
        s.close()
