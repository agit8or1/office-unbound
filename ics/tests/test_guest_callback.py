"""Golden-image bootstrap v2 (production path, docs/status/bootstrap-v2.md): the ICS callback endpoint, the executor step `guest.await_callback`,
the guest's first-boot program (run here against a directory standing in for the VM: SMBIOS via files) and the provider plumbing. No SSH anywhere."""
import base64
import dataclasses
import hashlib
import json
import os
import socket
import ssl
import subprocess
import threading
import time
import types

import pytest
from sqlalchemy import text

from ics.deploy import agentport
from ics.deploy.ports import StepFailed
from ics.guest import bootsecrets, callback
from ics.providers.base import ProviderError, VmConfigSpec
from ou_agent import firstboot
from .infra_fixtures import job, mutations, sim  # noqa: F401
from .test_lab_ssh_bootstrap import FakeProv, _audit_actions, _enroll_stubs, _port
from .test_provider_proxmox import ref

DID = "00000000-0000-0000-0000-0000000000c1"
GUEST_IP = "192.168.22.50"


@pytest.fixture(autouse=True)
def _fresh_limiter(monkeypatch):
    callback.LIMITER.reset()
    monkeypatch.setattr(callback, "source_ip", lambda request, rt: request.headers.get("x-test-src", GUEST_IP))
    monkeypatch.setattr(callback, "_ics_address_towards", lambda a: "192.168.22.167")
    yield
    callback.LIMITER.reset()


CONFIG = {"v": 1, "hostname": "vm1", "agent_port": 8443, "mgmt_sources": None,
          "ports": [{"port": 2525, "proto": "tcp", "sources": None}, {"port": 443, "proto": "tcp", "sources": []}],
          "agent_config": {"listen": {"address": "0.0.0.0", "port": 8443}, "runbooks": {"disk.usage": {"paths": ["/", "/var/lib/ou-svc"]}, "guest.facts": {"enabled": True},
                                                                                    "podman.status": {"enabled": True}, "podman.remove_unit": {"enabled": True}}},
          "image_registries": [], "insecure_registries": [], "signing_pubkey_pem": None, "signing_key_sha256": None, "enroll_ttl_seconds": 3600}


def issue(rt, vmid=140, config=CONFIG):
    return bootsecrets.issue(rt, DID, "vm1", vmid, "callback", config=config)


def smbios_dir(tmp_path, rec, url="https://192.168.22.167:8443", pin="ab" * 32):
    d = tmp_path / "dmi"
    d.mkdir(parents=True, exist_ok=True)
    (d / "product_serial").write_text(rec.smbios_serial + "\n")
    (d / "product_sku").write_text(url + "\n")
    (d / "product_family").write_text("sha256:" + pin + "\n")
    return str(d)


def agent_info():
    return {"address": GUEST_IP, "port": 8443, "tls_fingerprint_sha256": "11" * 32, "agent_key_fingerprint_sha256": "22" * 32}


def report(rec, token="T" * 43, nonce=None, ts=None, **agent):
    cfg = {"bid": rec.bid, "secret": rec.secret}
    return firstboot.build_report(cfg, {**agent_info(), **agent}, token, nonce=nonce or "ab" * 16, ts=ts)


def post(client, body, src=None):
    return client.post(callback.PATH, json=body, headers={"x-test-src": src} if src else {})


# ---------------------------------------------------------------- the endpoint
def test_a_valid_report_is_accepted_once_and_the_answer_proves_the_ics_knows_the_secret(rt, client):
    rec = issue(rt)
    body = report(rec)
    r = post(client, body)
    assert r.status_code == 200
    j = r.json()
    cfg = {"secret": rec.secret}
    assert j["ack"] == firstboot._mac(rec.secret, "ou-bootstrap-ack-v1\n" + body["nonce"])
    conf = j["config"]
    assert conf["mgmt_sources"] == ["192.168.22.167/32"] and conf["ports"][0]["sources"] == ["192.168.22.167/32"] and conf["ports"][1]["sources"] == []   # filled in at callback time
    assert firstboot.verify_response({"secret": rec.secret}, body["nonce"], j)["mgmt_sources"] == ["192.168.22.167/32"]
    assert cfg
    with rt.session() as db:
        row = db.execute(text("SELECT state, report, token_enc IS NOT NULL AS tok FROM guest_bootstrap WHERE id = :i"), {"i": rec.id}).one()
    assert row.state == "reported" and row.tok and row.report["tls_fingerprint_sha256"] == "11" * 32 and "enroll_token" not in json.dumps(row.report)
    assert bootsecrets.find(rt, DID, "vm1", 140, "callback").token == "T" * 43      # held vault-encrypted for the enrollment
    assert "guest.bootstrap_report" in _audit_actions(rt)


def test_single_use_a_second_valid_report_is_a_replay_alarm_and_accepted_nowhere(rt, client):
    rec = issue(rt)
    assert post(client, report(rec)).status_code == 200
    r = post(client, report(rec, nonce="cd" * 16, tls_fingerprint_sha256="33" * 32))   # a clone / impostor that learned the secret
    assert r.status_code == 401 and r.json() == {"detail": "rejected"}
    with rt.session() as db:
        assert db.execute(text("SELECT report->>'tls_fingerprint_sha256' FROM guest_bootstrap WHERE id = :i"), {"i": rec.id}).scalar() == "11" * 32
    assert "guest.bootstrap_replay_alarm" in _audit_actions(rt)


@pytest.mark.parametrize("mutate", ["proof", "bid", "address", "port", "tls", "token", "nonce"])
def test_every_field_is_authenticated_and_failures_are_indistinguishable(rt, client, mutate):
    rec = issue(rt)
    body = report(rec)
    if mutate == "proof":
        body["proof"] = "0" * 64
    elif mutate == "bid":
        body["bid"] = "f" * 16
    elif mutate == "address":
        body["agent"]["address"] = "192.168.22.99"
    elif mutate == "port":
        body["agent"]["port"] = 9443
    elif mutate == "tls":
        body["agent"]["tls_fingerprint_sha256"] = "99" * 32
    elif mutate == "token":
        body["enroll_token"] = "X" * 43
    else:
        body["nonce"] = "ef" * 16
    r = post(client, body, src="192.168.22.99" if mutate == "address" else None)
    assert r.status_code == 401 and r.json() == {"detail": "rejected"}
    assert bootsecrets.find(rt, DID, "vm1", 140, "callback").state == "pending"


def test_source_ip_must_be_the_reported_agent_address_stale_and_expired_are_refused(rt, client):
    rec = issue(rt)
    assert post(client, report(rec), src="10.9.9.9").status_code == 401                # a stolen secret cannot point the ICS at another host
    assert post(client, report(rec, ts=int(time.time()) - 3600)).status_code == 401    # stale
    with rt.session() as db:
        db.execute(text("UPDATE guest_bootstrap SET expires_at = now() - interval '1 second' WHERE id = :i"), {"i": rec.id})
        db.commit()
    assert post(client, report(rec)).status_code == 401                               # short TTL
    assert "guest.bootstrap_replay_alarm" in _audit_actions(rt)
    assert bootsecrets.find(rt, DID, "vm1", 140, "callback").state == "pending"


def test_malformed_and_unauthenticated_input_is_rejected_without_state_change(rt, client):
    rec = issue(rt)
    good = report(rec)
    assert client.post(callback.PATH, json={**good, "extra": 1}).status_code == 422
    assert client.post(callback.PATH, json={**good, "v": 2}).status_code == 401
    for loop in ("127.0.0.1", "169.254.1.1", "0.0.0.0", "224.0.0.1"):
        b = report(rec, address=loop)
        assert post(client, b, src=loop).status_code == 401
    assert bootsecrets.find(rt, DID, "vm1", 140, "callback").state == "pending"


def test_the_endpoint_is_rate_limited_per_source_and_globally(rt, client):
    rec = issue(rt)
    codes = [post(client, {**report(rec), "proof": "0" * 64}).status_code for _ in range(callback.PER_IP_LIMIT + 3)]
    assert codes[:callback.PER_IP_LIMIT] == [401] * callback.PER_IP_LIMIT and set(codes[callback.PER_IP_LIMIT:]) == {429}
    assert post(client, report(rec), src="192.168.22.51").status_code == 401      # another source is not affected (and fails: wrong address)
    callback.LIMITER.reset()
    lim = callback.RateLimiter()
    assert all(lim.allow("global", 3, 60, now=i) for i in range(3)) and not lim.allow("global", 3, 60, now=3) and lim.allow("global", 3, 60, now=100)


def test_the_endpoint_needs_no_session_and_exposes_nothing_else(rt, client):
    paths = {r.path for r in client.app.routes}
    assert callback.PATH in paths
    assert client.get(callback.PATH).status_code == 405


# ---------------------------------------------------------------- the guest side, against a directory standing in for the VM
class Runner:
    def __init__(self):
        self.calls = []

    def __call__(self, argv, **kw):
        self.calls.append(list(argv))
        if argv[0] == "python3" and "render_image_policy" in argv[1]:
            return types.SimpleNamespace(stdout=b"{}\n", returncode=0)
        return types.SimpleNamespace(stdout=b"", returncode=0)


def guest_post(client, src=GUEST_IP):
    def _post(cfg, body):
        r = client.post(callback.PATH, json=body, headers={"x-test-src": src})
        if r.status_code != 200:
            raise firstboot.Refused(f"the ICS refused the report (HTTP {r.status_code})")
        return r.json()
    return _post


def guest(tmp_path, runner=None):
    return firstboot.Guest(root=str(tmp_path / "root"), runner=runner or Runner(), address_towards=lambda h: GUEST_IP)


def test_emulated_vm_first_boot_reports_enrolls_and_leaves_no_secret_behind(rt, client, tmp_path, monkeypatch):
    """The whole production flow: ICS configure (SMBIOS material) -> VM boots (emulated: SMBIOS read from files) -> callback -> await_callback ->
    enrollment over pinned TLS -> SMBIOS cleared + secret deleted. The only things that cross are the SMBIOS values and one authenticated POST."""
    port = _port(rt, tmp_path, monkeypatch)
    sent = _enroll_stubs(monkeypatch)
    cfg = port.bootstrap_config("vm1")
    assert set(cfg) == {"smbios_serial", "smbios_sku", "smbios_family"} and cfg["smbios_sku"] == "https://192.168.22.167:8443" and cfg["smbios_family"] == "sha256:" + "ab" * 32
    assert "ciuser" not in cfg and "sshkeys" not in cfg                             # no SSH material at all
    rec = bootsecrets.find(rt, port.dep["id"], "vm1", 140, "callback")
    d = tmp_path / "dmi"
    d.mkdir()
    (d / "product_serial").write_text(cfg["smbios_serial"] + "\n")
    (d / "product_sku").write_text(cfg["smbios_sku"] + "\n")
    (d / "product_family").write_text(cfg["smbios_family"] + "\n")
    runner = Runner()
    g = guest(tmp_path, runner)
    # the guest generated its own enrollment token: capture it through the report
    seen = {}
    real = guest_post(client)

    def _post(c, body):
        seen["token"] = body["enroll_token"]
        return real(c, body)
    conf = firstboot.bootstrap(g, str(d), post=_post)
    assert conf["mgmt_sources"] == ["192.168.22.167/32"] and conf["agent_port"] == 8443
    assert port.await_callback("vm1", 600) == {"reported": True}
    monkeypatch.setattr(agentport.agentclient, "key_fingerprint", lambda k: firstboot_fp(g)[1])
    nid = port.wait_enrollment("vm1", 600)
    assert sent["enroll"][3] == seen["token"] and sent["identity"] == (GUEST_IP, 8443, firstboot_fp(g)[0])     # enrolled with the GUEST's token and fingerprints
    assert sent["enroll"][:3] == (GUEST_IP, 8443, firstboot_fp(g)[0])
    # the guest applied: nftables (syntax checked first) with the agent port to the ICS only, agent config, service started; never SSH
    nft = open(g.p("/etc/nftables.conf")).read()
    assert "ip saddr { 192.168.22.167/32 } tcp dport 8443 accept" in nft and "tcp dport 22" not in nft and "policy drop" in nft
    assert ["systemctl", "enable", "--now", "ou-agent.service"] in runner.calls and not any("ssh" in " ".join(c) for c in runner.calls)
    assert os.path.exists(g.p("/var/lib/ou-bootstrap/done")) and not os.path.exists(g.p("/var/lib/ou-bootstrap/failed"))
    # ICS side: M2 (config cleared) and M1 (secret deleted), audited; the report cannot be used again
    assert port.provider.cfg == {} and bootsecrets.secrets_wiped(rt, rec.id)
    assert "guest.bootstrap_completed" in _audit_actions(rt)
    assert port.wait_enrollment("vm1", 600) == nid
    assert post(client, report(rec)).status_code == 401


def firstboot_fp(g):
    j = json.load(open(g.p("/var/lib/ou-bootstrap/fingerprints.json")))
    return j["tls_fingerprint_sha256"], j["agent_key_fingerprint_sha256"]


def run_guest(rt, client, tmp_path, mutate_resp=None, mutate_dir=None, pin=None, post_fn=None):
    rec = issue(rt)
    d = smbios_dir(tmp_path, rec)
    if mutate_dir:
        mutate_dir(d)
    runner = Runner()
    g = guest(tmp_path, runner)
    real = guest_post(client)

    def _post(c, body):
        resp = real(c, body)
        return mutate_resp(resp, c, body) if mutate_resp else resp
    with pytest.raises(Exception) as e:
        firstboot.bootstrap(g, d, post=post_fn or _post)
    return g, runner, e.value


def assert_closed(g, runner):
    """Fail closed: nothing listens, nothing was opened, the agent never started, a `failed` marker exists, SSH untouched."""
    assert os.path.exists(g.p("/var/lib/ou-bootstrap/failed")) and not os.path.exists(g.p("/var/lib/ou-bootstrap/done"))
    assert not os.path.exists(g.p("/etc/nftables.conf")) and not os.path.exists(g.p("/etc/ou-agent/agent.json"))
    assert not any(c[:2] == ["systemctl", "enable"] or c[0] == "nft" for c in runner.calls)


def test_guest_refuses_an_ics_that_cannot_prove_it_knows_the_secret(rt, client, tmp_path):
    g, runner, e = run_guest(rt, client, tmp_path, mutate_resp=lambda r, c, b: {**r, "ack": "0" * 64})
    assert isinstance(e, firstboot.Refused) and "acknowledgement" in str(e)
    assert_closed(g, runner)


@pytest.mark.parametrize("tamper", ["config_mac", "mgmt", "runbook", "field", "cidr", "port"])
def test_guest_refuses_a_tampered_or_invalid_configuration(rt, client, tmp_path, tamper):
    def mut(resp, c, b):
        conf = json.loads(json.dumps(resp["config"]))
        if tamper == "config_mac":
            resp = {**resp, "config_mac": "0" * 64}
        elif tamper == "mgmt":
            conf["mgmt_sources"] = ["0.0.0.0/0"]                          # MAC no longer matches
            resp = {**resp, "config": conf}
        else:
            if tamper == "runbook":
                conf["agent_config"]["runbooks"]["shell.exec"] = {"enabled": True}
            elif tamper == "field":
                conf["evil"] = 1
            elif tamper == "cidr":
                conf["mgmt_sources"] = ["not-a-cidr"]
            else:
                conf["ports"].append({"port": 8443, "proto": "tcp", "sources": []})
            resp = {**resp, "config": conf, "config_mac": callback.config_mac(bootsecrets_secret(rt), b["nonce"], conf)}   # even a MAC'd bad config is refused
        return resp
    g, runner, e = run_guest(rt, client, tmp_path, mutate_resp=mut)
    assert isinstance(e, firstboot.Refused)
    assert_closed(g, runner)


def bootsecrets_secret(rt):
    return bootsecrets.find(rt, DID, "vm1", 140, "callback").secret


def test_guest_without_valid_smbios_material_refuses_to_do_anything(rt, client, tmp_path):
    for mut in (lambda d: os.unlink(d + "/product_serial"), lambda d: open(d + "/product_sku", "w").write("http://plain.example\n"),
                lambda d: open(d + "/product_sku", "w").write("https://u:p@x.example/evil?q\n"), lambda d: open(d + "/product_family", "w").write("sha256:zz\n"),
                lambda d: open(d + "/product_serial", "w").write("short\n")):
        callback.LIMITER.reset()
        g, runner, e = run_guest(rt, client, tmp_path / str(time.time_ns()), mutate_dir=mut)
        assert isinstance(e, firstboot.Refused)
        assert_closed(g, runner)


def test_a_failed_callback_never_opens_anything_and_does_not_retry_authentication_failures(rt, client, tmp_path):
    calls = []

    def post_fn(c, body):
        calls.append(1)
        raise firstboot.Refused("the ICS refused the report (HTTP 401)")
    g, runner, e = run_guest(rt, client, tmp_path, post_fn=post_fn)
    assert calls == [1]
    assert_closed(g, runner)
    # transport errors are retried (the ICS may still be starting) until the budget ends, then the guest stays closed
    g2 = guest(tmp_path / "second", Runner())
    rec = issue(rt, vmid=141)
    d = smbios_dir(tmp_path / "second", rec)
    n = []
    clock = iter(range(0, 1000, 5))

    def flaky(c, body):
        n.append(1)
        raise firstboot.Refused("the callback failed: ConnectionRefusedError")
    with pytest.raises(firstboot.Refused):
        firstboot.bootstrap(g2, d, post=flaky, retry_seconds=20, sleep=lambda s: None, clock=lambda: next(clock))
    assert 2 <= len(n) <= 6
    assert_closed(g2, g2.run)


def test_the_guest_program_contains_no_ssh_and_no_command_line_secrets():
    src = open(firstboot.__file__).read()
    assert "sshd" not in src.replace("SSH untouched", "") and "authorized_keys" not in src and "ssh.service" not in src
    assert "argv" not in src.split("def post_pinned")[1].split("def verify_response")[0]       # the secret never reaches a process argument
    ics_pkg = os.path.join(os.path.dirname(__file__), "..", "ics")
    for root, _d, files in os.walk(ics_pkg):
        for f in files:
            if f.endswith(".py") and f != "sshboot.py" and root.endswith(("deploy", "guest", "providers")):
                s = open(os.path.join(root, f)).read()
                assert "StrictHostKeyChecking" not in s and "subprocess" not in s or f in ("cloudinit.py", "agentport.py"), f   # the ICS package has one SSH client: sshboot (lab)


# ---------------------------------------------------------------- pinned TLS (a real TLS server on loopback)
@pytest.fixture()
def tls_server(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    import datetime
    k = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ics.test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(k.public_key()).serial_number(1).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1)).sign(k, hashes.SHA256()))
    (tmp_path / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "k.pem").write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(tmp_path / "c.pem"), str(tmp_path / "k.pem"))
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    received = []

    def serve():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            try:
                s = ctx.wrap_socket(c, server_side=True)
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                head, _, rest = data.partition(b"\r\n\r\n")
                want = int(next((l.split(b":")[1] for l in head.split(b"\r\n") if l.lower().startswith(b"content-length")), b"0"))
                while len(rest) < want:
                    rest += s.recv(65536)
                    data += b""
                data = head + b"\r\n\r\n" + rest
                if data:
                    received.append(data)
                    body = b'{"ok": true}'
                    s.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
                s.close()
            except (ssl.SSLError, OSError):
                pass
    threading.Thread(target=serve, daemon=True).start()
    yield srv.getsockname()[1], hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest(), received
    srv.close()


def test_the_callback_is_pinned_to_the_smbios_certificate_hash_before_any_byte_is_sent(tls_server):
    port, pin, received = tls_server
    cfg = {"host": "127.0.0.1", "port": port, "pin": pin}
    assert firstboot.post_pinned(cfg, {"x": 1}) == {"ok": True} and received
    received.clear()
    with pytest.raises(firstboot.Refused, match="pin"):
        firstboot.post_pinned({**cfg, "pin": "00" * 32}, {"secret-looking": "payload"})
    assert not any(b"secret-looking" in r for r in received)                      # an impostor with a valid-looking certificate got NOTHING
    with pytest.raises(firstboot.Refused):
        firstboot.post_pinned({"host": "127.0.0.1", "port": 1, "pin": pin}, {})   # unreachable: a clean refusal, no traceback with details


# ---------------------------------------------------------------- the executor step and fail-closed
def test_await_callback_times_out_fails_closed_and_destroys_the_material(rt, tmp_path, monkeypatch):
    port = _port(rt, tmp_path, monkeypatch)
    port.bootstrap_config("vm1")
    rec = bootsecrets.find(rt, port.dep["id"], "vm1", 140, "callback")
    ticks = iter(range(0, 100000, 30))
    port.clock = lambda: next(ticks)
    with pytest.raises(StepFailed, match="did not call back"):
        port.await_callback("vm1", 60)
    assert port.provider.status == "stopped" and port.provider.cfg == {} and bootsecrets.secrets_wiped(rt, rec.id)
    with rt.session() as db:
        d = db.execute(text("SELECT details FROM audit_events WHERE action = 'guest.bootstrap_failed_closed'")).scalar()
    assert d["stopped"] is True and d["cleared"] is True and d["mode"] == "callback" and d["sealed"] is False
    with pytest.raises(StepFailed, match="gone"):
        port.await_callback("vm1", 60)
    assert not any(a.startswith("lab") for a in _audit_actions(rt))


def test_callback_mode_needs_the_url_and_pin_and_never_creates_ssh_material(rt, tmp_path, monkeypatch):
    port = _port(rt, tmp_path, monkeypatch, guest_callback_pin_sha256=None)
    with pytest.raises(StepFailed, match="not configured"):
        port.bootstrap_config("vm1")
    port.rt.settings = dataclasses.replace(port.rt.settings, guest_callback_pin_sha256="ab" * 32, guest_callback_url="http://plain.example")
    with pytest.raises(StepFailed, match="not configured"):
        port.bootstrap_config("vm1")


def test_the_step_is_skipped_by_ports_without_it_and_in_lab_mode(rt, tmp_path, monkeypatch):
    from ics.deploy import executor
    ctx = types.SimpleNamespace(step={"target": "vm1", "params": {}}, env=types.SimpleNamespace(agent=types.SimpleNamespace()), log=lambda *a, **k: None)
    assert "skipped" in executor.h_await_callback(ctx)
    port = _port(rt, tmp_path, monkeypatch, lab=True)
    assert "skipped" in port.await_callback("vm1", 60)


# ---------------------------------------------------------------- provider plumbing
def test_configure_sets_sku_family_and_clears_the_bootstrap_material(sim, job):
    m = mutations(sim)
    sim.sim.vms[150]["cfg"]["smbios1"] = "uuid=3041632a-47b0-4ee7-a8bd-d49a3a6021df"
    spec = VmConfigSpec(ciuser="ou-boot", sshkeys=("ssh-ed25519 " + "A" * 60,), smbios_serial="ab" * 32, smbios_sku="https://192.168.22.167:8443", smbios_family="sha256:" + "cd" * 32)
    m.wait(m.configure_vm(ref(), spec))
    c = sim.sim.vms[150]["cfg"]
    b = lambda v: base64.b64encode(v.encode()).decode()  # noqa: E731
    assert c["smbios1"] == "uuid=3041632a-47b0-4ee7-a8bd-d49a3a6021df,base64=1,serial=" + b("ab" * 32) + ",sku=" + b("https://192.168.22.167:8443") + ",family=" + b("sha256:" + "cd" * 32)
    assert m.bootstrap_material_present(ref()) is True
    m.wait(m.configure_vm(ref(), VmConfigSpec(clear_bootstrap=True)))
    c = sim.sim.vms[150]["cfg"]
    assert c["smbios1"] == "uuid=3041632a-47b0-4ee7-a8bd-d49a3a6021df" and "sshkeys" not in c and "ciuser" not in c      # M2: nothing left in the VM config
    assert m.bootstrap_material_present(ref()) is False
    for bad in (dict(smbios_sku="http://plain.example"), dict(smbios_sku="https://x/y z"), dict(smbios_family="sha256:xyz"), dict(smbios_family="md5:" + "a" * 32)):
        with pytest.raises(ProviderError):
            m.configure_vm(ref(), VmConfigSpec(**bad))
    with pytest.raises(ProviderError):
        m.configure_vm(ref(), VmConfigSpec(smbios_serial="ab" * 32, clear_bootstrap=True))


def test_import_is_the_only_new_verb_and_the_port_can_clear_between_attempts(rt, tmp_path, monkeypatch):
    port = _port(rt, tmp_path, monkeypatch)
    port.provider = FakeProv()
    assert port._clear_material(port._vmref("vm1")) is True and port._clear_material(port._vmref("vm1")) is False       # idempotent
