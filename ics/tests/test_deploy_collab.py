"""Collaboration components (chat, meetings, telephony): catalog validation, placement/capacity, unpinned-artifact refusal, opt-in ports,
and the two new check runners (SIP OPTIONS over TLS, Jitsi XMPP token enforcement) against local fake servers."""
import re
import socket
import ssl
import threading

import pytest

from ics import checks
from ics.deploy.catalog import CatalogError, build_catalog, load_catalog
from ics.deploy.plan import generate_plan
from tests.test_deploy_plan import cap, codes, inp, pinned

COLLAB = ("chat", "meetings", "telephony")


def test_catalog_declares_collab_components_with_evidence():
    c = load_catalog()
    for n in COLLAB:
        comp = c.components[n]
        assert comp.depends_on == ["identity"]
        assert comp.backup.method in ("online_dump", "stateless", "config_tar")
        for f in (comp.resources.cores, comp.resources.memory_mb, comp.resources.disk_gb):
            assert f.source
    assert "collaboration-lab-results.md" in c.components["chat"].resources.memory_mb.source
    assert "telephony-productization.md" in c.components["telephony"].resources.memory_mb.source
    # packages are exact pins from the signed repo; everything unbuilt is an explicit unpinned OCI placeholder
    ast = next(a for a in c.components["telephony"].artifacts if a.name == "asterisk")
    assert ast.kind == "package" and ast.version == "22.12.0-ou1" and ast.repo == "ob-apt-dev"
    for n in COLLAB:
        assert c.components[n].unpinned, n
        for a in c.components[n].artifacts:
            if a.kind == "oci":
                assert a.digest == "sha256:"      # never an invented digest
    kinds = {h.kind for n in COLLAB for h in c.components[n].health_checks}
    assert {"http", "jitsi_jwt", "sip_options_tls"} <= kinds
    assert any(h.body_contains == "m.login.sso" for h in c.components["chat"].health_checks)
    fed = next(p for p in c.components["chat"].ports if p.name == "federation")
    assert fed.port == 8448 and fed.default_enabled is False
    rtp = next(p for p in c.components["telephony"].ports if p.name == "rtp")
    assert (rtp.port, rtp.last, rtp.proto) == (10000, 10200, "udp")
    assert not any(p.port in (5060, 5061) and p.name == "pstn" for p in c.components["telephony"].ports)   # no trunk port


def test_catalog_rejects_bad_port_range_and_body_contains(tmp_path):
    import shutil
    d = tmp_path / "cat"
    shutil.copytree(load_catalog.__globals__["default_dir"](), d)
    f = d / "components" / "chat.yaml"
    f.write_text(f.read_text().replace("port: 8448,", "port: 8448, port_end: 8000,"))
    with pytest.raises(CatalogError, match="port_end"):
        load_catalog(d)
    f.write_text(f.read_text().replace("port_end: 8000,", "").replace("kind: tcp_tls, port: 443}", "kind: tcp_tls, port: 443, body_contains: x}"))
    with pytest.raises(CatalogError, match="body_contains"):
        load_catalog(d)


def test_profile_defaults():
    c = load_catalog()
    for name, on in (("small", set()), ("medium", {"chat", "meetings"}), ("large", {"chat", "meetings"}), ("ha", {"chat", "meetings"})):
        p = c.profiles[name]
        assert set(COLLAB) <= set(p.optional_components)
        assert set(p.default_optional) & set(COLLAB) == on, name
        assert "telephony" not in p.default_optional
    assert all(v.replicas == 2 and v.anti_affinity for v in c.profiles["ha"].vms)


def test_unpinned_collab_artifacts_block_execution():
    p = generate_plan(inp(profile="medium", users=100), cap(3), load_catalog())
    unpinned = {e["component"] for e in p["errors"] if e["code"] == "artifact_unpinned"}
    assert {"chat", "meetings"} <= unpinned and not p["executable"]
    assert p["vms"] and p["steps"]                         # still previewable
    # enabling telephony adds ITS unpinned artifacts (the ou-asterisk package alone is pinned)
    p2 = generate_plan(inp(profile="medium", users=100, optional={"telephony": True}), cap(3), load_catalog())
    assert {"component": "telephony", "artifact": "pbx-helper"}.items() <= next(
        e for e in p2["errors"] if e.get("component") == "telephony").items()
    # a fully pinned catalog is executable
    assert generate_plan(inp(profile="medium", users=100), cap(3), pinned())["executable"]


def test_placement_small_optional_off_by_default_and_on_demand():
    c = pinned()
    off = generate_plan(inp(profile="small", users=40), cap(3), c)
    assert not {v["logical"] for v in off["vms"]} & {"chat", "meet", "pbx"}
    on = generate_plan(inp(profile="small", users=40, optional={"chat": True, "meetings": True, "telephony": True}), cap(3), c)
    assert on["errors"] == []
    assert {"chat", "meet", "pbx"} <= {v["logical"] for v in on["vms"]}
    assert on["consumption"]["memory_mb"] > off["consumption"]["memory_mb"] + 4000
    chat = next(v for v in on["vms"] if v["logical"] == "chat")
    assert chat["memory_mb"] >= 1536 + 512 + 3 * 40          # lab peak formula + VM overhead
    assert {d["name"] for d in chat["disks"]} >= {"chat-pgdata", "chat-media", "chat-config"}
    codes_ = codes(on["warnings"])
    assert "component_notice" in codes_ and "sizing_assumptions" in codes_ and "backup_not_drilled" in codes_
    assert any("emergency" in w["message"].lower() for w in on["warnings"])
    assert "component_os_unvalidated" in codes_             # telephony is Debian-12-validated, plan default is ubuntu
    # health checks are the real service-level kinds
    ck = {c_["name"].split("-", 3)[-1]: c_ for c_ in on["checks"]}
    assert {c_["kind"] for c_ in on["checks"]} >= {"http", "jitsi_jwt", "sip_options_tls"}
    login = next(c_ for c_ in on["checks"] if c_["name"].endswith("matrix-login-flows"))
    assert login["path"] == "/_matrix/client/v3/login" and login["body_contains"] == "m.login.sso" and login["host"].startswith("matrix.")
    # backups: Postgres dump for chat, config tar for the PBX, nothing for stateless Jitsi
    bk = {b["component"]: b for b in on["backups"]}
    assert bk["chat"]["method"] == "online_dump" and "/var/lib/matrix-synapse" in bk["chat"]["volumes"]
    assert bk["telephony"]["method"] == "config_tar" and "/var/spool/asterisk" in bk["telephony"]["volumes"]
    assert "meetings" not in bk


def test_federation_and_ports_are_opt_in():
    c = pinned()
    base = generate_plan(inp(profile="medium", users=50), cap(3), c)
    fw = [f for f in base["firewall"] if f["purpose"].startswith("chat:")]
    assert not any(f["port"] == 8448 for f in fw)
    on = generate_plan(inp(profile="medium", users=50, enabled_ports=["chat:federation"]), cap(3), c)
    assert any(f["port"] == 8448 and f["from"] == "any" for f in on["firewall"])
    assert on["plan_hash"] != base["plan_hash"]
    assert "unknown_enabled_port" in codes(generate_plan(inp(profile="medium", enabled_ports=["chat:nope"]), cap(3), c)["errors"])
    assert "enabled_port_component_absent" in codes(generate_plan(inp(profile="small", enabled_ports=["chat:federation"]), cap(3), c)["errors"])
    udp = {(f["port"], f.get("port_end")) for f in generate_plan(inp(profile="small", optional={"meetings": True, "telephony": True}), cap(3), c)["firewall"]
           if f["proto"] == "udp"}
    assert (10000, None) in udp and (10000, 10200) in udp


def test_colocation_conflicts_are_refused():
    """Two components that both want 443, or JVB UDP 10000 inside the PBX RTP range, may not share a VM."""
    c = pinned()
    lay = [{"name": "id", "components": ["identity", "edge"]},
           {"name": "x", "components": ["chat", "meetings"]}]
    p = generate_plan(inp(profile="custom", users=20, custom_layout=lay), cap(3), c)
    assert "port_conflict" in codes(p["errors"])
    lay = [{"name": "id", "components": ["identity"]}, {"name": "x", "components": ["meetings", "telephony"]}]
    msgs = [e["message"] for e in generate_plan(inp(profile="custom", users=20, custom_layout=lay), cap(3), c)["errors"] if e["code"] == "port_conflict"]
    assert any("10000-10200" in m or "udp/10000" in m for m in msgs)
    lay = [{"name": "id", "components": ["identity"]}, {"name": "m", "components": ["meetings"]}, {"name": "p", "components": ["telephony"]}]
    assert generate_plan(inp(profile="custom", users=20, custom_layout=lay), cap(3), c)["errors"] == []


def test_ha_spreads_collab_replicas_and_warns():
    p = generate_plan(inp(profile="ha", users=30, optional={"telephony": True}), cap(2), pinned())
    assert p["errors"] == []
    for logical in ("chat", "meet", "pbx"):
        vs = [v for v in p["vms"] if v["logical"] == logical]
        assert len(vs) == 2 and len({v["node"] for v in vs}) == 2 and all(v["anti_affinity"] for v in vs)
    notes = [w for w in p["warnings"] if w["code"] == "component_ha_note"]
    assert {n["component"] for n in notes} == set(COLLAB)
    # anti-affinity cannot be met on a single node -> refusal, not silent co-location
    one = generate_plan(inp(profile="ha", users=30), cap(1), pinned())
    assert not one["executable"]


def test_capacity_refusal_includes_collab():
    p = generate_plan(inp(profile="medium", users=200), cap(1, cores=8, mem=16384, sto=500), pinned())
    assert not p["executable"] and any(e["code"].startswith("insufficient") or "capacity" in e["code"] for e in p["errors"])


# ---- check runners -------------------------------------------------------------------------------------------------------

def _cert(tmp_path):
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    k = ec.generate_private_key(ec.SECP256R1())
    n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pbx.test")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key()).serial_number(1)
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=90))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("pbx.test")]), False).sign(k, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM)
    cf, kf = tmp_path / "c.pem", tmp_path / "k.pem"
    cf.write_bytes(pem)
    kf.write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return pem.decode(), str(cf), str(kf)


def _serve(tmp_path, handler):
    pem, cf, kf = _cert(tmp_path)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cf, kf)
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(2)

    def run():
        c, _ = ls.accept()
        try:
            with ctx.wrap_socket(c, server_side=True) as s:
                handler(s)
        except Exception:  # noqa: BLE001
            pass
        ls.close()
    threading.Thread(target=run, daemon=True).start()
    return pem, ls.getsockname()[1]


def _sip(tmp_path, reply: bytes):
    seen = {}

    def h(s):
        seen["req"] = s.recv(4096)
        s.sendall(reply)
    pem, port = _serve(tmp_path, h)
    return pem, port, seen


def test_sip_options_runner(tmp_path, monkeypatch):
    monkeypatch.setattr(checks, "_pinned_ip", lambda host, lb: "127.0.0.1")
    pem, port, seen = _sip(tmp_path, b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n")
    o = checks.run_check("sip_options_tls", {"host": "pbx.test", "port": port, "ca_pem": pem}, None, allow_loopback=True)
    assert o.status == "ok" and seen["req"].startswith(b"OPTIONS sip:pbx.test SIP/2.0")
    pem, port, _ = _sip(tmp_path, b"SIP/2.0 500 Server Error\r\n\r\n")
    assert checks.run_check("sip_options_tls", {"host": "pbx.test", "port": port, "ca_pem": pem}, None, allow_loopback=True).status == "critical"
    pem, port, _ = _sip(tmp_path, b"garbage\r\n\r\n")
    assert checks.run_check("sip_options_tls", {"host": "pbx.test", "port": port, "ca_pem": pem}, None, allow_loopback=True).status == "critical"
    # TLS trust is mandatory like every TLS check
    assert checks.run_check("sip_options_tls", {"host": "pbx.test", "port": port}, None, allow_loopback=True).status == "critical"


def _ws_frame(text: str) -> bytes:
    d = text.encode()
    return bytes([0x81, len(d)]) + d if len(d) < 126 else bytes([0x81, 126]) + len(d).to_bytes(2, "big") + d


def _read_ws(s):
    b0, b1 = s.recv(2)
    n = b1 & 0x7F
    mask = s.recv(4)
    data = b""
    while len(data) < n:
        data += s.recv(n - len(data))
    return bytes(b ^ mask[i % 4] for i, b in enumerate(data)).decode()


def _jitsi(tmp_path, mechanisms: bool, accept_anon: bool):
    def h(s):
        req = b""
        while b"\r\n\r\n" not in req:
            req += s.recv(1024)
        assert re.search(rb"GET /xmpp-websocket\?room=", req)
        s.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
        assert "<open" in _read_ws(s)
        s.sendall(_ws_frame("<open xmlns='urn:ietf:params:xml:ns:xmpp-framing' from='x'/>"))
        feat = "<stream:features>" + ("<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>ANONYMOUS</mechanism></mechanisms>" if mechanisms else "") + "</stream:features>"
        s.sendall(_ws_frame(feat))
        if mechanisms:
            _read_ws(s)
            s.sendall(_ws_frame("<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>" if accept_anon else "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-allowed/></failure>"))
    return _serve(tmp_path, h)


@pytest.mark.parametrize("mech,anon,status", [(False, False, "ok"), (True, False, "ok"), (True, True, "critical")])
def test_jitsi_runner_requires_token_enforcement(tmp_path, monkeypatch, mech, anon, status):
    monkeypatch.setattr(checks, "_pinned_ip", lambda host, lb: "127.0.0.1")
    pem, port = _jitsi(tmp_path, mech, anon)
    o = checks.run_check("jitsi_jwt", {"host": "pbx.test", "port": port, "ca_pem": pem}, None, allow_loopback=True)
    assert o.status == status, o.message


def test_jitsi_runner_reports_dead_service(tmp_path, monkeypatch):
    monkeypatch.setattr(checks, "_pinned_ip", lambda host, lb: "127.0.0.1")

    def h(s):
        s.recv(2048)
        s.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
    pem, port = _serve(tmp_path, h)
    o = checks.run_check("jitsi_jwt", {"host": "pbx.test", "port": port, "ca_pem": pem}, None, allow_loopback=True)
    assert o.status == "critical"
