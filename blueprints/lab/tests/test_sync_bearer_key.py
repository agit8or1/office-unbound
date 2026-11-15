"""Unit test of blueprints/lab/spike-groupware/ou-sync-bearer-key.py (pure functions; the end-to-end rotation test is in docs/status/sso-rollout-results.md).
Run: ics/.venv/bin/pytest blueprints/lab/tests/test_sync_bearer_key.py"""
import base64
import importlib.util
import json
import os

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

HERE = os.path.dirname(__file__)
spec = importlib.util.spec_from_file_location("sync", os.path.join(HERE, "..", "spike-groupware", "ou-sync-bearer-key.py"))
sync = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sync)


def mk(bits=2048):
    k = rsa.generate_private_key(65537, bits).public_key()
    n = k.public_numbers()
    b = lambda i: base64.urlsafe_b64encode(i.to_bytes((i.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()
    spki = base64.b64encode(k.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
    return {"kty": "RSA", "use": "sig", "alg": "RS256", "n": b(n.n), "e": b(n.e)}, spki


def test_jwk_to_spki_matches_openssl_encoding():
    for bits in (2048, 3072, 4096):
        jwk, spki = mk(bits)
        assert sync.jwk_to_spki_b64(jwk) == spki


def test_choose_picks_the_active_key_by_kid_among_several():
    (a, sa), (b, sb), (c, sc) = mk(), mk(), mk()
    keys = [{**a, "kid": "old"}, {**b, "kid": "new"}, {**c, "kid": "other", "use": "enc"}]
    assert sync.choose({"public_key": sb}, {"keys": keys})[0] == "new"
    assert sync.choose({"public_key": sa}, {"keys": keys})[0] == "old"
    with pytest.raises(ValueError):
        sync.choose({"public_key": sc}, {"keys": keys})          # active key missing / not a signing key: refuse, keep old file


def test_pem_roundtrip_and_write_only_when_changed(tmp_path):
    jwk, spki = mk()
    pem = sync.pem(spki)
    assert serialization.load_pem_public_key(pem.encode()).public_numbers().e == 65537
    f = tmp_path / "bearer_pubkey"
    assert sync.write_if_changed(str(f), pem, None) is True
    assert sync.write_if_changed(str(f), pem, None) is False
    assert oct(f.stat().st_mode & 0o777) == "0o640"


# ---- security review 4, L4 ----------------------------------------------------------------------------------------------------------
def test_weak_or_odd_keys_are_refused_and_old_key_stays():
    weak, sw = mk(1024)
    with pytest.raises(ValueError, match="1024 bits"):
        sync.choose({"public_key": sw}, {"keys": [{**weak, "kid": "w"}]})
    ok, so = mk(2048)
    assert sync.choose({"public_key": so}, {"keys": [{**ok, "kid": "ok"}]})[0] == "ok"
    exp3 = {**ok, "e": base64.urlsafe_b64encode(b"\x03").rstrip(b"=").decode()}
    with pytest.raises(ValueError, match="exponent"):
        sync.choose({"public_key": sync.jwk_to_spki_b64(exp3)}, {"keys": [{**exp3, "kid": "e3"}]})


def test_system_ca_bundle_is_refused_and_missing_ca_is_an_error(tmp_path):
    sysb = next((b for b in sync.SYSTEM_BUNDLES if os.path.exists(b)), None)
    if sysb:
        assert sync.main(["--ca", sysb, "--out", str(tmp_path / "k"), "--state-dir", str(tmp_path)]) == 4
    assert sync.main(["--ca", str(tmp_path / "nope.crt"), "--out", str(tmp_path / "k"), "--state-dir", str(tmp_path)]) == 4
    assert not (tmp_path / "k").exists()


def test_tls_only_trusts_the_pinned_ca(tmp_path):
    """Local TLS server with a cert from CA-A; the follower pinned to CA-B must not fetch (and thus never writes a key); pinned to CA-A it does."""
    import datetime, http.server, ssl, threading
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID

    def mkca(cn):
        k = rsa.generate_private_key(65537, 2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        now = datetime.datetime.now(datetime.timezone.utc)
        c = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(k.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=2))
             .add_extension(x509.BasicConstraints(ca=True, path_length=None), True).sign(k, hashes.SHA256()))
        return k, c

    def leaf(cak, cac):
        k = rsa.generate_private_key(65537, 2048)
        now = datetime.datetime.now(datetime.timezone.utc)
        c = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])).issuer_name(cac.subject)
             .public_key(k.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
             .not_valid_after(now + datetime.timedelta(days=2)).add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False).sign(cak, hashes.SHA256()))
        return k, c

    pem = lambda o: o.public_bytes(serialization.Encoding.PEM)
    cak, cac = mkca("CA-A")
    _bk, bc = mkca("CA-B")
    lk, lc = leaf(cak, cac)
    (tmp_path / "a.crt").write_bytes(pem(cac)); (tmp_path / "b.crt").write_bytes(pem(bc))
    (tmp_path / "l.crt").write_bytes(pem(lc))
    (tmp_path / "l.key").write_bytes(lk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    jwk, spki = mk(2048)
    jwk["kid"] = "k1"
    body = {"/realm": {"public_key": spki}, "/realm/protocol/openid-connect/certs": {"keys": [jwk]}}

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            b = json.dumps(body[self.path]).encode()
            self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp_path / "l.crt", tmp_path / "l.key")
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"https://localhost:{srv.server_address[1]}/realm"
    out = tmp_path / "bearer_pubkey"
    base = ["--realm-url", url, "--out", str(out), "--group", "", "--state-dir", str(tmp_path / "st")]
    assert sync.main(["--ca", str(tmp_path / "b.crt")] + base) == 2 and not out.exists()       # wrong pinned CA: fetch fails, nothing written
    assert sync.main(["--ca", str(tmp_path / "a.crt")] + base) == 0 and out.exists()
    srv.shutdown()


def test_oversized_response_is_refused(tmp_path, monkeypatch):
    class R:
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def read(self, n): return b"x" * n
    monkeypatch.setattr(sync.urllib.request, "urlopen", lambda *a, **k: R())
    with pytest.raises(ValueError, match="too large"):
        sync.fetch("https://x/", None)
