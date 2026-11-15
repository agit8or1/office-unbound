"""Unit test of blueprints/lab/spike-groupware/ou-sync-bearer-key.py (pure functions; the end-to-end rotation test is in docs/status/sso-rollout-results.md).
Run: ics/.venv/bin/pytest blueprints/lab/tests/test_sync_bearer_key.py"""
import base64
import importlib.util
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
