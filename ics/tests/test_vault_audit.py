import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import ProgrammingError

from ics import audit
from ics.vault import Vault, VaultError


def test_vault_roundtrip_and_nondeterministic(rt):
    blob = rt.vault.encrypt(b"s3cret", "ctx")
    assert rt.vault.decrypt(blob, "ctx") == b"s3cret"
    assert blob != rt.vault.encrypt(b"s3cret", "ctx") and b"s3cret" not in blob


def test_vault_tamper_wrongkey_wrongctx_raise(rt, other_vault):
    blob = bytearray(rt.vault.encrypt(b"s3cret", "ctx"))
    blob[-1] ^= 1
    with pytest.raises(VaultError):
        rt.vault.decrypt(bytes(blob), "ctx")
    good = rt.vault.encrypt(b"s3cret", "ctx")
    with pytest.raises(VaultError):
        rt.vault.decrypt(good, "other-ctx")
    with pytest.raises(VaultError):
        other_vault.decrypt(good, "ctx")
    with pytest.raises(VaultError):
        rt.vault.decrypt(b"plaintext", "ctx")
    with pytest.raises(VaultError):
        Vault(b"short")
    with pytest.raises(VaultError):
        Vault.from_file("/nonexistent/key")


def _fill(rt, n=5):
    with rt.session() as db:
        for i in range(n):
            audit.append(db, "test.event", actor_name="t", details={"i": i, "password": "hunter2", "token_id": "a@pve!t"})
        db.commit()


def test_chain_verifies_and_scrubs(rt):
    _fill(rt)
    with rt.session() as db:
        v = audit.verify_chain(db)
        assert v["ok"] and v["checked"] == 5
        d = db.execute(text("SELECT details FROM audit_events ORDER BY seq LIMIT 1")).scalar()
    assert d["password"] == "[redacted]" and d["token_id"] == "a@pve!t"


def test_chain_detects_alteration_and_deletion(rt, owner_engine):
    _fill(rt)
    with owner_engine.connect() as c:
        c.execute(text("UPDATE audit_events SET actor_name='mallory' WHERE seq=3"))
    with rt.session() as db:
        v = audit.verify_chain(db)
    assert not v["ok"] and any(p["seq"] == 3 and p["kind"] == "altered" for p in v["problems"])
    with owner_engine.connect() as c:
        c.execute(text("UPDATE audit_events SET actor_name='t' WHERE seq=3"))
        assert audit.verify_chain(type("S", (), {"execute": lambda s, *a, **k: c.execute(*a, **k)})())["ok"]
        c.execute(text("DELETE FROM audit_events WHERE seq=2"))
    with rt.session() as db:
        v = audit.verify_chain(db)
    assert not v["ok"] and any(p["kind"] == "broken_link" for p in v["problems"])


@pytest.mark.parametrize("sql", ["UPDATE audit_events SET action='x'", "DELETE FROM audit_events", "TRUNCATE audit_events"])
def test_app_role_cannot_modify_audit(rt, sql):
    _fill(rt, 1)
    with rt.session() as db:
        with pytest.raises(ProgrammingError, match="permission denied"):
            db.execute(text(sql))
        db.rollback()
        assert db.execute(text("SELECT count(*) FROM audit_events")).scalar() == 1  # SELECT/INSERT still fine
