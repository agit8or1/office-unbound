"""One linear alembic chain, and the production upgrade path: a database at 0007 (main's node scope, a legacy endpoint registered by
endpoint.register with provision_token_* + allowed_nodes) upgrades to head and the legacy secrets move into the credential vault."""
import os

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import text

from ics.credentials import service as cred_service

HERE = os.path.dirname(__file__)
EXPECTED = ["0001", "0002", "0003", "0004", "0005", "0006d", "0006b", "0006a", "0007", "0007s3", "0007l", "0007m", "0008i", "0008", "0009", "0009b", "0009a", "0010", "0009c"]


def _cfg(url):
    cfg = Config(os.path.join(HERE, "..", "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(HERE, "..", "migrations"))
    cfg.attributes["url"] = url
    cfg.attributes["app_role"] = "ics_test_app"
    return cfg


def test_single_linear_chain():
    sd = ScriptDirectory(os.path.join(HERE, "..", "migrations"))
    assert sd.get_heads() == ["0009c"]
    assert [s.revision for s in reversed(list(sd.walk_revisions()))] == EXPECTED


def test_upgrade_from_production_state_0007_with_a_legacy_endpoint(rt, base_settings, owner_engine):
    from tests.conftest import _test_env
    url = _test_env()["ICS_TEST_OWNER_DATABASE_URL"]
    cfg = _cfg(url)
    with owner_engine.connect() as c:
        c.execute(text("DROP SCHEMA public CASCADE"))
        c.execute(text("CREATE SCHEMA public"))
    command.upgrade(cfg, "0007")
    try:
        with owner_engine.connect() as c:
            c.execute(text("INSERT INTO users (username, role, password_hash, enrolled) VALUES ('u', 'admin', 'x', true)")) if False else None
            eid = c.execute(text(
                "INSERT INTO endpoints (name, type, base_url, token_id, token_secret_enc, fingerprint_sha256, provision_token_id, provision_secret_enc, "
                "allowed_pools, allowed_nodes) VALUES ('pve', 'proxmox', 'https://pve:8006', 'ics@pve!inv', '\\x01'::bytea, 'AA', 'ics@pve!prov', "
                "'\\x02'::bytea, '{p}', '{pve06}') RETURNING id")).scalar()
        command.upgrade(cfg, "head")
        with owner_engine.connect() as c:
            r = c.execute(text("SELECT customer_id, allowed_nodes, trust_binding, inventory_credential_id FROM endpoints WHERE id = :i"), {"i": eid}).first()
            assert r.allowed_nodes == ["pve06"] and str(r.customer_id) == "00000000-0000-0000-0000-00000000a001"
            assert r.trust_binding is None and r.inventory_credential_id is None   # migrated lazily by adopt_all (needs the vault key)
            assert c.execute(text("SELECT count(*) FROM deployment_locks")).scalar() == 0
    finally:
        # leave the shared test database at head with a clean slate for the other tests
        with owner_engine.connect() as c:
            c.execute(text("DROP SCHEMA public CASCADE"))
            c.execute(text("CREATE SCHEMA public"))
        command.upgrade(cfg, "head")


def test_upgrade_from_production_head_0008i(rt, base_settings, owner_engine):
    """Production is at 0008i: the whole remaining chain (backups, telephony, guest bootstrap, controller epoch) applies on top and leaves the expected tables."""
    from tests.conftest import _test_env
    cfg = _cfg(_test_env()["ICS_TEST_OWNER_DATABASE_URL"])
    with owner_engine.connect() as c:
        c.execute(text("DROP SCHEMA public CASCADE"))
        c.execute(text("CREATE SCHEMA public"))
    command.upgrade(cfg, "0008i")
    try:
        command.upgrade(cfg, "head")
        with owner_engine.connect() as c:
            assert c.execute(text("SELECT version_num FROM alembic_version")).scalar() == "0009c"
            have = {r[0] for r in c.execute(text("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"))}
            assert {"backup_policies", "idm_sip_credentials", "guest_bootstrap", "controller_state"} <= have
            assert c.execute(text("SELECT count(*) FROM information_schema.columns WHERE table_name = 'idm_users' AND column_name = 'extension'")).scalar() == 1
    finally:
        with owner_engine.connect() as c:
            c.execute(text("DROP SCHEMA public CASCADE"))
            c.execute(text("CREATE SCHEMA public"))
        command.upgrade(cfg, "head")




def test_upgrade_from_production_head_0008(rt, base_settings, owner_engine):
    """Production head 0008: the whole remaining chain (backups, telephony, guest bootstrap, controller epoch) applies on top and leaves the expected tables."""
    from tests.conftest import _test_env
    cfg = _cfg(_test_env()["ICS_TEST_OWNER_DATABASE_URL"])
    with owner_engine.connect() as c:
        c.execute(text("DROP SCHEMA public CASCADE"))
        c.execute(text("CREATE SCHEMA public"))
    command.upgrade(cfg, "0008")
    try:
        command.upgrade(cfg, "head")
        with owner_engine.connect() as c:
            assert c.execute(text("SELECT version_num FROM alembic_version")).scalar() == "0009c"
            have = {r[0] for r in c.execute(text("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"))}
            assert {"backup_policies", "idm_sip_credentials", "guest_bootstrap", "controller_state"} <= have
            assert c.execute(text("SELECT count(*) FROM information_schema.columns WHERE table_name = 'idm_users' AND column_name = 'extension'")).scalar() == 1
            for t in ("nodes", "checks", "alert_channels", "maintenance_windows", "backup_policies"):     # review 5 M5: customer binding, MSP-internal default
                assert c.execute(text("SELECT column_default FROM information_schema.columns WHERE table_name = :t AND column_name = 'customer_id'"), {"t": t}).scalar().startswith("'00000000-0000-0000-0000-00000000a001'")
    finally:
        with owner_engine.connect() as c:
            c.execute(text("DROP SCHEMA public CASCADE"))
            c.execute(text("CREATE SCHEMA public"))
        command.upgrade(cfg, "head")


def test_adopt_endpoint_binds_node_allowlist(rt, mk_user):
    from ics.actions import endpoint_binding, trust_binding
    from ics.credentials.service import CredentialUnavailable
    with rt.session() as db:
        b = endpoint_binding("https://pve:8006", "ics@pve!inv", "AA", None)
        eid = db.execute(text(
            "INSERT INTO endpoints (name, type, base_url, token_id, token_secret_enc, fingerprint_sha256, provision_token_id, provision_secret_enc, "
            "allowed_pools, allowed_nodes) VALUES ('pve', 'proxmox', 'https://pve:8006', 'ics@pve!inv', :s, 'AA', 'ics@pve!prov', :p, '{p}', '{pve06}') "
            "RETURNING id"),
            {"s": rt.vault.encrypt(b"inv-secret", f"endpoint-token:PLACEHOLDER:{b}"), "p": b"\x01"}).scalar()
        row = db.execute(text("SELECT * FROM endpoints WHERE id = :i"), {"i": eid}).first()
        b = endpoint_binding(row.base_url, row.token_id, row.fingerprint_sha256, row.ca_pem)
        db.execute(text("UPDATE endpoints SET token_secret_enc = :s, provision_secret_enc = :p WHERE id = :i"),
                   {"s": rt.vault.encrypt(b"inv-secret", f"endpoint-token:{eid}:{b}"),
                    "p": rt.vault.encrypt(b"prov-secret", f"endpoint-provision:{eid}:{b}:ics@pve!prov"), "i": eid})
        db.commit()
    assert cred_service.adopt_all(rt) == 2
    with rt.session() as db:
        ep = db.execute(text("SELECT * FROM endpoints WHERE id = :i"), {"i": eid}).first()
        assert ep.trust_binding == trust_binding(ep.base_url, ep.token_id, ep.fingerprint_sha256, ep.ca_pem, ["pve06"])
        assert cred_service.endpoint_secret(rt, ep, "inventory") == "inv-secret"
        db.execute(text("UPDATE endpoints SET allowed_nodes = '{pve06,pve05}' WHERE id = :i"), {"i": eid})
        db.commit()
        ep = db.execute(text("SELECT * FROM endpoints WHERE id = :i"), {"i": eid}).first()
        with pytest.raises(CredentialUnavailable):   # widening the node allowlist outside an approved update releases nothing
            cred_service.endpoint_secret(rt, ep, "inventory")
