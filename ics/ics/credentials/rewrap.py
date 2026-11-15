"""Master-key rotation (re-wrap). Credentials only re-wrap their per-credential data key (secret ciphertext is untouched); every other
vault-encrypted column (TOTP seeds, check/channel/IdM secrets, pending plan secrets, un-migrated endpoint blobs) is re-encrypted
under the new key with its original AAD. One transaction: either everything moves to the new key or nothing does.

Procedure (docs/status/credential-vault.md): generate a new 32-byte key file (0640 root:ics), run
`python -m ics.cli rewrap-master --new-key-file NEW`, replace the key file in settings with NEW, restart ics. Keep the old key
until the restart is verified."""
from sqlalchemy import text
from sqlalchemy.orm import Session

from .. import audit, identity, monitor
from ..vault import Vault
from . import envelope


def _targets(db: Session):
    """(table, id column, blob column, AAD function(row)) for every non-credential vault consumer."""
    yield "users", "id", "totp_secret_enc", "SELECT id, username, totp_secret_enc AS blob FROM users WHERE totp_secret_enc IS NOT NULL", \
        lambda r: f"user-totp:{r.username}"
    yield "checks", "id", "secret_enc", "SELECT id, config, secret_enc AS blob FROM checks WHERE secret_enc IS NOT NULL", \
        lambda r: monitor.check_aad(r.id, r.config)
    yield "alert_channels", "id", "secret_enc", "SELECT id, config, secret_enc AS blob FROM alert_channels WHERE secret_enc IS NOT NULL", \
        lambda r: monitor.channel_aad(r.id, r.config)
    yield "idm_stacks", "id", "secret_enc", "SELECT id, config, secret_enc AS blob FROM idm_stacks WHERE secret_enc IS NOT NULL", \
        lambda r: identity.stack_aad(r.id, r.config)
    yield "idm_enrollments", "id", "token_enc", "SELECT id, token_enc AS blob FROM idm_enrollments WHERE token_enc IS NOT NULL", \
        lambda r: f"idm-enroll:{r.id}"
    yield "plans", "id", "secret_enc", "SELECT id, secret_enc AS blob FROM plans WHERE secret_enc IS NOT NULL", lambda r: f"plan:{r.id}"


def rewrap_all(db: Session, old: Vault, new: Vault, actor: str = "cli") -> dict:
    """Caller commits. Raises (and the caller rolls back) on any decryption failure."""
    counts = {"credentials": 0}
    for r in db.execute(text("SELECT id, provider, customer_id, wrapped_key FROM credentials WHERE length(wrapped_key) > 0 FOR UPDATE")).all():
        wk, mk = envelope.rewrap_key(old, new, r.wrapped_key, r.id, r.provider, r.customer_id)
        db.execute(text("UPDATE credentials SET wrapped_key = :w, master_key_id = :m WHERE id = :i"), {"w": wk, "m": mk, "i": str(r.id)})
        counts["credentials"] += 1
    for table, idcol, col, sql, aad in _targets(db):
        n = 0
        for r in db.execute(text(sql)).all():
            if len(bytes(r.blob)) == 0:
                continue
            ctx = aad(r)
            blob = new.encrypt(old.decrypt(r.blob, ctx), ctx)
            db.execute(text(f"UPDATE {table} SET {col} = :b WHERE {idcol} = :i"), {"b": blob, "i": str(r.id)})  # constants only
            n += 1
        counts[table] = n
    for role, col in (("inventory", "token_secret_enc"), ("provision", "provision_secret_enc")):
        n = 0
        from . import service
        for ep in db.execute(text(f"SELECT * FROM endpoints WHERE {col} IS NOT NULL AND length({col}) > 0")).all():  # constants only
            ctx = service._legacy_aad(ep, role)
            db.execute(text(f"UPDATE endpoints SET {col} = :b WHERE id = :i"), {"b": new.encrypt(old.decrypt(getattr(ep, col), ctx), ctx), "i": str(ep.id)})
            n += 1
        counts[f"endpoints.{role}"] = n
    audit.append(db, "vault.master_key_rewrapped", actor_name=actor, resource="vault",
                 details={"from_mkid": envelope.vault_key_id(old), "to_mkid": envelope.vault_key_id(new), "counts": counts})
    return counts
