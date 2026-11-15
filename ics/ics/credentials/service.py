"""Central, provider-agnostic credential subsystem. Secrets live only in `credentials` (envelope encrypted); every other table
refers to a credential by id. Nothing here returns, logs or audits a secret; callers get plaintext only through `get_secret`."""
import logging
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from sqlalchemy import text
from sqlalchemy.orm import Session

from .. import audit
from ..runtime import Runtime
from ..vault import VaultError
from . import envelope

log = logging.getLogger("ics.credentials")

TYPES = ("api_token", "password", "ssh_key", "client_cert")
PURPOSES = ("inventory", "provision", "temporary_provisioning")
USABLE = ("active", "expiring")
RETIRE_GRACE_DAYS = 7
EXPIRY_WARN_DAYS = 14
USE_AUDIT_INTERVAL_SECONDS = 300

PUBLIC_COLS = ("id, provider, customer_id, label, datacenter, cluster, host, credential_type, purpose, identity, status, created_at, "
               "created_by, last_validated_at, last_used_at, expires_at, revoked_at, retire_after, purged_at, replaced_by, master_key_id")


class CredentialUnavailable(Exception):
    """The credential cannot be used (revoked/expired/invalid/retired/purged or missing). Callers surface this as a connection error."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _event(db: Session, cid, event: str, actor: str, reason: str | None = None, related=None) -> None:
    db.execute(text("INSERT INTO credential_events (credential_id, event, actor, reason, related_credential_id) VALUES (:c, :e, :a, :r, :x)"),
               {"c": str(cid), "e": event, "a": actor[:100], "r": (reason or None) and reason[:300], "x": str(related) if related else None})


def _audit(db: Session, action: str, cid, actor: str, actor_id=None, ip=None, **details) -> None:
    audit.append(db, action, actor_id=actor_id, actor_name=actor, ip=ip, resource="credential", resource_id=str(cid), details=details)


def create(db: Session, rt: Runtime, *, provider: str, customer_id, label: str, credential_type: str, purpose: str, secret: str,
           identity: str | None = None, datacenter=None, cluster=None, host=None, expires_at: datetime | None = None,
           actor: str = "system", actor_id=None, reason: str | None = None, ip=None, cred_id=None, event: str = "created") -> str:
    if credential_type not in TYPES or purpose not in PURPOSES:
        raise ValueError("invalid credential type or purpose")
    cid = cred_id or uuid.uuid4()
    wrapped, enc, mk = envelope.seal(rt.vault, secret.encode(), cid, provider, customer_id)
    db.execute(text(
        "INSERT INTO credentials (id, provider, customer_id, label, datacenter, cluster, host, credential_type, purpose, identity, wrapped_key, "
        "secret_enc, master_key_id, created_by, expires_at) VALUES (:id, :p, :c, :l, :dc, :cl, :h, :t, :pu, :i, :w, :s, :m, :cb, :e)"),
        {"id": str(cid), "p": provider, "c": str(customer_id), "l": label, "dc": datacenter, "cl": cluster, "h": host, "t": credential_type,
         "pu": purpose, "i": identity, "w": wrapped, "s": enc, "m": mk, "cb": actor[:100], "e": expires_at})
    _event(db, cid, event, actor, reason)
    _audit(db, "credential.created", cid, actor, actor_id, ip, provider=provider, customer_id=str(customer_id), purpose=purpose,
           credential_type=credential_type, identity=identity, expires_at=expires_at.isoformat() if expires_at else None, reason=reason)
    return str(cid)


def get_row(db: Session, cid):
    return db.execute(text("SELECT * FROM credentials WHERE id = :i"), {"i": str(cid)}).first()


def public_view(db: Session, cid) -> dict | None:
    r = db.execute(text(f"SELECT {PUBLIC_COLS} FROM credentials WHERE id = :i"), {"i": str(cid)}).first()
    return _pub(r) if r else None


def _pub(r) -> dict:
    d = {}
    for k in r._fields:
        v = getattr(r, k)
        d[k] = v.isoformat() if isinstance(v, datetime) else (str(v) if isinstance(v, uuid.UUID) else v)
    return d


def history(db: Session, cid) -> list[dict]:
    rows = db.execute(text("SELECT at, event, actor, reason, related_credential_id FROM credential_events WHERE credential_id = :c "
                           "ORDER BY id"), {"c": str(cid)}).all()
    return [{"at": r.at.isoformat(), "event": r.event, "actor": r.actor, "reason": r.reason,
             "related_credential_id": str(r.related_credential_id) if r.related_credential_id else None} for r in rows]


def get_secret(rt: Runtime, cid, *, use: str = "api", actor: str = "system") -> str:
    """The ONLY path to a plaintext credential. Refuses revoked/expired/invalid/retired credentials. Records last use and a
    (throttled) `credential.use` audit event feeding the access review report."""
    with rt.session() as db:
        r = db.execute(text("SELECT * FROM credentials WHERE id = :i FOR UPDATE"), {"i": str(cid)}).first()
        if r is None:
            raise CredentialUnavailable("credential not found")
        if r.status not in USABLE or r.purged_at is not None:
            raise CredentialUnavailable(f"credential is {r.status}; it must be replaced by the customer-approved procedure")
        if r.expires_at is not None and r.expires_at <= _now():
            db.execute(text("UPDATE credentials SET status = 'expired' WHERE id = :i"), {"i": str(cid)})
            db.commit()
            raise CredentialUnavailable("credential is expired")
        secret = envelope.unseal(rt.vault, r.wrapped_key, r.secret_enc, r.id, r.provider, r.customer_id).decode()
        now = _now()
        db.execute(text("UPDATE credentials SET last_used_at = :n WHERE id = :i"), {"n": now, "i": str(cid)})
        if r.purpose != "inventory" or r.last_use_audited_at is None or (now - r.last_use_audited_at).total_seconds() > USE_AUDIT_INTERVAL_SECONDS:
            db.execute(text("UPDATE credentials SET last_use_audited_at = :n WHERE id = :i"), {"n": now, "i": str(cid)})
            _audit(db, "credential.use", cid, actor, provider=r.provider, customer_id=str(r.customer_id), purpose=r.purpose, use=use)
        db.commit()
        return secret


def supersede(db: Session, rt: Runtime, old_id, *, secret: str, identity: str | None = None, expires_at: datetime | None = None,
              actor: str, actor_id=None, reason: str, kind: str = "rotated", ip=None) -> str:
    """Replace/rotate: a NEW credential row takes over (endpoints are re-pointed); the previous one is retired, kept (without
    losing history) for a grace period, then its secret is purged by `purge_retired`."""
    old = db.execute(text("SELECT * FROM credentials WHERE id = :i FOR UPDATE"), {"i": str(old_id)}).first()
    if old is None:
        raise CredentialUnavailable("credential not found")
    if old.status in ("revoked", "retired"):
        raise CredentialUnavailable(f"credential is {old.status}; create a new credential instead")
    nid = create(db, rt, provider=old.provider, customer_id=old.customer_id, label=old.label, credential_type=old.credential_type,
                 purpose=old.purpose, secret=secret, identity=identity or old.identity, datacenter=old.datacenter, cluster=old.cluster,
                 host=old.host, expires_at=expires_at, actor=actor, actor_id=actor_id, reason=reason, ip=ip, event=f"{kind}_from")
    _event(db, nid, f"{kind}_from", actor, reason, old.id)
    db.execute(text("UPDATE credentials SET status = 'retired', retire_after = :ra, replaced_by = :n WHERE id = :i"),
               {"ra": _now() + timedelta(days=RETIRE_GRACE_DAYS), "n": nid, "i": str(old.id)})
    _event(db, old.id, f"{kind}_to", actor, reason, nid)
    db.execute(text("UPDATE endpoints SET inventory_credential_id = :n WHERE inventory_credential_id = :o"), {"n": nid, "o": str(old.id)})
    db.execute(text("UPDATE endpoints SET provision_credential_id = :n WHERE provision_credential_id = :o"), {"n": nid, "o": str(old.id)})
    _audit(db, f"credential.{kind}", nid, actor, actor_id, ip, previous_credential_id=str(old.id), reason=reason,
           provider=old.provider, customer_id=str(old.customer_id), retire_after_days=RETIRE_GRACE_DAYS)
    return nid


def revoke(db: Session, cid, *, actor: str, actor_id=None, reason: str, ip=None) -> None:
    """Revocation destroys the stored secret immediately and is never undone by ICS: reconnecting needs new credentials issued by
    the customer (see docs/runbooks/provider-access-recovery.md). The credential at the provider is the customer's to delete."""
    r = db.execute(text("SELECT * FROM credentials WHERE id = :i FOR UPDATE"), {"i": str(cid)}).first()
    if r is None:
        raise CredentialUnavailable("credential not found")
    db.execute(text("UPDATE credentials SET status = 'revoked', revoked_at = now(), purged_at = now(), wrapped_key = '\\x'::bytea, "
                    "secret_enc = '\\x'::bytea WHERE id = :i"), {"i": str(cid)})
    _event(db, cid, "revoked", actor, reason)
    _audit(db, "credential.revoked", cid, actor, actor_id, ip, reason=reason, provider=r.provider, customer_id=str(r.customer_id))


def purge_retired(db: Session) -> int:
    rows = db.execute(text("UPDATE credentials SET purged_at = now(), wrapped_key = '\\x'::bytea, secret_enc = '\\x'::bytea "
                           "WHERE status = 'retired' AND purged_at IS NULL AND retire_after < now() RETURNING id")).all()
    for r in rows:
        _event(db, r.id, "purged", "system", "grace period elapsed")
        _audit(db, "credential.purged", r.id, "system")
    return len(rows)


# ---- provider connection tests ---------------------------------------------------------------------------------------------

TESTERS: dict = {}  # provider -> fn(rt, cred_row, secret, endpoint_row|None) -> (ok: bool, message: str)


def _proxmox_tester(rt, cred, secret, ep):
    from ..actions import _new_client
    if ep is None:
        return False, "credential is not attached to an endpoint"
    c = _new_client(rt, ep.base_url, cred.identity, secret, ep.ca_pem, ep.fingerprint_sha256)
    try:
        c.version()
    finally:
        c.close()
    return True, "authenticated"


TESTERS["proxmox"] = _proxmox_tester


def test(db: Session, rt: Runtime, cid, *, actor: str, actor_id=None, ip=None) -> dict:
    r = get_row(db, cid)
    if r is None:
        raise CredentialUnavailable("credential not found")
    tester = TESTERS.get(r.provider)
    if tester is None:
        return {"ok": None, "message": f"no connection test exists for provider {r.provider}"}
    secret = get_secret(rt, cid, use="credential.test", actor=actor)
    ep = db.execute(text("SELECT * FROM endpoints WHERE inventory_credential_id = :c OR provision_credential_id = :c"), {"c": str(cid)}).first()
    try:
        ok, msg = tester(rt, r, secret, ep)
    except Exception as e:  # noqa: BLE001
        ok, msg = False, audit.redact(f"{type(e).__name__}: {e}"[:200], [secret])
    db.execute(text("UPDATE credentials SET last_validated_at = CASE WHEN :ok THEN now() ELSE last_validated_at END, "
                    "status = CASE WHEN :ok AND status = 'invalid' THEN 'active' WHEN NOT :ok THEN 'invalid' ELSE status END WHERE id = :i"),
               {"ok": ok, "i": str(cid)})
    _event(db, cid, "test_ok" if ok else "test_failed", actor, None if ok else msg)
    _audit(db, "credential.tested", cid, actor, actor_id, ip, ok=ok, message=msg, customer_id=str(r.customer_id))
    return {"ok": ok, "message": msg}


# ---- endpoints <-> credentials -----------------------------------------------------------------------------------------------

ROLE_COL = {"inventory": "inventory_credential_id", "provision": "provision_credential_id"}


def _legacy_aad(ep, role: str) -> str:
    from ..actions import endpoint_binding
    b = endpoint_binding(ep.base_url, ep.token_id, ep.fingerprint_sha256, ep.ca_pem)
    return f"endpoint-token:{ep.id}:{b}" if role == "inventory" else f"endpoint-provision:{ep.id}:{b}:{ep.provision_token_id}"


def endpoint_secret(rt: Runtime, ep, role: str, *, actor: str = "ics") -> str:
    """Plaintext secret for an endpoint role. Prefers the credential record; un-migrated rows still use the legacy blob."""
    cid = getattr(ep, ROLE_COL[role], None)
    if cid:
        from ..actions import endpoint_binding
        tb = getattr(ep, "trust_binding", None)  # M5: a credential is only released for the trust anchors it was approved with
        from ..actions import trust_binding
        if tb is not None and tb != trust_binding(ep.base_url, ep.token_id, ep.fingerprint_sha256, ep.ca_pem, getattr(ep, "allowed_nodes", None)):
            raise CredentialUnavailable("endpoint trust anchors changed outside an approved update; credential not released")
        return get_secret(rt, cid, use=f"endpoint.{role}", actor=actor)
    blob = ep.token_secret_enc if role == "inventory" else ep.provision_secret_enc
    if blob is None or len(bytes(blob)) == 0:
        raise CredentialUnavailable(f"endpoint has no {role} credential")
    return rt.vault.decrypt(blob, _legacy_aad(ep, role)).decode()


def attach_endpoint_credential(db: Session, rt: Runtime, ep, role: str, identity: str, secret: str, *, actor: str,
                               reason: str, actor_id=None) -> str:
    """Create (or supersede) the credential record behind an endpoint role and re-point the endpoint. `ep` is the endpoint row."""
    existing = getattr(ep, ROLE_COL[role], None)
    if existing:
        cur = get_row(db, existing)
        if cur is not None and cur.status in USABLE + ("invalid", "expired"):
            nid = supersede(db, rt, existing, secret=secret, identity=identity, actor=actor, actor_id=actor_id, reason=reason,
                            kind="replaced" if cur.identity != identity else "rotated")
            return nid
    cluster = (ep.last_probe or {}).get("cluster_name") if getattr(ep, "last_probe", None) else None
    nid = create(db, rt, provider="proxmox", customer_id=ep.customer_id, label=f"{ep.name} {role}", credential_type="api_token",
                 purpose="inventory" if role == "inventory" else "provision", secret=secret, identity=identity, cluster=cluster,
                 host=urlparse(ep.base_url).hostname, actor=actor, actor_id=actor_id, reason=reason)
    db.execute(text(f"UPDATE endpoints SET {ROLE_COL[role]} = :c WHERE id = :e"), {"c": nid, "e": str(ep.id)})
    return nid


def release_endpoint_role(db: Session, ep, role: str, *, actor: str, reason: str) -> None:
    cid = getattr(ep, ROLE_COL[role], None)
    if cid:
        revoke(db, cid, actor=actor, reason=reason)
        db.execute(text(f"UPDATE endpoints SET {ROLE_COL[role]} = NULL WHERE id = :e"), {"e": str(ep.id)})


def adopt_endpoint(db: Session, rt: Runtime, endpoint_id, actor: str = "migration") -> int:
    """Move legacy per-endpoint secret blobs into the credential subsystem (idempotent). Returns credentials created."""
    ep = db.execute(text("SELECT * FROM endpoints WHERE id = :i FOR UPDATE"), {"i": str(endpoint_id)}).first()
    if ep is None or ep.detached_at is not None:
        return 0
    n = 0
    for role, blob, ident in (("inventory", ep.token_secret_enc, ep.token_id), ("provision", ep.provision_secret_enc, ep.provision_token_id)):
        if getattr(ep, ROLE_COL[role]) or not ident or blob is None or len(bytes(blob)) == 0:
            continue
        secret = rt.vault.decrypt(blob, _legacy_aad(ep, role)).decode()
        attach_endpoint_credential(db, rt, ep, role, ident, secret, actor=actor, reason="migrated from per-endpoint secret column")
        n += 1
    if n:
        from ..actions import trust_binding
        db.execute(text("UPDATE endpoints SET trust_binding = :b WHERE id = :e"),
                   {"b": trust_binding(ep.base_url, ep.token_id, ep.fingerprint_sha256, ep.ca_pem, ep.allowed_nodes), "e": str(ep.id)})
        db.execute(text("UPDATE endpoints SET token_secret_enc = NULL, provision_secret_enc = CASE WHEN provision_token_id IS NULL THEN NULL "
                        "ELSE '\\x'::bytea END WHERE id = :e"), {"e": str(ep.id)})
        audit.append(db, "credential.migrated", actor_name=actor, resource="endpoint", resource_id=str(ep.id), details={"credentials": n})
    return n


def adopt_all(rt: Runtime) -> int:
    """Startup/CLI data migration for pre-existing endpoints (safe to run repeatedly)."""
    total = 0
    with rt.session() as db:
        ids = [r.id for r in db.execute(text("SELECT id FROM endpoints WHERE detached_at IS NULL AND ((inventory_credential_id IS NULL "
                                             "AND token_secret_enc IS NOT NULL AND length(token_secret_enc) > 0) OR (provision_credential_id IS NULL "
                                             "AND provision_secret_enc IS NOT NULL AND length(provision_secret_enc) > 0))")).all()]
        for i in ids:
            try:
                total += adopt_endpoint(db, rt, i)
                db.commit()
            except (VaultError, ValueError) as e:
                db.rollback()
                log.error("credential migration failed for endpoint %s: %s", i, type(e).__name__)
    return total
