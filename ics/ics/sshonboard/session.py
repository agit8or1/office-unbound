"""Admin SSH sessions: the admin's SSH credential is a short-lived (30 min), customer-bound, single-purpose vault secret. It is stored only through the
credential subsystem (envelope encrypted; AAD binds credential id + provider + customer), never returned by any API, never logged, and destroyed when
the onboarding job ends, on cancel and on expiry."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import text
from sqlalchemy.orm import Session

from .. import audit
from ..credentials import service as cred_service
from ..proxmox import ProxmoxError, check_destination
from ..runtime import Runtime
from .client import HostKey, SshError, fetch_host_key

PROVIDER = "pve-ssh"
TTL_SECONDS = 30 * 60
PUBLIC = ("id, customer_id, host, port, username, auth, use_sudo, api_url, state, hk_algo, hk_candidate AS hostkey_candidate, hk_pinned AS hostkey_pinned, "
          "api_cert_ssh, api_cert_seen, api_cert_pinned, api_trust, api_proxy, created_at, expires_at, finished_at")


class SessionError(Exception):
    def __init__(self, status: int, msg: str):
        self.status, self.msg = status, msg


def now() -> datetime:
    return datetime.now(timezone.utc)


def create(db: Session, rt: Runtime, user, ip, *, customer_id, host: str, port: int, username: str, password: str | None, private_key: str | None,
           passphrase: str | None, api_url: str | None) -> dict:
    if bool(password) == bool(private_key):
        raise SessionError(422, "supply exactly one of password / private key")
    if passphrase and not private_key:
        raise SessionError(422, "a passphrase only applies to a private key")
    try:
        check_destination(host, rt.settings.allow_loopback_endpoints)
    except ProxmoxError as e:
        raise SessionError(422, str(e)) from None
    sid = uuid.uuid4()
    secret = {"password": password} if password else {"private_key": private_key, "passphrase": passphrase}
    cred_service.create(db, rt, provider=PROVIDER, customer_id=customer_id, label=f"SSH onboarding {host}:{port}",
                        credential_type="password" if password else "ssh_key", purpose="temporary_provisioning", secret=json.dumps(secret),
                        identity=username, host=host, expires_at=now() + timedelta(seconds=TTL_SECONDS), actor=user.username, actor_id=user.id,
                        reason="admin credential for SSH onboarding (single use, 30 minutes)", ip=ip, cred_id=sid)
    db.execute(text("INSERT INTO ssh_sessions (id, customer_id, created_by, host, port, username, auth, use_sudo, api_url, expires_at) "
                    "VALUES (:i, :c, :u, :h, :p, :n, :a, :s, :api, :e)"),
               {"i": str(sid), "c": str(customer_id), "u": str(user.id), "h": host, "p": port, "n": username, "a": "password" if password else "key",
                "s": username != "root", "api": api_url, "e": now() + timedelta(seconds=TTL_SECONDS)})
    audit.append(db, "ssh.session.created", actor_id=user.id, actor_name=user.username, ip=ip, resource="ssh_session", resource_id=str(sid),
                 details={"host": host, "port": port, "username": username, "auth": "password" if password else "key", "expires_in_s": TTL_SECONDS})
    return view(db, sid)


def row(db: Session, sid):
    return db.execute(text("SELECT * FROM ssh_sessions WHERE id = :i"), {"i": str(sid)}).first()


def view(db: Session, sid) -> dict:
    r = db.execute(text(f"SELECT {PUBLIC} FROM ssh_sessions WHERE id = :i"), {"i": str(sid)}).first()
    d = {k: (v.isoformat() if isinstance(v, datetime) else str(v) if isinstance(v, uuid.UUID) else v) for k, v in r._mapping.items()}
    d["hostkey_verify_command"] = None
    if r.hostkey_candidate:
        from .client import KEYFILE
        d["hostkey_verify_command"] = f"ssh-keygen -lf /etc/ssh/{KEYFILE[r.hk_algo]}"
    d["credential"] = "stored in the vault (never shown); destroyed after use, on cancel or after 30 minutes"
    return d


def live(db: Session, sid, user_id=None):
    """The session if it is usable now (not expired / finished); raises SessionError otherwise."""
    r = row(db, sid)
    if r is None:
        raise SessionError(404, "SSH session not found")
    if r.state in ("used", "cancelled", "expired", "failed") or r.expires_at <= now():
        raise SessionError(409, "this SSH session is finished or expired: enter the SSH credentials again")
    if user_id is not None and str(r.created_by) != str(user_id):
        raise SessionError(404, "SSH session not found")
    return r


def fetch_candidate(db: Session, rt: Runtime, sid) -> dict:
    """Unauthenticated host-key fetch (SSRF-guarded). Nothing is sent but the SSH handshake; nothing runs until the admin confirms the fingerprint."""
    r = live(db, sid)
    if r.state != "new":
        raise SessionError(409, "the host key was already confirmed for this session")
    try:
        check_destination(r.host, rt.settings.allow_loopback_endpoints)
        hk = fetch_host_key(r.host, r.port)
    except (ProxmoxError, SshError) as e:
        raise SessionError(502, str(e)) from None
    db.execute(text("UPDATE ssh_sessions SET hk_algo = :a, hk_candidate = :f WHERE id = :i"), {"a": hk.algo, "f": hk.fingerprint, "i": str(sid)})
    audit.append(db, "ssh.hostkey.presented", actor_name="ics", resource="ssh_session", resource_id=str(sid),
                 details={"host": r.host, "port": r.port, "algo": hk.algo, "fingerprint": hk.fingerprint})
    return view(db, sid)


def confirm(db: Session, user, ip, sid, fingerprint: str) -> dict:
    r = live(db, sid, user.id)
    if r.state != "new" or not r.hk_candidate:
        raise SessionError(409, "no host key is waiting for confirmation")
    import hmac
    if not hmac.compare_digest(fingerprint.strip(), r.hk_candidate):
        raise SessionError(422, "the fingerprint you typed does not match the one the node presented; nothing was confirmed")
    db.execute(text("UPDATE ssh_sessions SET hk_pinned = hk_candidate, state = 'pinned' WHERE id = :i"), {"i": str(sid)})
    audit.append(db, "ssh.hostkey.confirmed", actor_id=user.id, actor_name=user.username, ip=ip, resource="ssh_session", resource_id=str(sid),
                 details={"host": r.host, "port": r.port, "algo": r.hk_algo, "fingerprint": r.hk_candidate})
    return view(db, sid)


def confirm_proxy(db: Session, user, ip, sid, fingerprint: str) -> dict:
    """The API address is served by something other than the node (a reverse proxy) with a publicly valid certificate. The administrator confirms the
    proxy's certificate fingerprint (hex SHA-256, colons optional); trust stays 'public chain + host name'."""
    import hmac
    from ..proxmox import normalize_fingerprint
    r = live(db, sid, user.id)
    if r.api_proxy != "pending" or not r.api_cert_seen:
        raise SessionError(409, "no proxy confirmation is pending for this session")
    try:
        fp = normalize_fingerprint(fingerprint)
    except ValueError:
        raise SessionError(422, "fingerprint must be 64 hex characters (SHA-256)") from None
    if not hmac.compare_digest(fp, r.api_cert_seen):
        raise SessionError(422, "that is not the certificate the ICS sees on the API address; nothing was confirmed")
    db.execute(text("UPDATE ssh_sessions SET api_proxy = 'confirmed' WHERE id = :i"), {"i": str(sid)})
    audit.append(db, "ssh.api_proxy.confirmed", actor_id=user.id, actor_name=user.username, ip=ip, resource="ssh_session", resource_id=str(sid),
                 details={"proxy_leaf_sha256": fp, "node_leaf_sha256": r.api_cert_ssh, "trust": r.api_trust})
    return view(db, sid)


def pinned_key(r) -> HostKey:
    if r.state != "pinned" or not r.hk_pinned:
        raise ProxmoxError("the node's SSH host key has not been confirmed")
    return HostKey(r.hk_algo, r.hk_pinned)


def wipe(db: Session, sid, state: str, actor: str, reason: str) -> None:
    """Destroy the admin credential (ciphertext) and close the session. Idempotent."""
    c = cred_service.get_row(db, sid)
    if c is not None and c.purged_at is None:
        cred_service.revoke(db, sid, actor=actor, reason=reason)
    db.execute(text("UPDATE ssh_sessions SET state = :s, finished_at = COALESCE(finished_at, now()) WHERE id = :i AND state NOT IN ('used','cancelled','expired','failed')"),
               {"s": state, "i": str(sid)})
    audit.append(db, "ssh.session.wiped", actor_name=actor, resource="ssh_session", resource_id=str(sid), details={"state": state, "reason": reason})


def cancel(db: Session, user, ip, sid) -> None:
    live(db, sid, user.id)
    wipe(db, sid, "cancelled", user.username, "cancelled by the operator")


def load_secret(rt: Runtime, sid, actor: str) -> dict:
    try:
        return json.loads(cred_service.get_secret(rt, sid, use="ssh.onboard", actor=actor))
    except cred_service.CredentialUnavailable:
        raise ProxmoxError("the SSH credential is no longer available (expired, cancelled or already used): enter it again") from None


def sweep(db: Session) -> int:
    """Reaper hook: expired / abandoned sessions lose their credential; unused generated identity keys expire with the session."""
    n = 0
    for r in db.execute(text("SELECT id FROM ssh_sessions WHERE state NOT IN ('used','cancelled','expired','failed') AND expires_at <= now() FOR UPDATE")).all():
        wipe(db, r.id, "expired", "system", "SSH session expired (30 minutes)")
        n += 1
    for r in db.execute(text("SELECT c.id FROM credentials c WHERE c.provider = :p AND c.purged_at IS NULL AND c.expires_at IS NOT NULL AND c.expires_at <= now() "
                             "FOR UPDATE OF c"), {"p": PROVIDER}).all():
        cred_service.revoke(db, r.id, actor="system", reason="SSH onboarding credential expired")
        n += 1
    return n
