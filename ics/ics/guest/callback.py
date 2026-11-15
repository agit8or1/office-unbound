"""The guest bootstrap callback endpoint (production path, docs/status/bootstrap-v2.md): `POST /api/v1/guest-bootstrap/report`.

A guest booted from the golden image calls this once from its first-boot unit (`ou-bootstrap.service`, ics/agent/ou_agent/firstboot.py). It carries NO
session: its authenticator is an HMAC keyed with a random per-VM-instance secret that only the ICS (vault) and the hypervisor-delivered SMBIOS serial
know. Properties:

  * minimal: a fixed JSON object, validated field by field, 4 KiB cap; nothing from it is ever executed or interpolated anywhere;
  * authenticated: HMAC-SHA256 over a canonical string that binds the bootstrap id, a nonce, a timestamp (+-5 min), the agent's address/port/TLS
    fingerprint/key fingerprint and the hash of the enrollment token the guest generated; compared in constant time; the source IP must be the
    reported agent address (a stolen secret cannot point the ICS at another host);
  * single use + short TTL: the first valid report moves the record pending -> reported atomically; a second valid report with the same secret is a
    REPLAY (clone or impostor) and raises an alarm audit event; expired/used/unknown records are indistinguishable from a bad proof (one generic 401);
  * rate limited per source IP and globally (in memory, per process) and counted per bootstrap id;
  * CA-pinned on the guest side: the guest only talks to the SMBIOS-delivered URL after matching the delivered certificate pin; the response carries
    an HMAC acknowledgement so the guest also authenticates the ICS with the secret (a pinned-cert holder without the secret is rejected too);
  * the enrollment token the guest generated travels inside this authenticated call and is stored vault-encrypted until enrollment finishes."""
import hashlib
import hmac
import ipaddress
import re
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

from fastapi import HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text

from .. import audit
from . import bootsecrets

PATH = "/api/v1/guest-bootstrap/report"
SKEW_SECONDS = 300
PER_IP_LIMIT, PER_IP_WINDOW = 12, 60.0
GLOBAL_LIMIT, GLOBAL_WINDOW = 120, 60.0
HEX64 = re.compile(r"^[0-9a-f]{64}$")
BID = re.compile(r"^[0-9a-f]{16}$")
NONCE = re.compile(r"^[0-9a-f]{32}$")
TOKEN = re.compile(r"^[A-Za-z0-9_-]{32,64}$")


class AgentIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    address: str = Field(max_length=15)
    port: int = Field(ge=1024, le=65535)
    tls_fingerprint_sha256: str = Field(max_length=64)
    agent_key_fingerprint_sha256: str = Field(max_length=64)


class ReportIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    v: int
    bid: str = Field(max_length=16)
    nonce: str = Field(max_length=32)
    ts: int
    agent: AgentIn
    enroll_token: str = Field(max_length=64)
    proof: str = Field(max_length=64)


def canonical(bid: str, nonce: str, ts: int, address: str, port: int, tls: str, key: str, token: str) -> bytes:
    return "\n".join(["ou-bootstrap-report-v1", bid, nonce, str(ts), address, str(port), tls, key,
                      hashlib.sha256(token.encode()).hexdigest()]).encode()


def proof(secret_hex: str, msg: bytes) -> str:
    return hmac.new(bytes.fromhex(secret_hex), msg, hashlib.sha256).hexdigest()


def ack(secret_hex: str, nonce: str) -> str:
    return hmac.new(bytes.fromhex(secret_hex), f"ou-bootstrap-ack-v1\n{nonce}".encode(), hashlib.sha256).hexdigest()


class RateLimiter:
    def __init__(self):
        self._lock = threading.Lock()
        self._hits: dict[str, deque] = defaultdict(deque)

    def allow(self, key: str, limit: int, window: float, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        with self._lock:
            q = self._hits[key]
            while q and q[0] <= now - window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            if len(self._hits) > 10000:   # bounded memory under a spray from many addresses
                for k in [k for k, v in self._hits.items() if not v or v[-1] <= now - window][:5000]:
                    self._hits.pop(k, None)
            return True

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


LIMITER = RateLimiter()
_DENY = HTTPException(401, "rejected")   # one generic answer for every failure: no oracle for bids, expiry or use


def source_ip(request: Request, rt) -> str:
    host = request.client.host if request.client else ""
    tp = rt.settings.trusted_proxy
    if tp and host == tp:
        xff = request.headers.get("x-forwarded-for", "").split(",")[-1].strip()
        if xff:
            return xff
    return host


def handle_report(rt, body: ReportIn, src: str) -> dict:
    """Pure core (no HTTP objects): returns the response body or raises HTTPException."""
    if not LIMITER.allow("ip:" + src, PER_IP_LIMIT, PER_IP_WINDOW) or not LIMITER.allow("global", GLOBAL_LIMIT, GLOBAL_WINDOW):
        raise HTTPException(429, "too many requests", headers={"Retry-After": "30"})
    a = body.agent
    if (body.v != 1 or not BID.match(body.bid) or not NONCE.match(body.nonce) or not HEX64.match(a.tls_fingerprint_sha256)
            or not HEX64.match(a.agent_key_fingerprint_sha256) or not TOKEN.match(body.enroll_token) or not re.fullmatch(r"[0-9a-f]{64}", body.proof)):
        raise _DENY
    try:
        ip = ipaddress.IPv4Address(a.address)
    except ValueError:
        raise _DENY from None
    if ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_link_local or ip.is_reserved:
        raise _DENY
    row = bootsecrets.by_bid(rt, body.bid)
    dummy = "00" * 32
    secret = None
    if row is not None and row.secret_enc is not None:
        secret = rt.vault.decrypt(row.secret_enc, bootsecrets._ctx(str(row.id), "secret")).decode()
    want = proof(secret or dummy, canonical(body.bid, body.nonce, body.ts, a.address, a.port, a.tls_fingerprint_sha256, a.agent_key_fingerprint_sha256,
                                            body.enroll_token))
    good = hmac.compare_digest(want, body.proof) and secret is not None
    if not good:
        if row is not None:
            with rt.session() as db:   # counted per bootstrap id (an attacker without the secret cannot do more than this)
                db.execute(text("UPDATE guest_bootstrap SET attempts = attempts + 1 WHERE id = :i"), {"i": str(row.id)})
                if row.attempts + 1 in (1, 10, 100):
                    audit.append(db, "guest.bootstrap_report_rejected", actor_name="guest", resource="guest_bootstrap", resource_id=body.bid,
                                 ip=src, details={"reason": "bad proof", "attempts": row.attempts + 1})
                db.commit()
        raise _DENY
    now = datetime.now(timezone.utc)
    if abs(time.time() - body.ts) > SKEW_SECONDS or src != a.address:
        raise _DENY
    with rt.session() as db:
        upd = db.execute(text(
            "UPDATE guest_bootstrap SET state = 'reported', reported_at = now(), token_enc = :t, report = CAST(:r AS jsonb) "
            "WHERE id = :i AND state = 'pending' AND expires_at > :n AND secret_enc IS NOT NULL AND mode = 'callback' RETURNING id"),
            {"t": rt.vault.encrypt(body.enroll_token.encode(), bootsecrets._ctx(str(row.id), "token")), "i": str(row.id), "n": now,
             "r": audit.canon({"address": a.address, "port": a.port, "tls_fingerprint_sha256": a.tls_fingerprint_sha256,
                               "agent_key_fingerprint_sha256": a.agent_key_fingerprint_sha256, "ts": body.ts, "source_ip": src})}).first()
        if upd is None:
            # valid proof but not pending: a replay (a clone, or someone who read the secret) or an expired attempt -> ALARM, nothing accepted
            audit.append(db, "guest.bootstrap_replay_alarm", actor_name="guest", resource="guest_bootstrap", resource_id=body.bid, ip=src,
                         details={"state": row.state, "expired": row.expires_at <= now, "reported_address": a.address})
            db.commit()
            raise _DENY
        audit.append(db, "guest.bootstrap_report", actor_name="guest", resource="guest_bootstrap", resource_id=body.bid, ip=src,
                     details={"deployment_id": str(row.deployment_id), "vm": row.vm, "vmid": row.vmid, "address": a.address, "port": a.port,
                              "tls_fingerprint": a.tls_fingerprint_sha256, "agent_key_fingerprint": a.agent_key_fingerprint_sha256})
        db.commit()
    return {"ok": True, "ack": ack(secret, body.nonce)}


def register(app, rt) -> None:
    @app.post(PATH)
    def guest_bootstrap_report(body: ReportIn, request: Request):
        return handle_report(rt, body, source_ip(request, rt))
