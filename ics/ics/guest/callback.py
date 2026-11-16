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
  * rate limited per source IP, per bootstrap id (reserved budget of every known VM) and, separately, for unknown ids (in memory, per process); counted per bootstrap id;
  * CA-pinned on the guest side: the guest only talks to the SMBIOS-delivered URL after matching the delivered certificate pin; the response carries
    an HMAC acknowledgement so the guest also authenticates the ICS with the secret (a pinned-cert holder without the secret is rejected too);
  * the enrollment token the guest generated travels inside this authenticated call and is stored vault-encrypted until enrollment finishes."""
import hashlib
import hmac
import ipaddress
import json
import re
import socket
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
# Review 5 M1: NO single global bucket that an anonymous flood can drain for everybody. Requests naming a bootstrap id that exists are limited per
# bid (= per VM, their own reserved budget: it cannot be consumed by unknown-id traffic); requests naming unknown ids share a separate, bounded budget.
PER_BID_LIMIT, PER_BID_WINDOW = 30, 60.0
UNKNOWN_LIMIT, UNKNOWN_WINDOW = 60, 60.0
MAX_BODY = 4096                      # review 5 L2: enforced, not just documented
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

    def is_limited(self, key: str, limit: int, window: float, now: float | None = None) -> bool:
        """Read-only peek for the console: would the next request be refused? (consumes nothing)"""
        now = time.monotonic() if now is None else now
        with self._lock:
            q = self._hits.get(key)
            return bool(q) and sum(1 for t in q if t > now - window) >= limit

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


LIMITER = RateLimiter()
_DENY = HTTPException(401, "rejected")   # one generic answer for every failure: no oracle for bids, expiry or use


_DUMMY: dict = {}


def _dummy_work(rt) -> None:
    if "blob" not in _DUMMY:
        _DUMMY["blob"] = rt.vault.encrypt(b"0" * 64, "bootstrap-dummy")
    rt.vault.decrypt(_DUMMY["blob"], "bootstrap-dummy")
    with rt.session() as db:
        db.execute(text("UPDATE guest_bootstrap SET attempts = attempts WHERE id = :i"), {"i": "00000000-0000-0000-0000-000000000000"})
        db.commit()


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
    if not LIMITER.allow("ip:" + src, PER_IP_LIMIT, PER_IP_WINDOW):
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
    bucket_ok = (LIMITER.allow("bid:" + body.bid, PER_BID_LIMIT, PER_BID_WINDOW) if row is not None
                 else LIMITER.allow("unknown", UNKNOWN_LIMIT, UNKNOWN_WINDOW))
    if not bucket_ok:
        raise HTTPException(429, "too many requests", headers={"Retry-After": "30"})
    dummy = "00" * 32
    secret = None
    if row is not None and row.secret_enc is not None:
        secret = rt.vault.decrypt(row.secret_enc, bootsecrets._ctx(str(row.id), "secret")).decode()
    else:
        _dummy_work(rt)   # review 5 L3: the unknown-id path costs the same decrypt and the same DB round trip as a known one
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
            if row.state == "reported":
                # review 5 M2: a second valid proof before enrollment finished means two parties hold the secret: the deployment must STOP.
                # The record fails and its material is wiped; await_callback / the enrollment step see `failed` and fail the VM closed.
                db.execute(text("UPDATE guest_bootstrap SET state = 'failed', secret_enc = NULL, ssh_key_enc = NULL, token_enc = NULL, secret_deleted_at = now() "
                                "WHERE id = :i AND state IN ('pending', 'reported')"), {"i": str(row.id)})
                audit.append(db, "guest.bootstrap_failed_by_replay", actor_name="guest", resource="guest_bootstrap", resource_id=body.bid, ip=src,
                             details={"deployment_id": str(row.deployment_id), "vm": row.vm})
            db.commit()
            raise _DENY
        audit.append(db, "guest.bootstrap_report", actor_name="guest", resource="guest_bootstrap", resource_id=body.bid, ip=src,
                     details={"deployment_id": str(row.deployment_id), "vm": row.vm, "vmid": row.vmid, "address": a.address, "port": a.port,
                              "tls_fingerprint": a.tls_fingerprint_sha256, "agent_key_fingerprint": a.agent_key_fingerprint_sha256})
        db.commit()
    conf = _resolve_config(rt, row.config, src)
    return {"ok": True, "ack": ack(secret, body.nonce), "config": conf, "config_mac": config_mac(secret, body.nonce, conf)}


def config_mac(secret_hex: str, nonce: str, conf: dict) -> str:
    return hmac.new(bytes.fromhex(secret_hex), ("ou-bootstrap-config-v1\n" + nonce + "\n" + canon_json(conf)).encode(), hashlib.sha256).hexdigest()


def canon_json(v) -> str:
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _resolve_config(rt, conf: dict | None, guest_ip: str) -> dict:
    """The stored per-VM configuration with the ICS's own address towards the guest filled in where the plan said 'the ICS'."""
    conf = json.loads(json.dumps(conf or {}))
    if conf.get("mgmt_sources") is None or any(p.get("sources") is None for p in conf.get("ports", [])):
        mgmt = [_ics_address_towards(guest_ip) + "/32"]
        if conf.get("mgmt_sources") is None:
            conf["mgmt_sources"] = mgmt
        for p in conf.get("ports", []):
            if p.get("sources") is None:
                p["sources"] = list(conf["mgmt_sources"])
    return conf


def _ics_address_towards(addr: str) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sk:
        sk.connect((addr, 9))   # no packet is sent: only asks the kernel which local address routes there
        return sk.getsockname()[0]


def register(app, rt) -> None:
    @app.post(PATH)
    async def guest_bootstrap_report(request: Request):
        from fastapi.concurrency import run_in_threadpool
        from pydantic import ValidationError
        try:
            if int(request.headers.get("content-length", "0") or 0) > MAX_BODY:
                raise HTTPException(413, "body too large")
        except ValueError:
            raise HTTPException(400, "bad content-length") from None
        raw = bytearray()
        async for chunk in request.stream():   # also caps chunked bodies that carry no Content-Length
            raw += chunk
            if len(raw) > MAX_BODY:
                raise HTTPException(413, "body too large")
        try:
            body = ReportIn.model_validate_json(bytes(raw))
        except ValidationError:
            raise HTTPException(422, "invalid report") from None
        return await run_in_threadpool(handle_report, rt, body, source_ip(request, rt))


def create_callback_app():
    """Review 5 L4: a DEDICATED app that serves nothing but the bootstrap callback (and /healthz). Run it as its own listener (`python -m ics.serve_callback`,
    unit ics-callback.service) behind its own reverse-proxy server block / bind address; guest networks then reach no login page and no console API.
    Set ICS_GUEST_CALLBACK_DEDICATED=true so the console app stops serving the callback route as well."""
    from fastapi import FastAPI
    from ..runtime import Runtime
    from ..config import load_settings
    rt = Runtime(load_settings())
    app = FastAPI(title="Office Unbound guest callback", docs_url=None, redoc_url=None, openapi_url=None)
    register(app, rt)

    @app.get("/healthz")
    def healthz():
        return {"ok": True}
    return app
