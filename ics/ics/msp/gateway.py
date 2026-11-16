"""MSP API gateway: request authentication (HMAC-SHA256 signing + nonce + clock skew + optional mTLS), permission sets, customer scoping,
idempotency, rate limiting, audit and the uniform response envelope. Routes (api.py) are plain functions `fn(ctx, **path) -> (status, body)`.

Signature (docs/api/msp-v1.yaml, "Authentication"):
  string_to_sign = "OU-MSP1\\n" + METHOD + "\\n" + request-target + "\\n" + timestamp + "\\n" + nonce + "\\n" + hex(sha256(body))
  X-MSP-Signature: v1=<hex HMAC-SHA256(secret, string_to_sign)>
The request-target is the raw path plus "?query" exactly as sent. The secret is the one-time-revealed `mspk_...` key.
"""
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

from fastapi import FastAPI, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationError
from sqlalchemy import text

from .. import audit, auth
from ..tenancy import scope as tscope

BASE = "/api/msp/v1"
SKEW_SECONDS = 120
NONCE_TTL = 2 * SKEW_SECONDS + 30
IDEM_TTL = timedelta(hours=24)
IDEM_STALE = 300
_NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
_IDEM_RE = re.compile(r"^[A-Za-z0-9._:~-]{8,128}$")
_CLIENT_RE = re.compile(r"^mspc_[0-9a-f]{16}$")
MUTATING = ("POST", "PUT", "PATCH", "DELETE")
# route name -> {"sunset": datetime, "successor": "/path"}; empty in v1.0. A deprecated route keeps working until its sunset date.
DEPRECATIONS: dict[str, dict] = {}


class MspError(Exception):
    def __init__(self, status: int, code: str, message: str, details=None, headers: dict | None = None):
        super().__init__(message)
        self.status, self.code, self.message, self.details, self.headers = status, code, message, details, headers or {}


def string_to_sign(method: str, target: str, ts: str, nonce: str, body: bytes) -> bytes:
    return "\n".join(["OU-MSP1", method.upper(), target, ts, nonce, hashlib.sha256(body).hexdigest()]).encode()


def sign(secret: str, method: str, target: str, ts: str, nonce: str, body: bytes) -> str:
    return "v1=" + hmac.new(secret.encode(), string_to_sign(method, target, ts, nonce, body), hashlib.sha256).hexdigest()


@dataclass
class Client:
    row: object
    user: object
    perms: frozenset
    customer_ids: frozenset | None

    @property
    def client_id(self) -> str:
        return self.row.client_id


@dataclass
class Ctx:
    rt: object
    db: object
    client: Client
    request_id: str
    method: str
    target: str
    body: bytes
    query: dict
    ip: str | None
    audit_extra: dict = field(default_factory=dict)

    def json(self, model: type[BaseModel] | None = None, *, optional: bool = False):
        if not self.body.strip():
            if optional:
                return model.model_validate({}) if model else {}
            raise MspError(422, "validation_error", "a JSON body is required")
        try:
            raw = json.loads(self.body)
        except ValueError:
            raise MspError(422, "validation_error", "body is not valid JSON") from None
        if model is None:
            return raw
        try:
            return model.model_validate(raw)
        except ValidationError as e:
            raise MspError(422, "validation_error", "request validation failed",
                           [{"loc": [str(x) for x in err["loc"]], "msg": err["msg"]} for err in e.errors()]) from None

    def need(self, perm: str) -> None:
        if perm not in self.client.perms:
            raise MspError(403, "forbidden", f"this API client lacks the '{perm}' permission", {"required_permission": perm})

    def scope_clause(self, column: str) -> str:
        return tscope.clause(self.client.user, column)

    def in_scope(self, customer_id) -> bool:
        return tscope.allowed(self.client.user, customer_id)


# ---- rate limit / failure throttles (per process) ------------------------------------------------------------------------------------

_lock = threading.Lock()
_buckets: dict[str, list[float]] = {}   # client uuid -> [tokens, last monotonic]
_fails: dict[str, list[float]] = {}     # ip -> failure timestamps
_housekeeping = {"at": 0.0}
FAIL_LIMIT = 30


def reset_state() -> None:
    with _lock:
        _buckets.clear()
        _fails.clear()
        _housekeeping["at"] = 0.0


def _take(client_key: str, per_minute: int) -> tuple[bool, int, float]:
    """Token bucket: capacity = per_minute, refill per_minute/60 per second. Returns (allowed, remaining, seconds until a token is free)."""
    now = time.monotonic()
    with _lock:
        b = _buckets.setdefault(client_key, [float(per_minute), now])
        b[0] = min(float(per_minute), b[0] + (now - b[1]) * per_minute / 60.0)
        b[1] = now
        if b[0] >= 1:
            b[0] -= 1
            return True, int(b[0]), 0.0
        return False, 0, (1 - b[0]) * 60.0 / per_minute


def _fail_count(ip: str) -> int:
    now = time.monotonic()
    with _lock:
        v = [t for t in _fails.get(ip, []) if now - t < 60]
        if v:
            _fails[ip] = v
        else:
            _fails.pop(ip, None)
        return len(v)


def _note_fail(ip: str) -> None:
    with _lock:
        if ip not in _fails and len(_fails) >= 10000:   # review 6 L6: evict the stalest address, never reset everyone's counters
            _fails.pop(min(_fails, key=lambda a: _fails[a][-1] if _fails[a] else 0.0), None)
        _fails.setdefault(ip, []).append(time.monotonic())


# ---- authentication ------------------------------------------------------------------------------------------------------------------

def _authenticate(rt, db, method: str, target: str, headers, body: bytes, ip: str | None) -> tuple[Client, str]:
    def deny(code: str, msg: str = "authentication failed", status: int = 401):
        raise MspError(status, code, msg, headers={"WWW-Authenticate": 'OU-MSP1 realm="msp"'} if status == 401 else None)

    cid, ts, nonce, sig = (headers.get(h, "") for h in ("x-msp-client", "x-msp-timestamp", "x-msp-nonce", "x-msp-signature"))
    if not (cid and ts and nonce and sig):
        deny("auth_headers_missing", "X-MSP-Client, X-MSP-Timestamp, X-MSP-Nonce and X-MSP-Signature are required")
    if not _CLIENT_RE.match(cid) or not _NONCE_RE.match(nonce) or not re.fullmatch(r"[0-9]{1,12}", ts) or not re.fullmatch(r"v1=[0-9a-f]{64}", sig):
        deny("auth_malformed")
    if abs(time.time() - int(ts)) > SKEW_SECONDS:
        deny("timestamp_out_of_window", f"clock skew exceeds {SKEW_SECONDS}s")
    row = db.execute(text("SELECT * FROM msp_clients WHERE client_id = :c"), {"c": cid}).first()
    ok, version = False, None
    if row is not None and row.status == "active" and row.secret_enc is not None:
        cands = [(row.secret_enc, row.secret_version)]
        if row.prev_secret_enc is not None and row.prev_secret_expires_at and row.prev_secret_expires_at > datetime.now(timezone.utc):
            cands.append((row.prev_secret_enc, row.prev_secret_version))
        for blob, v in cands:  # every candidate is compared (no early exit that leaks which key matched)
            try:
                secret = rt.vault.decrypt(blob, f"msp-client:{row.id}:{v}").decode()
            except Exception:  # noqa: BLE001
                continue
            if hmac.compare_digest(sign(secret, method, target, ts, nonce, body), sig):
                ok, version = True, v
    else:
        hmac.compare_digest(sig, sig)
    if not ok:
        deny("invalid_signature")
    if row.mtls_fingerprint:
        # The TLS proxy terminates mTLS and forwards the verified certificate fingerprint in X-Client-Cert-SHA256 (it always OVERWRITES that header) together with
        # a shared secret in X-OU-Proxy-Auth (review 6 L5). The peer address is not a usable proof here: behind the proxy uvicorn rewrites it to the forwarded
        # client address, and a loopback proxy is indistinguishable from any other local process.
        fp = (headers.get("x-client-cert-sha256") or "").replace(":", "").lower()
        sec = rt.settings.msp_proxy_auth or ""
        proxy_ok = bool(sec) and hmac.compare_digest((headers.get("x-ou-proxy-auth") or "").encode(), sec.encode())
        if not (proxy_ok and hmac.compare_digest(fp.encode(), row.mtls_fingerprint.encode())):
            deny("client_certificate_required", "a valid client certificate is required for this API client", 401)
    n = db.execute(text("INSERT INTO msp_nonces (client_id, nonce, expires_at) VALUES (:c, :n, now() + make_interval(secs => :t)) ON CONFLICT DO NOTHING"),
                   {"c": str(row.id), "n": nonce, "t": NONCE_TTL}).rowcount
    if n == 0:
        deny("replayed_request", "this nonce was already used")
    urow = db.execute(text("SELECT * FROM users WHERE id = :u"), {"u": str(row.user_id)}).first()
    user = auth.User(urow)
    user.msp_client = row.client_id
    ids = None if row.all_customers else frozenset(str(r.customer_id) for r in db.execute(
        text("SELECT customer_id FROM msp_client_customers WHERE client_id = :c"), {"c": str(row.id)}))
    user.customer_ids = ids
    db.info["customer_ids"] = ids
    db.execute(text("UPDATE msp_clients SET last_used_at = now() WHERE id = :i"), {"i": str(row.id)})
    return Client(row, user, frozenset(row.permissions), ids), ("previous" if version != row.secret_version else "current")


def _housekeep(db) -> None:
    now = time.monotonic()
    if now - _housekeeping["at"] < 60:
        return
    _housekeeping["at"] = now
    db.execute(text("DELETE FROM msp_nonces WHERE expires_at < now()"))
    db.execute(text("DELETE FROM msp_idempotency WHERE created_at < now() - make_interval(secs => :t)"), {"t": int(IDEM_TTL.total_seconds())})


# ---- idempotency ---------------------------------------------------------------------------------------------------------------------

def _idem_begin(ctx: Ctx, key: str | None):
    """Returns a stored (status, body) to replay, or None after inserting this request's marker inside the CURRENT transaction (so the marker,
    the plan it creates and the stored response commit atomically; a concurrent request with the same key blocks on the unique index)."""
    if key is None or not _IDEM_RE.match(key):
        raise MspError(400, "idempotency_key_required" if key is None else "idempotency_key_invalid",
                       "mutating requests need an Idempotency-Key header (8-128 chars of A-Za-z0-9._:~-)")
    rh = hashlib.sha256(f"{ctx.method}\n{ctx.target}\n{hashlib.sha256(ctx.body).hexdigest()}".encode()).hexdigest()
    p = {"c": str(ctx.client.row.id), "k": key, "h": rh}
    for _ in range(3):
        n = ctx.db.execute(text("INSERT INTO msp_idempotency (client_id, idem_key, request_hash) VALUES (:c, :k, :h) ON CONFLICT DO NOTHING"), p).rowcount
        if n:
            return None
        row = ctx.db.execute(text("SELECT request_hash, status, response_enc, extract(epoch FROM now() - created_at) AS age FROM msp_idempotency "
                                  "WHERE client_id = :c AND idem_key = :k"), p).first()
        if row is None:
            continue
        if row.age > IDEM_TTL.total_seconds() or (row.status is None and row.age > IDEM_STALE):
            ctx.db.execute(text("DELETE FROM msp_idempotency WHERE client_id = :c AND idem_key = :k"), p)
            continue
        if row.request_hash != rh:
            raise MspError(409, "idempotency_key_reused", "this Idempotency-Key was already used with a different request")
        if row.status is None:
            raise MspError(409, "idempotency_in_progress", "a request with this Idempotency-Key is still being processed; retry shortly")
        body = json.loads(ctx.rt.vault.decrypt(row.response_enc, f"msp-idem:{ctx.client.row.id}:{key}"))
        return row.status, body
    raise MspError(409, "idempotency_in_progress", "could not settle the Idempotency-Key; retry")


def _idem_finish(ctx: Ctx, key: str, status: int, body) -> None:
    blob = ctx.rt.vault.encrypt(json.dumps(body).encode(), f"msp-idem:{ctx.client.row.id}:{key}")
    ctx.db.execute(text("UPDATE msp_idempotency SET status = :s, response_enc = :r WHERE client_id = :c AND idem_key = :k"),
                   {"s": status, "r": blob, "c": str(ctx.client.row.id), "k": key})


# ---- dispatch ------------------------------------------------------------------------------------------------------------------------

def _error_body(e: MspError, rid: str) -> dict:
    err = {"code": e.code, "message": e.message, "request_id": rid}
    if e.details is not None:
        err["details"] = e.details
    return {"error": err}


def _handle(rt, name: str, perm: str, mutation: bool, fn, method: str, target: str, headers: dict, body: bytes, ip: str | None, params: dict, query: dict):
    rid = "req_" + uuid.uuid4().hex[:20]
    out_headers = {"X-Request-Id": rid, "X-MSP-API-Version": "1"}
    dep = DEPRECATIONS.get(name)
    if dep:
        out_headers["Deprecation"] = "true"
        out_headers["Sunset"] = format_datetime(dep["sunset"], usegmt=True)
        if dep.get("successor"):
            out_headers["Link"] = f'<{dep["successor"]}>; rel="successor-version"'
    if ip and _fail_count(ip) >= FAIL_LIMIT:
        return JSONResponse(_error_body(MspError(429, "too_many_failures", "too many failed authentications from this address"), rid), 429,
                            {**out_headers, "Retry-After": "60"})
    db = rt.session()
    ctx = None
    status, resp, key, replay = 500, None, None, False
    try:
        try:
            _housekeep(db)
            client, which = _authenticate(rt, db, method, target, headers, body, ip)
            db.commit()  # the nonce is consumed for good, whatever happens next (429, 403, handler error)
        except MspError as e:
            db.rollback()
            if ip:
                _note_fail(ip)
            audit.append(db, "msp.auth_failed", actor_name="msp:" + (headers.get("x-msp-client", "")[:40] or "?"), ip=ip,
                         details={"reason": e.code, "method": method, "path": target[:300], "request_id": rid})
            db.commit()
            return JSONResponse(_error_body(e, rid), e.status, {**out_headers, **e.headers})
        ctx = Ctx(rt, db, client, rid, method, target, body, query, ip)
        ok, remaining, wait = _take(str(client.row.id), client.row.rate_limit_per_minute)
        out_headers.update({"X-RateLimit-Limit": str(client.row.rate_limit_per_minute), "X-RateLimit-Remaining": str(remaining)})
        try:
            if not ok:
                raise MspError(429, "rate_limited", "rate limit exceeded", headers={"Retry-After": str(int(wait) + 1)})
            ctx.need(perm)
            if which == "previous":
                out_headers["X-MSP-Key-Status"] = "previous-key-in-grace-period; rotate your integration to the new key"
            if mutation:
                key = headers.get("idempotency-key")
                replayed = _idem_begin(ctx, key)
                if replayed:
                    status, resp, replay = replayed[0], replayed[1], True
            if not replay:
                status, resp = fn(ctx, **params)
                if mutation:
                    _idem_finish(ctx, key, status, resp)
        except MspError as e:
            db.rollback()
            status, resp = e.status, _error_body(e, rid)
            out_headers.update(e.headers)
            ctx.audit_extra["error"] = e.code
        except Exception:  # noqa: BLE001
            db.rollback()
            import logging
            logging.getLogger("ics.msp").exception("unhandled error in %s", name)
            status, resp = 500, {"error": {"code": "internal_error", "message": "internal error; quote the request_id to the MSP", "request_id": rid}}
            ctx.audit_extra["error"] = "internal_error"
        audit.append(db, "msp.request", actor_id=client.user.id, actor_name=f"msp:{client.client_id}", ip=ip, resource="msp_client",
                     resource_id=str(client.row.id),
                     details={"method": method, "path": target[:300], "route": name, "status": status, "request_id": rid, "replay": replay,
                              "idempotency_key": key, "permission": perm, **ctx.audit_extra})
        db.commit()
        if replay:
            out_headers["Idempotent-Replay"] = "true"
        return JSONResponse(resp, status, out_headers)
    finally:
        db.close()


def register(app: FastAPI, rt_getter=None) -> "Router":
    return Router(app)


class Router:
    def __init__(self, app: FastAPI):
        self.app = app

    def route(self, method: str, path: str, perm: str, name: str):
        mutation = method in MUTATING

        def deco(fn):
            async def endpoint(request: Request):
                body = await request.body()
                raw = request.scope.get("raw_path") or request.url.path.encode()
                qs = request.scope.get("query_string", b"")
                target = raw.decode("latin-1") + (("?" + qs.decode("latin-1")) if qs else "")
                rt = request.app.state.rt
                ip = request.client.host if request.client else None
                return await run_in_threadpool(_handle, rt, name, perm, mutation, fn, request.method, target, dict(request.headers), body, ip,
                                               dict(request.path_params), dict(request.query_params))
            endpoint.__name__ = f"msp_{name}"
            self.app.add_api_route(BASE + path, endpoint, methods=[method], include_in_schema=False, name=f"msp.{name}")
            return fn
        return deco
