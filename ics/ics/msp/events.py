"""MSP webhooks: transactional outbox + signed, retried, at-least-once delivery.

Events are captured from the hash-chained audit log (audit.append -> on_audit) inside the transaction that produced them, so an event exists
iff the state change committed. Delivery runs on the worker (tick); a consumer must de-duplicate on `id` (the same event id is re-sent on retry).

Signature (docs/api/msp-v1.yaml, "Webhooks"):  X-MSP-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256(webhook secret, "<t>.<raw body>")>
"""
import hashlib
import hmac
import json
import logging
import ipaddress
import secrets
import socket
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import httpx
from sqlalchemy import text

from .. import audit

log = logging.getLogger("ics.msp.events")

EVENT_TYPES = ("plan.approved", "plan.rejected", "job.completed", "job.failed", "incident.opened", "incident.recovered")
BACKOFF = (5, 30, 120, 600, 3600, 6 * 3600, 12 * 3600)   # seconds before attempt 2..8
MAX_ATTEMPTS = len(BACKOFF) + 1
TIMEOUT = 10.0
LEASE_SECONDS = 90


def new_webhook_secret() -> str:
    return "whsec_" + secrets.token_urlsafe(32)


def sign(secret: str, body: bytes, t: int) -> str:
    mac = hmac.new(secret.encode(), f"{t}.".encode() + body, hashlib.sha256).hexdigest()
    return f"t={t},v1={mac}"


DENIED = "webhook destination is not allowed"   # ONE message for every resolution/range refusal: no oracle about the network behind the ICS
_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_EXTRA_DENY = (_CGNAT, ipaddress.ip_network("192.0.0.0/24"), ipaddress.ip_network("198.18.0.0/15"), ipaddress.ip_network("64:ff9b::/96"),
               ipaddress.ip_network("2002::/16"))


def _resolve(host: str, port: int) -> list[str]:
    """Seam for tests. Every address the name resolves to."""
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return sorted({i[4][0].split("%")[0] for i in infos})


def _allowed(host: str, ip: str, allow_loopback: bool, allow: tuple[str, ...]) -> bool:
    a = ipaddress.ip_address(ip)
    if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped:
        a = a.ipv4_mapped
    for entry in allow:   # explicit, operator-approved exceptions (hostname or CIDR)
        try:
            if a in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            if entry.lower() == host.lower():
                return True
    if a.is_loopback:
        return allow_loopback
    if a.is_unspecified or a.is_multicast or a.is_link_local or a.is_reserved or a.is_private or not a.is_global or any(a in n for n in _EXTRA_DENY):
        return False
    return True


class Pin:
    """The validated destination: connect to `ips` (never resolve again), TLS name and Host header stay the original hostname."""

    def __init__(self, scheme: str, host: str, port: int, target: str, ips: list[str]):
        self.scheme, self.host, self.port, self.target, self.ips = scheme, host, port, target, ips

    def url_for(self, ip: str) -> str:
        h = f"[{ip}]" if ":" in ip else ip
        return f"{self.scheme}://{h}:{self.port}{self.target}"

    @property
    def host_header(self) -> str:
        default = 443 if self.scheme == "https" else 80
        return self.host if self.port == default else f"{self.host}:{self.port}"


def resolve_checked(url: str, allow_loopback: bool, allow: tuple[str, ...] = ()) -> Pin:
    """Raises ValueError. https only (plain http only when the lab/test loopback flag is set); the name must resolve, and EVERY address must be a
    global unicast one (no private/loopback/link-local/CGNAT/ULA/metadata) unless explicitly allow-listed. Returns the addresses to connect to."""
    u = urlparse(url)
    if u.scheme not in ("https", "http") or not u.hostname or u.username or u.password or u.fragment:
        raise ValueError("url must be https://host[:port]/path without credentials")
    if u.scheme == "http" and not allow_loopback:
        raise ValueError("webhook urls must be https")
    try:
        port = u.port or (443 if u.scheme == "https" else 80)
    except ValueError:
        raise ValueError("url must be https://host[:port]/path without credentials") from None
    try:
        ips = _resolve(u.hostname, port)
    except (OSError, UnicodeError):
        raise ValueError(DENIED) from None
    if not ips or not all(_allowed(u.hostname, ip, allow_loopback, allow) for ip in ips):
        raise ValueError(DENIED)
    return Pin(u.scheme, u.hostname, port, (u.path or "/") + (f"?{u.query}" if u.query else ""), ips)


def check_url(url: str, allow_loopback: bool, allow: tuple[str, ...] = ()) -> None:
    resolve_checked(url, allow_loopback, allow)


# ---- capture -------------------------------------------------------------------------------------------------------------------

def _origin(db, user_id) -> str:
    r = db.execute(text("SELECT c.client_id FROM msp_clients c WHERE c.user_id = :u"), {"u": str(user_id)}).first()
    return f"msp_client:{r.client_id}" if r else "console"


def _plan_event(db, plan_id) -> tuple | None:
    p = db.execute(text("SELECT id, action, risk, customer_id, requested_by FROM plans WHERE id = :i"), {"i": str(plan_id)}).first()
    return (p, str(p.customer_id) if p.customer_id else None) if p else None


def on_audit(db, action: str, resource_id, details: dict) -> None:
    etype = data = cust = None
    if action == "job.queued":
        got = _plan_event(db, details.get("plan_id"))
        if got:
            p, cust = got
            etype, data = "plan.approved", {"plan_id": str(p.id), "action": p.action, "risk": p.risk, "job_id": str(resource_id),
                                            "auto_approved": bool(details.get("auto_approved")), "origin": _origin(db, p.requested_by)}
    elif action in ("plan.reject", "plan.expired"):
        got = _plan_event(db, resource_id)
        if got:
            p, cust = got
            etype, data = "plan.rejected", {"plan_id": str(p.id), "action": p.action, "risk": p.risk,
                                            "reason": "expired" if action == "plan.expired" else "rejected", "origin": _origin(db, p.requested_by)}
    elif action in ("job.succeeded", "job.failed"):
        j = db.execute(text("SELECT j.plan_id FROM jobs j WHERE j.id = :i"), {"i": str(resource_id)}).first()
        got = _plan_event(db, j.plan_id) if j else None
        if got:
            p, cust = got
            ok = action == "job.succeeded"
            etype = "job.completed" if ok else "job.failed"
            data = {"job_id": str(resource_id), "plan_id": str(p.id), "action": p.action, "origin": _origin(db, p.requested_by)}
            if ok:
                data["result"] = audit.scrub(details.get("result"))
            else:
                data["error"] = {"type": (details.get("error") or {}).get("type"), "message": (details.get("error") or {}).get("message")}
    elif action in ("incident.opened", "incident.recovered"):
        i = db.execute(text("SELECT i.id, i.check_id, i.severity, i.title, c.name AS check_name, d.slug, cu.id AS customer_id FROM incidents i "
                            "JOIN checks c ON c.id = i.check_id LEFT JOIN deployments d ON d.id = c.deployment_id "
                            "LEFT JOIN customers cu ON cu.slug = d.customer_id WHERE i.id = :i"), {"i": str(resource_id)}).first()
        if i:
            etype = "incident.opened" if action == "incident.opened" else "incident.recovered"
            cust = str(i.customer_id) if i.customer_id else None
            data = {"incident_id": str(i.id), "check_id": str(i.check_id), "check_name": i.check_name, "severity": i.severity, "title": i.title,
                    "deployment": i.slug}
    if etype:
        emit(db, etype, cust, data)


def emit(db, etype: str, customer_id: str | None, data: dict) -> str:
    eid = db.execute(text("INSERT INTO msp_events (type, customer_id, data) VALUES (:t, :c, CAST(:d AS jsonb)) RETURNING id"),
                     {"t": etype, "c": customer_id, "d": audit.canon(audit.sanitize(data))}).scalar()
    db.execute(text(
        "INSERT INTO msp_deliveries (event_id, webhook_id) SELECT :e, w.id FROM msp_webhooks w JOIN msp_clients c ON c.id = w.client_id "
        "WHERE w.enabled AND w.deleted_at IS NULL AND c.status = 'active' AND :t = ANY(w.events) AND "
        "(c.all_customers OR (CAST(:cu AS uuid) IS NOT NULL AND EXISTS (SELECT 1 FROM msp_client_customers m WHERE m.client_id = c.id AND m.customer_id = CAST(:cu AS uuid))))"),
        {"e": str(eid), "t": etype, "cu": customer_id})
    return str(eid)


def envelope(ev) -> dict:
    return {"id": str(ev.id), "type": ev.type, "api_version": "v1", "created_at": ev.created_at.isoformat(),
            "customer_id": str(ev.customer_id) if ev.customer_id else None, "data": ev.data}


# ---- delivery ------------------------------------------------------------------------------------------------------------------

def tick(rt, limit: int = 20, transport: httpx.BaseTransport | None = None) -> int:
    """Claim due deliveries (lease), send them, record the outcome. Returns the number attempted."""
    with rt.session() as db:
        rows = db.execute(text("SELECT id FROM msp_deliveries WHERE status = 'pending' AND next_attempt_at <= now() ORDER BY next_attempt_at "
                               "LIMIT :n FOR UPDATE SKIP LOCKED"), {"n": limit}).all()
        ids = [str(r.id) for r in rows]
        if ids:
            db.execute(text("UPDATE msp_deliveries SET next_attempt_at = now() + make_interval(secs => :l) WHERE id = ANY(CAST(:i AS uuid[]))"),
                       {"l": LEASE_SECONDS, "i": ids})
        db.commit()
    for d in ids:
        try:
            deliver(rt, d, transport)
        except Exception:  # noqa: BLE001
            log.exception("webhook delivery %s crashed", d)
    return len(ids)


def deliver(rt, delivery_id: str, transport: httpx.BaseTransport | None = None) -> None:
    with rt.session() as db:
        r = db.execute(text("SELECT d.attempts, d.webhook_id, w.url, w.secret_enc, w.enabled, w.deleted_at, e.id, e.type, e.customer_id, e.data, e.created_at FROM msp_deliveries d "
                            "JOIN msp_webhooks w ON w.id = d.webhook_id JOIN msp_events e ON e.id = d.event_id WHERE d.id = :i AND d.status = 'pending'"),
                       {"i": delivery_id}).first()
        if r is None:
            return
        attempt = r.attempts + 1
        status, err = None, None
        if not r.enabled or r.deleted_at is not None:
            db.execute(text("UPDATE msp_deliveries SET status = 'dead', last_error = 'webhook disabled' WHERE id = :i"), {"i": delivery_id})
            db.commit()
            return
        try:
            pin = resolve_checked(r.url, rt.settings.allow_loopback_endpoints, rt.settings.msp_webhook_allow)   # re-resolved NOW: a rebound name is refused
            secret = rt.vault.decrypt(r.secret_enc, f"msp-webhook:{r.webhook_id}").decode()
            body = audit.canon(envelope(r)).encode()
            t = int(time.time())
            headers = {"content-type": "application/json", "user-agent": "OfficeUnbound-ICS-MSP/1", "x-msp-event-id": str(r.id),
                       "x-msp-event-type": r.type, "x-msp-delivery-id": delivery_id, "x-msp-delivery-attempt": str(attempt),
                       "x-msp-signature": sign(secret, body, t)}
            headers["host"] = pin.host_header
            resp = None
            with httpx.Client(timeout=TIMEOUT, follow_redirects=False, trust_env=False, transport=transport) as c:
                for ip in pin.ips:   # connect to the address that was just checked, TLS verified against the ORIGINAL name (SNI), no second lookup
                    try:
                        resp = c.post(pin.url_for(ip), content=body, headers=headers, extensions={"sni_hostname": pin.host} if pin.scheme == "https" else {})
                        break
                    except httpx.ConnectError:
                        continue
            if resp is None:
                raise OSError("connect")
            status = resp.status_code
            if not 200 <= status < 300:
                err = "failed"
        except Exception as e:  # noqa: BLE001  (never store transport text that might echo secrets: class name only)
            err = "failed"   # one generic outcome for the API client; the network detail never leaves the ICS (no reachability oracle)
        if err is None:
            db.execute(text("UPDATE msp_deliveries SET status = 'delivered', attempts = :a, last_status = :s, last_error = NULL, delivered_at = now() WHERE id = :i"),
                       {"a": attempt, "s": status, "i": delivery_id})
        elif attempt >= MAX_ATTEMPTS:
            db.execute(text("UPDATE msp_deliveries SET status = 'dead', attempts = :a, last_status = :s, last_error = :e WHERE id = :i"),
                       {"a": attempt, "s": status, "e": err, "i": delivery_id})
            audit.append(db, "msp.webhook.dead", actor_name="worker", resource="msp_webhook", resource_id=str(r.webhook_id),
                         details={"event_id": str(r.id), "type": r.type, "last_error": err})
        else:
            db.execute(text("UPDATE msp_deliveries SET attempts = :a, last_status = :s, last_error = :e, "
                            "next_attempt_at = now() + make_interval(secs => :b) WHERE id = :i"),
                       {"a": attempt, "s": status, "e": err, "b": BACKOFF[attempt - 1], "i": delivery_id})
        db.commit()


def purge(rt) -> None:
    with rt.session() as db:
        db.execute(text("DELETE FROM msp_events WHERE created_at < now() - interval '30 days' AND NOT EXISTS "
                        "(SELECT 1 FROM msp_deliveries d WHERE d.event_id = msp_events.id AND d.status = 'pending')"))
        db.commit()
