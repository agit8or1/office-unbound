"""Webhook helpers: verify the X-MSP-Signature header and de-duplicate deliveries (at-least-once delivery => the same event id can arrive twice)."""
import hashlib
import hmac
import json
import time


def verify_signature(secret: str, raw_body: bytes, header: str, *, tolerance: int = 300, now: float | None = None) -> bool:
    """`header` is `t=<unix>,v1=<hex>`; the MAC covers `"<t>.<raw body>"`. Verify against the RAW bytes, not re-serialised JSON."""
    try:
        parts = dict(p.split("=", 1) for p in header.split(","))
        t, mac = int(parts["t"]), parts["v1"]
    except (KeyError, ValueError):
        return False
    if abs((now if now is not None else time.time()) - t) > tolerance:
        return False
    expect = hmac.new(secret.encode(), f"{t}.".encode() + raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expect, mac)


class EventDeduper:
    """Remember processed event ids (replace the set with your database in production)."""

    def __init__(self):
        self.seen: set[str] = set()

    def first_time(self, event: dict) -> bool:
        if event["id"] in self.seen:
            return False
        self.seen.add(event["id"])
        return True


def parse_event(secret: str, raw_body: bytes, headers: dict) -> dict:
    sig = {k.lower(): v for k, v in headers.items()}.get("x-msp-signature", "")
    if not verify_signature(secret, raw_body, sig):
        raise PermissionError("bad webhook signature")
    return json.loads(raw_body)
