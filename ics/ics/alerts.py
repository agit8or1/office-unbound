"""Alert delivery channels. Interface: validate_config(cfg)->cfg, send(cfg, secret, message).

email    SMTP to a configured relay (STARTTLS/implicit TLS verified against a CA bundle or pinned leaf, or explicit plaintext for a lab relay).
webhook  HTTPS POST, JSON body, HMAC-SHA256 signed: X-OU-Timestamp + X-OU-Signature: v1=hex(hmac(key, f"{timestamp}.{body}")).
pushover / sms  interface + config validation only. DISABLED: they are third-party paid services (ADR-0007: opt-in, default off, $0), so
                a channel of these kinds can be stored (disabled) but `send` always raises ChannelDisabled.
"""
import hashlib
import hmac
import json
import smtplib
import time
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Literal
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .checks import HOST_RE, USER_RE, _Base, _Trust, _https_url
from .proxmox import check_destination


class ChannelDisabled(Exception):
    pass


class ChannelError(Exception):
    pass


@dataclass
class Message:
    event: str          # opened | recovered | severity_changed | escalated | reminder | test
    subject: str
    text: str
    payload: dict       # structured form for webhooks


class EmailConfig(_Base):
    model_config = ConfigDict(extra="forbid")
    host: str = Field(pattern=HOST_RE)
    port: int = Field(default=25, ge=1, le=65535)
    tls: Literal["starttls", "implicit", "none"] = "starttls"
    allow_plaintext: bool = False
    from_addr: str = Field(max_length=200, pattern=r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$")
    to_addrs: list[str] = Field(min_length=1, max_length=10)
    username: str | None = Field(default=None, pattern=USER_RE)
    ca_pem: str | None = Field(default=None, max_length=100_000)
    fingerprint_sha256: str | None = None

    @field_validator("to_addrs")
    @classmethod
    def _to(cls, v):
        import re
        for a in v:
            if not re.fullmatch(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+", a) or len(a) > 200:
                raise ValueError("invalid recipient address")
        return v

    @model_validator(mode="after")
    def _tls(self):
        if self.tls == "none":
            if not self.allow_plaintext:
                raise ValueError("tls=none sends alert text unencrypted: set allow_plaintext=true to accept that (lab relays only)")
            if self.ca_pem or self.fingerprint_sha256:
                raise ValueError("no trust anchor with tls=none")
            if self.username:
                raise ValueError("refusing to send credentials without TLS")
        else:
            _Trust(ca_pem=self.ca_pem, fingerprint_sha256=self.fingerprint_sha256)  # exactly one anchor, validated
        return self


class WebhookConfig(_Trust):
    url: str
    _u = field_validator("url")(_https_url)
    timeout_seconds: int = Field(default=10, ge=1, le=30)

    @property
    def host(self):
        return urlparse(self.url).hostname or ""


class PushoverConfig(_Base):
    model_config = ConfigDict(extra="forbid")
    user_key: str = Field(pattern=r"^[A-Za-z0-9]{20,40}$")
    priority: int = Field(default=0, ge=-1, le=1)


class SmsConfig(_Base):
    model_config = ConfigDict(extra="forbid")
    to_number: str = Field(pattern=r"^\+[1-9][0-9]{6,14}$")
    gateway_url: str
    _u = field_validator("gateway_url")(_https_url)


MODELS = {"email": EmailConfig, "webhook": WebhookConfig, "pushover": PushoverConfig, "sms": SmsConfig}
DISABLED_KINDS = {"pushover", "sms"}   # paid third-party services: ADR-0007, never enabled by default or by code path
NEEDS_SECRET = {"webhook": True, "pushover": True, "sms": True, "email": False}


def validate_config(kind: str, cfg: dict) -> dict:
    return MODELS[kind].model_validate(cfg).model_dump(mode="json", exclude_none=True)


def validate_secret(kind: str, secret: str | None, cfg: dict) -> None:
    if kind == "webhook" and (not secret or len(secret) < 16):
        raise ValueError("webhook needs a signing secret of at least 16 characters")
    if kind == "email" and cfg.get("username") and not secret:
        raise ValueError("email username given without a password")
    if kind == "email" and secret and not cfg.get("username"):
        raise ValueError("email password given without a username")


def config_host(kind: str, cfg: dict) -> str | None:
    if kind in ("email",):
        return cfg["host"]
    if kind == "webhook":
        return urlparse(cfg["url"]).hostname
    return None  # disabled kinds are never contacted


def sign_webhook(key: str, timestamp: str, body: bytes) -> str:
    return "v1=" + hmac.new(key.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()


def verify_webhook(key: str, timestamp: str, body: bytes, signature: str, *, max_age: int = 300, now: float | None = None) -> bool:
    try:
        if abs((now or time.time()) - int(timestamp)) > max_age:
            return False
    except ValueError:
        return False
    return hmac.compare_digest(sign_webhook(key, timestamp, body), signature)


def _send_email(cfg: dict, secret: str | None, msg: Message, allow_loopback: bool) -> None:
    c = EmailConfig.model_validate(cfg)
    check_destination(c.host, allow_loopback)
    em = EmailMessage()
    em["From"], em["To"], em["Subject"] = c.from_addr, ", ".join(c.to_addrs), msg.subject[:200]
    em["X-OU-ICS-Event"] = msg.event
    em.set_content(msg.text)
    ctx = None if c.tls == "none" else _Trust(ca_pem=c.ca_pem, fingerprint_sha256=c.fingerprint_sha256).ctx()
    try:
        if c.tls == "implicit":
            s = smtplib.SMTP_SSL(c.host, c.port, timeout=15, context=ctx)
        else:
            s = smtplib.SMTP(c.host, c.port, timeout=15)
        with s:
            s.ehlo()
            if c.tls == "starttls":
                s.starttls(context=ctx)
                s.ehlo()
            if c.username and secret:
                s.login(c.username, secret)
            refused = s.send_message(em)
            if refused:
                raise ChannelError("recipient refused")
    except (smtplib.SMTPException, OSError) as e:
        raise ChannelError(f"smtp failed: {type(e).__name__}: {str(e)[:150]}") from None


def _send_webhook(cfg: dict, secret: str | None, msg: Message, allow_loopback: bool) -> None:
    from . import egress
    c = WebhookConfig.model_validate(cfg)
    check_destination(c.host, allow_loopback)
    body = json.dumps(msg.payload, sort_keys=True, separators=(",", ":")).encode()
    ts = str(int(time.time()))
    try:
        with httpx.Client(verify=c.ctx(), timeout=httpx.Timeout(c.timeout_seconds), follow_redirects=False, trust_env=False, event_hooks=egress.hooks()) as h:
            r = h.post(c.url, content=body, headers={"Content-Type": "application/json", "X-OU-Timestamp": ts,
                                                      "X-OU-Signature": sign_webhook(secret or "", ts, body), "X-OU-Event": msg.event})
    except Exception as e:  # noqa: BLE001
        raise ChannelError(f"webhook failed: {type(e).__name__}") from None
    if not 200 <= r.status_code < 300:
        raise ChannelError(f"webhook returned HTTP {r.status_code}")


def send(kind: str, cfg: dict, secret: str | None, msg: Message, *, allow_loopback: bool = False) -> None:
    from . import egress
    egress.require()      # review 7 H-5: no notification from a fenced/standby controller
    if kind in DISABLED_KINDS:
        raise ChannelDisabled(f"{kind} is a paid third-party service and is disabled (ADR-0007)")
    {"email": _send_email, "webhook": _send_webhook}[kind](cfg, secret, msg, allow_loopback)
