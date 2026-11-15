"""Deterministic service checks (no LLM). Typed config models + runners.

Every TLS-capable check requires exactly one trust anchor (CA bundle or leaf SHA-256 pin), like Proxmox endpoints (ADR-0002 item 3);
nothing here ever disables verification. Runners return an Outcome and never raise: failures are results. Secrets (mailbox / EWS
passwords) come from the vault, are passed in by the caller, and are scrubbed from every message.
"""
import datetime
import imaplib
import json
import re
import smtplib
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Any, Literal, Self
from urllib.parse import urlparse

import httpx
from cryptography import x509
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .proxmox import ProxmoxError, build_ssl_context, check_destination, normalize_fingerprint

KINDS = ("http", "tcp_tls", "imap_login", "smtp_banner", "ews_getfolder")
HOST_RE = r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$"
USER_RE = r"^[A-Za-z0-9][A-Za-z0-9._@+-]{0,127}$"
MAX_BODY = 1024 * 1024


@dataclass
class Outcome:
    status: Literal["ok", "warning", "critical"]
    message: str
    latency_ms: int | None = None
    details: dict = field(default_factory=dict)


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid")


class _Trust(_Base):
    ca_pem: str | None = Field(default=None, max_length=100_000)
    fingerprint_sha256: str | None = None

    @field_validator("ca_pem")
    @classmethod
    def _pem(cls, v):
        if v is None:
            return v
        try:
            if not x509.load_pem_x509_certificates(v.encode()):
                raise ValueError
        except Exception:  # noqa: BLE001
            raise ValueError("ca_pem must contain valid PEM certificate(s)") from None
        return v

    @field_validator("fingerprint_sha256")
    @classmethod
    def _fp(cls, v):
        return normalize_fingerprint(v) if v is not None else None

    @model_validator(mode="after")
    def _one_trust(self) -> Self:
        if bool(self.ca_pem) == bool(self.fingerprint_sha256):
            raise ValueError("TLS trust is required: provide exactly one of ca_pem or fingerprint_sha256")
        return self

    def ctx(self) -> ssl.SSLContext:
        return build_ssl_context(ca_pem=self.ca_pem, fingerprint_sha256=self.fingerprint_sha256)


def _https_url(cls, v):
    u = urlparse(v)
    if u.scheme != "https" or not u.hostname or u.username or u.password or u.fragment:
        raise ValueError("url must be https://host[:port]/path with no credentials")
    return v


class HttpCheck(_Trust):
    url: str
    expect_status: int = Field(default=200, ge=100, le=599)
    body_contains: str | None = Field(default=None, max_length=200)
    json_path: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_]+([.][A-Za-z0-9_]+)*$", max_length=100)
    json_equals: str | int | bool | None = None
    warn_latency_ms: int | None = Field(default=None, ge=1, le=60000)
    timeout_seconds: int = Field(default=10, ge=1, le=30)

    _chk_url = field_validator("url")(_https_url)

    @property
    def host(self) -> str:
        return urlparse(self.url).hostname or ""


class TcpTlsCheck(_Trust):
    host: str = Field(pattern=HOST_RE)
    port: int = Field(ge=1, le=65535)
    warn_days: int = Field(default=21, ge=1, le=3650)
    crit_days: int = Field(default=7, ge=0, le=3650)
    timeout_seconds: int = Field(default=10, ge=1, le=30)

    @model_validator(mode="after")
    def _days(self) -> Self:
        if self.crit_days >= self.warn_days:
            raise ValueError("crit_days must be smaller than warn_days")
        return self


class ImapLoginCheck(_Trust):
    host: str = Field(pattern=HOST_RE)
    port: int = Field(default=993, ge=1, le=65535)
    username: str = Field(pattern=USER_RE)
    mailbox: str = Field(default="INBOX", pattern=r"^[A-Za-z0-9 ._/-]{1,64}$")
    timeout_seconds: int = Field(default=10, ge=1, le=30)


class SmtpBannerCheck(_Base):
    host: str = Field(pattern=HOST_RE)
    port: int = Field(default=25, ge=1, le=65535)
    banner_contains: str | None = Field(default=None, max_length=100)
    timeout_seconds: int = Field(default=10, ge=1, le=30)


class EwsGetFolderCheck(_Trust):
    url: str
    username: str = Field(pattern=USER_RE)
    folder: Literal["inbox", "calendar", "contacts", "sentitems", "drafts"] = "inbox"
    timeout_seconds: int = Field(default=15, ge=1, le=30)

    _chk_url = field_validator("url")(_https_url)

    @property
    def host(self) -> str:
        return urlparse(self.url).hostname or ""


MODELS: dict[str, type[BaseModel]] = {"http": HttpCheck, "tcp_tls": TcpTlsCheck, "imap_login": ImapLoginCheck,
                                      "smtp_banner": SmtpBannerCheck, "ews_getfolder": EwsGetFolderCheck}
NEEDS_PASSWORD = {"imap_login", "ews_getfolder"}


def validate_config(kind: str, cfg: dict) -> dict:
    return MODELS[kind].model_validate(cfg).model_dump(mode="json", exclude_none=True)


def config_host(kind: str, cfg: dict) -> str:
    m = MODELS[kind].model_validate(cfg)
    return m.host  # type: ignore[attr-defined]


def _scrub(s: str, secret: str | None) -> str:
    s = s.replace(secret, "[secret]") if secret and len(secret) >= 4 else s
    return re.sub(r"[^\x20-\x7e]", "?", s)[:300]


def _ms(t0: float) -> int:
    return int((time.monotonic() - t0) * 1000)


def _fail(t0, msg, secret=None, status="critical", **d) -> Outcome:
    return Outcome(status, _scrub(msg, secret), _ms(t0), d)


# ---- runners ---------------------------------------------------------------------------------

def run_http(cfg: HttpCheck, allow_loopback: bool) -> Outcome:
    t0 = time.monotonic()
    check_destination(cfg.host, allow_loopback)
    buf = bytearray()
    with httpx.Client(verify=cfg.ctx(), timeout=httpx.Timeout(cfg.timeout_seconds), follow_redirects=False, trust_env=False) as c:
        with c.stream("GET", cfg.url) as r:
            for ch in r.iter_raw():
                buf += ch
                if len(buf) > MAX_BODY:
                    return _fail(t0, "response body exceeds 1 MiB")
            code = r.status_code
    lat = _ms(t0)
    if code != cfg.expect_status:
        return Outcome("critical", f"HTTP {code}, expected {cfg.expect_status}", lat, {"status": code})
    text = bytes(buf).decode("utf-8", "replace")
    if cfg.body_contains and cfg.body_contains not in text:
        return Outcome("critical", "expected body text not found", lat, {"status": code})
    if cfg.json_path:
        try:
            v: Any = json.loads(text)
            for part in cfg.json_path.split("."):
                v = v[int(part)] if isinstance(v, list) else v[part]
        except (ValueError, KeyError, IndexError, TypeError):
            return Outcome("critical", f"JSON field {cfg.json_path} missing", lat, {"status": code})
        if cfg.json_equals is not None and v != cfg.json_equals:
            return Outcome("critical", f"JSON field {cfg.json_path} has unexpected value", lat, {"status": code})
    if cfg.warn_latency_ms and lat > cfg.warn_latency_ms:
        return Outcome("warning", f"HTTP {code} but slow: {lat} ms > {cfg.warn_latency_ms} ms", lat, {"status": code})
    return Outcome("ok", f"HTTP {code} in {lat} ms", lat, {"status": code})


def run_tcp_tls(cfg: TcpTlsCheck, allow_loopback: bool) -> Outcome:
    t0 = time.monotonic()
    check_destination(cfg.host, allow_loopback)
    ctx = cfg.ctx()
    with socket.create_connection((cfg.host, cfg.port), timeout=cfg.timeout_seconds) as raw:
        with ctx.wrap_socket(raw, server_hostname=cfg.host) as s:
            der = s.getpeercert(binary_form=True)
    cert = x509.load_der_x509_certificate(der)
    left = (cert.not_valid_after_utc - datetime.datetime.now(datetime.timezone.utc)).total_seconds() / 86400
    days = int(left // 1)
    det = {"days_left": days, "not_after": cert.not_valid_after_utc.isoformat()}
    if left < cfg.crit_days:
        return Outcome("critical", f"certificate expires in {days} days" if left > 0 else "certificate has expired", _ms(t0), det)
    if left < cfg.warn_days:
        return Outcome("warning", f"certificate expires in {days} days", _ms(t0), det)
    return Outcome("ok", f"certificate valid for {days} more days", _ms(t0), det)


def run_imap(cfg: ImapLoginCheck, password: str, allow_loopback: bool) -> Outcome:
    t0 = time.monotonic()
    check_destination(cfg.host, allow_loopback)
    m = imaplib.IMAP4_SSL(cfg.host, cfg.port, ssl_context=cfg.ctx(), timeout=cfg.timeout_seconds)
    try:
        m.login(cfg.username, password)
        typ, data = m.select(cfg.mailbox, readonly=True)
        if typ != "OK":
            return _fail(t0, f"SELECT {cfg.mailbox} failed", password)
        n = int(data[0]) if data and data[0] and data[0].isdigit() else None
        return Outcome("ok", f"login + SELECT {cfg.mailbox} ok ({n} messages)", _ms(t0), {"exists": n})
    finally:
        try:
            m.logout()
        except Exception:  # noqa: BLE001
            pass


def run_smtp(cfg: SmtpBannerCheck, allow_loopback: bool) -> Outcome:
    t0 = time.monotonic()
    check_destination(cfg.host, allow_loopback)
    s = smtplib.SMTP(timeout=cfg.timeout_seconds)
    try:
        code, banner = s.connect(cfg.host, cfg.port)
        b = banner.decode("ascii", "replace")
        if code != 220:
            return _fail(t0, f"SMTP greeting {code}")
        if cfg.banner_contains and cfg.banner_contains not in b:
            return _fail(t0, "SMTP banner does not contain the expected text")
        c2, _ = s.ehlo()
        if c2 != 250:
            return _fail(t0, f"EHLO returned {c2}")
        return Outcome("ok", "SMTP 220 banner + EHLO ok", _ms(t0), {"banner": _scrub(b, None)[:100]})
    finally:
        try:
            s.close()
        except Exception:  # noqa: BLE001
            pass


_SOAP = ('<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" '
         'xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" '
         'xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"><soap:Header>'
         '<t:RequestServerVersion Version="Exchange2013"/></soap:Header><soap:Body><m:GetFolder><m:FolderShape>'
         '<t:BaseShape>Default</t:BaseShape></m:FolderShape><m:FolderIds><t:DistinguishedFolderId Id="{folder}"/>'
         '</m:FolderIds></m:GetFolder></soap:Body></soap:Envelope>')


def run_ews(cfg: EwsGetFolderCheck, password: str, allow_loopback: bool) -> Outcome:
    t0 = time.monotonic()
    check_destination(cfg.host, allow_loopback)
    buf = bytearray()
    with httpx.Client(verify=cfg.ctx(), timeout=httpx.Timeout(cfg.timeout_seconds), follow_redirects=False, trust_env=False,
                      auth=httpx.BasicAuth(cfg.username, password)) as c:
        with c.stream("POST", cfg.url, content=_SOAP.replace("{folder}", cfg.folder).encode(),
                      headers={"Content-Type": "text/xml; charset=utf-8"}) as r:
            for ch in r.iter_raw():
                buf += ch
                if len(buf) > MAX_BODY:
                    return _fail(t0, "EWS response exceeds 1 MiB", password)
            code = r.status_code
    text = bytes(buf).decode("utf-8", "replace")
    if code != 200:
        return _fail(t0, f"EWS HTTP {code}", password, status_code=code)
    if "<!DOCTYPE" in text or "<!ENTITY" in text:
        return _fail(t0, "EWS response contains a DTD; refusing to parse", password)
    ok = 'ResponseClass="Success"' in text and "NoError" in text
    if not ok:
        return _fail(t0, "EWS GetFolder did not return Success/NoError", password)
    return Outcome("ok", f"EWS GetFolder {cfg.folder} Success", _ms(t0), {})


def run_check(kind: str, cfg: dict, password: str | None, allow_loopback: bool = False) -> Outcome:
    """Never raises. Any exception becomes a critical Outcome carrying the class name (and a scrubbed message for TLS/connect errors)."""
    t0 = time.monotonic()
    try:
        m = MODELS[kind].model_validate(cfg)
        if kind == "http":
            return run_http(m, allow_loopback)  # type: ignore[arg-type]
        if kind == "tcp_tls":
            return run_tcp_tls(m, allow_loopback)  # type: ignore[arg-type]
        if kind == "smtp_banner":
            return run_smtp(m, allow_loopback)  # type: ignore[arg-type]
        if password is None:
            return _fail(t0, "no password stored for this check")
        if kind == "imap_login":
            return run_imap(m, password, allow_loopback)  # type: ignore[arg-type]
        if kind == "ews_getfolder":
            return run_ews(m, password, allow_loopback)  # type: ignore[arg-type]
        return _fail(t0, "unknown check kind")
    except ProxmoxError as e:  # destination guard / pin errors
        return _fail(t0, str(e), password)
    except imaplib.IMAP4.error as e:
        return _fail(t0, "IMAP error: " + str(e), password)
    except (ssl.SSLError, socket.timeout, TimeoutError, ConnectionError, OSError) as e:
        return _fail(t0, f"{type(e).__name__}: {e}", password)
    except httpx.HTTPError as e:  # transport text may echo headers, so only TLS/socket causes (no credentials) are surfaced
        cause = e
        for _ in range(5):
            cause = cause.__cause__ or cause.__context__
            if cause is None or isinstance(cause, (ssl.SSLError, OSError)):
                break
        extra = f": {cause}" if isinstance(cause, (ssl.SSLError, OSError)) else ""
        return _fail(t0, f"{type(e).__name__}{extra}", password)
    except Exception as e:  # noqa: BLE001
        return _fail(t0, f"check error: {type(e).__name__}", password)
