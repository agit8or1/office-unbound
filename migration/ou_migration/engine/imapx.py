"""IMAP transport for the migration engine.

Safety properties enforced in code (not by convention):

* TLS is mandatory and always verified (system CAs, or ``cafile`` = pinned lab CA / self-signed server cert).
  Plain TCP is accepted ONLY to a loopback address (unit tests).
* A command allow-list guards every connection. The SOURCE connection can only run read commands
  (CAPABILITY LOGIN AUTHENTICATE LIST EXAMINE STATUS UID FETCH|SEARCH NOOP LOGOUT STARTTLS); FETCH must use BODY.PEEK
  (a plain BODY[]/RFC822 fetch would set \\Seen on the source). The TARGET adds only CREATE and APPEND.
  STORE, EXPUNGE, DELETE, COPY, MOVE, RENAME, SELECT are unreachable on either side.
* Credentials never appear in exceptions or logs.
"""
from __future__ import annotations

import imaplib
import ipaddress
import logging
import random
import re
import socket
import ssl
import time
from dataclasses import dataclass

from ..secrets import Redacted
from . import mutf7  # noqa: F401  (re-exported for callers)

log = logging.getLogger("ou_migration.engine.imap")

READ_COMMANDS = {"CAPABILITY", "LOGIN", "AUTHENTICATE", "LIST", "EXAMINE", "STATUS", "UID", "NOOP", "LOGOUT", "STARTTLS"}
WRITE_COMMANDS = READ_COMMANDS | {"CREATE", "APPEND"}
UID_SUBCOMMANDS = {"FETCH", "SEARCH"}
_UNSAFE_FETCH = re.compile(r"\bBODY\[|\bRFC822(?:\.TEXT)?(?![\w.])", re.I)


class ImapError(Exception):
    pass


class AuthFailed(ImapError):
    pass


class Transient(ImapError):
    pass


class Fatal(ImapError):
    pass


class GuardViolation(Fatal):
    """The engine tried to send a command it must never send (programming error; nothing was transmitted)."""


# ---------------------------------------------------------------- auth
class TokenProvider:
    """Interface for OAuth2 access tokens (XOAUTH2). Implementations never log tokens. ``force_refresh`` is set
    after the server rejected the previous token."""

    def get_token(self, user: str, force_refresh: bool = False) -> str:  # pragma: no cover - interface
        raise NotImplementedError


class StaticTokenProvider(TokenProvider):
    def __init__(self, token: str):
        self._t = Redacted(token)

    def get_token(self, user, force_refresh=False):
        return self._t.reveal()


def xoauth2_string(user: str, token: str) -> bytes:
    return f"user={user}\x01auth=Bearer {token}\x01\x01".encode()


class LoginAuth:
    mechanism = "LOGIN"

    def __init__(self, user: str, password: str):
        self.user = user
        self._pw = Redacted(password)

    def authenticate(self, imap, force_refresh=False):
        imap.login(self.user, self._pw.reveal())


class XOAuth2Auth:
    mechanism = "XOAUTH2"

    def __init__(self, user: str, provider: TokenProvider):
        self.user, self.provider = user, provider

    def authenticate(self, imap, force_refresh=False):
        tok = self.provider.get_token(self.user, force_refresh=force_refresh)
        state = {"n": 0}

        def responder(challenge):
            # first call: the initial client response; a second call means the server sent an error JSON -> send empty
            state["n"] += 1
            return xoauth2_string(self.user, tok) if state["n"] == 1 else b""

        imap.authenticate("XOAUTH2", responder)


# ---------------------------------------------------------------- guarded imaplib
class _Guard:
    allowed = READ_COMMANDS

    def _command(self, name, *args):  # imaplib funnels every command through here
        n = name.upper()
        if n not in self.allowed:
            raise GuardViolation(f"command {n} is not permitted on this connection")
        if n == "UID":
            sub = str(args[0]).upper() if args else ""
            if sub not in UID_SUBCOMMANDS:
                raise GuardViolation(f"UID {sub} is not permitted")
            if sub == "FETCH" and _UNSAFE_FETCH.search(" ".join(str(a) for a in args[1:])):
                raise GuardViolation("FETCH must use BODY.PEEK (read-only access)")
        return super()._command(name, *args)


class _SourceSSL(_Guard, imaplib.IMAP4_SSL):
    allowed = READ_COMMANDS


class _TargetSSL(_Guard, imaplib.IMAP4_SSL):
    allowed = WRITE_COMMANDS


class _SourcePlain(_Guard, imaplib.IMAP4):
    allowed = READ_COMMANDS


class _TargetPlain(_Guard, imaplib.IMAP4):
    allowed = WRITE_COMMANDS


@dataclass
class Endpoint:
    host: str
    port: int = 993
    security: str = "tls"        # tls | starttls | plain (loopback only)
    cafile: str | None = None    # pinned CA / self-signed server cert (PEM); default: system trust store
    timeout: float = 60.0
    label: str = "imap"          # used in messages only


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost"


def _ctx(cafile):
    ctx = ssl.create_default_context(cafile=cafile)  # CERT_REQUIRED + hostname check
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def open_connection(ep: Endpoint, write: bool) -> imaplib.IMAP4:
    if ep.security == "plain":
        if not _is_loopback(ep.host):
            raise Fatal("plaintext IMAP is refused for non-loopback hosts")
        return (_TargetPlain if write else _SourcePlain)(ep.host, ep.port, timeout=ep.timeout)
    if ep.security == "tls":
        return (_TargetSSL if write else _SourceSSL)(ep.host, ep.port, ssl_context=_ctx(ep.cafile), timeout=ep.timeout)
    if ep.security == "starttls":
        c = (_TargetPlain if write else _SourcePlain)(ep.host, ep.port, timeout=ep.timeout)
        c.starttls(_ctx(ep.cafile))
        return c
    raise Fatal(f"unknown security mode {ep.security!r}")


# ---------------------------------------------------------------- throttle
class Throttle:
    """Rate limit in messages/s and bytes/s (0 = unlimited). Injectable clock/sleep for tests."""

    def __init__(self, msgs_per_s=0.0, bytes_per_s=0.0, clock=time.monotonic, sleep=time.sleep):
        self.mps, self.bps, self.clock, self.sleep = msgs_per_s, bytes_per_s, clock, sleep
        self._next = clock()
        self.slept = 0.0

    def acquire(self, nbytes=0):
        cost = 0.0
        if self.mps:
            cost += 1.0 / self.mps
        if self.bps:
            cost += nbytes / self.bps
        if not cost:
            return
        now = self.clock()
        if self._next > now:
            d = self._next - now
            self.sleep(d)
            self.slept += d
            now = self.clock()
        self._next = max(self._next, now) + cost


_TRANSIENT_TEXT = re.compile(r"throttl|too many|try again|temporar|busy|unavailable|rate[ -]?limit|\[LIMIT\]|\[UNAVAILABLE\]|"
                             r"system error|server error|timed out", re.I)
_FATAL_TEXT = re.compile(r"over\s?quota|\[OVERQUOTA\]|\[NOPERM\]|\[AUTHORIZATIONFAILED\]", re.I)


class Session:
    """One authenticated connection with reconnect + exponential backoff (full jitter).

    ``run(fn)`` re-executes ``fn(imap)`` after reconnecting on connection loss / throttling responses. Operations that
    are not idempotent (APPEND) are executed with ``retry=False`` and handled by the caller."""

    def __init__(self, ep: Endpoint, auth, *, write: bool, sleep=time.sleep, rng=random.random,
                 max_retries=6, base_delay=1.0, max_delay=60.0, opener=open_connection):
        self.ep, self.auth, self.write = ep, auth, write
        self.sleep, self.rng, self.max_retries, self.base_delay, self.max_delay = sleep, rng, max_retries, base_delay, max_delay
        self._open = opener
        self.imap = None
        self._selected = None
        self.reconnects = 0
        self._had_conn = False
        self.retries = 0
        self.throttle_events = 0

    # -- connection management
    def connect(self):
        self.run(lambda imap: None)
        return self

    def _connect(self):
        self.close()
        try:
            self.imap = self._open(self.ep, self.write)
            try:
                self.auth.authenticate(self.imap)
            except imaplib.IMAP4.abort:
                raise
            except imaplib.IMAP4.error as e:
                if _TRANSIENT_TEXT.search(str(e)):
                    raise
                if self.auth.mechanism != "XOAUTH2":
                    raise AuthFailed(f"{self.ep.label}: authentication failed") from None
                # expired token: refresh once
                self.imap = self._open(self.ep, self.write)
                try:
                    self.auth.authenticate(self.imap, force_refresh=True)
                except imaplib.IMAP4.abort:
                    raise
                except imaplib.IMAP4.error:
                    raise AuthFailed(f"{self.ep.label}: XOAUTH2 authentication failed") from None
        except ssl.SSLCertVerificationError as e:
            raise Fatal(f"{self.ep.label}: TLS certificate verification failed ({e.verify_message})") from None
        return self

    def close(self):
        if self.imap is not None:
            try:
                self.imap.logout()
            except Exception:
                pass
            self.imap = None

    def _backoff(self, attempt):
        d = min(self.max_delay, self.base_delay * (2 ** attempt)) * (0.5 + self.rng() / 2)
        self.sleep(d)

    def run(self, fn, retry=True):
        attempt = 0
        while True:
            try:
                if self.imap is None:
                    if self._had_conn:
                        self.reconnects += 1
                    self._connect()
                    self._had_conn = True
                    if self._selected:
                        self._examine_raw(self._selected)
                return fn(self.imap)
            except Fatal:
                raise
            except imaplib.IMAP4.abort as e:  # connection dropped / BYE / server abort
                err = Transient(f"{self.ep.label}: connection lost")
            except ssl.SSLCertVerificationError as e:
                raise Fatal(f"{self.ep.label}: TLS certificate verification failed") from None
            except (OSError, EOFError, ssl.SSLError):
                err = Transient(f"{self.ep.label}: network error")
            except imaplib.IMAP4.error as e:
                txt = str(e)
                if _FATAL_TEXT.search(txt):
                    raise Fatal(f"{self.ep.label}: {_scrub(txt)}") from None
                if not _TRANSIENT_TEXT.search(txt):
                    raise ImapError(f"{self.ep.label}: {_scrub(txt)}") from None
                self.throttle_events += 1
                err = Transient(f"{self.ep.label}: throttled/temporary: {_scrub(txt)}")
            if not retry:
                self.close()
                raise err
            if attempt >= self.max_retries:
                self.close()
                raise err
            log.warning("%s (retry %d/%d)", err, attempt + 1, self.max_retries)
            self.close()
            self.retries += 1
            self._backoff(attempt)
            attempt += 1

    # -- helpers used by the mailbox layer
    def _examine_raw(self, name):
        typ, data = self.imap.select(quote(name), readonly=True)  # imaplib readonly=True sends EXAMINE
        if typ != "OK":
            raise ImapError(f"{self.ep.label}: EXAMINE failed")
        return data

    def examine(self, wire_name):
        def f(imap):
            data = self._examine_raw(wire_name)
            exists = int(data[0]) if data and data[0] else 0
            uv = _first_int(imap.response("UIDVALIDITY"))
            nxt = _first_int(imap.response("UIDNEXT"))
            if uv is None:
                typ, d = imap.status(quote(wire_name), "(UIDVALIDITY UIDNEXT)")
                m = re.search(rb"UIDVALIDITY (\d+)", d[0] or b"")
                uv = int(m.group(1)) if m else 0
                m = re.search(rb"UIDNEXT (\d+)", d[0] or b"")
                nxt = int(m.group(1)) if m else None
            self._selected = wire_name
            return uv, exists, nxt

        return self.run(f)


def _first_int(resp):
    try:
        v = resp[1][0]
        return int(v) if v is not None else None
    except (TypeError, IndexError, ValueError):
        return None


def _scrub(txt):
    return re.sub(r"\s+", " ", txt)[:200]


def quote(name: str) -> str:
    return '"' + name.replace("\\", "\\\\").replace('"', '\\"') + '"'
