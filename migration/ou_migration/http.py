"""Small stdlib HTTP client: TLS always verified, throttling-aware, never follows redirects blindly.

* 429 / 503 (and 500/502/504): honour ``Retry-After`` (delta-seconds or HTTP-date), else exponential
  backoff with jitter. Microsoft Graph and Google APIs both document this behaviour
  (https://learn.microsoft.com/en-us/graph/throttling ;
  https://developers.google.com/workspace/admin/directory/v1/limits).
* Redirects are NOT followed automatically (Graph report endpoints answer 302 to a pre-authenticated
  URL that must be fetched WITHOUT the Authorization header).
* ``http://`` is refused except for loopback hosts when ``allow_loopback_http`` is set (test fake server).
* Logging never contains headers, bodies, or query strings.
"""
from __future__ import annotations

import email.utils
import http.client
import json
import logging
import random
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

log = logging.getLogger("ou_migration.http")

RETRY_STATUS = {429, 500, 502, 503, 504}
MAX_BODY = 256 * 1024 * 1024  # a report CSV for a very large tenant; hard cap against runaway responses


class HttpError(Exception):
    def __init__(self, status: int, message: str = "", body: bytes = b""):
        super().__init__(f"HTTP {status}: {message}")
        self.status = status
        self.body = body


class TransportError(Exception):
    pass


@dataclass
class Response:
    status: int
    headers: dict  # lower-cased keys
    body: bytes

    def json(self):
        return json.loads(self.body.decode("utf-8")) if self.body else None

    def text(self):
        return self.body.decode("utf-8-sig")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def parse_retry_after(value: str | None, now: float | None = None) -> float | None:
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        dt = email.utils.parsedate_to_datetime(value)
        return max(0.0, dt.timestamp() - (now if now is not None else time.time()))
    except (TypeError, ValueError):
        return None


class HttpClient:
    def __init__(self, *, max_retries=6, base_delay=1.0, max_delay=120.0, timeout=60.0,
                 allow_loopback_http=False, sleep=time.sleep, rng=random.random, ca_file=None,
                 min_interval=0.0, clock=time.monotonic):
        self.max_retries, self.base_delay, self.max_delay = max_retries, base_delay, max_delay
        self.timeout, self.allow_loopback_http = timeout, allow_loopback_http
        self._sleep, self._rng, self._clock = sleep, rng, clock
        self.min_interval = min_interval  # client-side pacing (Google per-minute quotas)
        self._last = 0.0
        self.throttle_events = 0
        self.retries = 0
        self._ctx = ssl.create_default_context(cafile=ca_file)  # verification on, hostname check on
        self._opener = urllib.request.build_opener(
            _NoRedirect, urllib.request.HTTPSHandler(context=self._ctx))

    def _check_url(self, url: str):
        p = urllib.parse.urlsplit(url)
        if p.scheme == "https":
            return
        if p.scheme == "http" and self.allow_loopback_http and p.hostname in ("127.0.0.1", "localhost", "::1"):
            return
        raise TransportError(f"refusing non-https URL scheme {p.scheme!r}")

    def request(self, method: str, url: str, *, headers=None, params=None, data: bytes | None = None,
                expect=(200,), allow_redirect_status=False) -> Response:
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params, safe="$,()'")
        self._check_url(url)
        path_for_log = urllib.parse.urlsplit(url)
        path_for_log = f"{path_for_log.netloc}{path_for_log.path}"
        attempt = 0
        while True:
            if self.min_interval:
                wait = self.min_interval - (self._clock() - self._last)
                if wait > 0:
                    self._sleep(wait)
                self._last = self._clock()
            req = urllib.request.Request(url, data=data, method=method, headers=dict(headers or {}))
            try:
                with self._opener.open(req, timeout=self.timeout) as r:
                    resp = Response(r.status, {k.lower(): v for k, v in r.headers.items()}, self._read(r))
            except urllib.error.HTTPError as e:
                resp = Response(e.code, {k.lower(): v for k, v in e.headers.items()}, self._read(e))
            except (urllib.error.URLError, socket.timeout, http.client.HTTPException, ConnectionError, ssl.SSLError) as e:
                if attempt >= self.max_retries:
                    raise TransportError(f"{type(e).__name__} contacting {path_for_log}") from None
                self._backoff(attempt, None, path_for_log, f"transport {type(e).__name__}")
                attempt += 1
                continue
            if (resp.status in RETRY_STATUS or (resp.status == 403 and _is_google_rate_limit(resp))) \
                    and attempt < self.max_retries:
                if resp.status in (429, 403):
                    self.throttle_events += 1
                self._backoff(attempt, resp.headers.get("retry-after"), path_for_log, f"status {resp.status}")
                attempt += 1
                continue
            if resp.status in expect or (allow_redirect_status and resp.status in (301, 302, 303, 307, 308)):
                return resp
            raise HttpError(resp.status, _err_summary(resp), resp.body[:2048])

    def _read(self, r) -> bytes:
        body = r.read(MAX_BODY + 1)
        if len(body) > MAX_BODY:
            raise TransportError("response exceeds size cap")
        return body

    def _backoff(self, attempt, retry_after, what, why):
        ra = parse_retry_after(retry_after)
        delay = ra if ra is not None else min(self.max_delay, self.base_delay * (2 ** attempt))
        if ra is None:
            delay *= 0.5 + self._rng() / 2  # jitter
        delay = min(delay, self.max_delay) if ra is None else min(ra, self.max_delay * 5)
        self.retries += 1
        log.warning("retrying %s after %.1fs (%s, attempt %d)", what, delay, why, attempt + 1)
        self._sleep(delay)

    def get_json(self, url, *, headers=None, params=None):
        return self.request("GET", url, headers=headers, params=params).json()


_G_RATE_REASONS = {"rateLimitExceeded", "userRateLimitExceeded", "quotaExceeded", "RATE_LIMIT_EXCEEDED"}


def _is_google_rate_limit(resp: Response) -> bool:
    """Google APIs signal quota exhaustion as 403 + reason rateLimitExceeded/userRateLimitExceeded
    (https://developers.google.com/workspace/admin/directory/v1/limits)."""
    try:
        e = resp.json().get("error", {})
        reasons = {x.get("reason") for x in e.get("errors", []) if isinstance(x, dict)}
        reasons |= {d.get("reason") for d in e.get("details", []) if isinstance(d, dict)}
        return bool(reasons & _G_RATE_REASONS)
    except Exception:
        return False


def _err_summary(resp: Response) -> str:
    """Error code/message only (APIs put no secrets there); truncated."""
    try:
        j = resp.json()
        e = j.get("error")
        if isinstance(e, dict):
            return f"{e.get('code', '')} {str(e.get('message', ''))[:200]}".strip()
        if isinstance(e, str):
            return f"{e} {str(j.get('error_description', ''))[:200]}".strip()
    except Exception:
        pass
    return ""
