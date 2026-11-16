"""Client for the ICS tenant admin API (/api/v1/tenant/*). Every call carries the customer's SERVICE credential (who the customer is) and, for
anything about people, the signed-in administrator's own Keycloak access token (who is asking). The portal never holds an infrastructure
credential and never sees a password: initial passwords do not exist (one-time sign-up links), resets go through the same link or Keycloak."""
from __future__ import annotations

import time
from datetime import datetime

import httpx

from .config import Settings


class ICSError(Exception):
    """status: HTTP status of the ICS answer, or 0 when it could not be reached. msg is plain language when the ICS wrote it."""

    def __init__(self, status: int, msg: str = ""):
        super().__init__(f"{status} {msg}")
        self.status, self.msg = status, msg


class ICS:
    def __init__(self, cfg: Settings, transport: httpx.AsyncBaseTransport | None = None):
        self.cfg = cfg
        self.http = httpx.AsyncClient(base_url=cfg.ics_url or "", timeout=cfg.http_timeout + 30, verify=cfg.ics_ca_bundle or True, transport=transport,
                                      follow_redirects=False, headers={"User-Agent": "ou-portal/admin"})
        self._brand: tuple[float, dict] | None = None
        self._logo: tuple[float, bytes, str] | None = None

    async def close(self) -> None:
        await self.http.aclose()

    async def call(self, method: str, path: str, token: str | None = None, *, json=None, content: bytes | None = None, params=None):
        h = {"X-OU-Tenant-Key": self.cfg.ics_key}
        if token:
            h["X-OU-User-Token"] = token
        try:
            r = await self.http.request(method, "/api/v1/tenant" + path, headers=h, json=json, content=content, params=params)
        except httpx.HTTPError:
            raise ICSError(0, "The administration service did not answer.") from None
        if r.status_code >= 400:
            msg = ""
            try:
                d = r.json().get("detail")
                msg = d if isinstance(d, str) else ""
            except ValueError:
                pass
            raise ICSError(r.status_code, msg)
        return r.json() if r.content and r.headers.get("content-type", "").startswith("application/json") else r

    # ---- public branding (service credential only; cached briefly) ----------------------------------------------------------------
    async def branding(self) -> dict | None:
        if self._brand and time.monotonic() - self._brand[0] < 60:
            return self._brand[1]
        try:
            b = await self.call("GET", "/branding")
        except ICSError:
            return self._brand[1] if self._brand else None
        self._brand = (time.monotonic(), b)
        return b

    async def logo(self) -> tuple[bytes, str] | None:
        if self._logo and time.monotonic() - self._logo[0] < 60:
            return self._logo[1], self._logo[2]
        try:
            r = await self.call("GET", "/branding/logo")
        except ICSError:
            return None
        self._logo = (time.monotonic(), r.content, r.headers.get("content-type", "image/png"))
        return r.content, self._logo[2]

    def forget_branding(self) -> None:
        self._brand = self._logo = None


def parse_time(s: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(s) if s else None
    except ValueError:
        return None
