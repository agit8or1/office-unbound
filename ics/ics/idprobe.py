"""Active credential-path probes for the user lifecycle (VERIFY step) and the lab acceptance script.

Every probe returns `True` (credential ACCEPTED), `False` (credential REFUSED) or `None` (inconclusive: network/TLS/5xx - never counts as
"refused"). Probes only ever present a credential and read one harmless thing (a folder listing / OPTIONS / /me). TLS is always verified
against the CA given in the stack config; destinations pass the same SSRF guard as every other outbound ICS request.
`measure()` polls the probes after a revocation and records, per path, the seconds until the first refusal.
"""
import imaplib
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

from .proxmox import ProxmoxError, check_destination

PROBE_TIMEOUT = 8.0
_EWS = ('<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" '
        'xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" '
        'xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"><soap:Header>'
        '<t:RequestServerVersion Version="Exchange2013"/></soap:Header><soap:Body><m:GetFolder><m:FolderShape>'
        '<t:BaseShape>Default</t:BaseShape></m:FolderShape><m:FolderIds><t:DistinguishedFolderId Id="inbox"/>'
        '</m:FolderIds></m:GetFolder></soap:Body></soap:Envelope>')


@dataclass
class ProbeConfig:
    kc_url: str                 # https://auth.example
    realm: str
    client_id: str              # public client with direct grants (probe/test client)
    files_url: str | None       # https://cloud.example
    mail_host: str | None
    kc_ca_pem: str
    files_ca_pem: str | None = None
    mail_ca_pem: str | None = None
    imap_port: int = 993
    allow_loopback: bool = False
    _guarded: set = field(default_factory=set)

    def guard(self, host: str | None) -> None:
        if host and host not in self._guarded:
            try:
                check_destination(host, self.allow_loopback)
            except ProxmoxError as e:
                raise ValueError(str(e)) from None
            self._guarded.add(host)

    def ctx(self, pem: str | None) -> ssl.SSLContext:
        c = ssl.create_default_context(cadata=pem)
        c.minimum_version = ssl.TLSVersion.TLSv1_2
        return c


def _http(cfg: ProbeConfig, url: str, pem: str | None, method: str, **kw) -> httpx.Response | None:
    cfg.guard(urlparse(url).hostname)
    try:
        with httpx.Client(verify=cfg.ctx(pem), timeout=PROBE_TIMEOUT, follow_redirects=False, trust_env=False) as c:
            return c.request(method, url, **kw)
    except (httpx.HTTPError, ssl.SSLError, OSError):
        return None


def _verdict(r: httpx.Response | None, ok=(200, 207), refused=(400, 401, 403)) -> bool | None:
    if r is None or r.status_code >= 500:
        return None
    if r.status_code in ok:
        return True
    return False if r.status_code in refused else None


# ---- Keycloak -----------------------------------------------------------------------------------------------------------------------
def kc_token_url(cfg: ProbeConfig) -> str:
    return f"{cfg.kc_url.rstrip('/')}/realms/{cfg.realm}/protocol/openid-connect/token"


def kc_password_grant(cfg: ProbeConfig, uid: str, password: str, offline: bool = False) -> tuple[bool | None, dict]:
    """-> (verdict, tokens). `tokens` holds access_token/refresh_token only when accepted."""
    r = _http(cfg, kc_token_url(cfg), cfg.kc_ca_pem, "POST",
              data={"grant_type": "password", "client_id": cfg.client_id, "username": uid, "password": password,
                    "scope": "openid profile email" + (" offline_access" if offline else "")})
    v = _verdict(r, ok=(200,))
    return v, (r.json() if v and r is not None else {})


def kc_refresh(cfg: ProbeConfig, refresh_token: str) -> bool | None:
    r = _http(cfg, kc_token_url(cfg), cfg.kc_ca_pem, "POST",
              data={"grant_type": "refresh_token", "client_id": cfg.client_id, "refresh_token": refresh_token})
    return _verdict(r, ok=(200,))


# ---- OpenCloud ----------------------------------------------------------------------------------------------------------------------
def files_bearer(cfg: ProbeConfig, access_token: str, uid: str) -> bool | None:
    """An access token issued BEFORE the revocation presented to OpenCloud (Graph /me)."""
    r = _http(cfg, f"{cfg.files_url.rstrip('/')}/graph/v1.0/me", cfg.files_ca_pem, "GET", headers={"Authorization": f"Bearer {access_token}"})
    return _verdict(r, ok=(200,))


def files_webdav_bearer(cfg: ProbeConfig, access_token: str, uid: str) -> bool | None:
    r = _http(cfg, f"{cfg.files_url.rstrip('/')}/remote.php/dav/files/{uid}/", cfg.files_ca_pem, "PROPFIND",
              headers={"Authorization": f"Bearer {access_token}", "Depth": "0"})
    return _verdict(r)


def files_webdav_basic(cfg: ProbeConfig, uid: str, secret: str) -> bool | None:
    """WebDAV with Basic auth user:app-token (what opencloudcmd sends)."""
    r = _http(cfg, f"{cfg.files_url.rstrip('/')}/remote.php/dav/files/{uid}/", cfg.files_ca_pem, "PROPFIND",
              headers={"Depth": "0"}, auth=(uid, secret))
    return _verdict(r)


# ---- Gromox (IMAP / EWS / ActiveSync) -----------------------------------------------------------------------------------------------
def imap_login(cfg: ProbeConfig, mail: str, password: str) -> bool | None:
    cfg.guard(cfg.mail_host)
    try:
        m = imaplib.IMAP4_SSL(cfg.mail_host, cfg.imap_port, ssl_context=cfg.ctx(cfg.mail_ca_pem), timeout=PROBE_TIMEOUT)
    except (OSError, ssl.SSLError, imaplib.IMAP4.error):
        return None
    try:
        m.login(mail, password)
        m.logout()
        return True
    except imaplib.IMAP4.error:
        return False
    except (OSError, ssl.SSLError):
        return None


def imap_open(cfg: ProbeConfig, mail: str, password: str):
    """An authenticated, SELECTed session (kept open across the revocation). None if the login is not accepted."""
    cfg.guard(cfg.mail_host)
    try:
        m = imaplib.IMAP4_SSL(cfg.mail_host, cfg.imap_port, ssl_context=cfg.ctx(cfg.mail_ca_pem), timeout=PROBE_TIMEOUT)
        m.login(mail, password)
        if m.select("INBOX")[0] != "OK":
            return None
        return m
    except (OSError, ssl.SSLError, imaplib.IMAP4.error):
        return None


def imap_session_alive(m) -> bool | None:
    """True while the OLD session can still read the mailbox (NOOP + SEARCH both OK); False once the server refuses/ends it."""
    try:
        if m.noop()[0] != "OK":
            return False
        typ, _ = m.search(None, "ALL")
        return typ == "OK"
    except (imaplib.IMAP4.error, imaplib.IMAP4.abort):
        return False
    except (OSError, ssl.SSLError, socket.timeout, EOFError):
        return False  # connection dropped by the server = access ended


def ews_getfolder(cfg: ProbeConfig, mail: str, password: str) -> bool | None:
    r = _http(cfg, f"https://{cfg.mail_host}/EWS/Exchange.asmx", cfg.mail_ca_pem, "POST", content=_EWS.encode(), auth=(mail, password),
              headers={"Content-Type": "text/xml; charset=utf-8"})
    if r is None or r.status_code >= 500:
        return None
    if r.status_code == 200:
        return 'ResponseClass="Success"' in r.text
    return False if r.status_code in (401, 403) else None


def activesync_options(cfg: ProbeConfig, mail: str, password: str) -> bool | None:
    r = _http(cfg, f"https://{cfg.mail_host}/Microsoft-Server-ActiveSync", cfg.mail_ca_pem, "OPTIONS", auth=(mail, password))
    return _verdict(r, ok=(200,))


# ---- measurement --------------------------------------------------------------------------------------------------------------------
def measure(probes: dict, t0: float, timeout: float, interval: float = 1.0) -> dict:
    """Poll `probes` ({name: callable -> True|False|None}) until each was REFUSED once or `timeout` seconds after t0 (monotonic) passed.
    -> {name: {"status": "refused"|"still_accepted"|"inconclusive", "seconds": float|None (first refusal, measured from t0), "epoch": wall clock of the
    first refusal, "polls": n}}"""
    out = {n: {"status": "still_accepted", "seconds": None, "polls": 0, "_last": None} for n in probes}
    pending = set(probes)
    with ThreadPoolExecutor(max_workers=max(1, min(16, len(probes)))) as ex:
        while pending:
            tick = time.monotonic()
            futs = {n: ex.submit(probes[n]) for n in sorted(pending)}
            for n, f in futs.items():
                try:
                    v = f.result(timeout=PROBE_TIMEOUT + 5)
                except Exception:  # noqa: BLE001
                    v = None
                o = out[n]
                o["polls"] += 1
                o["_last"] = v
                if v is False:
                    o["status"], o["seconds"], o["epoch"] = "refused", round(time.monotonic() - t0, 1), round(time.time(), 3)
                    pending.discard(n)
            if time.monotonic() - t0 >= timeout:
                break
            time.sleep(max(0.0, interval - (time.monotonic() - tick)))
    for n, o in out.items():
        if o["status"] == "still_accepted" and o["_last"] is None:
            o["status"] = "inconclusive"
        o.pop("_last")
    return out
