"""Proxmox administration client for MODE A (temporary provisioning credentials).

Authenticates with a PVE admin user + password (POST /access/ticket) or with an existing privileged API token. The credential lives only
in this object: `discard()` wipes it (headers, cookie, CSRF token, password) and closes the connection. Callers hold it for the duration of
one job; nothing here persists anything. Mutating calls are only available inside job execution (providers.base.require_job_execution).
"""
from __future__ import annotations

import re
from urllib.parse import quote, urlparse

import httpx

from ... import egress

from ...proxmox import (ProxmoxError, ProxmoxHTTPError, ProxmoxWriteClient, _SECRET_RE, _TOKEN_ID_RE, build_ssl_context,
                        check_destination)
from ..base import ProviderError, require_job_execution
from .provider import map_error

_USER_RE = re.compile(r"^[^@\s!:/]{1,64}@[A-Za-z0-9._-]{1,32}$")
_SEG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+:-]{0,127}$")
_TICKET_RE = re.compile(r"^PVE:[\x21-\x7e]{1,4096}$")
_CSRF_RE = re.compile(r"^[\x21-\x7e]{8,512}$")
_TFA_CODE = re.compile(r"^[A-Za-z0-9-]{4,64}$")


def tfa_methods(challenge_ticket: str) -> list[str]:
    """Second factors the account offers, read from the PVE challenge ticket ('PVE:!tfa!<url-encoded JSON>:...'). Unknown shape -> TOTP + recovery."""
    import json
    from urllib.parse import unquote
    out: list[str] = []
    try:
        part = challenge_ticket.split(":", 2)[1]
        if part.startswith("!tfa!"):
            c = json.loads(unquote(part[5:]))
            if c.get("totp"):
                out.append("totp")
            if c.get("yubico"):
                out.append("yubico")
            if c.get("webauthn") or c.get("u2f"):
                out.append("webauthn")
            if c.get("recovery"):
                out.append("recovery")
    except (IndexError, ValueError, AttributeError):
        pass
    return out or ["totp", "recovery"]


def seg(s: str) -> str:
    """One URL path segment from an operator-influenced name (never allows '/', '..', spaces)."""
    if not _SEG.match(s or "") or ".." in s:
        raise ProxmoxError("invalid name for an API path")
    return quote(s, safe="@+:")


class ProxmoxAdminClient(ProxmoxWriteClient):
    def __init__(self, base_url: str, *, username: str | None = None, password: str | None = None, token_id: str | None = None,
                 token_secret: str | None = None, ca_pem: str | None = None, fingerprint_sha256: str | None = None, timeout: float = 5.0,
                 deadline: float = 30.0, max_bytes: int = 16 * 1024 * 1024, allow_loopback: bool = False,
                 ticket: str | None = None, csrf: str | None = None, tfa_challenge: str | None = None):
        u = urlparse(base_url)
        if u.scheme != "https" or not u.hostname:
            raise ValueError("base_url must be https://host[:port]")
        use_tk = bool(ticket or csrf)
        use_ch = bool(tfa_challenge)
        use_pw = bool(username and password) and not use_tk
        use_tok = bool(token_id and token_secret)
        if int(use_pw) + int(use_tok) + int(use_tk) + int(use_ch) != 1:
            raise ValueError("supply either username+password, an API token id+secret, or a session ticket")
        if use_ch and not (_TICKET_RE.match(tfa_challenge) and username and _USER_RE.match(username)):
            raise ValueError("provisioning session has an invalid format")
        if use_tk and not (ticket and csrf and username and _TICKET_RE.match(ticket) and _CSRF_RE.match(csrf) and _USER_RE.match(username)):
            raise ValueError("provisioning session has an invalid format")
        if use_pw and (not _USER_RE.match(username) or len(password) > 256 or re.search(r"[\x00-\x1f]", password)):
            raise ValueError("provisioning credential has an invalid format")
        if use_tok and (not _TOKEN_ID_RE.match(token_id) or not _SECRET_RE.match(token_secret)):
            raise ValueError("provisioning credential has an invalid format")
        check_destination(u.hostname, allow_loopback)
        self._deadline, self._max_bytes = deadline, max_bytes
        self._base = f"https://{u.netloc}/api2/json"
        self._client = httpx.Client(verify=build_ssl_context(ca_pem=ca_pem, fingerprint_sha256=fingerprint_sha256),
                                    timeout=httpx.Timeout(timeout), follow_redirects=False, trust_env=False,
                                    event_hooks=egress.hooks())     # H-5: fenced/standby -> no admin call either; names the controller + epoch
        self.username = None
        self.mode = "token" if use_tok else "ticket"
        self.discarded = False
        self.need_tfa, self.tfa_methods, self._tfa_challenge, self._ticket = False, [], None, None
        if use_ch:
            self.need_tfa, self._tfa_challenge, self.username = True, tfa_challenge, username
            self.tfa_methods = tfa_methods(tfa_challenge)
        elif use_tk:
            self._set_ticket({"ticket": ticket, "CSRFPreventionToken": csrf, "username": username})
        elif use_tok:
            self.username = token_id
            self._client.headers["Authorization"] = f"PVEAPIToken={token_id}={token_secret}"
        else:
            try:
                d = self._request("POST", "/access/ticket", {"username": username, "password": password, "new-format": "1"})   # PVE 7: challenge-style TFA; ignored by 8+
            except ProxmoxHTTPError as e:
                self._client.close()
                raise ProviderError("auth", "Proxmox rejected the login (wrong user name, realm or password, or the account is disabled)." if e.status == 401
                                    else f"login failed (HTTP {e.status})") from None
            except ProxmoxError:
                self._client.close()
                raise
            if d.get("NeedTFA"):
                # the account has a second factor: the response carries only a TFA challenge ticket (no access). Nothing works until complete_tfa().
                self.need_tfa, self._tfa_challenge = True, str(d.get("ticket", ""))
                self.tfa_methods = tfa_methods(self._tfa_challenge)
                self.username = str(d.get("username") or username)
            else:
                self._set_ticket(d)
            del d, password

    def _set_ticket(self, d: dict) -> None:
        self.username = d["username"]
        self._ticket = (d["ticket"], d["CSRFPreventionToken"])
        self._client.headers["Cookie"] = f"PVEAuthCookie={d['ticket']}"
        self._client.headers["CSRFPreventionToken"] = d["CSRFPreventionToken"]

    def complete_tfa(self, method: str, code: str) -> None:
        """Second login step (PVE >= 7.2): POST /access/ticket with the challenge ticket and '<method>:<code>'. TOTP, recovery keys and Yubico OTP
        are supported. WebAuthn cannot be answered here: the assertion is bound to the Proxmox web origin, not the ICS (see docs)."""
        self._live()
        if not self.need_tfa or not self._tfa_challenge:
            raise ProxmoxError("no second-factor challenge is pending")
        if method not in ("totp", "recovery", "yubico") or not _TFA_CODE.match(code or ""):
            raise ProviderError("auth", "second factor has an invalid format")
        try:
            d = self._request("POST", "/access/ticket", {"username": self.username, "tfa-challenge": self._tfa_challenge, "password": f"{method}:{code}"})
        except ProxmoxHTTPError as e:
            raise ProviderError("auth", "Proxmox rejected the second factor (wrong or expired code)." if e.status == 401
                                else f"second-factor login failed (HTTP {e.status})") from None
        if d.get("NeedTFA") or not d.get("CSRFPreventionToken"):
            raise ProviderError("auth", "Proxmox did not accept the second factor")
        self.need_tfa, self._tfa_challenge = False, None
        self._set_ticket(d)

    def export_ticket(self) -> dict:
        """The session ticket for the ICS's short-lived vault entry (never the password). Only after a complete login."""
        self._live()
        if self.need_tfa or not self._ticket:
            raise ProxmoxError("login is not complete")
        return {"admin_ticket": self._ticket[0], "admin_csrf": self._ticket[1], "admin_ticket_user": self.username}

    def discard(self) -> None:
        """Wipe every trace of the temporary credential held by this client."""
        self._ticket = self._tfa_challenge = None
        self._client.headers.clear()
        self._client.close()
        self.username = None
        self.discarded = True

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.discard()

    def _live(self):
        if self.discarded:
            raise ProxmoxError("provisioning credential was already discarded")

    def get(self, path: str):
        self._live()
        return super().get(path)

    def _write(self, fn, *a):
        require_job_execution()
        self._live()
        try:
            return fn(*a)
        except ProxmoxHTTPError as e:
            raise map_error(e, "access-control change") from None

    def post(self, path, data=None):
        return self._write(super().post, path, data)

    def put(self, path, data=None):
        return self._write(super().put, path, data)

    def delete(self, path):
        return self._write(super().delete, path)

    # ---- typed helpers (names are validated before they reach a path) ----
    def version(self):
        return self.get("/version")

    def permissions(self, path: str | None = None, userid: str | None = None) -> dict:
        q = []
        if path:
            q.append("path=" + quote(path, safe="/"))
        if userid:
            q.append("userid=" + quote(userid, safe="@!"))
        return self.get("/access/permissions" + ("?" + "&".join(q) if q else ""))

    def users(self):
        return self.get("/access/users")

    def roles(self):
        return self.get("/access/roles")

    def acl(self):
        return self.get("/access/acl")

    def groups(self):
        return self.get("/access/groups")

    def user_add(self, userid: str, comment: str):
        return self.post("/access/users", {"userid": userid, "comment": comment, "enable": "1"})

    def user_delete(self, userid: str):
        return self.delete(f"/access/users/{seg(userid)}")

    def token_add(self, userid: str, name: str, comment: str, privsep: int = 1) -> dict:
        return self.post(f"/access/users/{seg(userid)}/token/{seg(name)}", {"privsep": str(privsep), "comment": comment})

    def token_delete(self, userid: str, name: str):
        return self.delete(f"/access/users/{seg(userid)}/token/{seg(name)}")

    def role_add(self, name: str, privs: list[str]):
        return self.post("/access/roles", {"roleid": name, "privs": ",".join(sorted(privs))})

    def role_set(self, name: str, privs: list[str]):
        return self.put(f"/access/roles/{seg(name)}", {"privs": ",".join(sorted(privs))})

    def role_delete(self, name: str):
        return self.delete(f"/access/roles/{seg(name)}")

    def acl_set(self, path: str, role: str, *, user: str | None = None, token: str | None = None, propagate: int = 1, delete: bool = False):
        d = {"path": path, "roles": role, "propagate": str(propagate)}
        if user:
            d["users"] = user
        if token:
            d["tokens"] = token
        if delete:
            d["delete"] = "1"
        return self.put("/access/acl", d)

    def pool_add(self, pool: str, comment: str = ""):
        return self.post("/pools", {"poolid": pool, "comment": comment})

    def pool_delete(self, pool: str):
        """Proxmox refuses to delete a pool that still has members; the planner only offers empty Office Unbound pools."""
        return self.delete(f"/pools/{seg(pool)}")
