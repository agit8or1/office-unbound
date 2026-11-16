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


def seg(s: str) -> str:
    """One URL path segment from an operator-influenced name (never allows '/', '..', spaces)."""
    if not _SEG.match(s or "") or ".." in s:
        raise ProxmoxError("invalid name for an API path")
    return quote(s, safe="@+:")


class ProxmoxAdminClient(ProxmoxWriteClient):
    def __init__(self, base_url: str, *, username: str | None = None, password: str | None = None, token_id: str | None = None,
                 token_secret: str | None = None, ca_pem: str | None = None, fingerprint_sha256: str | None = None, timeout: float = 5.0,
                 deadline: float = 30.0, max_bytes: int = 16 * 1024 * 1024, allow_loopback: bool = False):
        u = urlparse(base_url)
        if u.scheme != "https" or not u.hostname:
            raise ValueError("base_url must be https://host[:port]")
        use_pw = bool(username and password)
        use_tok = bool(token_id and token_secret)
        if use_pw == use_tok:
            raise ValueError("supply either username+password or an API token id+secret")
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
        if use_tok:
            self.username = token_id
            self._client.headers["Authorization"] = f"PVEAPIToken={token_id}={token_secret}"
        else:
            try:
                d = self._request("POST", "/access/ticket", {"username": username, "password": password})
            except ProxmoxHTTPError as e:
                self._client.close()
                raise ProviderError("auth", "Proxmox rejected the provisioning credentials (wrong user/password, disabled user, or two-factor "
                                            "authentication is required: use a privileged API token instead)." if e.status == 401
                                    else f"login failed (HTTP {e.status})") from None
            except ProxmoxError:
                self._client.close()
                raise
            self.username = d["username"]
            self._client.headers["Cookie"] = f"PVEAuthCookie={d['ticket']}"
            self._client.headers["CSRFPreventionToken"] = d["CSRFPreventionToken"]
            del d, password

    def discard(self) -> None:
        """Wipe every trace of the temporary credential held by this client."""
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
