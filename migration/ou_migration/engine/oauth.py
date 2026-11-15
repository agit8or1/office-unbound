"""XOAUTH2 token providers for IMAP sources. NOT exercised against any real tenant (no tenant access); the request
shapes follow the vendor documentation and are unit-tested against stubs only.

* Google Workspace: service account with domain-wide delegation, scope ``https://mail.google.com/``, ``sub`` = mailbox
  (reuses auth.GoogleAuth; the scope must be allow-listed in the Admin console).
* Microsoft 365: client-credentials, scope ``https://outlook.office365.com/.default``; the app needs the
  ``IMAP.AccessAsApp`` role, a service principal registered in Exchange Online and ``Add-MailboxPermission`` per mailbox.
"""
from __future__ import annotations

import time
import urllib.parse

from ..auth import AuthError, _Cache
from ..http import HttpClient, HttpError
from ..secrets import Redacted
from .imapx import TokenProvider

GOOGLE_IMAP_SCOPE = "https://mail.google.com/"
M365_IMAP_SCOPE = "https://outlook.office365.com/.default"


class GoogleImapTokens(TokenProvider):
    def __init__(self, google_auth):
        self.auth = google_auth

    def get_token(self, user, force_refresh=False):
        if force_refresh:
            self.auth._cache = type(self.auth._cache)(self.auth._clock)  # drop cached tokens
        return self.auth.token([GOOGLE_IMAP_SCOPE], subject=user)


class M365ImapTokens(TokenProvider):
    def __init__(self, http: HttpClient, tenant_id, client_id, client_secret, login_base="https://login.microsoftonline.com",
                 clock=time.time):
        self.http, self.tenant_id, self.client_id = http, tenant_id, client_id
        self._secret = Redacted(client_secret)
        self.login_base = login_base.rstrip("/")
        self._cache = _Cache(clock)

    def get_token(self, user, force_refresh=False):
        t = None if force_refresh else self._cache.get("imap")
        if t:
            return t.reveal()
        body = urllib.parse.urlencode({"client_id": self.client_id, "client_secret": self._secret.reveal(),
                                       "scope": M365_IMAP_SCOPE, "grant_type": "client_credentials"}).encode()
        try:
            r = self.http.request("POST", f"{self.login_base}/{self.tenant_id}/oauth2/v2.0/token", data=body,
                                  headers={"Content-Type": "application/x-www-form-urlencoded"})
        except HttpError as e:
            raise AuthError(f"Microsoft IMAP token request failed: HTTP {e.status}") from None
        j = r.json()
        self._cache.put("imap", j["access_token"], j.get("expires_in", 3600))
        return j["access_token"]
