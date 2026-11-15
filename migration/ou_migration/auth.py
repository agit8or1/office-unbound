"""Token acquisition. Access tokens are kept in memory only (never written to checkpoint/report/log).

* Microsoft: OAuth2 client-credentials, ``scope=https://graph.microsoft.com/.default``
  https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow
* Google: service account with domain-wide delegation: signed JWT (RS256, ``sub`` = impersonated user)
  exchanged at the token endpoint (grant_type urn:ietf:params:oauth:grant-type:jwt-bearer)
  https://developers.google.com/identity/protocols/oauth2/service-account
"""
from __future__ import annotations

import base64
import json
import time
import urllib.parse

from .http import HttpClient, HttpError
from .secrets import Redacted, SecretError, load_secret, read_secret_file

GRAPH_SCOPE = "https://graph.microsoft.com/.default"


class AuthError(Exception):
    pass


class _Cache:
    def __init__(self, clock=time.time):
        self._clock = clock
        self._t: dict[str, tuple[Redacted, float]] = {}

    def get(self, key):
        v = self._t.get(key)
        if v and v[1] - 60 > self._clock():  # refresh 60 s early
            return v[0]
        return None

    def put(self, key, token, ttl):
        self._t[key] = (Redacted(token), self._clock() + float(ttl))


class GraphAuth:
    def __init__(self, http: HttpClient, tenant_id: str, client_id: str, client_secret: str,
                 login_base="https://login.microsoftonline.com", clock=time.time):
        self.http, self.tenant_id, self.client_id = http, tenant_id, client_id
        self._secret = Redacted(client_secret)
        self.login_base = login_base.rstrip("/")
        self._cache = _Cache(clock)

    @classmethod
    def from_env(cls, http, environ=None, **kw):
        import os
        environ = os.environ if environ is None else environ
        try:
            tenant = environ["OU_M365_TENANT_ID"]
            client = environ["OU_M365_CLIENT_ID"]
        except KeyError as e:
            raise SecretError(f"missing {e.args[0]}") from None
        return cls(http, tenant, client, load_secret("OU_M365_CLIENT_SECRET", environ=environ), **kw)

    def token(self) -> str:
        t = self._cache.get("graph")
        if t:
            return t.reveal()
        body = urllib.parse.urlencode({
            "client_id": self.client_id, "client_secret": self._secret.reveal(),
            "scope": GRAPH_SCOPE, "grant_type": "client_credentials"}).encode()
        try:
            r = self.http.request("POST", f"{self.login_base}/{self.tenant_id}/oauth2/v2.0/token", data=body,
                                  headers={"Content-Type": "application/x-www-form-urlencoded"})
        except HttpError as e:
            raise AuthError(f"Microsoft token request failed: HTTP {e.status}") from None
        j = r.json()
        self._cache.put("graph", j["access_token"], j.get("expires_in", 3600))
        return j["access_token"]

    def headers(self):
        return {"Authorization": f"Bearer {self.token()}", "Accept": "application/json"}


def _b64(b: bytes) -> bytes:
    return base64.urlsafe_b64encode(b).rstrip(b"=")


class GoogleAuth:
    def __init__(self, http: HttpClient, sa_email: str, private_key_pem: str, admin_subject: str,
                 token_uri="https://oauth2.googleapis.com/token", clock=time.time):
        self.http, self.sa_email, self.admin_subject = http, sa_email, admin_subject
        self._key = Redacted(private_key_pem)
        self.token_uri = token_uri
        self._clock = clock
        self._cache = _Cache(clock)

    @classmethod
    def from_env(cls, http, environ=None, **kw):
        import os
        environ = os.environ if environ is None else environ
        try:
            path = environ["OU_GOOGLE_SA_KEY_FILE"]
            subject = environ["OU_GOOGLE_ADMIN_SUBJECT"]
        except KeyError as e:
            raise SecretError(f"missing {e.args[0]}") from None
        key = json.loads(read_secret_file(path))
        return cls(http, key["client_email"], key["private_key"], subject,
                   token_uri=key.get("token_uri", "https://oauth2.googleapis.com/token"), **kw)

    def _assertion(self, subject: str, scopes: list[str]) -> bytes:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        now = int(self._clock())
        header = {"alg": "RS256", "typ": "JWT"}
        claims = {"iss": self.sa_email, "sub": subject, "scope": " ".join(scopes),
                  "aud": self.token_uri, "iat": now, "exp": now + 3600}
        signing_input = _b64(json.dumps(header).encode()) + b"." + _b64(json.dumps(claims).encode())
        key = serialization.load_pem_private_key(self._key.reveal().encode(), password=None)
        sig = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        return signing_input + b"." + _b64(sig)

    def token(self, scopes: list[str], subject: str | None = None) -> str:
        subject = subject or self.admin_subject
        ck = subject + "|" + " ".join(sorted(scopes))
        t = self._cache.get(ck)
        if t:
            return t.reveal()
        body = urllib.parse.urlencode({
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": self._assertion(subject, scopes).decode()}).encode()
        try:
            r = self.http.request("POST", self.token_uri, data=body,
                                  headers={"Content-Type": "application/x-www-form-urlencoded"})
        except HttpError as e:
            # e.g. unauthorized_client = scope not allow-listed for domain-wide delegation
            raise AuthError(f"Google token request failed: HTTP {e.status} {_oauth_error(e.body)}") from None
        j = r.json()
        self._cache.put(ck, j["access_token"], j.get("expires_in", 3600))
        return j["access_token"]

    def headers(self, scopes, subject=None):
        return {"Authorization": f"Bearer {self.token(scopes, subject)}", "Accept": "application/json"}


def _oauth_error(body: bytes) -> str:
    try:
        return json.loads(body).get("error", "")
    except Exception:
        return ""
