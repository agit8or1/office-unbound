"""OIDC authorization-code + PKCE (S256) client, server side (BFF). Tokens never leave this process.

Validation of the ID token: RS256/ES256 signature via the issuer's JWKS, iss, aud, exp, nonce, azp.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
import time
from urllib.parse import urlencode

import httpx
import jwt

from .config import Settings


class OIDCError(Exception):
    pass


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def new_pkce() -> tuple[str, str]:
    verifier = _b64url(secrets.token_bytes(48))
    return verifier, _b64url(hashlib.sha256(verifier.encode()).digest())


class OIDC:
    def __init__(self, cfg: Settings, client: httpx.AsyncClient):
        self.cfg, self.http = cfg, client
        self._disc: dict | None = None
        self._jwks: dict[str, jwt.PyJWK] = {}
        self._jwks_at = 0.0

    async def discovery(self) -> dict:
        if self._disc is None:
            r = await self.http.get(self.cfg.issuer + "/.well-known/openid-configuration")
            r.raise_for_status()
            d = r.json()
            if d.get("issuer") != self.cfg.issuer:
                raise OIDCError("issuer mismatch in discovery document")
            self._disc = d
        return self._disc

    async def auth_url(self, state: str, nonce: str, challenge: str) -> str:
        d = await self.discovery()
        q = {
            "response_type": "code", "client_id": self.cfg.client_id, "redirect_uri": self.cfg.base_url + "/auth/callback",
            "scope": "openid profile email", "state": state, "nonce": nonce,
            "code_challenge": challenge, "code_challenge_method": "S256",
        }
        return d["authorization_endpoint"] + "?" + urlencode(q)

    async def _token(self, form: dict) -> dict:
        d = await self.discovery()
        r = await self.http.post(d["token_endpoint"], data=form, auth=(self.cfg.client_id, self.cfg.client_secret))
        if r.status_code != 200:
            raise OIDCError(f"token endpoint answered {r.status_code}")
        return r.json()

    async def exchange_code(self, code: str, verifier: str) -> dict:
        return await self._token({
            "grant_type": "authorization_code", "code": code, "code_verifier": verifier,
            "redirect_uri": self.cfg.base_url + "/auth/callback"})

    async def refresh(self, refresh_token: str) -> dict:
        return await self._token({"grant_type": "refresh_token", "refresh_token": refresh_token})

    async def _key(self, kid: str) -> jwt.PyJWK:
        if kid not in self._jwks or time.time() - self._jwks_at > 3600:
            d = await self.discovery()
            r = await self.http.get(d["jwks_uri"])
            r.raise_for_status()
            self._jwks = {k["kid"]: jwt.PyJWK(k) for k in r.json()["keys"] if k.get("use", "sig") == "sig" and "kid" in k}
            self._jwks_at = time.time()
        if kid not in self._jwks:
            raise OIDCError("unknown signing key")
        return self._jwks[kid]

    async def verify_id_token(self, id_token: str, nonce: str) -> dict:
        try:
            kid = jwt.get_unverified_header(id_token).get("kid", "")
            key = await self._key(kid)
            claims = jwt.decode(id_token, key.key, algorithms=["RS256", "ES256", "PS256"], audience=self.cfg.client_id,
                                issuer=self.cfg.issuer, options={"require": ["exp", "iat", "iss", "aud", "sub"]}, leeway=30)
        except jwt.PyJWTError as e:
            raise OIDCError(f"invalid id_token: {type(e).__name__}") from e
        if claims.get("nonce") != nonce:
            raise OIDCError("nonce mismatch")
        if claims.get("azp", self.cfg.client_id) != self.cfg.client_id:
            raise OIDCError("azp mismatch")
        return claims

    async def logout_url(self, id_token: str | None) -> str:
        d = await self.discovery()
        q = {"client_id": self.cfg.client_id, "post_logout_redirect_uri": self.cfg.base_url + "/"}
        if id_token:
            q["id_token_hint"] = id_token
        return d["end_session_endpoint"] + "?" + urlencode(q)
