"""Minimal JWT verification for the user's Keycloak access token (RS256 / ES256 only, via `cryptography`; no extra dependency).

The expected issuer, client (azp) and audience-of-trust come from the ICS database for the customer the SERVICE credential belongs to, never from the
token. alg `none`/HS* are refused because only the two asymmetric algorithms are accepted and the key comes from the realm's JWKS."""
import base64
import json
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

MAX_LIFETIME = 900  # Keycloak access tokens are minutes; anything longer is not a normal user token


class TokenError(Exception):
    pass


def _b64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _int(s: str) -> int:
    return int.from_bytes(_b64(s), "big")


def _public_key(jwk: dict):
    if jwk.get("kty") == "RSA":
        return rsa.RSAPublicNumbers(_int(jwk["e"]), _int(jwk["n"])).public_key()
    if jwk.get("kty") == "EC" and jwk.get("crv") == "P-256":
        return ec.EllipticCurvePublicNumbers(_int(jwk["x"]), _int(jwk["y"]), ec.SECP256R1()).public_key()
    raise TokenError("unsupported key type")


def verify(token: str, jwks: dict, *, issuer: str, client_id: str, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    try:
        h, p, s = token.split(".")
        header, claims, sig = json.loads(_b64(h)), json.loads(_b64(p)), _b64(s)
    except (ValueError, TypeError, AttributeError):
        raise TokenError("malformed token") from None
    if len(token) > 16384 or not isinstance(claims, dict) or not isinstance(header, dict):
        raise TokenError("malformed token")
    alg = header.get("alg")
    if alg not in ("RS256", "ES256"):
        raise TokenError("unsupported algorithm")
    keys = [k for k in jwks.get("keys", []) if k.get("kid") == header.get("kid") and k.get("use", "sig") == "sig"]
    if len(keys) != 1:
        raise TokenError("unknown signing key")
    try:
        pub = _public_key(keys[0])
        signed = f"{h}.{p}".encode()
        if alg == "RS256":
            if not isinstance(pub, rsa.RSAPublicKey):
                raise TokenError("key does not match algorithm")
            pub.verify(sig, signed, padding.PKCS1v15(), hashes.SHA256())
        else:
            if not isinstance(pub, ec.EllipticCurvePublicKey) or len(sig) != 64:
                raise TokenError("key does not match algorithm")
            pub.verify(encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")), signed, ec.ECDSA(hashes.SHA256()))
    except TokenError:
        raise
    except Exception:
        raise TokenError("bad signature") from None
    exp, iat = claims.get("exp"), claims.get("iat")
    if not isinstance(exp, (int, float)) or not isinstance(iat, (int, float)):
        raise TokenError("missing exp/iat")
    if exp < now - 30 or iat > now + 60 or exp - iat > MAX_LIFETIME:
        raise TokenError("token expired or implausible lifetime")
    if claims.get("iss") != issuer:
        raise TokenError("wrong issuer")
    if claims.get("typ") != "Bearer":   # an ID token (typ ID) or a refresh token is not an access token (review 6 L2)
        raise TokenError("not an access token")
    if claims.get("azp") != client_id:
        raise TokenError("token was not issued to the portal client")
    if not claims.get("sub") or not isinstance(claims.get("sub"), str):
        raise TokenError("no subject")
    return claims


def realm_roles(claims: dict) -> set[str]:
    r = set()
    ra = claims.get("realm_access")
    if isinstance(ra, dict) and isinstance(ra.get("roles"), list):
        r |= {x for x in ra["roles"] if isinstance(x, str)}
    return r   # ONLY realm_access.roles: a flat `roles` claim can come from a mapper over user-editable attributes (review 6 L2)
