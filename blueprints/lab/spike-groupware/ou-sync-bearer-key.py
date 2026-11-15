#!/usr/bin/env python3
"""Keep gromox's /etc/gromox/bearer_pubkey equal to the realm's ACTIVE RS256 signing key (Keycloak key rotation).

gromox (authmgr verify_token) reads exactly one PEM key, per verification (no restart needed). Keycloak signs access tokens with the active key of the
realm; after a rotation (or a new higher-priority key) every webmail SSO login would fail with "Token did not validate" until the file follows.
This job runs on the groupware node (systemd timer, every 30 s). Stdlib only.

How the key is chosen (by kid, not by position): GET <realm>  -> `public_key` (the key Keycloak currently SIGNS with); GET <realm>/protocol/openid-connect/certs
-> JWKS; the JWKS entry (use=sig, alg=RS256, kty=RSA) whose public key equals it gives the kid. The PEM written is built from that JWKS entry. If no JWKS entry
matches (inconsistent response) nothing is written and the exit code is 3 (the old key stays).
Exit: 0 unchanged/updated, 2 fetch error (old key stays), 3 inconsistent answer. State (kid, timestamp) -> /var/lib/ou-sync-bearer-key/state.json.
Limitation (documented in docs/status/sso-rollout-results.md): gromox holds ONE key, so tokens signed by the previous key (max. access-token lifetime, 5 min)
stop validating at the switch; webmail refreshes its token every 280 s and logs in again through Keycloak when it fails.
"""
import argparse
import base64
import json
import os
import ssl
import sys
import tempfile
import time
import urllib.request


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(body)) + body


def _int(b: bytes) -> bytes:
    b = b.lstrip(b"\0") or b"\0"
    if b[0] & 0x80:
        b = b"\0" + b
    return _tlv(0x02, b)


def _b64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jwk_to_spki_b64(jwk: dict) -> str:
    """RSA JWK -> base64 of the SubjectPublicKeyInfo DER (the format of Keycloak's realm `public_key`)."""
    rsa = _tlv(0x30, _int(_b64u(jwk["n"])) + _int(_b64u(jwk["e"])))
    alg = _tlv(0x30, bytes.fromhex("06092a864886f70d010101") + bytes.fromhex("0500"))
    return base64.b64encode(_tlv(0x30, alg + _tlv(0x03, b"\0" + rsa))).decode()


def pem(b64: str) -> str:
    return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64)) + "\n-----END PUBLIC KEY-----\n"


def choose(realm: dict, jwks: dict) -> tuple[str, str]:
    """-> (kid, spki_b64) of the JWKS entry equal to the realm's active signing key. ValueError if none matches."""
    want = "".join(realm["public_key"].split())
    for k in jwks.get("keys", []):
        if k.get("kty") == "RSA" and k.get("use", "sig") == "sig" and k.get("alg", "RS256") == "RS256" and jwk_to_spki_b64(k) == want:
            return k["kid"], want
    raise ValueError("active realm key not found in JWKS")


def fetch(url: str, ctx) -> dict:
    with urllib.request.urlopen(url, context=ctx, timeout=10) as r:
        return json.load(r)


def write_if_changed(path: str, content: str, group: str | None) -> bool:
    try:
        if open(path).read() == content:
            return False
    except FileNotFoundError:
        pass
    d = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".bearer.")
    with os.fdopen(fd, "w") as f:
        f.write(content)
    os.chmod(tmp, 0o640)
    if group:
        import grp
        os.chown(tmp, 0, grp.getgrnam(group).gr_gid)
    os.replace(tmp, path)
    return True


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--realm-url", default="https://auth.ou-lab.internal/realms/ou-lab")
    ap.add_argument("--ca", default="/etc/ssl/certs/ca-certificates.crt")
    ap.add_argument("--out", default="/etc/gromox/bearer_pubkey")
    ap.add_argument("--group", default="gromoxcf")
    ap.add_argument("--state-dir", default="/var/lib/ou-sync-bearer-key")
    a = ap.parse_args(argv)
    ctx = ssl.create_default_context(cafile=a.ca)
    try:
        realm = fetch(a.realm_url, ctx)
        jwks = fetch(a.realm_url + "/protocol/openid-connect/certs", ctx)
    except Exception as e:  # noqa: BLE001
        print(f"fetch failed ({type(e).__name__}); keeping the current key", file=sys.stderr)
        return 2
    try:
        kid, b64 = choose(realm, jwks)
    except (ValueError, KeyError) as e:
        print(f"inconsistent realm answer ({e}); keeping the current key", file=sys.stderr)
        return 3
    changed = write_if_changed(a.out, pem(b64), a.group)
    os.makedirs(a.state_dir, exist_ok=True)
    json.dump({"kid": kid, "checked_at": int(time.time()), "changed": changed}, open(os.path.join(a.state_dir, "state.json"), "w"))
    print(f"bearer key kid={kid} {'UPDATED' if changed else 'unchanged'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
