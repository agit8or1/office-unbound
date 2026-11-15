"""ICS side of the node-agent protocol (see agent/ou_agent/proto.py for the wire format).

Requests are signed with the ICS Ed25519 key (`ICS_SIGNING_KEY_FILE`, root:ics 0640, never in the DB); responses must be signed by the
agent key recorded at enrollment. The agent's TLS certificate is pinned (SHA-256 of the leaf, supplied out of band at enrollment).
There is no way to send anything but {action, params}: free-form commands cannot be expressed in the envelope.
"""
import base64
import json
import secrets
import ssl
import time
import uuid

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .proxmox import ProxmoxError, build_ssl_context, check_destination
from .vault import VaultError, read_key_file

REQ_PREFIX = b"ou-agent-req-v1\n"
RESP_PREFIX = b"ou-agent-resp-v1\n"
MAX_RESPONSE = 64 * 1024


class AgentError(Exception):
    """Message is safe to store and show (no transport text)."""


def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def load_signing_key(path: str | None) -> Ed25519PrivateKey:
    if not path:
        raise AgentError("ICS signing key is not configured (ICS_SIGNING_KEY_FILE)")
    try:
        raw = read_key_file(path, "signing key")
    except VaultError as e:
        raise AgentError(str(e)) from None
    if len(raw) != 32:
        raise AgentError("signing key must be exactly 32 raw bytes")
    return Ed25519PrivateKey.from_private_bytes(raw)


def pub_b64(pub: Ed25519PublicKey) -> str:
    return base64.b64encode(pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()


def pub_from_b64(s: str) -> Ed25519PublicKey:
    raw = base64.b64decode(s, validate=True)
    if len(raw) != 32:
        raise ValueError("bad key length")
    return Ed25519PublicKey.from_public_bytes(raw)


def key_fingerprint(pub_b64_: str) -> str:
    import hashlib
    return hashlib.sha256(base64.b64decode(pub_b64_)).hexdigest()


def sign(priv: Ed25519PrivateKey, prefix: bytes, obj) -> str:
    return base64.b64encode(priv.sign(prefix + canon(obj))).decode()


def verify(pub: Ed25519PublicKey, prefix: bytes, obj, sig: str) -> bool:
    try:
        pub.verify(base64.b64decode(sig, validate=True), prefix + canon(obj))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def build_request(priv, *, action: str, params: dict, node_id: str, job_id: str, ttl: int = 60, now: int | None = None,
                  nonce: str | None = None, epoch: int | None = None) -> dict:
    """`epoch` is the controller epoch (ADR-0012): agents refuse a request whose epoch is lower than the highest they have seen.
    None omits the field (pre-epoch wire format; accepted by agents only until they have seen any epoch)."""
    now = int(time.time()) if now is None else now
    req = {"v": 1, "action": action, "params": params, "node_id": node_id, "job_id": job_id,
           "issued_at": now, "expires_at": now + ttl, "nonce": nonce or secrets.token_urlsafe(24)}
    if epoch is not None:
        req["epoch"] = int(epoch)
    return {"req": req, "sig": sign(priv, REQ_PREFIX, req)}


def _post(address: str, port: int, tls_fp: str, path: str, body: dict | None, *, allow_loopback: bool, deadline: float) -> tuple[int, dict]:
    try:
        check_destination(address, allow_loopback)
        ctx = build_ssl_context(ca_pem=None, fingerprint_sha256=tls_fp)
        with httpx.Client(verify=ctx, timeout=httpx.Timeout(5.0, read=deadline), follow_redirects=False, trust_env=False) as c:
            url = f"https://{address}:{port}{path}"
            with (c.stream("POST", url, content=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
                  if body is not None else c.stream("GET", url)) as r:
                buf = bytearray()
                for chunk in r.iter_raw():
                    buf += chunk
                    if len(buf) > MAX_RESPONSE:
                        raise AgentError("agent response too large")
                code = r.status_code
        return code, json.loads(bytes(buf))
    except AgentError:
        raise
    except ProxmoxError as e:
        raise AgentError(str(e)) from None
    except (httpx.HTTPError, ssl.SSLError, OSError, ValueError) as e:
        raise AgentError(f"agent unreachable or untrusted: {type(e).__name__}") from None


def identity(address: str, port: int, tls_fp: str, *, allow_loopback: bool = False) -> dict:
    code, d = _post(address, port, tls_fp, "/v1/identity", None, allow_loopback=allow_loopback, deadline=10)
    if code != 200 or not isinstance(d.get("agent_pubkey"), str):
        raise AgentError("unexpected identity response")
    return d


def enroll(address: str, port: int, tls_fp: str, *, token: str, ics_pubkey_b64: str, node_id: str, expect_agent_pubkey_b64: str,
           allow_loopback: bool = False) -> dict:
    """One-time enrollment. The response must be signed by the agent key whose fingerprint the operator supplied."""
    code, d = _post(address, port, tls_fp, "/v1/enroll", {"token": token, "ics_pubkey": ics_pubkey_b64, "node_id": node_id},
                    allow_loopback=allow_loopback, deadline=15)
    if code != 200:
        raise AgentError(f"agent refused enrollment: {str(d.get('error', code))[:60]}")
    resp, sig = d.get("resp"), d.get("sig")
    if not isinstance(resp, dict) or not isinstance(sig, str) or not verify(pub_from_b64(expect_agent_pubkey_b64), RESP_PREFIX, resp, sig):
        raise AgentError("enrollment response signature invalid")
    if resp.get("type") != "enroll" or resp.get("node_id") != node_id or resp.get("agent_pubkey") != expect_agent_pubkey_b64:
        raise AgentError("enrollment response does not match the request")
    return resp


def call(node, priv, *, action: str, params: dict, job_id: str, ttl: int = 60, deadline: float = 90.0, allow_loopback: bool = False,
         req_override: dict | None = None) -> tuple[dict, dict]:
    """Send one signed request and return (request_envelope, verified_response). `node` needs address, port, tls_fingerprint_sha256,
    agent_pubkey, id. A response that does not verify, or does not echo job id / nonce / node id, is an error."""
    if getattr(node, "status", None) == "decommissioned":  # trust was revoked: no request may ever be sent again
        raise AgentError("node is decommissioned")
    body = req_override or build_request(priv, action=action, params=params, node_id=str(node.id), job_id=job_id, ttl=ttl)
    code, d = _post(node.address, node.port, node.tls_fingerprint_sha256.strip(), "/v1/exec", body, allow_loopback=allow_loopback, deadline=deadline)
    resp, sig = d.get("resp"), d.get("sig")
    if code == 403 and isinstance(d.get("error"), str) and sig is None:   # pre-authentication refusal: deliberately unsigned (review L2)
        raise AgentError(f"agent refused the request before authentication: {d['error'][:40]}")
    if not isinstance(resp, dict) or not isinstance(sig, str):
        raise AgentError("agent returned an unsigned/malformed response")
    if not verify(pub_from_b64(node.agent_pubkey), RESP_PREFIX, resp, sig):
        raise AgentError("agent response signature invalid")
    req = body["req"]
    if resp.get("type") != "exec":
        raise AgentError("agent response has the wrong type")
    if resp.get("nonce") != req.get("nonce") or resp.get("job_id") != req.get("job_id") or resp.get("node_id") != str(node.id):
        raise AgentError("agent response does not match the request (nonce/job/node)")
    if resp.get("code") in ("stale_epoch", "epoch_required") and stale_epoch_hook is not None:
        try:
            stale_epoch_hook(resp.get("agent_epoch"))
        except Exception:  # noqa: BLE001 - never mask the refusal itself
            pass
    return req, resp


# Set by Runtime: called with the agent's highest-seen epoch when an agent refuses us as stale (we were fenced).
stale_epoch_hook = None


def new_job_id() -> str:
    return str(uuid.uuid4())
