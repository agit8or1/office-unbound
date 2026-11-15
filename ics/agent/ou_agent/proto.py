"""Wire protocol shared (by specification, not by import) with the ICS side `ics/agentclient.py`.

ICS -> agent request:  {"req": {v, action, params, node_id, job_id, issued_at, expires_at, nonce}, "sig": b64(Ed25519)}
  signature input = b"ou-agent-req-v1\\n" + canonical_json(req)
agent -> ICS response: {"resp": {...}, "sig": b64(Ed25519)}   signature input = b"ou-agent-resp-v1\\n" + canonical_json(resp)
canonical_json = sorted keys, no whitespace, ASCII only, no floats / NaN.
Stdlib + cryptography only.
"""
import base64
import json
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

REQ_PREFIX = b"ou-agent-req-v1\n"
RESP_PREFIX = b"ou-agent-resp-v1\n"
MAX_WINDOW = 120   # expires_at - issued_at
MAX_SKEW = 120     # |now - issued_at| tolerated clock difference
REQ_FIELDS = {"v", "action", "params", "node_id", "job_id", "issued_at", "expires_at", "nonce"}
REQ_FIELDS_EPOCH = REQ_FIELDS | {"epoch"}   # controller epoch (ADR-0012): optional for backward compatibility with pre-epoch ICS releases
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{22,64}$")


class Reject(Exception):
    """A request refused; `code` is machine readable, `msg` is safe to return."""

    def __init__(self, code: str, msg: str = ""):
        super().__init__(code)
        self.code, self.msg = code, msg or code


def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def _no_floats(v, depth=0):
    if depth > 6:
        raise Reject("bad_format", "nesting too deep")
    if isinstance(v, float):
        raise Reject("bad_format", "floats are not allowed")
    if isinstance(v, dict):
        for k, x in v.items():
            if not isinstance(k, str):
                raise Reject("bad_format", "keys must be strings")
            _no_floats(x, depth + 1)
    elif isinstance(v, list):
        for x in v:
            _no_floats(x, depth + 1)


def sign(priv, prefix: bytes, obj) -> str:
    return base64.b64encode(priv.sign(prefix + canon(obj))).decode()


def verify(pub: Ed25519PublicKey, prefix: bytes, obj, sig_b64: str) -> bool:
    try:
        pub.verify(base64.b64decode(sig_b64, validate=True), prefix + canon(obj))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def pub_from_b64(s: str) -> Ed25519PublicKey:
    raw = base64.b64decode(s, validate=True)
    if len(raw) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def check_envelope(req, *, now: int, node_id: str) -> dict:
    """Strict structural + temporal validation of an (already signature-verified) request."""
    if not isinstance(req, dict) or set(req) not in (REQ_FIELDS, REQ_FIELDS_EPOCH):
        raise Reject("bad_format", "unexpected or missing fields")
    _no_floats(req)
    if req["v"] != 1:
        raise Reject("bad_format", "unsupported version")
    if "epoch" in req and (type(req["epoch"]) is not int or not 0 <= req["epoch"] < 2**62):
        raise Reject("bad_format", "epoch must be a non-negative integer")
    if not isinstance(req["action"], str) or not isinstance(req["params"], dict):
        raise Reject("bad_format")
    for k in ("issued_at", "expires_at"):
        if type(req[k]) is not int:
            raise Reject("bad_format", f"{k} must be an integer")
    for k in ("node_id", "job_id"):
        if not isinstance(req[k], str) or not UUID_RE.fullmatch(req[k]):
            raise Reject("bad_format", f"{k} must be a lowercase uuid")
    if not isinstance(req["nonce"], str) or not NONCE_RE.fullmatch(req["nonce"]):
        raise Reject("bad_format", "bad nonce")
    if req["node_id"] != node_id:
        raise Reject("wrong_node", "request is for a different node")
    if req["expires_at"] - req["issued_at"] > MAX_WINDOW or req["expires_at"] <= req["issued_at"]:
        raise Reject("window_too_long", f"validity window must be 1..{MAX_WINDOW}s")
    if now > req["expires_at"]:
        raise Reject("expired", "request expired")
    if req["issued_at"] - now > MAX_SKEW:
        raise Reject("not_yet_valid", "issued_at is in the future beyond the allowed skew")
    return req


class EpochGate:
    """Highest controller epoch ever accepted (ADR-0012 fencing). Persisted with fsync BEFORE a request runs, so it survives crashes.
    A request with a LOWER epoch is refused (a resurrected old primary cannot drive this node); a higher epoch raises the mark
    (the agent learns a promotion from the first authenticated request of the promoted controller). A request WITHOUT an epoch is
    only accepted while the mark is still 0 (a node that never met an epoch-aware controller keeps working through the upgrade)."""

    def __init__(self, path: str):
        import threading
        self.path, self.lock = path, threading.Lock()
        try:
            with open(path) as f:
                self.max_epoch = int(json.load(f)["max_epoch"])
        except (FileNotFoundError, ValueError, KeyError, TypeError):
            self.max_epoch = 0

    def admit(self, epoch) -> int:
        """Call only for an authenticated, structurally valid request. Returns the (possibly raised) mark or raises Reject."""
        with self.lock:
            if epoch is None:
                if self.max_epoch > 0:
                    raise Reject("epoch_required", f"controller epoch required (highest seen {self.max_epoch})")
                return self.max_epoch
            if epoch < self.max_epoch:
                raise Reject("stale_epoch", f"controller epoch {epoch} is lower than the highest seen {self.max_epoch}: this controller was fenced")
            if epoch > self.max_epoch:
                import os
                tmp = self.path + ".tmp"
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w") as f:
                    json.dump({"max_epoch": epoch}, f)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp, self.path)
                self.max_epoch = epoch
            return self.max_epoch
