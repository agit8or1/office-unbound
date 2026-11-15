"""Hash-chained, MAC-authenticated append-only audit log.

Design ported from rem0te apps/api/src/audit/chain.ts (MIT, (c) agit8or1):
  hash(n) = sha256(hash(n-1) + "\\n" + entry n), hash(0) = 64 zeros.
v2 entries (this module): entry = canonical_json(header) + "\\n" + details_canon, where details_canon is the exact
text stored in `audit_events.details_canon`; verification hashes those stored bytes, so jsonb number
normalisation can never break the chain (M4). details are sanitised first: non-finite / huge numbers and
unknown types become strings. Each row also carries mac = HMAC-SHA256(audit_key, "ics-audit-v2\\n" + hash)
with a key that is NOT in the database (L4): SQL-only write access cannot forge valid entries. A DB trigger
additionally forces prev_hash == current tail hash and a server-assigned seq.
Legacy v1 rows (details_canon NULL, from before migration 0002) are verified the old way and counted as unauthenticated.
Truncation of the tail is only detectable against an off-host copy of the head hash (see README).
"""
import hashlib
import hmac
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

GENESIS = "0" * 64
_SECRET_KEYS = ("secret", "password", "token", "totp", "key", "cookie", "csrf")
_ALLOWED_TOKENISH = {"token_id"}  # an identifier, not a credential
_LOCK_ID = 7_001_001
_PVE_TOKEN_RE = re.compile(r"PVEAPIToken=\S*", re.IGNORECASE)
_MAX_INT = 2**53
_audit_key: bytes | None = None


def set_key(key: bytes | None) -> None:
    if key is not None and len(key) < 32:
        raise ValueError("audit key must be at least 32 bytes")
    global _audit_key
    _audit_key = key


def mac_for(hash_: str) -> str:
    if _audit_key is None:
        raise RuntimeError("audit key not configured")
    return hmac.new(_audit_key, b"ics-audit-v2\n" + hash_.encode(), hashlib.sha256).hexdigest()


def canon(v: Any) -> str:
    """Canonical JSON. Rejects NaN/Infinity (allow_nan=False); callers must pass sanitize()d data for untrusted input."""
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def sanitize(v: Any, depth: int = 0) -> Any:
    """Make arbitrary (possibly remote-controlled) data safe to canonicalise: floats and huge ints -> str, unknown types -> str."""
    if depth > 12:
        return "[truncated]"
    if v is None or isinstance(v, (bool, str)):
        return v[:4096] if isinstance(v, str) else v
    if isinstance(v, int):
        return v if abs(v) <= _MAX_INT else str(v)
    if isinstance(v, float):
        return str(v)  # never a JSON number: avoids jsonb round-trip differences
    if isinstance(v, dict):
        return {str(k)[:200]: sanitize(x, depth + 1) for k, x in list(v.items())[:500]}
    if isinstance(v, (list, tuple)):
        return [sanitize(x, depth + 1) for x in list(v)[:500]]
    return str(v)[:4096]


def sanitize_numbers(v: Any, depth: int = 0) -> Any:
    """For stored remote data (inventory): keep structure, make numbers jsonb/JSON safe (no NaN/Infinity, no huge ints)."""
    if depth > 30:
        return "[truncated]"
    if isinstance(v, float):
        return v if abs(v) < 1e15 and v == v else str(v)
    if isinstance(v, int) and not isinstance(v, bool):
        return v if abs(v) <= _MAX_INT else str(v)
    if isinstance(v, dict):
        return {str(k): sanitize_numbers(x, depth + 1) for k, x in v.items()}
    if isinstance(v, list):
        return [sanitize_numbers(x, depth + 1) for x in v]
    return v


def redact(v: Any, secrets: "list[str] | tuple[str, ...]" = ()) -> Any:
    """Remove every known secret value (raw, stripped, JSON-escaped) and any `PVEAPIToken=...` pattern from strings in v."""
    variants: set[str] = set()
    for sec in secrets:
        if sec:
            variants.update({sec, sec.strip(), json.dumps(sec)[1:-1], repr(sec)[1:-1]})
    variants = {x for x in variants if x}
    ordered = sorted(variants, key=len, reverse=True)

    def go(x: Any) -> Any:
        if isinstance(x, str):
            for sec in ordered:
                x = x.replace(sec, "[redacted]")
            return _PVE_TOKEN_RE.sub("PVEAPIToken=[redacted]", x)
        if isinstance(x, dict):
            return {k: go(y) for k, y in x.items()}
        if isinstance(x, list):
            return [go(y) for y in x]
        return x
    return go(v)


def scrub(v: Any) -> Any:
    """Defensive: never let credential-looking keys or PVEAPIToken strings into the audit log."""
    if isinstance(v, dict):
        return {
            k: ("[redacted]" if any(s in k.lower() for s in _SECRET_KEYS) and k not in _ALLOWED_TOKENISH else scrub(x))
            for k, x in v.items()
        }
    if isinstance(v, list):
        return [scrub(x) for x in v]
    if isinstance(v, str):
        return _PVE_TOKEN_RE.sub("PVEAPIToken=[redacted]", v)
    return v


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds")


def entry_json(id_: str, at: datetime, action: str, actor_id, actor_name, ip, resource, resource_id, details) -> str:
    return canon({
        "v": 1, "id": str(id_), "at": iso(at), "action": action,
        "actor_id": str(actor_id) if actor_id else None, "actor_name": actor_name, "ip": ip,
        "resource": resource, "resource_id": resource_id, "details": details,
    })


def entry_v2(id_: str, at: datetime, action: str, actor_id, actor_name, ip, resource, resource_id, details_canon: str) -> str:
    header = canon({
        "v": 2, "id": str(id_), "at": iso(at), "action": action,
        "actor_id": str(actor_id) if actor_id else None, "actor_name": actor_name, "ip": ip,
        "resource": resource, "resource_id": resource_id,
    })
    return f"{header}\n{details_canon}"


def link(prev: str, entry: str) -> str:
    return hashlib.sha256(f"{prev}\n{entry}".encode()).hexdigest()


def append(db: Session, action: str, *, actor_id=None, actor_name=None, ip=None, resource=None,
           resource_id=None, details: dict | None = None) -> str:
    """Append inside the caller's transaction (commit is the caller's job). Serialized by an advisory lock."""
    details = sanitize(scrub(details or {}))
    details_canon = canon(details)
    db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _LOCK_ID})
    prev = db.execute(text("SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1")).scalar() or GENESIS
    id_ = uuid.uuid4()
    at = datetime.now(timezone.utc)
    actor_name = actor_name[:200] if actor_name else actor_name
    h = link(prev, entry_v2(id_, at, action, actor_id, actor_name, ip, resource, resource_id, details_canon))
    db.execute(text(
        "INSERT INTO audit_events (id, at, action, actor_id, actor_name, ip, resource, resource_id, details, details_canon, prev_hash, hash, mac) "
        "VALUES (CAST(:id AS uuid), :at, :action, CAST(:actor_id AS uuid), :actor_name, :ip, :resource, :resource_id, "
        "CAST(:details AS jsonb), :dc, :prev, :hash, :mac)"),
        {"id": str(id_), "at": at, "action": action, "actor_id": str(actor_id) if actor_id else None, "actor_name": actor_name, "ip": ip,
         "resource": resource, "resource_id": resource_id, "details": details_canon, "dc": details_canon, "prev": prev, "hash": h,
         "mac": mac_for(h)})
    return h


_COLS = "seq, id, at, action, actor_id, actor_name, ip, resource, resource_id, details, details_canon, mac, prev_hash, hash"


def verify_chain(db: Session, tail: int | None = None) -> dict:
    """Recompute the chain. tail=N checks only the last N rows (anchored on the stored prev_hash of the first)."""
    if tail:
        rows = list(reversed(db.execute(text(f"SELECT {_COLS} FROM audit_events ORDER BY seq DESC LIMIT :n"), {"n": tail}).all()))
        prev = rows[0].prev_hash if rows else GENESIS
        first = True
    else:
        rows = db.execute(text(f"SELECT {_COLS} FROM audit_events ORDER BY seq")).all()
        prev, first = GENESIS, False
    problems: list[dict] = []
    legacy = 0
    for r in rows:
        if not first and r.prev_hash != prev:
            problems.append({"seq": r.seq, "kind": "broken_link", "detail": "prev_hash does not match previous row (deleted/inserted row?)"})
        if r.details_canon is None:  # legacy v1 row
            legacy += 1
            expect = link(r.prev_hash, entry_json(r.id, r.at, r.action, r.actor_id, r.actor_name, r.ip, r.resource, r.resource_id, r.details))
        else:
            expect = link(r.prev_hash, entry_v2(r.id, r.at, r.action, r.actor_id, r.actor_name, r.ip, r.resource, r.resource_id, r.details_canon))
            try:
                if json.loads(r.details_canon) != r.details:
                    problems.append({"seq": r.seq, "kind": "details_mismatch", "detail": "details column differs from the hashed canonical text"})
            except ValueError:
                problems.append({"seq": r.seq, "kind": "details_mismatch", "detail": "details_canon is not valid JSON"})
            if _audit_key is not None and not (r.mac and hmac.compare_digest(r.mac, mac_for(r.hash))):
                problems.append({"seq": r.seq, "kind": "bad_mac", "detail": "missing or invalid MAC (entry not written by ICS)"})
        if expect != r.hash:
            problems.append({"seq": r.seq, "kind": "altered", "detail": "hash does not match row contents"})
        prev, first = r.hash, False
    return {"ok": not problems, "checked": len(rows), "head": prev if rows else GENESIS, "legacy_unauthenticated": legacy,
            "mac_checked": _audit_key is not None, "problems": problems[:50]}
