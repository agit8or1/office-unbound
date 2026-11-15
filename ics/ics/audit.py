"""Hash-chained append-only audit log.

Design ported from rem0te apps/api/src/audit/chain.ts (MIT, (c) agit8or1):
  hash(n) = sha256(hash(n-1) + "\\n" + canonical_json(entry n)), hash(0) = 64 zeros.
Detects altered or deleted-in-the-middle rows. Truncation of the tail is only detectable against
an off-host copy of the head hash (not implemented yet; see README).
"""
import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

GENESIS = "0" * 64
_SECRET_KEYS = ("secret", "password", "token", "totp", "key", "cookie", "csrf")
_ALLOWED_TOKENISH = {"token_id"}  # an identifier, not a credential
_LOCK_ID = 7_001_001


def canon(v: Any) -> str:
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def scrub(v: Any) -> Any:
    """Defensive: never let credential-looking keys into the audit log."""
    if isinstance(v, dict):
        return {
            k: ("[redacted]" if any(s in k.lower() for s in _SECRET_KEYS) and k not in _ALLOWED_TOKENISH else scrub(x))
            for k, x in v.items()
        }
    if isinstance(v, list):
        return [scrub(x) for x in v]
    return v


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds")


def entry_json(id_: str, at: datetime, action: str, actor_id, actor_name, ip, resource, resource_id, details) -> str:
    return canon({
        "v": 1, "id": str(id_), "at": iso(at), "action": action,
        "actor_id": str(actor_id) if actor_id else None, "actor_name": actor_name, "ip": ip,
        "resource": resource, "resource_id": resource_id, "details": details,
    })


def link(prev: str, entry: str) -> str:
    return hashlib.sha256(f"{prev}\n{entry}".encode()).hexdigest()


def append(db: Session, action: str, *, actor_id=None, actor_name=None, ip=None, resource=None,
           resource_id=None, details: dict | None = None) -> str:
    """Append inside the caller's transaction (commit is the caller's job). Serialized by an advisory lock."""
    details = scrub(details or {})
    db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _LOCK_ID})
    prev = db.execute(text("SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1")).scalar() or GENESIS
    id_ = uuid.uuid4()
    at = datetime.now(timezone.utc)
    h = link(prev, entry_json(id_, at, action, actor_id, actor_name, ip, resource, resource_id, details))
    db.execute(text(
        "INSERT INTO audit_events (id, at, action, actor_id, actor_name, ip, resource, resource_id, details, prev_hash, hash) "
        "VALUES (CAST(:id AS uuid), :at, :action, CAST(:actor_id AS uuid), :actor_name, :ip, :resource, :resource_id, CAST(:details AS jsonb), :prev, :hash)"),
        {"id": str(id_), "at": at, "action": action, "actor_id": str(actor_id) if actor_id else None, "actor_name": actor_name, "ip": ip,
         "resource": resource, "resource_id": resource_id, "details": canon(details), "prev": prev, "hash": h})
    return h


_COLS = "seq, id, at, action, actor_id, actor_name, ip, resource, resource_id, details, prev_hash, hash"


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
    for r in rows:
        if not first and r.prev_hash != prev:
            problems.append({"seq": r.seq, "kind": "broken_link", "detail": "prev_hash does not match previous row (deleted/inserted row?)"})
        expect = link(r.prev_hash, entry_json(r.id, r.at, r.action, r.actor_id, r.actor_name, r.ip, r.resource, r.resource_id, r.details))
        if expect != r.hash:
            problems.append({"seq": r.seq, "kind": "altered", "detail": "hash does not match row contents"})
        prev, first = r.hash, False
    return {"ok": not problems, "checked": len(rows), "head": prev if rows else GENESIS, "problems": problems[:50]}
