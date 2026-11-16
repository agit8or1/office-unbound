"""Shared (cross-process) rate limiting on PostgreSQL.

One token bucket per key (`rate_limits`, UNLOGGED). `allow()` is ONE atomic statement: INSERT ... ON CONFLICT DO UPDATE refills the bucket from the
elapsed database time (capacity = `limit`, refill = limit/window per second), takes a token if at least one is there and records whether it did.
The row lock taken by the upsert serialises concurrent callers of the same key across every worker process, so N workers share exactly one budget
(no advisory locks, no read-modify-write in Python). Denied calls consume nothing, so a flood cannot extend its own lock-out.
Time comes from the database (one clock for all workers). Old rows are purged opportunistically (1 in PURGE_EVERY calls). A database error propagates
(fail closed: the endpoint answers 5xx rather than letting traffic through unlimited)."""
import random

from sqlalchemy import text

PURGE_EVERY = 200
PURGE_AFTER_SECONDS = 3600

_REFILLED = "LEAST(:cap, r.tokens + EXTRACT(EPOCH FROM (clock_timestamp() - r.ts)) * :rate)"
_SQL = text(f"""
INSERT INTO rate_limits AS r (key, tokens, ts, allowed) VALUES (:k, :cap - 1, clock_timestamp(), true)
ON CONFLICT (key) DO UPDATE SET
  tokens  = CASE WHEN {_REFILLED} >= 1 THEN {_REFILLED} - 1 ELSE {_REFILLED} END,
  allowed = {_REFILLED} >= 1,
  ts      = clock_timestamp()
RETURNING allowed""")

_LAST = {"rt": None}   # tests only: reset() without naming a runtime


def allow(rt, key: str, limit: int, window: float) -> bool:
    """True if the call may proceed: `limit` calls per `window` seconds, burst = limit."""
    _LAST["rt"] = rt
    with rt.engine.begin() as c:
        allowed = c.execute(_SQL, {"k": key[:200], "cap": float(limit), "rate": limit / window}).scalar_one()
        if random.randrange(PURGE_EVERY) == 0:
            c.execute(text("DELETE FROM rate_limits WHERE ts < now() - make_interval(secs => :s)"), {"s": PURGE_AFTER_SECONDS})
    return bool(allowed)


def reset(rt=None) -> None:
    rt = rt or _LAST["rt"]
    if rt is None:
        return
    with rt.engine.begin() as c:
        c.execute(text("DELETE FROM rate_limits"))
