"""Warm-standby support (ADR-0012): passive-mode guard, standby console page, replication status.

A standby runs `ICS_ROLE=standby`: no worker/monitor/inventory/backup loops, every mutating HTTP method is refused with a clear
503 + `X-OU-Role: standby`, signed agent requests are refused in code (epoch.check_active), and /readyz reports replication lag.
The standby's PostgreSQL is a hot standby (read-only), so even a bug cannot write.
"""
from datetime import datetime, timezone

from sqlalchemy import text

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

STANDBY_MESSAGE = ("This Office Unbound controller is a warm STANDBY (read-only). It mirrors the primary controller and takes over only "
                   "when an operator promotes it (docs/runbooks/ics-recovery.md). Use the primary controller console for changes.")

PAGE = b"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Office Unbound - standby controller</title>
<meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/standby.css"></head>
<body><div class="banner" role="alert"><strong>STANDBY CONTROLLER (read-only)</strong></div>
<main><h1>This is the standby controller</h1>
<p>This controller mirrors the primary and is <strong>passive</strong>: it runs no monitoring, jobs or agent requests and refuses every change.
Sign in on the primary controller for normal operations.</p>
<p>Replication state and role: <a href="/readyz">/readyz</a></p>
<p>An operator takes this controller over with the documented fenced promotion (<code>ics-promote</code>), never automatically.</p>
</main></body></html>"""

CSS = b"""body{font:16px/1.5 system-ui,sans-serif;margin:0;background:#fff;color:#111}
.banner{background:#b45309;color:#fff;padding:.9rem 1.2rem;font-size:1.1rem;letter-spacing:.03em}
main{max-width:46rem;margin:2rem auto;padding:0 1rem}code{background:#eee;padding:0 .3em}
@media (prefers-color-scheme:dark){body{background:#111;color:#eee}code{background:#333}}"""


class StandbyGuard:
    """Pure ASGI middleware, active only on a standby."""

    def __init__(self, app, message: str = STANDBY_MESSAGE):
        self.app, self.message = app, message

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        method, path = scope["method"], scope["path"]

        async def respond(status: int, ctype: bytes, body: bytes, extra=()):
            await send({"type": "http.response.start", "status": status, "headers": [
                (b"content-type", ctype), (b"content-length", str(len(body)).encode()), (b"x-ou-role", b"standby"), *extra]})
            await send({"type": "http.response.body", "body": b"" if method == "HEAD" else body})

        if method not in SAFE_METHODS:
            import json
            return await respond(503, b"application/json", json.dumps({"detail": self.message, "role": "standby"}).encode(), [(b"retry-after", b"30")])
        if path == "/standby.css":
            return await respond(200, b"text/css", CSS, [(b"content-security-policy", b"default-src 'none'")])
        headers = dict(scope["headers"])
        if path in ("/", "/index.html") or (b"text/html" in headers.get(b"accept", b"") and not path.startswith(("/api/", "/assets/", "/readyz", "/healthz"))):
            return await respond(200, b"text/html; charset=utf-8", PAGE,
                                 [(b"content-security-policy", b"default-src 'none'; style-src 'self'; frame-ancestors 'none'")])

        async def send_role(msg):
            if msg["type"] == "http.response.start":
                msg = {**msg, "headers": list(msg.get("headers", [])) + [(b"x-ou-role", b"standby")]}
            await send(msg)
        await self.app(scope, receive, send_role)


def replication_status(db, max_lag_seconds: int) -> dict:
    """Works on a hot standby as the unprivileged app role. `heartbeat_age_seconds` is end-to-end freshness: the primary's worker
    writes worker_heartbeat every ~5 s, so a replica that is current has a young heartbeat; a dead primary or broken stream ages it."""
    r = db.execute(text(
        "SELECT pg_is_in_recovery() AS rec, extract(epoch FROM now() - pg_last_xact_replay_timestamp()) AS delay, "
        "pg_wal_lsn_diff(pg_last_wal_receive_lsn(), pg_last_wal_replay_lsn()) AS replay_backlog, "
        "(SELECT max(at) FROM worker_heartbeat) AS hb")).first()
    hb_age = (datetime.now(timezone.utc) - r.hb).total_seconds() if r.hb else None
    ok = bool(r.rec) and hb_age is not None and hb_age <= max_lag_seconds
    return {"ok": ok, "in_recovery": bool(r.rec), "heartbeat_age_seconds": None if hb_age is None else round(hb_age, 1),
            "replay_delay_seconds": None if r.delay is None else round(float(r.delay), 1),
            "replay_backlog_bytes": None if r.replay_backlog is None else int(r.replay_backlog), "max_lag_seconds": max_lag_seconds}
