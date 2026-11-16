"""hardening: PostgreSQL-backed token buckets so rate limits hold with several uvicorn workers/processes (ics/ratelimit.py).
UNLOGGED: no WAL, truncated on crash recovery (a limiter that forgets after a crash is acceptable; it never holds anything that must survive)."""
from alembic import context, op

revision = "0011"
down_revision = "0010"

DDL = """
CREATE UNLOGGED TABLE rate_limits (
  key text PRIMARY KEY,
  tokens double precision NOT NULL,
  ts timestamptz NOT NULL DEFAULT now(),
  allowed boolean NOT NULL DEFAULT true
);
CREATE INDEX rate_limits_ts ON rate_limits (ts);
GRANT SELECT, INSERT, UPDATE, DELETE ON rate_limits TO {APP}
"""


def upgrade() -> None:
    app = context.config.attributes.get("app_role", "ics_app")
    for stmt in [s for s in DDL.replace("{APP}", app).split(";\n") if s.strip()]:
        op.execute(stmt)


def downgrade() -> None:
    raise RuntimeError("irreversible by design")
