"""monitoring review fixes (2026-11-15): per-(node, unit) restart budget columns, `superseded` remediation attempts (M3),
incident remediation_skipped_at (M1), maintenance window end-summary marker (M4)"""
from alembic import op

revision = "0006d"
down_revision = "0005"

STMTS = [
    "ALTER TABLE remediation_attempts ADD COLUMN node_id uuid, ADD COLUMN target text",
    "ALTER TABLE remediation_attempts DROP CONSTRAINT remediation_attempts_status_check",
    "ALTER TABLE remediation_attempts ADD CONSTRAINT remediation_attempts_status_check "
    "CHECK (status IN ('queued','pending_approval','running','verified','failed','superseded'))",
    "CREATE INDEX remediation_node_target ON remediation_attempts (node_id, target, at DESC)",
    "ALTER TABLE incidents ADD COLUMN remediation_skipped_at timestamptz",
    "ALTER TABLE maintenance_windows ADD COLUMN summary_sent_at timestamptz",
    # windows that already ended before this migration never get a retroactive summary
    "UPDATE maintenance_windows SET summary_sent_at = now() WHERE ends_at <= now()",
]


def upgrade() -> None:
    for s in STMTS:
        op.execute(s)


def downgrade() -> None:
    raise RuntimeError("irreversible by design")
