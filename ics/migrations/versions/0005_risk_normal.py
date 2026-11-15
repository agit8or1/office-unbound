"""plan risk tier `normal` (one approver other than the requester, not auto-approved): used by the identity lifecycle actions"""
from alembic import op

revision = "0005"
down_revision = "0004"


def upgrade() -> None:
    op.execute("ALTER TABLE plans DROP CONSTRAINT plans_risk_check")
    op.execute("ALTER TABLE plans ADD CONSTRAINT plans_risk_check CHECK (risk IN ('low','normal','high'))")


def downgrade() -> None:
    raise RuntimeError("irreversible by design")
