"""one policy per repository URL (agent AU). The customer binding column itself is migration 0010 (review 5 M5): one model, not two."""
from alembic import op

revision = "0011"
down_revision = "0010"

DDL = """
CREATE UNIQUE INDEX backup_policies_repo_url ON backup_policies ((repo->>'url'))
"""


def upgrade() -> None:
    for stmt in [s for s in DDL.split(";\n") if s.strip()]:
        op.execute(stmt)


def downgrade() -> None:
    raise RuntimeError("irreversible by design")
