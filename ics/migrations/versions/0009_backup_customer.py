"""per-customer backup boundaries (agent AU): backup_policies.customer_id (NULL = legacy/MSP-internal) and one policy per repository URL"""
from alembic import op

revision = "0009"
down_revision = "0008"

DDL = """
ALTER TABLE backup_policies ADD COLUMN customer_id uuid REFERENCES customers(id);
CREATE INDEX backup_policies_customer ON backup_policies (customer_id);
CREATE UNIQUE INDEX backup_policies_repo_url ON backup_policies ((repo->>'url'))
"""


def upgrade() -> None:
    for stmt in [s for s in DDL.split(";\n") if s.strip()]:
        op.execute(stmt)


def downgrade() -> None:
    raise RuntimeError("irreversible by design")
