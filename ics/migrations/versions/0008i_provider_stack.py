"""provider stack integration: provision artifacts (previews, packages) belong to a customer so operator scoping applies to them"""
from alembic import op

revision = "0008i"
down_revision = "0007m"

DDL = """
ALTER TABLE provision_artifacts ADD COLUMN customer_id uuid REFERENCES customers(id);
UPDATE provision_artifacts a SET customer_id = COALESCE((SELECT e.customer_id FROM endpoints e WHERE e.id = a.endpoint_id), '00000000-0000-0000-0000-00000000a001');
CREATE INDEX provision_artifacts_customer ON provision_artifacts (customer_id)
"""


def upgrade() -> None:
    for stmt in [s for s in DDL.split(";\n") if s.strip()]:
        op.execute(stmt)


def downgrade() -> None:
    raise RuntimeError("irreversible by design")
