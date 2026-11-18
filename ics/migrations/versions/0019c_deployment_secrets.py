"""Per-deployment secrets (ADR-0009 s5, guest configuration): passwords the components share (directory bind, database, admin bootstrap) and the
deployment CA. Values are vault-encrypted (AES-GCM, context = deployment_secrets:<deployment>:<name>); wiped when the deployment is destroyed."""
from alembic import context, op

revision = "0019c"
down_revision = "0018h"
branch_labels = None
depends_on = None

DDL = """
CREATE TABLE deployment_secrets (
  deployment_id uuid NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
  name text NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{1,40}$'),
  value_enc bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (deployment_id, name)
);
GRANT SELECT, INSERT, UPDATE, DELETE ON deployment_secrets TO {APP}
"""


def upgrade() -> None:
    app = context.config.attributes.get("app_role", "ics_app")
    for stmt in [s for s in DDL.replace("{APP}", app).split(";\n") if s.strip()]:
        op.execute(stmt)


def downgrade() -> None:
    op.execute("DROP TABLE deployment_secrets")
