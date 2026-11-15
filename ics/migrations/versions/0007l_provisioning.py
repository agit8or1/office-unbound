"""provider provisioning: stored policy per endpoint (+ what the ICS created, last verification/drift) and proposed plans / generated packages"""
from alembic import context, op

revision = "0007l"
down_revision = "0007s3"

DDL = """
CREATE TABLE endpoint_policy (
  endpoint_id uuid PRIMARY KEY REFERENCES endpoints(id) ON DELETE CASCADE,
  policy jsonb NOT NULL,
  design jsonb NOT NULL,
  plan_hash text,
  mode text NOT NULL CHECK (mode IN ('A','B')),
  managed jsonb NOT NULL DEFAULT '{}',
  tokens jsonb NOT NULL DEFAULT '{}',
  status text NOT NULL DEFAULT 'ok',
  last_verification jsonb,
  last_verified_at timestamptz,
  last_drift jsonb,
  last_drift_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE provision_artifacts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kind text NOT NULL CHECK (kind IN ('plan','package')),
  endpoint_id uuid REFERENCES endpoints(id) ON DELETE SET NULL,
  plan_hash text,
  data jsonb NOT NULL,
  created_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX provision_artifacts_ep ON provision_artifacts (endpoint_id);
GRANT SELECT, INSERT, UPDATE, DELETE ON endpoint_policy, provision_artifacts TO {APP}
"""


def upgrade() -> None:
    app = context.config.attributes.get("app_role", "ics_app")
    for stmt in [s for s in DDL.replace("{APP}", app).split(";\n") if s.strip()]:
        op.execute(stmt)


def downgrade() -> None:
    raise RuntimeError("irreversible by design")
