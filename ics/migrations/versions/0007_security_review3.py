"""security review 3: per-deployment execution lock with fencing token (H1), plan-hash-keyed step carry-over (M3),
base revision / diff hash on change revisions (M5), independently approved maintenance windows (L2), deployment-owned checks (L4)"""
from alembic import context, op

revision = "0007s3"
down_revision = "0007"

DDL = """
CREATE TABLE deployment_locks (
  deployment_id uuid PRIMARY KEY REFERENCES deployments(id) ON DELETE CASCADE,
  job_id uuid NOT NULL,
  token bigint NOT NULL DEFAULT 1,
  lease_expires_at timestamptz NOT NULL,
  acquired_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE job_steps ADD COLUMN plan_hash char(64);
ALTER TABLE deployment_revisions ADD COLUMN base_revision integer;
ALTER TABLE deployment_revisions ADD COLUMN diff_hash char(64);
ALTER TABLE maintenance_windows ADD COLUMN independently_approved boolean NOT NULL DEFAULT false;
ALTER TABLE checks ADD COLUMN deployment_id uuid REFERENCES deployments(id) ON DELETE SET NULL;
ALTER TABLE plans ADD COLUMN archived_at timestamptz;
ALTER TABLE nodes ADD COLUMN decommissioned_at timestamptz;
GRANT SELECT, INSERT, UPDATE, DELETE ON deployment_locks TO {APP}
"""


def upgrade() -> None:
    app = context.config.attributes.get("app_role", "ics_app")
    for stmt in [s for s in DDL.replace("{APP}", app).split(";\n") if s.strip()]:
        op.execute(stmt)
