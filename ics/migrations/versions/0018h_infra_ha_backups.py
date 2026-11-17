"""Read-only HA status and backup evidence from the inventory token (ADR-0016 amendment): HA services / LRM state, the newest
backup volume per guest on readable backup storage, recent vzdump task results; per-endpoint list of entity kinds fetched completely."""
from alembic import context, op

revision = "0018h"
down_revision = "0017i"
branch_labels = None
depends_on = None

DDL = """
CREATE TABLE infra_ha (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  endpoint_id uuid NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
  sid text NOT NULL, kind text NOT NULL CHECK (kind IN ('service','lrm')), node text NOT NULL DEFAULT '', state text NOT NULL,
  request_state text, observed_at timestamptz NOT NULL, source text NOT NULL DEFAULT 'proxmox',
  UNIQUE (endpoint_id, sid)
);
CREATE TABLE infra_backups (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  endpoint_id uuid NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
  vmid integer NOT NULL, last_at timestamptz NOT NULL, storage text NOT NULL, size bigint, copies integer NOT NULL DEFAULT 1,
  observed_at timestamptz NOT NULL, source text NOT NULL DEFAULT 'proxmox',
  UNIQUE (endpoint_id, vmid)
);
CREATE TABLE infra_backup_tasks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  endpoint_id uuid NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
  upid text NOT NULL, node text NOT NULL, vmid text NOT NULL DEFAULT '', status text, started_at timestamptz, ended_at timestamptz,
  observed_at timestamptz NOT NULL, source text NOT NULL DEFAULT 'proxmox',
  UNIQUE (endpoint_id, upid)
);
ALTER TABLE infra_collect_state ADD COLUMN complete text[] NOT NULL DEFAULT '{}';
GRANT SELECT, INSERT, UPDATE, DELETE ON infra_ha, infra_backups, infra_backup_tasks TO {APP}
"""


def upgrade() -> None:
    app = context.config.attributes.get("app_role", "ics_app")
    for stmt in [s for s in DDL.replace("{APP}", app).split(";\n") if s.strip()]:
        op.execute(stmt)


def downgrade() -> None:
    op.execute("ALTER TABLE infra_collect_state DROP COLUMN complete")
    op.execute("DROP TABLE infra_backup_tasks")
    op.execute("DROP TABLE infra_backups")
    op.execute("DROP TABLE infra_ha")
