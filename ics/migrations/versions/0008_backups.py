"""backup product (ADR-0010): policies, runs, verifications"""
from alembic import context, op

revision = "0008"
down_revision = "0008i"

DDL = """
CREATE TABLE backup_policies (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE,
  tier text NOT NULL CHECK (tier IN ('files','identity','groupware','ics')),
  deployment text NOT NULL,
  runner_node_id uuid NOT NULL REFERENCES nodes(id),
  schedule jsonb NOT NULL,
  retention jsonb NOT NULL,
  rpo_seconds integer NOT NULL CHECK (rpo_seconds >= 300),
  rto_seconds integer NOT NULL CHECK (rto_seconds >= 60),
  repo jsonb NOT NULL,
  copies_required integer NOT NULL DEFAULT 1,
  verify jsonb NOT NULL,
  repo_secret_enc bytea NOT NULL,
  repo_id text,
  recovery_fp text,
  recovery_exported_at timestamptz,
  enabled boolean NOT NULL DEFAULT true,
  created_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE backup_runs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  policy_id uuid NOT NULL REFERENCES backup_policies(id) ON DELETE CASCADE,
  kind text NOT NULL CHECK (kind IN ('backup','prune')),
  trigger text NOT NULL DEFAULT 'manual' CHECK (trigger IN ('manual','schedule')),
  status text NOT NULL CHECK (status IN ('running','succeeded','failed')),
  job_id uuid,
  started_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz,
  snapshot_id text,
  bytes_added bigint,
  bytes_processed bigint,
  repo_bytes bigint,
  snapshots_total integer,
  duration_ms integer,
  repo_confirmed boolean,
  canary_recorded boolean,
  detail jsonb,
  error text
);
CREATE INDEX backup_runs_policy ON backup_runs (policy_id, started_at DESC);
CREATE TABLE backup_verifications (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  policy_id uuid NOT NULL REFERENCES backup_policies(id) ON DELETE CASCADE,
  level text NOT NULL CHECK (level IN ('check','restore')),
  state text NOT NULL CHECK (state IN ('pending','running','passed','failed','error','cancelled')),
  trigger text NOT NULL DEFAULT 'manual' CHECK (trigger IN ('manual','schedule')),
  snapshot_id text,
  job_id uuid,
  started_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz,
  rto_seconds numeric,
  detail jsonb,
  error text
);
CREATE INDEX backup_verifications_policy ON backup_verifications (policy_id, started_at DESC);
ALTER TABLE checks DROP CONSTRAINT checks_kind_check;
ALTER TABLE checks ADD CONSTRAINT checks_kind_check CHECK (kind IN ('http','tcp_tls','imap_login','smtp_banner','ews_getfolder','backup'));
GRANT SELECT, INSERT, UPDATE, DELETE ON backup_policies, backup_runs, backup_verifications TO {APP}
"""


def upgrade() -> None:
    app = context.config.attributes.get("app_role", "ics_app")
    for stmt in [s for s in DDL.replace("{APP}", app).split(";\n") if s.strip()]:
        op.execute(stmt)


def downgrade() -> None:
    raise RuntimeError("irreversible by design")
