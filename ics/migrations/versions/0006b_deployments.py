"""deployment engine (ADR-0009 section 3/4): deployments, resources (desired/actual), revisions, events, durable job steps"""
from alembic import context, op

revision = "0006b"
down_revision = "0006d"

DDL = """
CREATE TABLE deployments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  slug text NOT NULL UNIQUE,
  customer_id text NOT NULL,
  profile text NOT NULL,
  profile_version text NOT NULL,
  endpoint_id uuid REFERENCES endpoints(id),
  status text NOT NULL CHECK (status IN ('planned','provisioning','active','failed','changing','destroying','destroyed')),
  desired_spec jsonb NOT NULL,
  current_revision integer NOT NULL DEFAULT 0,
  created_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE deployment_revisions (
  id bigserial PRIMARY KEY,
  deployment_id uuid NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
  revision integer NOT NULL,
  kind text NOT NULL CHECK (kind IN ('create','change','destroy')),
  plan_hash char(64) NOT NULL,
  spec_hash char(64) NOT NULL,
  spec jsonb NOT NULL,
  plan jsonb NOT NULL,
  diff jsonb,
  risk text,
  status text NOT NULL DEFAULT 'proposed' CHECK (status IN ('proposed','applying','applied','failed','superseded')),
  job_id uuid REFERENCES jobs(id),
  created_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  applied_at timestamptz,
  UNIQUE (deployment_id, plan_hash)
);
CREATE INDEX deployment_revisions_dep ON deployment_revisions (deployment_id, revision);
CREATE TABLE deployment_resources (
  id bigserial PRIMARY KEY,
  deployment_id uuid NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
  kind text NOT NULL CHECK (kind IN ('vm','container','service','volume','dns','check')),
  logical_name text NOT NULL,
  provider_ref jsonb,
  desired jsonb NOT NULL,
  actual jsonb,
  state text NOT NULL DEFAULT 'planned' CHECK (state IN ('planned','creating','present','changing','removing','removed','failed')),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (deployment_id, kind, logical_name)
);
CREATE TABLE deployment_events (
  id bigserial PRIMARY KEY,
  deployment_id uuid NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
  at timestamptz NOT NULL DEFAULT now(),
  kind text NOT NULL,
  message text NOT NULL,
  job_id uuid,
  details jsonb
);
CREATE INDEX deployment_events_dep ON deployment_events (deployment_id, id);
CREATE TABLE job_steps (
  id bigserial PRIMARY KEY,
  job_id uuid NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  deployment_id uuid REFERENCES deployments(id) ON DELETE CASCADE,
  revision integer,
  seq integer NOT NULL,
  step_key text NOT NULL,
  kind text NOT NULL,
  target text NOT NULL,
  op text NOT NULL,
  params jsonb NOT NULL,
  depends_on jsonb NOT NULL DEFAULT '[]'::jsonb,
  disruptive boolean NOT NULL DEFAULT false,
  est_seconds integer NOT NULL DEFAULT 0,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','succeeded','failed','cancelled')),
  attempts integer NOT NULL DEFAULT 0,
  progress integer NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
  log_excerpt text NOT NULL DEFAULT '',
  error_message text,
  error_explanation text,
  result jsonb,
  carried_from_job uuid,
  started_at timestamptz,
  finished_at timestamptz,
  UNIQUE (job_id, step_key)
);
CREATE INDEX job_steps_job ON job_steps (job_id, seq);
CREATE INDEX job_steps_dep ON job_steps (deployment_id, revision, step_key);
ALTER TABLE jobs ADD COLUMN cancel_requested boolean NOT NULL DEFAULT false;
GRANT SELECT, INSERT, UPDATE, DELETE ON deployments, deployment_revisions, deployment_resources, deployment_events, job_steps TO {APP};
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO {APP}
"""


def upgrade() -> None:
    app = context.config.attributes.get("app_role", "ics_app")
    for stmt in [s for s in DDL.replace("{APP}", app).split(";\n") if s.strip()]:
        op.execute(stmt)


def downgrade() -> None:
    raise RuntimeError("irreversible by design")
