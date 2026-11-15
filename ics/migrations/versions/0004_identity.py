"""identity lifecycle: customer stacks (LDAP/Keycloak/gromox/OpenCloud wiring), directory users with stable id, one-time enrollments, reconcile runs"""
from alembic import context, op

revision = "0004"
down_revision = "0003"

DDL = """
CREATE TABLE idm_stacks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE,
  config jsonb NOT NULL,
  secret_enc bytea NOT NULL,
  last_reconcile_at timestamptz,
  created_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE idm_users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  stack_id uuid NOT NULL REFERENCES idm_stacks(id),
  uid text NOT NULL,
  entry_uuid text NOT NULL UNIQUE,
  mail text NOT NULL,
  display_name text NOT NULL,
  groups jsonb NOT NULL DEFAULT '[]'::jsonb,
  state text NOT NULL DEFAULT 'active' CHECK (state IN ('active','disabled','deleted')),
  created_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  disabled_at timestamptz,
  last_verification jsonb
);
CREATE UNIQUE INDEX idm_users_uid ON idm_users (stack_id, uid) WHERE state <> 'deleted';
CREATE TABLE idm_enrollments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES idm_users(id),
  plan_id uuid REFERENCES plans(id),
  requested_by uuid NOT NULL REFERENCES users(id),
  token_sha256 char(64) NOT NULL,
  token_enc bytea,
  failures integer NOT NULL DEFAULT 0,
  expires_at timestamptz NOT NULL,
  revealed_at timestamptz,
  used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idm_enrollments_plan ON idm_enrollments (plan_id);
CREATE TABLE idm_reconcile_runs (
  id bigserial PRIMARY KEY,
  stack_id uuid NOT NULL REFERENCES idm_stacks(id),
  at timestamptz NOT NULL DEFAULT now(),
  trigger text NOT NULL,
  ok boolean NOT NULL,
  findings jsonb NOT NULL
);
CREATE INDEX idm_reconcile_stack_at ON idm_reconcile_runs (stack_id, at DESC);
GRANT SELECT, INSERT, UPDATE, DELETE ON idm_stacks, idm_users, idm_enrollments, idm_reconcile_runs TO {APP};
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO {APP}
"""


def upgrade() -> None:
    app = context.config.attributes.get("app_role", "ics_app")
    for stmt in [s for s in DDL.replace("{APP}", app).split(";\n") if s.strip()]:
        op.execute(stmt)


def downgrade() -> None:
    raise RuntimeError("irreversible by design")
