"""telephony downstream: extension per directory user, one-time SIP device credentials (encrypted at rest until revealed once)"""
from alembic import context, op

revision = "0009"
down_revision = "0008"

DDL = """
ALTER TABLE idm_users ADD COLUMN extension text CHECK (extension IS NULL OR extension ~ '^[1-9][0-9]{3}$');
CREATE UNIQUE INDEX idm_users_extension ON idm_users (stack_id, extension) WHERE extension IS NOT NULL AND state <> 'deleted';
CREATE TABLE idm_sip_credentials (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES idm_users(id),
  plan_id uuid REFERENCES plans(id),
  requested_by uuid NOT NULL REFERENCES users(id),
  device text NOT NULL CHECK (device IN ('web','native','desk')),
  secret_enc bytea,
  expires_at timestamptz NOT NULL,
  revealed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idm_sip_credentials_plan ON idm_sip_credentials (plan_id);
GRANT SELECT, INSERT, UPDATE, DELETE ON idm_sip_credentials TO {APP};
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO {APP}
"""


def upgrade() -> None:
    app = context.config.attributes.get("app_role", "ics_app")
    for stmt in [s for s in DDL.replace("{APP}", app).split(";\n") if s.strip()]:
        op.execute(stmt)


def downgrade() -> None:
    raise RuntimeError("irreversible by design")
