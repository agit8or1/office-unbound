"""Mailbox administration (agent BE): aliases, shared mailboxes + grants, per-user quota settings"""
from alembic import context, op

revision = "0012d"
down_revision = "0012c"

DDL = """
CREATE TABLE idm_aliases (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  stack_id uuid NOT NULL REFERENCES idm_stacks(id),
  uid text NOT NULL,
  alias text NOT NULL CHECK (alias = lower(alias)),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (stack_id, alias)
);
CREATE INDEX idm_aliases_uid ON idm_aliases (stack_id, uid);
CREATE TABLE idm_shared_mailboxes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  stack_id uuid NOT NULL REFERENCES idm_stacks(id),
  name text NOT NULL,
  mail text NOT NULL,
  display_name text NOT NULL,
  state text NOT NULL DEFAULT 'active' CHECK (state IN ('active','deleted')),
  created_by text,
  created_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  UNIQUE (stack_id, name)
);
CREATE TABLE idm_shared_grants (
  shared_id uuid NOT NULL REFERENCES idm_shared_mailboxes(id) ON DELETE CASCADE,
  uid text NOT NULL,
  kind text NOT NULL CHECK (kind IN ('full_access','send_as','send_on_behalf')),
  granted_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (shared_id, uid, kind)
);
CREATE TABLE idm_quotas (
  stack_id uuid NOT NULL REFERENCES idm_stacks(id),
  uid text NOT NULL,
  mail_send_kb bigint,
  mail_receive_kb bigint,
  mail_storage_kb bigint,
  files_quota_bytes bigint,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (stack_id, uid)
);
GRANT SELECT, INSERT, UPDATE, DELETE ON idm_aliases, idm_shared_mailboxes, idm_shared_grants, idm_quotas TO {APP}
"""


def upgrade() -> None:
    app = context.config.attributes.get("app_role", "ics_app")
    for stmt in [s for s in DDL.replace("{APP}", app).split(";\n") if s.strip()]:
        op.execute(stmt)


def downgrade() -> None:
    raise RuntimeError("irreversible by design")
