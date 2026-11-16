"""idm_stacks.customer_id is the ONE owner of a stack: NOT NULL, default the MSP-internal customer (same model as review-5 M5 nodes/checks); backfilled from the stack config where one was set.
Organization admin (tenant admin API): per-customer binding to an identity stack, service credential hash, policy, branding, request log (agent AX)"""
from alembic import context, op

revision = "0012a"
down_revision = "0011"

DEF = "00000000-0000-0000-0000-00000000a001"

DDL = """
ALTER TABLE idm_stacks ADD COLUMN customer_id uuid NOT NULL DEFAULT '{DEF}' REFERENCES customers(id);
UPDATE idm_stacks s SET customer_id = (s.config->>'customer_id')::uuid WHERE s.config->>'customer_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND EXISTS (SELECT 1 FROM customers c WHERE c.id::text = s.config->>'customer_id');
CREATE INDEX idm_stacks_customer ON idm_stacks (customer_id);
ALTER TABLE plans ADD COLUMN tenant_required integer CHECK (tenant_required BETWEEN 0 AND 3);
CREATE TABLE tenant_admin_bindings (
  customer_id uuid PRIMARY KEY REFERENCES customers(id),
  stack_id uuid NOT NULL UNIQUE REFERENCES idm_stacks(id),
  key_id text NOT NULL UNIQUE CHECK (key_id ~ '^[a-z0-9]{12}$'),
  key_sha256 char(64) NOT NULL,
  requester_id uuid NOT NULL REFERENCES users(id),
  approver_id uuid NOT NULL REFERENCES users(id),
  portal_client_id text NOT NULL DEFAULT 'ou-portal',
  admin_role text NOT NULL DEFAULT 'org-admin',
  policy jsonb NOT NULL DEFAULT '{}',
  app_access jsonb NOT NULL DEFAULT '{}',
  branding jsonb NOT NULL DEFAULT '{}',
  logo bytea,
  logo_type text,
  created_at timestamptz NOT NULL DEFAULT now(),
  rotated_at timestamptz,
  disabled_at timestamptz
);
CREATE TABLE tenant_requests (
  plan_id uuid PRIMARY KEY REFERENCES plans(id),
  customer_id uuid NOT NULL REFERENCES customers(id),
  kind text NOT NULL,
  target_uid text,
  summary text NOT NULL,
  requester_sub text NOT NULL,
  requester_name text NOT NULL,
  approval_mode text NOT NULL CHECK (approval_mode IN ('auto','second_admin','msp')),
  decision text CHECK (decision IN ('approved','rejected')),
  decided_by_sub text,
  decided_by_name text,
  decided_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX tenant_requests_cust ON tenant_requests (customer_id, created_at DESC);
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_admin_bindings, tenant_requests TO {APP}
"""


def upgrade() -> None:
    app = context.config.attributes.get("app_role", "ics_app")
    for stmt in [s for s in DDL.replace("{APP}", app).replace("{DEF}", DEF).split(";\n") if s.strip()]:
        op.execute(stmt)


def downgrade() -> None:
    raise RuntimeError("irreversible by design")
