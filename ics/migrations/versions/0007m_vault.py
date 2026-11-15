"""credential vault, MSP customers + policies, operator customer scoping, customer approval workflow (agent M)"""
from alembic import context, op

revision = "0007m"
down_revision = "0007l"

DEFAULT_CUSTOMER = "00000000-0000-0000-0000-00000000a001"

DDL = """
CREATE TABLE customers (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 100),
  msp_owned boolean NOT NULL DEFAULT false,
  provisioning_mode text NOT NULL DEFAULT 'customer_approval' CHECK (provisioning_mode IN ('auto','customer_approval','monitoring_only')),
  extra_approvals jsonb NOT NULL DEFAULT '{}',
  contact_name text,
  contact_email text,
  created_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  disabled_at timestamptz
);
INSERT INTO customers (id, name, msp_owned, provisioning_mode) VALUES ('{DEF}', 'MSP (internal)', true, 'auto');

ALTER TABLE users ADD COLUMN all_customers boolean NOT NULL DEFAULT true;
CREATE TABLE operator_customers (
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  customer_id uuid NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
  PRIMARY KEY (user_id, customer_id)
);

CREATE TABLE credentials (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  provider text NOT NULL CHECK (provider ~ '^[a-z][a-z0-9_-]{1,30}$'),
  customer_id uuid NOT NULL REFERENCES customers(id),
  label text NOT NULL CHECK (length(label) BETWEEN 1 AND 100),
  datacenter text, cluster text, host text,
  credential_type text NOT NULL CHECK (credential_type IN ('api_token','password','ssh_key','client_cert')),
  purpose text NOT NULL CHECK (purpose IN ('inventory','provision','temporary_provisioning')),
  identity text,
  wrapped_key bytea NOT NULL,
  secret_enc bytea NOT NULL,
  master_key_id text NOT NULL,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','expiring','expired','revoked','invalid','retired')),
  created_at timestamptz NOT NULL DEFAULT now(),
  created_by text,
  last_validated_at timestamptz,
  last_used_at timestamptz,
  last_use_audited_at timestamptz,
  expires_at timestamptz,
  revoked_at timestamptz,
  retire_after timestamptz,
  purged_at timestamptz,
  replaced_by uuid REFERENCES credentials(id)
);
CREATE INDEX credentials_customer ON credentials (customer_id);
CREATE TABLE credential_events (
  id bigserial PRIMARY KEY,
  credential_id uuid NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
  at timestamptz NOT NULL DEFAULT now(),
  event text NOT NULL,
  actor text NOT NULL,
  reason text,
  related_credential_id uuid
);
CREATE TABLE credential_alerts (
  credential_id uuid NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
  kind text NOT NULL,
  at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (credential_id, kind)
);

ALTER TABLE endpoints
  ADD COLUMN customer_id uuid NOT NULL DEFAULT '{DEF}' REFERENCES customers(id),
  ADD COLUMN inventory_credential_id uuid REFERENCES credentials(id),
  ADD COLUMN provision_credential_id uuid REFERENCES credentials(id),
  ADD COLUMN trust_binding text;
ALTER TABLE endpoints ALTER COLUMN token_secret_enc DROP NOT NULL;

ALTER TABLE plans
  ADD COLUMN customer_id uuid REFERENCES customers(id),
  ADD COLUMN extra_approvals integer NOT NULL DEFAULT 0,
  ADD COLUMN customer_approval_id uuid;

CREATE TABLE customer_approvals (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  customer_id uuid NOT NULL REFERENCES customers(id),
  plan_id uuid REFERENCES plans(id),
  title text NOT NULL CHECK (length(title) BETWEEN 1 AND 200),
  proposal jsonb NOT NULL,
  proposal_hash char(64) NOT NULL,
  status text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','pending','approved','rejected','changes_requested','provisioned','expired','cancelled')),
  token_hash char(64),
  token_expires_at timestamptz,
  completion_token_hash char(64),
  completion_expires_at timestamptz,
  created_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  submitted_at timestamptz,
  decided_at timestamptz,
  approver_name text, approver_email text, approver_ip text, approver_user_agent text, approver_statement text,
  decision_note text,
  completed_at timestamptz
);
CREATE INDEX customer_approvals_plan ON customer_approvals (plan_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON customers, operator_customers, credentials, credential_events, credential_alerts, customer_approvals TO {APP};
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {APP}
"""


def upgrade() -> None:
    app = context.config.attributes.get("app_role", "ics_app")
    for stmt in [s for s in DDL.replace("{APP}", app).replace("{DEF}", DEFAULT_CUSTOMER).split(";\n") if s.strip()]:
        op.execute(stmt)


def downgrade() -> None:
    raise RuntimeError("irreversible by design")
