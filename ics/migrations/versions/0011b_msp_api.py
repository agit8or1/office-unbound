"""MSP provisioning API (ADR-0013, roadmap P4.3): API clients (HMAC keys in the vault), nonces, idempotency, webhooks + event outbox,
customer slug/external_ref (deployment <-> customer mapping), stack -> customer link"""
from alembic import context, op

revision = "0011b"
down_revision = "0011a"

DDL = """
ALTER TABLE customers ADD COLUMN slug text, ADD COLUMN external_ref text;
-- review 6 M3: the slug of an EXISTING customer is NOT derived from its name. A deployment's free-text customer_id could otherwise equal such a
-- name-derived slug ("lab", "acme") and be bound to that customer implicitly. Existing customers get an id-derived slug; deployments are bound
-- only explicitly (customer.update slug + adopt_existing_deployments, an approved high-risk plan).
UPDATE customers SET slug = 'c-' || left(replace(id::text, '-', ''), 12);
ALTER TABLE customers ALTER COLUMN slug SET NOT NULL;
CREATE UNIQUE INDEX customers_slug ON customers (slug);
CREATE UNIQUE INDEX customers_external_ref ON customers (external_ref) WHERE external_ref IS NOT NULL;
-- idm_stacks.customer_id is defined once, in 0011a (NOT NULL, default MSP-internal); msp.stack.link updates it

CREATE TABLE msp_clients (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  client_id text NOT NULL UNIQUE CHECK (client_id ~ '^mspc_[0-9a-f]{16}$'),
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
  user_id uuid NOT NULL REFERENCES users(id),
  secret_enc bytea,
  secret_version integer NOT NULL DEFAULT 1,
  prev_secret_enc bytea,
  prev_secret_version integer,
  prev_secret_expires_at timestamptz,
  permissions text[] NOT NULL DEFAULT '{view,plan}',
  all_customers boolean NOT NULL DEFAULT false,
  mtls_fingerprint text,
  rate_limit_per_minute integer NOT NULL DEFAULT 120 CHECK (rate_limit_per_minute BETWEEN 1 AND 6000),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
  created_by uuid REFERENCES users(id),
  created_plan_id uuid REFERENCES plans(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  revoked_at timestamptz
);
CREATE TABLE msp_client_customers (
  client_id uuid NOT NULL REFERENCES msp_clients(id) ON DELETE CASCADE,
  customer_id uuid NOT NULL REFERENCES customers(id),
  PRIMARY KEY (client_id, customer_id)
);
CREATE TABLE msp_client_reveals (
  plan_id uuid PRIMARY KEY REFERENCES plans(id),
  client_id uuid NOT NULL REFERENCES msp_clients(id) ON DELETE CASCADE,
  requested_by uuid NOT NULL REFERENCES users(id),
  revealed_by uuid REFERENCES users(id),
  secret_enc bytea,
  expires_at timestamptz NOT NULL,
  revealed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE msp_nonces (
  client_id uuid NOT NULL REFERENCES msp_clients(id) ON DELETE CASCADE,
  nonce text NOT NULL,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (client_id, nonce)
);
CREATE INDEX msp_nonces_exp ON msp_nonces (expires_at);
CREATE TABLE msp_idempotency (
  client_id uuid NOT NULL REFERENCES msp_clients(id) ON DELETE CASCADE,
  idem_key text NOT NULL,
  request_hash char(64) NOT NULL,
  status integer,
  response_enc bytea,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (client_id, idem_key)
);
CREATE INDEX msp_idempotency_created ON msp_idempotency (created_at);
CREATE TABLE msp_webhooks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  client_id uuid NOT NULL REFERENCES msp_clients(id) ON DELETE CASCADE,
  url text NOT NULL CHECK (length(url) <= 500),
  description text,
  events text[] NOT NULL,
  secret_enc bytea NOT NULL,
  enabled boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz
);
CREATE INDEX msp_webhooks_client ON msp_webhooks (client_id);
CREATE TABLE msp_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  seq bigserial UNIQUE,
  type text NOT NULL,
  customer_id uuid REFERENCES customers(id),
  data jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE msp_deliveries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id uuid NOT NULL REFERENCES msp_events(id) ON DELETE CASCADE,
  webhook_id uuid NOT NULL REFERENCES msp_webhooks(id) ON DELETE CASCADE,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','delivered','dead')),
  attempts integer NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  last_status integer,
  last_error text,
  delivered_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (event_id, webhook_id)
);
CREATE INDEX msp_deliveries_due ON msp_deliveries (next_attempt_at) WHERE status = 'pending';

GRANT SELECT, INSERT, UPDATE, DELETE ON msp_clients, msp_client_customers, msp_client_reveals, msp_nonces, msp_idempotency, msp_webhooks,
  msp_events, msp_deliveries TO {APP};
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {APP}
"""

FUNCTION = """
CREATE FUNCTION customers_default_slug() RETURNS trigger LANGUAGE plpgsql AS $f$
BEGIN
  IF NEW.slug IS NULL THEN
    NEW.slug := 'c-' || left(replace(NEW.id::text, '-', ''), 12);
  END IF;
  RETURN NEW;
END $f$
"""


def upgrade() -> None:
    app = context.config.attributes.get("app_role", "ics_app")
    for stmt in [s for s in DDL.replace("{APP}", app).split(";\n") if s.strip()]:
        op.execute(stmt)
    op.execute(FUNCTION)
    op.execute("""
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT slug, customer_id FROM deployments ORDER BY slug LOOP
    RAISE NOTICE 'deployment % (customer_id=%) is not bound to any customer; bind it explicitly with an approved customer.update (slug + adopt_existing_deployments)', r.slug, r.customer_id;
  END LOOP;
END $$""")
    op.execute("CREATE TRIGGER customers_default_slug BEFORE INSERT ON customers FOR EACH ROW EXECUTE FUNCTION customers_default_slug()")


def downgrade() -> None:
    raise RuntimeError("irreversible by design")
