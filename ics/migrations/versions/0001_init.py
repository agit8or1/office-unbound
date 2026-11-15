"""initial schema + least-privilege grants

Runs as ics_owner. The runtime role ics_app gets NO UPDATE/DELETE/TRUNCATE on audit_events.
"""
from alembic import op

revision = "0001"
down_revision = None

DDL = """
CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  username text NOT NULL UNIQUE,
  password_hash text NOT NULL,
  totp_secret_enc bytea NOT NULL,
  last_totp_step bigint NOT NULL DEFAULT 0,
  role text NOT NULL CHECK (role IN ('viewer','operator','approver','admin')),
  disabled boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash text NOT NULL UNIQUE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf_token text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_seen timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL
);
CREATE TABLE login_attempts (
  id bigserial PRIMARY KEY,
  username text NOT NULL,
  ip text,
  at timestamptz NOT NULL DEFAULT now(),
  success boolean NOT NULL
);
CREATE INDEX login_attempts_user_at ON login_attempts (username, at);
CREATE INDEX login_attempts_ip_at ON login_attempts (ip, at);
CREATE TABLE audit_events (
  seq bigserial PRIMARY KEY,
  id uuid NOT NULL UNIQUE,
  at timestamptz NOT NULL,
  action text NOT NULL,
  actor_id uuid,
  actor_name text,
  ip text,
  resource text,
  resource_id text,
  details jsonb NOT NULL,
  prev_hash char(64) NOT NULL,
  hash char(64) NOT NULL UNIQUE
);
CREATE TABLE endpoints (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE,
  type text NOT NULL CHECK (type IN ('proxmox')),
  base_url text NOT NULL CHECK (base_url LIKE 'https://%'),
  token_id text NOT NULL,
  token_secret_enc bytea NOT NULL,
  ca_pem text,
  fingerprint_sha256 char(64),
  created_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((ca_pem IS NOT NULL) <> (fingerprint_sha256 IS NOT NULL))
);
CREATE TABLE plans (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  action text NOT NULL,
  params jsonb NOT NULL,
  secret_enc bytea,
  risk text NOT NULL CHECK (risk IN ('low','high')),
  status text NOT NULL CHECK (status IN ('pending_approval','approved','rejected')),
  requested_by uuid NOT NULL REFERENCES users(id),
  decided_by uuid REFERENCES users(id),
  decided_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  plan_id uuid NOT NULL UNIQUE REFERENCES plans(id),
  action text NOT NULL,
  status text NOT NULL CHECK (status IN ('queued','running','succeeded','failed')),
  created_at timestamptz NOT NULL DEFAULT now(),
  started_at timestamptz,
  finished_at timestamptz,
  result jsonb,
  error jsonb
);
CREATE INDEX jobs_queued ON jobs (created_at) WHERE status = 'queued';
CREATE TABLE worker_heartbeat (name text PRIMARY KEY, at timestamptz NOT NULL);
CREATE TABLE inventory_snapshots (
  id bigserial PRIMARY KEY,
  endpoint_id uuid NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
  collected_at timestamptz NOT NULL,
  data jsonb NOT NULL
);
CREATE INDEX inventory_snapshots_ep ON inventory_snapshots (endpoint_id, collected_at DESC);

-- least privilege for the runtime role
GRANT USAGE ON SCHEMA public TO ics_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON users, sessions, login_attempts, endpoints, plans, jobs,
      worker_heartbeat, inventory_snapshots TO ics_app;
GRANT SELECT, INSERT ON audit_events TO ics_app;   -- deliberately no UPDATE/DELETE/TRUNCATE
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO ics_app;
"""


def upgrade() -> None:
    for stmt in [s for s in DDL.split(";\n") if s.strip()]:
        op.execute(stmt)


def downgrade() -> None:
    raise RuntimeError("irreversible by design")
