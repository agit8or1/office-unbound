"""monitoring slice: nodes (agents), checks + results, incidents, maintenance, alert channels, notification outbox, remediation"""
from alembic import context, op

revision = "0003"
down_revision = "0002"

DDL = """
CREATE TABLE nodes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE,
  address text NOT NULL,
  port integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
  tls_fingerprint_sha256 char(64) NOT NULL,
  agent_pubkey text NOT NULL,
  agent_key_fp char(64) NOT NULL,
  capabilities jsonb NOT NULL DEFAULT '{}'::jsonb,
  agent_version text,
  status text NOT NULL DEFAULT 'enrolled',
  last_seen_at timestamptz,
  created_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE agent_requests (
  id bigserial PRIMARY KEY,
  node_id uuid NOT NULL REFERENCES nodes(id),
  job_id uuid NOT NULL UNIQUE,
  nonce text NOT NULL UNIQUE,
  action text NOT NULL,
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  status text NOT NULL DEFAULT 'sent',
  response_code text,
  finished_at timestamptz
);
CREATE TABLE checks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE,
  kind text NOT NULL CHECK (kind IN ('http','tcp_tls','imap_login','smtp_banner','ews_getfolder')),
  config jsonb NOT NULL,
  secret_enc bytea,
  interval_seconds integer NOT NULL CHECK (interval_seconds BETWEEN 5 AND 86400),
  fail_threshold integer NOT NULL DEFAULT 3 CHECK (fail_threshold BETWEEN 1 AND 20),
  recover_threshold integer NOT NULL DEFAULT 2 CHECK (recover_threshold BETWEEN 1 AND 20),
  enabled boolean NOT NULL DEFAULT true,
  state text NOT NULL DEFAULT 'unknown' CHECK (state IN ('ok','warning','critical','unknown')),
  last_raw text,
  consecutive_bad integer NOT NULL DEFAULT 0,
  consecutive_ok integer NOT NULL DEFAULT 0,
  last_run_at timestamptz,
  next_run_at timestamptz NOT NULL DEFAULT now(),
  last_state_change_at timestamptz,
  last_message text,
  last_latency_ms integer,
  remediation jsonb,
  created_by uuid NOT NULL REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX checks_due ON checks (next_run_at) WHERE enabled;
CREATE TABLE check_results (
  id bigserial PRIMARY KEY,
  check_id uuid NOT NULL REFERENCES checks(id) ON DELETE CASCADE,
  at timestamptz NOT NULL DEFAULT now(),
  status text NOT NULL CHECK (status IN ('ok','warning','critical')),
  latency_ms integer,
  message text,
  details jsonb
);
CREATE INDEX check_results_check_at ON check_results (check_id, at DESC);
CREATE INDEX check_results_at ON check_results (at);
CREATE TABLE incidents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  check_id uuid NOT NULL REFERENCES checks(id) ON DELETE CASCADE,
  severity text NOT NULL CHECK (severity IN ('warning','critical')),
  status text NOT NULL CHECK (status IN ('open','acked','recovered')),
  title text NOT NULL,
  message text,
  opened_at timestamptz NOT NULL DEFAULT now(),
  acked_by uuid REFERENCES users(id),
  acked_at timestamptz,
  ack_note text,
  recovered_at timestamptz,
  escalated_at timestamptz,
  last_notified_at timestamptz,
  notify_count integer NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX incidents_one_active ON incidents (check_id) WHERE status IN ('open','acked');
CREATE INDEX incidents_opened ON incidents (opened_at DESC);
CREATE TABLE maintenance_windows (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  check_id uuid REFERENCES checks(id) ON DELETE CASCADE,
  starts_at timestamptz NOT NULL,
  ends_at timestamptz NOT NULL CHECK (ends_at > starts_at),
  reason text,
  created_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE alert_channels (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE,
  kind text NOT NULL CHECK (kind IN ('email','webhook','pushover','sms')),
  config jsonb NOT NULL,
  secret_enc bytea,
  enabled boolean NOT NULL DEFAULT false,
  created_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE notifications (
  id bigserial PRIMARY KEY,
  incident_id uuid REFERENCES incidents(id) ON DELETE CASCADE,
  channel_id uuid NOT NULL REFERENCES alert_channels(id) ON DELETE CASCADE,
  event text NOT NULL,
  status text NOT NULL CHECK (status IN ('pending','sent','failed','suppressed')),
  attempts integer NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  last_error text,
  detail text,
  created_at timestamptz NOT NULL DEFAULT now(),
  sent_at timestamptz
);
CREATE INDEX notifications_pending ON notifications (next_attempt_at) WHERE status = 'pending';
CREATE TABLE remediation_attempts (
  id bigserial PRIMARY KEY,
  check_id uuid NOT NULL REFERENCES checks(id) ON DELETE CASCADE,
  incident_id uuid REFERENCES incidents(id) ON DELETE SET NULL,
  plan_id uuid REFERENCES plans(id),
  job_id uuid REFERENCES jobs(id),
  runbook text NOT NULL,
  attempt_no integer NOT NULL,
  at timestamptz NOT NULL DEFAULT now(),
  status text NOT NULL CHECK (status IN ('queued','pending_approval','running','verified','failed')),
  verified boolean,
  message text,
  finished_at timestamptz
);
CREATE INDEX remediation_check_at ON remediation_attempts (check_id, at DESC);
GRANT SELECT, INSERT, UPDATE, DELETE ON nodes, agent_requests, checks, check_results, incidents, maintenance_windows,
      alert_channels, notifications, remediation_attempts TO {APP};
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO {APP}
"""


def upgrade() -> None:
    app = context.config.attributes.get("app_role", "ics_app")
    for stmt in [s for s in DDL.replace("{APP}", app).split(";\n") if s.strip()]:
        op.execute(stmt)


def downgrade() -> None:
    raise RuntimeError("irreversible by design")
