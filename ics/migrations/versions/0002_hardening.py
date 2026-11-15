"""security review 2026-11-15: enrollment/provenance, approvals table, audit canon+MAC+guard trigger, job leases"""
from alembic import context, op

revision = "0002"
down_revision = "0001"

DDL = """
ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;
ALTER TABLE users ALTER COLUMN totp_secret_enc DROP NOT NULL;
ALTER TABLE users ADD COLUMN enrolled boolean NOT NULL DEFAULT true;
ALTER TABLE users ADD COLUMN created_by uuid REFERENCES users(id);
ALTER TABLE users ADD COLUMN role_set_by uuid REFERENCES users(id);
ALTER TABLE users ADD COLUMN role_set_at timestamptz;
ALTER TABLE users ADD COLUMN enrollment_token_hash text;
ALTER TABLE users ADD COLUMN enrollment_expires_at timestamptz;
CREATE INDEX login_attempts_user_ip_at ON login_attempts (username, ip, at);
ALTER TABLE audit_events ADD COLUMN details_canon text;
ALTER TABLE audit_events ADD COLUMN mac text;
ALTER TABLE plans ADD COLUMN params_hash text;
ALTER TABLE jobs ADD COLUMN lease_expires_at timestamptz;
CREATE TABLE plan_approvals (
  id bigserial PRIMARY KEY,
  plan_id uuid NOT NULL REFERENCES plans(id),
  approver_id uuid NOT NULL REFERENCES users(id),
  params_hash text NOT NULL,
  at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (plan_id, approver_id)
);
GRANT SELECT, INSERT ON plan_approvals TO {APP};
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO {APP}
"""

GUARD = """
CREATE FUNCTION audit_chain_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE tail text;
BEGIN
  PERFORM pg_advisory_xact_lock(7001001);
  SELECT hash INTO tail FROM audit_events ORDER BY seq DESC LIMIT 1;
  IF NEW.prev_hash IS DISTINCT FROM COALESCE(tail, repeat('0', 64)) THEN
    RAISE EXCEPTION 'audit chain: prev_hash must equal the current tail hash';
  END IF;
  IF NEW.mac IS NULL OR NEW.details_canon IS NULL THEN
    RAISE EXCEPTION 'audit chain: mac and details_canon are required';
  END IF;
  -- seq must come from the column default (the sequence); an explicit forged seq differs from currval
  BEGIN
    IF NEW.seq IS DISTINCT FROM currval(pg_get_serial_sequence('audit_events', 'seq')) THEN
      RAISE EXCEPTION 'audit chain: seq must be assigned by the sequence';
    END IF;
  EXCEPTION WHEN object_not_in_prerequisite_state THEN
    RAISE EXCEPTION 'audit chain: seq must be assigned by the sequence';
  END;
  RETURN NEW;
END $$
"""


def upgrade() -> None:
    app = context.config.attributes.get("app_role", "ics_app")
    for stmt in [s for s in DDL.replace("{APP}", app).split(";\n") if s.strip()]:
        op.execute(stmt)
    op.execute(GUARD)
    op.execute("CREATE TRIGGER audit_chain_guard BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION audit_chain_guard()")


def downgrade() -> None:
    raise RuntimeError("irreversible by design")
