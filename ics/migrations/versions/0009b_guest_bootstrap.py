"""guest bootstrap v2: per-VM-INSTANCE one-time bootstrap secrets (random, vault-encrypted, deleted after use) - review M1"""
from alembic import context, op

revision = "0009b"
down_revision = "0008i"

DDL = """
CREATE TABLE guest_bootstrap (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  bid text NOT NULL UNIQUE,
  deployment_id uuid NOT NULL,
  vm text NOT NULL,
  vmid integer NOT NULL,
  mode text NOT NULL CHECK (mode IN ('callback','ssh-lab')),
  secret_enc bytea,
  ssh_key_enc bytea,
  token_enc bytea,
  state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','reported','enrolled','sealed','expired','revoked','failed')),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  reported_at timestamptz,
  secret_deleted_at timestamptz,
  sealed_at timestamptz,
  attempts integer NOT NULL DEFAULT 0,
  report jsonb,
  config jsonb
);
CREATE INDEX guest_bootstrap_dep ON guest_bootstrap (deployment_id, vm, vmid);
GRANT SELECT, INSERT, UPDATE ON guest_bootstrap TO {APP}
"""


def upgrade() -> None:
    app = context.config.attributes.get("app_role", "ics_app")
    for stmt in [s for s in DDL.replace("{APP}", app).split(";\n") if s.strip()]:
        op.execute(stmt)


def downgrade() -> None:
    raise RuntimeError("irreversible by design")
