"""Check kind agent_probe (ics/guest/probe.py) and per-deployment secrets (ADR-0009 s5, guest configuration): passwords the components share (directory bind, database, admin bootstrap) and the
deployment CA. Values are vault-encrypted (AES-GCM, context = deployment_secrets:<deployment>:<name>); wiped when the deployment is destroyed."""
from alembic import context, op

revision = "0019c"
down_revision = "0018h"
branch_labels = None
depends_on = None

DDL = """
CREATE TABLE deployment_secrets (
  deployment_id uuid NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
  name text NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{1,40}$'),
  value_enc bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (deployment_id, name)
);
GRANT SELECT, INSERT, UPDATE, DELETE ON deployment_secrets TO {APP};
ALTER TABLE checks DROP CONSTRAINT checks_kind_check;
ALTER TABLE checks ADD CONSTRAINT checks_kind_check CHECK (kind IN ({KINDS},'infra','agent_probe'))
"""
KINDS = "'http','tcp_tls','imap_login','smtp_banner','ews_getfolder','backup','sip_options_tls','jitsi_jwt'"


def upgrade() -> None:
    app = context.config.attributes.get("app_role", "ics_app")
    for stmt in [s for s in DDL.replace("{APP}", app).replace("{KINDS}", KINDS).split(";\n") if s.strip()]:
        op.execute(stmt)


def downgrade() -> None:
    op.execute("DELETE FROM checks WHERE kind = 'agent_probe'")
    op.execute("ALTER TABLE checks DROP CONSTRAINT checks_kind_check")
    op.execute(f"ALTER TABLE checks ADD CONSTRAINT checks_kind_check CHECK (kind IN ({KINDS},'infra'))")
    op.execute("DROP TABLE deployment_secrets")
