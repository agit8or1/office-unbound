"""Proxmox administrator sessions for the connection wizard (password + optional second factor, no API token needed).

The ICS logs in to the Proxmox API itself (POST /access/ticket, then the TFA step when the account needs one). Only the resulting short-lived
PVE ticket and CSRF token are kept, as a vault credential (id = session id, purpose temporary_provisioning, provider pve-admin, <= 30 min).
The administrator's password is never stored; it lives only for the duration of the login request.

endpoints.managed_vmids: EXISTING guests the administrator authorized individually (operations preset; power control only).
inventory_ledger: what the ICS has seen per endpoint (new / missing / moved / renamed / VMID identity changes); review state never grants access."""
from alembic import op

revision = "0016p"
down_revision = "0015g"

DDL = """
CREATE TABLE pve_admin_sessions (
  id uuid PRIMARY KEY,
  credential_id uuid REFERENCES credentials(id),  -- vault entry holding the TFA challenge, then the PVE ticket (never the password)
  customer_id uuid NOT NULL REFERENCES customers(id),
  created_by uuid NOT NULL REFERENCES users(id),
  base_url text NOT NULL,
  ca_pem text, fingerprint_sha256 text,
  trust text NOT NULL CHECK (trust IN ('public_ca','ca','fingerprint')),
  username text NOT NULL,
  state text NOT NULL DEFAULT 'need_tfa' CHECK (state IN ('need_tfa','ready','used','cancelled','expired','failed')),
  tfa_methods jsonb NOT NULL DEFAULT '[]'::jsonb,
  tfa_attempts integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  finished_at timestamptz,
  CHECK ((ca_pem IS NULL) <> (fingerprint_sha256 IS NULL))
);
CREATE INDEX pve_admin_sessions_user ON pve_admin_sessions (created_by);
GRANT SELECT, INSERT, UPDATE, DELETE ON pve_admin_sessions TO {APP};
ALTER TABLE endpoints ADD COLUMN managed_vmids integer[] NOT NULL DEFAULT '{}';
ALTER TABLE endpoints DROP CONSTRAINT endpoints_provision_scope;
ALTER TABLE endpoints ADD CONSTRAINT endpoints_provision_scope CHECK (provision_token_id IS NULL OR cardinality(allowed_pools) > 0 OR cardinality(managed_vmids) > 0);
CREATE TABLE inventory_ledger (
  endpoint_id uuid NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
  kind text NOT NULL CHECK (kind IN ('node','guest','storage','network','pool')),
  key text NOT NULL,                          -- stable Proxmox identity: vmid / node name / storage id / bridge or vnet / pool id
  name text, node text, type text,
  first_seen timestamptz NOT NULL DEFAULT now(),
  last_seen timestamptz NOT NULL DEFAULT now(),
  missing_since timestamptz,
  change text CHECK (change IN ('renamed','moved','identity_changed')),
  change_detail jsonb,
  acknowledged_at timestamptz,               -- an administrator reviewed it (new or changed); NEVER grants access
  PRIMARY KEY (endpoint_id, kind, key)
);
GRANT SELECT, INSERT, UPDATE, DELETE ON inventory_ledger TO {APP}
"""


def upgrade() -> None:
    from alembic import context
    app = context.config.attributes.get("app_role", "ics_app")
    for stmt in [s for s in DDL.replace("{APP}", app).split(";\n") if s.strip()]:
        op.execute(stmt)


def downgrade() -> None:
    op.execute("DROP TABLE inventory_ledger")
    op.execute("ALTER TABLE endpoints DROP CONSTRAINT endpoints_provision_scope")
    op.execute("ALTER TABLE endpoints ADD CONSTRAINT endpoints_provision_scope CHECK (provision_token_id IS NULL OR cardinality(allowed_pools) > 0)")
    op.execute("ALTER TABLE endpoints DROP COLUMN managed_vmids")
    op.execute("DROP TABLE pve_admin_sessions")
