"""ADR-0014 SSH onboarding: short-lived admin SSH sessions (credential lives in the vault, not here) and the ICS-owned SSH identities."""
from alembic import op

revision = "0014s"
down_revision = "0013r7"

DDL = """
CREATE TABLE ssh_sessions (
  id uuid PRIMARY KEY,                       -- = id of the vault credential holding the admin secret
  customer_id uuid NOT NULL REFERENCES customers(id),
  created_by uuid NOT NULL REFERENCES users(id),
  host text NOT NULL, port integer NOT NULL CHECK (port BETWEEN 1 AND 65535), username text NOT NULL,
  auth text NOT NULL CHECK (auth IN ('password','key')), use_sudo boolean NOT NULL DEFAULT false,
  api_url text,
  state text NOT NULL DEFAULT 'new' CHECK (state IN ('new','pinned','used','cancelled','expired','failed')),
  hk_algo text, hk_candidate text, hk_pinned text,
  api_cert_ssh text, api_cert_seen text, api_cert_pinned text,
  api_trust text CHECK (api_trust IN ('public_ca','cluster_ca','fingerprint','proxy_public')), api_ca_pem text,
  api_proxy text NOT NULL DEFAULT 'none' CHECK (api_proxy IN ('none','pending','confirmed')),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  finished_at timestamptz
);
CREATE INDEX ssh_sessions_customer ON ssh_sessions (customer_id);
CREATE TABLE ssh_identities (
  endpoint_id uuid PRIMARY KEY REFERENCES endpoints(id) ON DELETE CASCADE,
  customer_id uuid NOT NULL REFERENCES customers(id),
  credential_id uuid NOT NULL REFERENCES credentials(id),
  host text NOT NULL, port integer NOT NULL, account text NOT NULL, node text NOT NULL,
  hostkey_algo text NOT NULL, hostkey_fp text NOT NULL, key_fp text NOT NULL,
  helper_sha256 text NOT NULL, conf_sha256 text NOT NULL, sudoers_sha256 text NOT NULL, authorized_line text NOT NULL,
  installed_at timestamptz NOT NULL DEFAULT now(), removed_at timestamptz
);
GRANT SELECT, INSERT, UPDATE, DELETE ON ssh_sessions, ssh_identities TO {APP}
"""


def upgrade() -> None:
    from alembic import context
    app = context.config.attributes.get("app_role", "ics_app")
    for stmt in [s for s in DDL.replace("{APP}", app).split(";\n") if s.strip()]:
        op.execute(stmt)


def downgrade() -> None:
    raise RuntimeError("irreversible by design")
