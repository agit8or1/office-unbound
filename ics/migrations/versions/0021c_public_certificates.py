"""Public certificate reuse (ADR-0018 section 11, amendment 2026-11-22): the production Let's Encrypt lineage a gateway serves (account files,
certificate, chain and private key), captured after issuance and restored on a rebuilt gateway for the same names, so a rebuild does not order
a new certificate (Let's Encrypt allows 5 duplicate certificates per week). Keyed by the exact name set, NOT by deployment: it must survive the
deployment that obtained it. The bundle is vault-encrypted (AES-GCM, context = public_certificates:<names_key>)."""
from alembic import context, op

revision = "0021c"
down_revision = "0020n"
branch_labels = None
depends_on = None

DDL = """
CREATE TABLE public_certificates (
  names_key text PRIMARY KEY CHECK (length(names_key) BETWEEN 4 AND 4200),
  names text[] NOT NULL,
  not_after timestamptz NOT NULL,
  bundle_enc bytea NOT NULL,
  source_deployment text NOT NULL,
  captured_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON public_certificates TO {APP}
"""


def upgrade() -> None:
    app = context.config.attributes.get("app_role", "ics_app")
    for stmt in [s for s in DDL.replace("{APP}", app).split(";\n") if s.strip()]:
        op.execute(stmt)


def downgrade() -> None:
    op.execute("DROP TABLE public_certificates")
