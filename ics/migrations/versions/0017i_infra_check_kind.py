"""Check kind `infra`: infrastructure alert rules evaluated from collected inventory/metrics (node offline, guest stopped, CPU/memory/storage)."""
from alembic import op

revision = "0017i"
down_revision = "0016p"
branch_labels = None
depends_on = None

KINDS = "'http','tcp_tls','imap_login','smtp_banner','ews_getfolder','backup','sip_options_tls','jitsi_jwt'"


def upgrade() -> None:
    op.execute("ALTER TABLE checks DROP CONSTRAINT checks_kind_check")
    op.execute(f"ALTER TABLE checks ADD CONSTRAINT checks_kind_check CHECK (kind IN ({KINDS},'infra'))")


def downgrade() -> None:
    op.execute("DELETE FROM checks WHERE kind = 'infra'")
    op.execute("ALTER TABLE checks DROP CONSTRAINT checks_kind_check")
    op.execute(f"ALTER TABLE checks ADD CONSTRAINT checks_kind_check CHECK (kind IN ({KINDS}))")
