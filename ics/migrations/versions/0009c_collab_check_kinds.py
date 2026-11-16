"""Check kinds for the collaboration components: sip_options_tls (PBX) and jitsi_jwt (Jitsi Prosody token enforcement)."""
from alembic import op

revision = "0009c"
down_revision = "0013r7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE checks DROP CONSTRAINT checks_kind_check")
    op.execute("ALTER TABLE checks ADD CONSTRAINT checks_kind_check CHECK (kind IN "
               "('http','tcp_tls','imap_login','smtp_banner','ews_getfolder','backup','sip_options_tls','jitsi_jwt'))")


def downgrade() -> None:
    raise RuntimeError("irreversible by design")
