"""authorized nodes per endpoint (deny by default): ICS only creates/changes/migrates guests on these cluster nodes"""
revision = "0007"
down_revision = "0006a"

DDL = """
ALTER TABLE endpoints ADD COLUMN allowed_nodes text[] NOT NULL DEFAULT '{}';
"""


def upgrade():
    from alembic import op
    op.execute(DDL)


def downgrade():
    from alembic import op
    op.execute("ALTER TABLE endpoints DROP COLUMN allowed_nodes")
