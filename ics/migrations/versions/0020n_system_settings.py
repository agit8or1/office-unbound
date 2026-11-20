"""System settings (Settings -> Network & domains): one row per settings group, validated by the application (ics/netsettings.py) and written
only by the typed action settings.network.update (plan -> approval -> job -> audit). Additive: no existing table changes."""
from alembic import context, op

revision = "0020n"
down_revision = "0019c"
branch_labels = None
depends_on = None

DDL = """
CREATE TABLE system_settings (
  key text PRIMARY KEY CHECK (key ~ '^[a-z][a-z0-9_.]{1,40}$'),
  value jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  updated_by text
);
GRANT SELECT, INSERT, UPDATE ON system_settings TO {APP}
"""


def upgrade() -> None:
    app = context.config.attributes.get("app_role", "ics_app")
    for stmt in [s for s in DDL.replace("{APP}", app).split(";\n") if s.strip()]:
        op.execute(stmt)


def downgrade() -> None:
    op.execute("DROP TABLE system_settings")
