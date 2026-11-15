"""controller epoch / role row for warm-standby fencing (ADR-0012)"""
from alembic import context, op

revision = "0009a"
down_revision = "0008i"

TABLE = """
CREATE TABLE controller_state (
  id int PRIMARY KEY CHECK (id = 1),
  epoch bigint NOT NULL CHECK (epoch >= 1),
  role text NOT NULL CHECK (role IN ('primary','fenced')),
  node_name text,
  changed_at timestamptz NOT NULL DEFAULT now(),
  note text
)"""

FUNC = """
CREATE FUNCTION controller_state_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'controller_state cannot be deleted'; END IF;
  IF NEW.epoch < OLD.epoch THEN RAISE EXCEPTION 'controller epoch is monotonic (% -> %)', OLD.epoch, NEW.epoch; END IF;
  NEW.changed_at := now();
  RETURN NEW;
END $$"""


def upgrade() -> None:
    app = context.config.attributes.get("app_role", "ics_app")
    op.execute(TABLE)
    op.execute("INSERT INTO controller_state (id, epoch, role) VALUES (1, 1, 'primary')")
    op.execute(FUNC)
    op.execute("CREATE TRIGGER controller_state_guard BEFORE UPDATE OR DELETE ON controller_state "
               "FOR EACH ROW EXECUTE FUNCTION controller_state_guard()")
    op.execute(f"GRANT SELECT, UPDATE ON controller_state TO {app}")


def downgrade() -> None:
    raise RuntimeError("irreversible by design")
