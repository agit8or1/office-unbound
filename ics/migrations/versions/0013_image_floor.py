"""review 7 M-4 (review 5 M7): the golden-image downgrade floor lives in the ICS database, per OS, and can only go UP. It used to be read from the tags of the
Proxmox templates visible to the token, so deleting or re-tagging the newest template silently lowered it."""
from alembic import op
from alembic import context

revision = "0013"
down_revision = "0012"

TABLE = """
CREATE TABLE image_floor (
  os text PRIMARY KEY CHECK (os IN ('debian-12', 'ubuntu-24.04')),
  release_date text NOT NULL CHECK (release_date ~ '^[0-9]{8}$'),
  updated_at timestamptz NOT NULL DEFAULT now()
)"""
FUNC = """
CREATE FUNCTION image_floor_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'image_floor cannot be deleted'; END IF;
  IF NEW.release_date < OLD.release_date THEN RAISE EXCEPTION 'image floor is monotonic (% -> %)', OLD.release_date, NEW.release_date; END IF;
  NEW.updated_at := now();
  RETURN NEW;
END $$"""


def upgrade() -> None:
    app = context.config.attributes.get("app_role", "ics_app")
    op.execute(TABLE)
    op.execute(FUNC)
    op.execute("CREATE TRIGGER image_floor_guard BEFORE UPDATE OR DELETE ON image_floor FOR EACH ROW EXECUTE FUNCTION image_floor_guard()")
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON image_floor TO {app}")


def downgrade() -> None:
    raise RuntimeError("irreversible by design")
