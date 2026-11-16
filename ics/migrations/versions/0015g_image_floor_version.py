"""Golden images v2 (manifest version + image hash) on the ONE downgrade-floor table from 0013r7: image_floor gains version / image_sha256 / image_name.
The guard now refuses lowering EITHER the release date or the manifest version, and still refuses deletes. Replaces the golden-prod branch's separate
golden_image_floor table (same concept; consolidated at integration so there is one floor)."""
from alembic import op

revision = "0015g"
down_revision = "0014s"

FUNC = """
CREATE OR REPLACE FUNCTION image_floor_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'image_floor cannot be deleted'; END IF;
  IF NEW.release_date < OLD.release_date THEN RAISE EXCEPTION 'image floor is monotonic (% -> %)', OLD.release_date, NEW.release_date; END IF;
  IF OLD.version IS NOT NULL AND (NEW.version IS NULL OR NEW.version < OLD.version) THEN
    RAISE EXCEPTION 'image floor version is monotonic (% -> %)', OLD.version, NEW.version;
  END IF;
  NEW.updated_at := now();
  RETURN NEW;
END $$"""


def upgrade() -> None:
    op.execute("ALTER TABLE image_floor ADD COLUMN version bigint CHECK (version > 0), "
               "ADD COLUMN image_sha256 text CHECK (image_sha256 ~ '^[0-9a-f]{64}$'), ADD COLUMN image_name text")
    op.execute(FUNC)


def downgrade() -> None:
    raise RuntimeError("irreversible by design")
