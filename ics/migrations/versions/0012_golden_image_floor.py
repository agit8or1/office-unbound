"""golden image rollback floor in the ICS database (security review 7 M-4): the newest signed release version ever accepted per OS. It can only go up:
the application role has no DELETE, and a trigger refuses any UPDATE that does not raise the version, so deleting or re-tagging a Proxmox template (the
old, mutable source of the floor) can no longer re-enable a downgrade."""
from alembic import context, op

revision = "0012"
down_revision = "0011"

DDL = """
CREATE TABLE golden_image_floor (
  os text PRIMARY KEY CHECK (os IN ('debian-12','ubuntu-24.04')),
  version bigint NOT NULL CHECK (version > 0),
  image_sha256 text NOT NULL CHECK (image_sha256 ~ '^[0-9a-f]{64}$'),
  image_name text NOT NULL,
  advanced_at timestamptz NOT NULL DEFAULT now()
);
CREATE FUNCTION golden_image_floor_monotonic() RETURNS trigger LANGUAGE plpgsql AS $f$
BEGIN
  IF NEW.os <> OLD.os OR NEW.version <= OLD.version THEN
    RAISE EXCEPTION 'golden image floor can only increase (os %, % -> %)', OLD.os, OLD.version, NEW.version;
  END IF;
  RETURN NEW;
END $f$;
CREATE TRIGGER golden_image_floor_monotonic BEFORE UPDATE ON golden_image_floor FOR EACH ROW EXECUTE FUNCTION golden_image_floor_monotonic();
GRANT SELECT, INSERT, UPDATE ON golden_image_floor TO {APP}
"""


def upgrade() -> None:
    app = context.config.attributes.get("app_role", "ics_app")
    # one statement per execute: the plpgsql body contains semicolons
    stmts = [
        DDL[DDL.index("CREATE TABLE"):DDL.index("CREATE FUNCTION")],
        DDL[DDL.index("CREATE FUNCTION"):DDL.index("CREATE TRIGGER")],
        DDL[DDL.index("CREATE TRIGGER"):DDL.index("GRANT")],
        DDL[DDL.index("GRANT"):].replace("{APP}", app),
    ]
    for s in stmts:
        op.execute(s.strip().rstrip(";"))


def downgrade() -> None:
    raise RuntimeError("irreversible by design")
