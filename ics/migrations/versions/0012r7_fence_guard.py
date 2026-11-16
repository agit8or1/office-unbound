"""review 7 H-5 / L8: a FENCED controller can only become primary again through a promotion (a higher epoch). The trigger used to guard the epoch only, so
`UPDATE controller_state SET role='primary'` (a bug, a restore script, a stale replica rewind) silently un-fenced a superseded controller."""
from alembic import op

revision = "0012r7"
down_revision = "0013h"

FUNC = """
CREATE OR REPLACE FUNCTION controller_state_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'controller_state cannot be deleted'; END IF;
  IF NEW.epoch < OLD.epoch THEN RAISE EXCEPTION 'controller epoch is monotonic (% -> %)', OLD.epoch, NEW.epoch; END IF;
  IF OLD.role = 'fenced' AND NEW.role = 'primary' AND NEW.epoch <= OLD.epoch THEN
    RAISE EXCEPTION 'a fenced controller becomes primary only through a promotion (epoch must rise: % -> %)', OLD.epoch, NEW.epoch;
  END IF;
  NEW.changed_at := now();
  RETURN NEW;
END $$"""


def upgrade() -> None:
    op.execute(FUNC)


def downgrade() -> None:
    raise RuntimeError("irreversible by design")
