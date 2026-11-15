"""python -m ics.migrate  - run Alembic migrations as the owner role. Run as root (systemd ics-migrate.service)."""
import os
import sys

from alembic import command
from alembic.config import Config

ROOT = os.path.join(os.path.dirname(__file__), "..")


def main() -> int:
    cfg = Config(os.path.join(ROOT, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(ROOT, "migrations"))
    command.upgrade(cfg, "head")
    return 0


if __name__ == "__main__":
    sys.exit(main())
