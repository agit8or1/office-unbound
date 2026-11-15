"""python -m ics.migrate  - run Alembic migrations as the owner role. Run as root (systemd ics-migrate.service)."""
import os
import sys

from alembic import command
from alembic.config import Config

ROOT = os.path.join(os.path.dirname(__file__), "..")


def in_recovery() -> bool:
    """A hot standby is read-only and gets its schema by replication from the primary: never migrate there (ADR-0012)."""
    from sqlalchemy import create_engine, text
    from .config import load_migrate_url
    eng = create_engine(load_migrate_url())
    try:
        with eng.connect() as c:
            return bool(c.execute(text("SELECT pg_is_in_recovery()")).scalar())
    finally:
        eng.dispose()


def main() -> int:
    if in_recovery():
        print("database is a hot standby (in recovery): migrations are applied on the primary and replicated; skipping")
        return 0
    cfg = Config(os.path.join(ROOT, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(ROOT, "migrations"))
    command.upgrade(cfg, "head")
    return 0


if __name__ == "__main__":
    sys.exit(main())
