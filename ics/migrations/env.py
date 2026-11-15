from alembic import context
from sqlalchemy import create_engine

from ics.config import load_settings

url = context.config.attributes.get("url") or load_settings().migrate_database_url
if not url:
    raise RuntimeError("ICS_MIGRATE_DATABASE_URL not set")
engine = create_engine(url)
with engine.connect() as conn:
    context.configure(connection=conn, target_metadata=None)
    with context.begin_transaction():
        context.run_migrations()
