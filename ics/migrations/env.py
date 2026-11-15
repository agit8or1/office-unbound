from alembic import context
from sqlalchemy import create_engine

from ics.config import load_migrate_url

url = context.config.attributes.get("url") or load_migrate_url()
engine = create_engine(url)
with engine.connect() as conn:
    context.configure(connection=conn, target_metadata=None)
    with context.begin_transaction():
        context.run_migrations()
