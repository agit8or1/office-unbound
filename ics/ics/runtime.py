from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from . import audit
from .config import Settings, load_settings
from .vault import Vault, read_key_file


class Runtime:
    """Engine + session factory + vault, built once per process. Holds ics_app credentials only."""

    def __init__(self, settings: Settings | None = None):
        self.settings = settings or load_settings()
        self.engine = create_engine(self.settings.database_url, pool_pre_ping=True, pool_size=10)
        self.sessionmaker = sessionmaker(self.engine, expire_on_commit=False)
        self.vault = Vault.from_file(self.settings.vault_key_file)
        audit.set_key(read_key_file(self.settings.audit_key_file, "audit key"))

    def session(self) -> Session:
        return self.sessionmaker()
