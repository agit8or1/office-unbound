from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from . import agentclient, audit, egress, epoch
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
        agentclient.stale_epoch_hook = lambda seen: epoch.self_fence(self, seen)
        from .guest import golden
        golden.set_floor_store(golden.DbFloor(self))        # review 7 M-4: the downgrade floor is ICS database state
        try:
            golden.configure(open(self.settings.guest_release_pubkey_file).read() if self.settings.guest_release_pubkey_file else None, self.settings.guest_release_pin_sha256)
        except OSError:
            golden.configure(None, None)                    # unreadable key file: image import stays refused
        self.own_epoch: int | None = None          # the controller epoch this process runs at (fixed at the first epoch.assert_active)
        self.fenced_reason: str | None = None      # sticky: set when this controller learns it is superseded; nothing leaves the process afterwards
        egress.guard = lambda: epoch.assert_active(self)   # every egress path (agent, provider, notification, promotion, ssh) asks first

    def assert_active(self, db=None, *, lock: bool = False) -> int:
        return epoch.assert_active(self, db, lock=lock)

    def agent_epoch(self) -> int:
        """Epoch to stamp on a signed agent request; raises (and nothing is sent) when this controller is a standby or fenced."""
        return epoch.current_epoch(self)

    def session(self) -> Session:
        return self.sessionmaker()
