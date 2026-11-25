import socket

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from . import agentclient, audit, egress, epoch
from .config import Settings, load_settings
from .vault import Vault, read_key_file


class Runtime:
    """Engine + session factory + vault, built once per process. Holds ics_app credentials only."""

    def __init__(self, settings: Settings | None = None):
        self.settings = settings or load_settings()
        from . import experimental
        experimental.configure(getattr(self.settings, "experimental", ()))   # every process (API, worker, CLI) gates the same way
        self.engine = create_engine(self.settings.database_url, pool_pre_ping=True, pool_size=10)
        self.sessionmaker = sessionmaker(self.engine, expire_on_commit=False)
        self.vault = Vault.from_file(self.settings.vault_key_file)
        audit.set_key(read_key_file(self.settings.audit_key_file, "audit key"))
        agentclient.stale_epoch_hook = lambda seen: epoch.self_fence(self, seen)
        from .guest import golden
        golden.set_floor_store(golden.DbFloor(self))        # review 7 M-4: the downgrade floor is ICS database state
        golden.set_trust_source(lambda: golden.trust_from_settings(self.settings))   # review 8 M-4: one trust configuration, read by the import verb
        self.own_epoch: int | None = None          # the controller epoch this process runs at (fixed at the first epoch.assert_active)
        self.fenced_reason: str | None = None      # sticky: set when this controller learns it is superseded; nothing leaves the process afterwards
        egress.identity = self._identity_headers
        from . import lease as leasemod
        self.lease = leasemod.build(self)            # None unless ICS_LEASE_WITNESS_URL is set on a primary (lease mode, review 7 H-5)
        egress.guard = lambda: epoch.assert_active(self)   # every egress path (agent, provider, notification, promotion, ssh) asks first

    def _identity_headers(self) -> dict:
        """Who is calling (evidence for an external recorder): controller host name, the epoch this process runs at and the job being executed (if any)."""
        from .providers.base import current_job
        h = {"X-OU-Controller": socket.gethostname(), "X-OU-Epoch": str(self.own_epoch if self.own_epoch is not None else 0)}
        if (j := current_job()):
            h["X-OU-Job"] = str(j)[:64]
        return h

    def assert_active(self, db=None, *, lock: bool = False) -> int:
        return epoch.assert_active(self, db, lock=lock)

    def agent_epoch(self) -> int:
        """Epoch to stamp on a signed agent request; raises (and nothing is sent) when this controller is a standby or fenced."""
        return epoch.current_epoch(self)

    def session(self) -> Session:
        return self.sessionmaker()
