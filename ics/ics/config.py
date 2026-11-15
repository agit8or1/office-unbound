"""Configuration from the environment, optionally seeded from an env file outside the repo.

App file:     /etc/office-unbound/ics.env          (root:ics 0640; ics_app DB credentials only)
Migrate file: /etc/office-unbound/ics-migrate.env  (root:root 0600; ics_owner URL; never read by the app process)
Real environment variables (ICS_*) win over the app file. The migrate URL is only ever read by
`load_migrate_url()`, which is called by Alembic / `python -m ics.migrate`, never by `load_settings()`.
"""
import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_ENV_FILE = "/etc/office-unbound/ics.env"
DEFAULT_MIGRATE_ENV_FILE = "/etc/office-unbound/ics-migrate.env"


def _load_env_file(path: str) -> dict[str, str]:
    out: dict[str, str] = {}
    p = Path(path)
    if not p.is_file():
        return out
    for line in p.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


@dataclass(frozen=True)
class Settings:
    database_url: str
    vault_key_file: str
    audit_key_file: str
    signing_key_file: str | None = None  # Ed25519 key (32 raw bytes) that signs ICS->agent requests; root:ics 0640
    cookie_secure: bool = True
    worker_enabled: bool = True
    enable_docs: bool = False
    session_absolute_seconds: int = 12 * 3600
    session_idle_seconds: int = 3600
    max_sessions_per_user: int = 10
    login_max_failures: int = 5          # failures per (username, ip) before backoff starts
    login_window_seconds: int = 900
    login_backoff_base_seconds: int = 15
    login_backoff_cap_seconds: int = 900
    login_ip_max_failures: int = 100     # coarse per-IP spray limit (all usernames)
    heartbeat_max_age_seconds: int = 30
    required_approvals_high: int = 2
    plan_expiry_seconds: int = 7 * 24 * 3600
    enrollment_ttl_seconds: int = 24 * 3600
    max_body_bytes: int = 256 * 1024
    job_timeout_seconds: int = 120
    job_lease_slack_seconds: int = 60
    pve_request_deadline_seconds: float = 30.0
    pve_max_response_bytes: int = 16 * 1024 * 1024
    snapshot_retention: int = 50
    allow_loopback_endpoints: bool = False  # SSRF guard: tests/lab only
    monitor_enabled: bool = True
    monitor_parallelism: int = 8
    check_result_retention_days: int = 14
    agent_request_ttl_seconds: int = 60          # signed-request validity (agent enforces <= 120)
    agent_deadline_seconds: float = 90.0
    notify_max_attempts: int = 5
    incident_renotify_seconds: int = 3600        # re-notify unacknowledged incidents; 0 = never
    allow_loopback_agents: bool = False


def load_settings() -> Settings:
    env = _load_env_file(os.environ.get("ICS_ENV_FILE", DEFAULT_ENV_FILE))
    env.update({k: v for k, v in os.environ.items() if k.startswith("ICS_")})

    def b(name: str, default: bool) -> bool:
        return env.get(name, str(default)).lower() in ("1", "true", "yes")

    try:
        return Settings(
            database_url=env["ICS_DATABASE_URL"],
            vault_key_file=env["ICS_VAULT_KEY_FILE"],
            audit_key_file=env["ICS_AUDIT_KEY_FILE"],
            signing_key_file=env.get("ICS_SIGNING_KEY_FILE") or None,
            monitor_enabled=b("ICS_MONITOR_ENABLED", True),
            cookie_secure=b("ICS_COOKIE_SECURE", True),
            worker_enabled=b("ICS_WORKER_ENABLED", True),
            enable_docs=b("ICS_ENABLE_DOCS", False),
            login_max_failures=int(env.get("ICS_LOGIN_MAX_FAILURES", 5)),
            allow_loopback_endpoints=b("ICS_ALLOW_LOOPBACK_ENDPOINTS", False),
        )
    except KeyError as e:  # pragma: no cover
        raise RuntimeError(f"missing required config {e}; see README (config)") from None


def load_migrate_url() -> str:
    """Owner URL for migrations. Separate root-only file; real env var ICS_MIGRATE_DATABASE_URL also accepted."""
    env = _load_env_file(os.environ.get("ICS_MIGRATE_ENV_FILE", DEFAULT_MIGRATE_ENV_FILE))
    url = os.environ.get("ICS_MIGRATE_DATABASE_URL") or env.get("ICS_MIGRATE_DATABASE_URL")
    if not url:
        raise RuntimeError("ICS_MIGRATE_DATABASE_URL not found (run migrations as root; see README)")
    return url
