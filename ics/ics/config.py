"""Configuration from the environment, optionally seeded from an env file outside the repo.

Default file: /etc/office-unbound/ics.env (override with ICS_ENV_FILE). Real environment wins.
"""
import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_ENV_FILE = "/etc/office-unbound/ics.env"


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
    migrate_database_url: str | None
    vault_key_file: str
    cookie_secure: bool = True
    worker_enabled: bool = True
    session_absolute_seconds: int = 12 * 3600
    session_idle_seconds: int = 3600
    login_max_failures: int = 5
    login_window_seconds: int = 900
    heartbeat_max_age_seconds: int = 30


def load_settings() -> Settings:
    env = _load_env_file(os.environ.get("ICS_ENV_FILE", DEFAULT_ENV_FILE))
    env.update({k: v for k, v in os.environ.items() if k.startswith("ICS_")})

    def b(name: str, default: bool) -> bool:
        return env.get(name, str(default)).lower() in ("1", "true", "yes")

    try:
        return Settings(
            database_url=env["ICS_DATABASE_URL"],
            migrate_database_url=env.get("ICS_MIGRATE_DATABASE_URL"),
            vault_key_file=env["ICS_VAULT_KEY_FILE"],
            cookie_secure=b("ICS_COOKIE_SECURE", True),
            worker_enabled=b("ICS_WORKER_ENABLED", True),
            login_max_failures=int(env.get("ICS_LOGIN_MAX_FAILURES", 5)),
        )
    except KeyError as e:  # pragma: no cover
        raise RuntimeError(f"missing required config {e}; see README (config)") from None
