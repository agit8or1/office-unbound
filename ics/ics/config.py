"""Configuration from the environment, optionally seeded from an env file outside the repo.

App file:     /etc/office-unbound/ics.env          (root:ics 0640; ics_app DB credentials only)
Migrate file: /etc/office-unbound/ics-migrate.env  (root:root 0600; ics_owner URL; never read by the app process)
Real environment variables (ICS_*) win over the app file. The migrate URL is only ever read by
`load_migrate_url()`, which is called by Alembic / `python -m ics.migrate`, never by `load_settings()`.
"""
import os
from dataclasses import dataclass, field
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
    guest_callback_dedicated: bool = False      # the callback is served by `python -m ics.serve_callback` only, not by the console app (review 5 L4)
    guest_require_nic_binding: bool = True     # production bootstrap: the reporting address must resolve to the VM's net0 MAC (review 5 M2)
    release_promote_cmd: str | None = None  # release.promote executor: command taking a signed manifest file (repo.sh promote-manifest)
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
    job_timeout_seconds: int = 180               # >= agent deadline (90) + max verify (45) + one check timeout (30) + slack (review L3)
    job_lease_slack_seconds: int = 60
    deployment_lease_seconds: int = 60           # review 3 H1: deployments are lease-based (renewed per heartbeat), no fixed job wall clock
    deployment_step_deadline_seconds: int = 1800  # per step, not per job
    backup_job_timeout_seconds: int = 3600      # backup.* jobs run on their own lane (a restore verification takes minutes; it must not block remediation)
    backup_scheduler_enabled: bool = True
    pve_request_deadline_seconds: float = 30.0
    pve_max_response_bytes: int = 16 * 1024 * 1024
    snapshot_retention: int = 50
    allow_loopback_endpoints: bool = False  # SSRF guard: tests/lab only
    msp_proxy_auth: str | None = field(default=None, repr=False)  # review 6 L5: shared secret the TLS proxy sets in X-OU-Proxy-Auth next to X-Client-Cert-SHA256
    msp_webhook_allow: tuple[str, ...] = ()  # review 6 M2: operator-approved exceptions for webhook targets (exact hostnames or CIDRs that may be private)
    monitor_enabled: bool = True
    monitor_parallelism: int = 8
    check_result_retention_days: int = 14
    agent_request_ttl_seconds: int = 60          # signed-request validity (agent enforces <= 120)
    agent_deadline_seconds: float = 90.0
    notify_max_attempts: int = 5
    incident_renotify_seconds: int = 3600        # re-notify unacknowledged incidents; 0 = never
    allow_loopback_agents: bool = False
    # review 2026-11-15 (M1) remediation bounds
    remediation_unit_budget: int = 3             # service.restart attempts per (node, unit) across ALL checks ...
    remediation_unit_budget_window_seconds: int = 3600   # ... per this window
    remediation_min_backoff_seconds: int = 30
    remediation_min_window_seconds: int = 300
    remediation_plan_ttl_seconds: int = 4 * 3600  # (M3) a pending remediation plan older than this is superseded
    # (M2) a worker component that has not made progress for this long stops the heartbeat (readyz goes red)
    monitor_stall_seconds: int = 300
    # (L5) quotas
    max_checks: int = 200
    check_min_interval_seconds: int = 15
    check_min_interval_credentialed_seconds: int = 30
    check_results_max_per_check: int = 20000
    # (M4) alert silencing needs a second person beyond these bounds
    maintenance_max_unapproved_minutes: int = 60
    ack_burst_limit: int = 5                     # incident.ack plans per user per hour before approval is required
    inventory_discovery_seconds: int = 300
    metrics_interval_seconds: int = 60
    metrics_retention_days: int = 30
    inventory_stale_seconds: int = 900
    # guest bootstrap (ICS-driven first boot, guest/sshboot.py) and the image supply chain pushed into every guest
    guest_agent_dir: str | None = None           # directory with ou_agent/ and deploy/ (the agent bundle source); default: <repo>/ics/agent
    guest_image_registries: tuple[str, ...] = ()           # host[:port] registries the guests' agents may pull from (signed images only)
    guest_insecure_registries: tuple[str, ...] = ()        # subset of the above that is reached over plain HTTP (lab); signatures still required
    guest_image_signing_pubkey_file: str | None = None     # PEM of the ONE cosign-format ECDSA P-256 public key images must be signed with
    guest_image_signing_key_sha256: str | None = None      # operator-confirmed pin: sha256 of that key's DER SubjectPublicKeyInfo (checked at render time)
    guest_mgmt_sources: tuple[str, ...] = ()               # CIDRs allowed to reach guest agents; default: this host's source address towards the guest
    guest_bootstrap_timeout_seconds: int = 1500
    environment: str = "production"              # "production" (default) | "lab"; lab-only features are refused unless this is "lab"
    lab_ssh_bootstrap: bool = False              # LAB ONLY (ICS_LAB_SSH_BOOTSTRAP): the ICS-driven SSH guest bootstrap of docs/status/first-real-deployment.md; ADR-0002 addendum
    guest_callback_url: str | None = None        # https://<ics-host>:<port> the guests call back (golden-image bootstrap); no path
    guest_callback_pin_sha256: str | None = None # sha256 (hex) of the certificate (CA or leaf) the guests pin for that URL
    guest_bootstrap_ttl_seconds: int = 1800      # lifetime of a per-VM one-time bootstrap secret
    guest_keep_bootstrap_ssh: bool = False       # DEBUG ONLY: do not seal the bootstrap SSH access after enrollment (the guest's own timer still seals it after bootstrap_seal_seconds)
    role: str = "primary"                        # ADR-0012: 'standby' = passive warm standby (no worker, no mutations, never signs agent requests)
    standby_max_lag_seconds: int = 60            # /readyz replication check on a standby
    trusted_proxy: str | None = None             # exact IP of a local reverse proxy whose X-Forwarded-For is honoured (e.g. 127.0.0.1); None = ignore XFF

    def __post_init__(self):
        _check_lab_only(self)   # lab-only features are refused in production no matter how the Settings object was built


def _check_lab_only(s: "Settings") -> None:
    if s.environment not in ("production", "lab"):
        raise RuntimeError("ICS_ENVIRONMENT must be 'production' or 'lab'")
    if (s.lab_ssh_bootstrap or s.guest_keep_bootstrap_ssh) and s.environment != "lab":
        raise RuntimeError("ICS_LAB_SSH_BOOTSTRAP / ICS_GUEST_KEEP_BOOTSTRAP_SSH are lab-only (ADR-0002 addendum): refused unless ICS_ENVIRONMENT=lab")
    if s.guest_keep_bootstrap_ssh and not s.lab_ssh_bootstrap:
        raise RuntimeError("ICS_GUEST_KEEP_BOOTSTRAP_SSH needs ICS_LAB_SSH_BOOTSTRAP")


def _trusted_proxy(v: str | None) -> str | None:
    """Only a single literal loopback IP may be trusted (the proxy must run on this host)."""
    if not v:
        return None
    import ipaddress
    ip = ipaddress.ip_address(v.strip())
    if not ip.is_loopback:
        raise RuntimeError("ICS_TRUSTED_PROXY must be a loopback address (local reverse proxy only)")
    return str(ip)


def _csv(v: str | None) -> tuple[str, ...]:
    return tuple(x.strip() for x in (v or "").split(",") if x.strip())


def _role(v: str | None) -> str:
    v = (v or "primary").strip().lower()
    if v not in ("primary", "standby"):
        raise RuntimeError("ICS_ROLE must be 'primary' or 'standby'")
    return v


def load_settings() -> Settings:
    env = _load_env_file(os.environ.get("ICS_ENV_FILE", DEFAULT_ENV_FILE))
    env.update({k: v for k, v in os.environ.items() if k.startswith("ICS_")})

    def b(name: str, default: bool) -> bool:
        return env.get(name, str(default)).lower() in ("1", "true", "yes")

    try:
        s = Settings(
            database_url=env["ICS_DATABASE_URL"],
            vault_key_file=env["ICS_VAULT_KEY_FILE"],
            audit_key_file=env["ICS_AUDIT_KEY_FILE"],
            signing_key_file=env.get("ICS_SIGNING_KEY_FILE") or None,
            release_promote_cmd=env.get("ICS_RELEASE_PROMOTE_CMD") or None,
            guest_callback_dedicated=b("ICS_GUEST_CALLBACK_DEDICATED", False),
            guest_require_nic_binding=b("ICS_GUEST_REQUIRE_NIC_BINDING", True),
            monitor_enabled=b("ICS_MONITOR_ENABLED", True),
            cookie_secure=b("ICS_COOKIE_SECURE", True),
            worker_enabled=b("ICS_WORKER_ENABLED", True) and _role(env.get("ICS_ROLE")) == "primary",
            enable_docs=b("ICS_ENABLE_DOCS", False),
            login_max_failures=int(env.get("ICS_LOGIN_MAX_FAILURES", 5)),
            allow_loopback_endpoints=b("ICS_ALLOW_LOOPBACK_ENDPOINTS", False),
            role=_role(env.get("ICS_ROLE")),
            msp_webhook_allow=_csv(env.get("ICS_MSP_WEBHOOK_ALLOW")),
            msp_proxy_auth=(Path(env["ICS_MSP_PROXY_AUTH_FILE"]).read_text().strip() or None) if env.get("ICS_MSP_PROXY_AUTH_FILE") else None,
            trusted_proxy=_trusted_proxy(env.get("ICS_TRUSTED_PROXY")),
            job_timeout_seconds=int(env.get("ICS_JOB_TIMEOUT_SECONDS", 180)),
            guest_agent_dir=env.get("ICS_GUEST_AGENT_DIR") or None,
            guest_image_registries=_csv(env.get("ICS_GUEST_IMAGE_REGISTRIES")),
            guest_insecure_registries=_csv(env.get("ICS_GUEST_INSECURE_REGISTRIES")),
            guest_image_signing_pubkey_file=env.get("ICS_GUEST_IMAGE_SIGNING_PUBKEY_FILE") or None,
            guest_image_signing_key_sha256=env.get("ICS_GUEST_IMAGE_SIGNING_KEY_SHA256") or None,
            guest_mgmt_sources=_csv(env.get("ICS_GUEST_MGMT_SOURCES")),
            guest_bootstrap_timeout_seconds=int(env.get("ICS_GUEST_BOOTSTRAP_TIMEOUT_SECONDS", 1500)),
            guest_keep_bootstrap_ssh=b("ICS_GUEST_KEEP_BOOTSTRAP_SSH", False),
            environment=env.get("ICS_ENVIRONMENT", "production").strip().lower(),
            lab_ssh_bootstrap=b("ICS_LAB_SSH_BOOTSTRAP", False),
            guest_callback_url=env.get("ICS_GUEST_CALLBACK_URL") or None,
            guest_callback_pin_sha256=env.get("ICS_GUEST_CALLBACK_PIN_SHA256") or None,
            guest_bootstrap_ttl_seconds=int(env.get("ICS_GUEST_BOOTSTRAP_TTL_SECONDS", 1800)),
            backup_scheduler_enabled=b("ICS_BACKUP_SCHEDULER_ENABLED", True),
        )
        return s
    except KeyError as e:  # pragma: no cover
        raise RuntimeError(f"missing required config {e}; see README (config)") from None


def load_migrate_url() -> str:
    """Owner URL for migrations. Separate root-only file; real env var ICS_MIGRATE_DATABASE_URL also accepted."""
    env = _load_env_file(os.environ.get("ICS_MIGRATE_ENV_FILE", DEFAULT_MIGRATE_ENV_FILE))
    url = os.environ.get("ICS_MIGRATE_DATABASE_URL") or env.get("ICS_MIGRATE_DATABASE_URL")
    if not url:
        raise RuntimeError("ICS_MIGRATE_DATABASE_URL not found (run migrations as root; see README)")
    return url
