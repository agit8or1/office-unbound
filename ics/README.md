# Office Unbound ICS (backend)

FastAPI + SQLAlchemy 2 + Alembic + PostgreSQL 16. Typed actions -> approval -> durable job -> hash-chained, MAC-authenticated audit (ADR-0001/0002).
Security review 2026-11-15 findings are remediated; see `docs/status/security-review-ics-2026-11-15.md` (Remediation section).

## Deployment layout (this host)
| item | value |
|---|---|
| service | `ics.service` (systemd), user/group `ics` (system account, nologin), binds `127.0.0.1:8088`, `python -m ics.serve` (proxy headers NOT trusted) |
| migrations | `ics-migrate.service` (oneshot, root) runs `python -m ics.migrate` before the service; reads `/etc/office-unbound/ics-migrate.env` |
| code | `/opt/office-unbound/ics` (root-owned copy + venv, installed by `sudo sh deploy/install.sh`; re-run after changes) |
| units | `deploy/ics.service`, `deploy/ics-migrate.service` (NoNewPrivileges, ProtectSystem=strict, ProtectHome, PrivateTmp/Devices, empty capability set, syscall filter, MemoryDenyWriteExecute, read-only code/config) |

### Config files in `/etc/office-unbound/` (directory `root:root 0711`)
| file | mode | content |
|---|---|---|
| `ics.env` | `root:ics 0640` | app config: `ICS_DATABASE_URL` (**ics_app** role), `ICS_VAULT_KEY_FILE`, `ICS_AUDIT_KEY_FILE`, optional `ICS_COOKIE_SECURE`, `ICS_WORKER_ENABLED`, `ICS_ENABLE_DOCS` (default false), `ICS_ALLOW_LOOPBACK_ENDPOINTS` (default false), `ICS_LOGIN_MAX_FAILURES` |
| `ics-migrate.env` | `root:root 0600` | `ICS_MIGRATE_DATABASE_URL` (**ics_owner**). Read only by Alembic / `ics.migrate`; `load_settings()` never reads it and the app process cannot |
| `vault.key` | `root:ics 0640` | 32 raw bytes, AES-256 key for stored secrets. Losing it loses all stored secrets. `Vault.from_file` refuses symlinks, non-regular files, and world-accessible/group-writable files |
| `ics-signing.key` | `root:ics 0640` | 32 raw bytes, Ed25519 private key that signs ICS->node-agent requests (`ICS_SIGNING_KEY_FILE`). Same file checks as the vault key. Public half is given to each agent at enrollment; rotating it means re-enrolling agents |
| `audit.key` | `root:ics 0640` | >= 32 bytes, HMAC key for audit entries (never stored in the database) |
| `ics-test.env` | `root:administrator 0640` | test-only DB credentials for database `ics_test` (roles `ics_test_owner`, `ics_test_app`; no access to the `ics` database) |

The interactive user (`administrator`) is not in group `ics` and cannot read the vault key, audit key, app env or migrate env.
Break-glass operations are run with `sudo -u ics /opt/office-unbound/ics/.venv/bin/python -m ics.cli ...` (needs root on the host).

### Postgres (one-time, as postgres superuser; passwords only in the env files)
```
CREATE ROLE ics_owner LOGIN PASSWORD '...'; CREATE ROLE ics_app LOGIN PASSWORD '...';
CREATE DATABASE ics OWNER ics_owner; REVOKE ALL ON DATABASE ics FROM PUBLIC; GRANT CONNECT ON DATABASE ics TO ics_app;
-- tests: CREATE ROLE ics_test_owner/ics_test_app; CREATE DATABASE ics_test OWNER ics_test_owner (+ GRANT CONNECT to ics_test_app)
```
Migration 0001/0002 grant `ics_app` SELECT/INSERT only on `audit_events` and `plan_approvals` (no UPDATE/DELETE/TRUNCATE) - tested.
Migrations: `sudo systemctl restart ics-migrate` (or `sudo .venv/bin/python -m ics.migrate` with `ICS_MIGRATE_ENV_FILE`).

## Run / operate
```
sudo -u ics .venv/bin/python -m ics.cli create-admin --username admin   # prints a ONE-TIME enrollment token on the host (no password is ever chosen/shown)
sudo -u ics .venv/bin/python -m ics.cli issue-enrollment --username X   # (re)issue token; resets password+TOTP+sessions (recovery); never rate limited
sudo -u ics .venv/bin/python -m ics.cli unlock --username X             # clear login throttling
sudo -u ics .venv/bin/python -m ics.cli verify-chain                    # exit 1 if the audit chain/MACs are broken
```
Tests (real Postgres `ics_test`, own throwaway vault/audit keys in a temp dir; schema dropped and rebuilt by the suite): `.venv/bin/pytest`.
`/docs` and `/openapi.json` are disabled unless `ICS_ENABLE_DOCS=true` (dev only: the Swagger UI loads from a CDN and the CSP is relaxed for `/docs`).

## Account lifecycle (no credential ever travels to the creator)
1. `POST users {username, role}` (admin) creates an **invited** viewer/operator: no password, no TOTP, cannot log in. Response only says an invite exists.
2. A host operator issues the one-time enrollment token (`ics.cli issue-enrollment`) and hands it to the person out of band (24 h, single use, stored hashed).
3. The user calls `POST auth/enroll {username, token, password}` (sets their OWN password; server returns the TOTP URI to them) and
   `POST auth/enroll/confirm {username, token, totp_code}`. Only then is the account usable.
4. **approver/admin accounts, and any role change, are high-risk plan actions** (`user.create`, `user.set_role`; requester must be admin): they need the
   normal approval (see below). `users.created_by` / `role_set_by` record provenance.
5. Approval rules: the requester never decides their own plan; an approver created or elevated (directly or via a chain) by the requester cannot decide
   the requester's plans; a user cannot decide a plan changing their own role; **high-risk plans need 2 distinct approvers**; a job re-verifies this before running.

### Residual risk (break-glass)
A person with **root on the host** (or `sudo -u ics`) can always create accounts with the CLI, read the keys, and run anything - that is the
break-glass path by design (ADR-0002 item 1) and is recorded in the audit log (`cli` actor) but not preventable. Likewise a single admin with
host root can enrol sockpuppets from the CLI; the approval rules protect against a compromised *ICS admin session*, not against host root.
A compromise of the running app process yields `ics_app` + vault key + audit key: it can read/decrypt secrets and write validly-MACed audit
entries. What it cannot do: change/delete audit rows, alter approvals (insert-only table), or obtain owner credentials.

## Integrity / audit
- `audit_events` rows: `hash = sha256(prev_hash + "\n" + canonical_header + "\n" + details_canon)`; `details_canon` is the exact stored text that is hashed
  (no jsonb round-trip, remote data is sanitised: floats/huge ints/odd types become strings; NaN/Infinity can never be canonicalised).
- `mac = HMAC-SHA256(audit.key, "ics-audit-v2\n" + hash)` per row (L4). An attacker with only SQL write access (`ics_app` credentials, injection) cannot forge
  entries: a DB trigger also forces `prev_hash == current tail`, a sequence-assigned `seq`, and a non-null MAC. `verify` reports `bad_mac`, `altered`,
  `broken_link`, `details_mismatch`. Pre-0002 rows are verified the old way and counted as `legacy_unauthenticated`.
- Still **not** implemented: off-host export of a signed head (tail truncation by the DB owner is undetectable from the DB alone); the audit key lives in the app
  process, so code execution in the app can still append validly-MACed entries.
- Plans: `params_hash = sha256(canon(action, params, sha256(secret_enc), endpoint binding))`. Each approval row (insert-only) stores it; the job recomputes it
  and refuses on mismatch. Endpoint tokens are encrypted with AAD `endpoint-token:{id}:{binding}` (binding = base_url, token_id, fingerprint, CA hash), so
  changing a trust anchor makes the token undecryptable.

## Runtime limits
Proxmox requests: overall 30 s wall-clock deadline, 16 MiB response cap, 5 s connect/read timeouts, destination guard (loopback, link-local/metadata, unspecified,
multicast refused at plan time and at execution; RFC1918 allowed; resolved IPs are shown in the plan audit entry / response). Jobs: 120 s wall-clock budget
(`JobTimeout`), lease + reaper marks hung/crashed jobs failed (never re-run) and wipes their plan secret; heartbeat runs in its own thread. Request bodies capped at 256 KiB;
passwords at 1024 chars. Pending plans expire after 7 days (secret wiped). Inventory snapshots: newest 50 per endpoint. At most 10 sessions per user; `auth/logout-all`.
Login throttling is per (username, IP) with exponential backoff (15 s base, 15 min cap; 429s are not recorded), plus a coarse per-IP limit; the CLI path is never throttled.

## API summary (`/api/v1`, JSON)
Auth is a cookie `__Host-ics_session` (HttpOnly, Secure, SameSite=Strict) + `X-CSRF-Token` header (returned by login / `auth/me`) on every non-GET.
Roles: viewer < operator < approver < admin. Every response carries CSP (`default-src 'none'; frame-ancestors 'none'`), nosniff, no-referrer, X-Frame-Options DENY.
- `POST auth/login {username,password,totp_code}`, `POST auth/logout`, `POST auth/logout-all`, `GET auth/me`, `POST auth/enroll`, `POST auth/enroll/confirm`
- `POST users {username,role}` (admin; viewer/operator only; returns `{invite:true}`)
- `GET actions` (catalog), `POST plans {action,params}` (operator; `user.*` admin), `POST plans/{id}/approve|reject` (approver), `GET plans`, `GET jobs`, `GET jobs/{id}`
  - `endpoint.register`, `user.create`, `user.set_role`: high risk (2 approvers). `inventory.refresh`: low risk, auto-approved, job queued at once.
- `GET users[?status&role&q]` (viewer+: status active/disabled/invited/locked/revoked, role + provenance, created_by, last_login_at, MFA, active sessions; `last_login_ip` admin only), `GET users/{id}` (recent auth events, role history, pending plans; sessions + addresses admin only), `GET invitations[?status=pending|expired|revoked]` (never returns tokens), `GET access-policy` (effective approval counts, session/lockout/MFA policy, role permission matrix; read-only)
- User-management plan actions (admin requests): `user.invite` (viewer/operator low, approver/admin **high** + mandatory justification), `user.revoke_invite` (low), `user.disable` / `user.enable` (normal; **high** for approver/admin targets), `user.revoke_sessions` (low), `user.set_role` (high); `user.create` remains as an alias. Nobody can target their own account, the last active admin is protected, and the target cannot decide the plan.
- `GET plans[?status&limit]` (adds `params_hash`, `requested_by_username`, `approval_count`, `approvers`, `approvals_required`), `GET jobs[?status&limit]`, `GET audit[?limit&before_seq]`, `auth/me` and login return the user `id`
- `GET endpoints`, `GET endpoints/{id}/inventory/refresh-state`, `GET endpoints/{id}/inventory`, `GET endpoints/{id}/inventory/snapshots` (viewer)
- `POST plans/preview {blueprint_yaml}` (operator) -> `{valid, errors}` or `{valid, plan}`; dry run only
- `GET audit`, `GET audit/verify` (approver)
- `GET /healthz`, `GET /readyz` (booleans only: database, worker heartbeat, audit tail check; 503 when not ready)

## Monitoring, alerting, node agent (slice 2)
All **mutations are typed plans** (catalog via `GET actions`); the views below are read-only (viewer):
`GET nodes|checks|checks/{id}/results|checks/{id}/remediation|incidents[?status=open|acked|recovered|active]|incidents/{id}|alert-channels|maintenance`.

| action | risk | notes |
|---|---|---|
| `check.create` | low | kinds `http`, `tcp_tls`, `imap_login`, `smtp_banner`, `ews_getfolder`; interval 15 s..24 h (30 s for credentialed kinds), at most 200 checks, 20 000 stored results per check; `fail_threshold` (flap damping), `recover_threshold`; optional `remediation` policy. TLS checks require exactly one trust anchor (CA bundle or SHA-256 pin) like Proxmox endpoints. Mailbox/EWS password is vault-encrypted with AAD bound to check id + config hash (changing the host in the DB makes it undecryptable). Destination guard as for endpoints |
| `check.bind_remediation`, `alert_channel.test`, `check.set_enabled` (enable), `maintenance.create` (one check, <= 60 min), `incident.ack` (first 5 per user per hour) | low | auto-approved, still plan + job + audit |
| `check.set_enabled` (disable), `incident.ack` beyond 5 per hour | **normal** (1 approver other than the requester) | alerting must not be silenced by one person (review M4); disabling a check with an open incident also notifies every channel |
| `maintenance.create` global (no `check_id`) or > 60 min (<= 8 h) | **high** (2 approvers) | start and end are announced on every channel and are never suppressed; at the end one summary of the suppressed alerts is sent and still-open incidents are re-notified |
| `alert_channel.create` | **high** (2 approvers) | `email` (SMTP relay: STARTTLS/implicit TLS verified by CA or pin; `tls=none` only with explicit `allow_plaintext`, never with credentials), `webhook` (https, HMAC-SHA256: `X-OU-Timestamp`, `X-OU-Signature: v1=hex(hmac(key, ts + "." + body))`, 5 min replay window), `pushover` and `sms`: interface + config validation only, **always disabled** (third-party paid services, ADR-0007: a plan with `enabled=true` is refused and `send` raises `ChannelDisabled`) |
| `node.enroll` | **high** | see node agent |
| `runbook.execute` | low, **high** for `service.restart mariadb` | `service.restart`, `service.status`, `disk.usage` only; ICS validates against the capabilities the agent reported at enrollment, the agent re-validates against its own root-owned allowlist |

**State machine** (worker thread, same loop as jobs): `unknown -> ok | warning | critical`. A bad state needs `fail_threshold` consecutive identical bad results, return to ok needs `recover_threshold` consecutive ok results. Results go to `check_results` (retention 14 days, pruned hourly). **Incidents** open on the first non-ok state (one active incident per check, enforced by a partial unique index), severity changes and recovery update the same incident; `ack` stops reminders; maintenance windows (global or per check) mark notifications `suppressed` and block remediation. Notifications go through a durable outbox (`notifications`): 5 attempts with exponential backoff, then `failed` (audited).
**Remediation policy** (per check): `{node_id, runbook, unit|path, mode auto|approval, max_attempts, window_seconds, backoff_seconds, verify_timeout_seconds}`. Starts when the check turns critical. Each attempt = a `runbook.execute` plan + job + audit; at most one in flight; exponential backoff; at most `max_attempts` per sliding window, then **escalation** (incident `escalated_at`, notification, audit), which is **terminal**: nothing more runs for that incident until a human acknowledges it (`incident.ack` re-arms, counting attempts from the acknowledgement) or the check recovers. Further bounds (review M1): a global budget of 3 `service.restart` per (node, unit) per hour across all checks, `backoff_seconds >= 30` and `window_seconds >= 300`, a pending approval of any age blocks a new attempt, and results tagged `cause: auth|config` (IMAP login rejected, EWS 401/403, bad config, missing/undecryptable secret) never trigger a restart (one notice per incident, audit `remediation.skipped`). A pending/queued remediation is **superseded** (plan rejected, queued job failed) when the check recovers or after 4 h, and `runbook.execute` re-checks that the check is still critical immediately before it acts, also at approval time (M3). `verify_timeout_seconds <= 45`; the job budget (180 s) covers agent deadline + verification. After the agent call the job re-runs the check until it is ok or `verify_timeout_seconds` passes and records `verified` true/false. High-risk runbooks (`mariadb` restart) cannot be `auto`: the policy creates a pending 2-approver plan instead.

### Node agent (`ics/agent/`, stdlib + `cryptography`)
- **Push model**: ICS -> `https://<node lab IP>:8443`. Lab machines cannot reach host services, and ICS keeps its API bound to 127.0.0.1, so there is no agent->ICS channel. Agent TLS cert is self-signed and **pinned by SHA-256** at enrollment; there is no client certificate: mutual authentication is application-layer Ed25519 inside TLS.
- **Enrollment**: on the node console `ou-agent init` generates the agent Ed25519 key + TLS cert and prints a one-time token (1 h, single use, stored hashed; wrong guesses throttle the source address (5 per 10 min, plus 0.5 s per guess) instead of burning the token) plus two fingerprints. The operator puts address, token and both fingerprints in a `node.enroll` plan (2 approvers). The job checks the TLS pin and that the agent public key matches the supplied fingerprint *before* sending the token, then sends the ICS public key; the agent stores it and replies with a response signed by its key. ICS records the agent public key. Re-enrolling needs a deliberate action on the node.
- **Requests** `{v, action, params, node_id, job_id, issued_at, expires_at, nonce}` signed Ed25519 (`ou-agent-req-v1\n` + canonical JSON). Agent: signature -> strict field/type check (no floats, unknown fields refused) -> node id -> window <= 120 s, expiry, future skew <= 120 s -> **nonce and job id recorded O_EXCL+fsync in a journal before anything runs** (survives restarts; a job id never runs twice) -> allowlist (exact string match of unit/path; params must be exactly `{unit}` or `{path}`) -> execute with `systemctl` argv (no shell). Responses to authenticated requests are signed by the agent key and must echo type/nonce/job/node; ICS rejects anything else. Requests that fail authentication (not enrolled, malformed, bad signature) get an unsigned `{"error": code}` and nothing from the request is echoed or signed. ICS also records each request in `agent_requests` (unique job id and nonce).
- **Privilege**: the agent runs as unprivileged user `ou-agent` (hardened unit: NoNewPrivileges, ProtectSystem=strict, empty capability set, ...). Its only privilege is a **polkit rule generated from the root-owned `/etc/ou-agent/agent.json`**: `restart` on exactly the allowlisted `*.service` units for user `ou-agent`; every other `org.freedesktop.systemd1.*` action is denied for that user (checked: `stop console-getty` -> Access denied). `status` needs no privilege. No sudo, no setuid. The allowlist is read from a root-owned file (the agent refuses to start if it is not root-owned or is group/world-writable).
- Install on a node (as root, on the node): `sh deploy/install-agent.sh <bind-ip> <hostname>`; the demo `scripts/lab_monitoring_demo.py` and `scripts/lab_agent_proofs.py` drive/prove it on `ou-gw1`.
- Limits: one agent exec at a time; request body 16 KiB; ICS response cap 64 KiB; no streaming output; `disk.usage` is the only non-service runbook. Jobs and the monitor loop (checks, notifications, identity reconcile) run on separate threads; every check has a hard wall-clock deadline equal to its `timeout_seconds` (sockets are closed, the runner thread is abandoned, at most 32 stuck at once), and the heartbeat is only written while both loops make progress (jobs: job timeout + 30 s; monitor: 300 s), so /readyz turns red on a stall. Checks connect to the address validated by the SSRF guard (no second DNS lookup); `Host`/SNI keep the name.

## Identity lifecycle (slice 3): provision -> change -> deprovision for one customer stack
Typed actions (all through plans; `GET actions` lists them). Details, measurements and gaps: `docs/status/user-lifecycle-results.md`.

| action | risk | notes |
|---|---|---|
| `idm.stack.register` | **high** (2 approvers) | wires one customer stack: LDAP (ldaps, CA-verified incl. hostname) + Keycloak realm + Gromox/OpenCloud nodes + probe settings. The LDAP bind password and the Keycloak client secret go to the vault (AAD = stack id + config hash: re-pointing the stack voids them). Hosts pass the SSRF guard at plan time and at use |
| `idm.user.create` | **normal** (1 approver, never the requester) | LDAP entry + groups; the directory's immutable `entryUUID` is recorded as the user's stable id (`idm_users`); Gromox mailbox sync (`externid = entryUUID`, verified); OpenCloud visibility check; one-time enrollment token. Refuses to adopt an unmanaged directory entry. Group changes touching `privileged_groups` make the plan **high** |
| `idm.user.update_groups` | normal (high for privileged groups) | add/remove members of allow-listed groups; entitlement change re-syncs Gromox; removals end the Keycloak SSO session so tokens do not keep old roles |
| `idm.user.disable` | normal | LDAP lock (+ optional credential rotation), Keycloak disable + logout + consent/offline-token revoke, Gromox suspend + **mailbox quarantine** (ends already-open IMAP sessions), then **VERIFY**: every credential path is probed once per second and the seconds until refusal are recorded (target <= 60 s). A path that stays valid FAILS the job loudly (the user stays disabled) |
| `idm.user.disable` options | `wipe_devices` (**high**, 2 approvers) + `wipe_wait_seconds` (0..300) | requests an ActiveSync remote wipe for ALL of the user's devices BEFORE anything else changes (a device can only receive it while it can still authenticate), optionally waits until the devices picked it up, records per device `wipe_pending -> wipe_delivered -> wiped_acknowledged`. Every disable also **revokes all OpenCloud app tokens** (before the lock; the user must still be resolvable) and sends a Gromox **USER-KICK** that closes the user's open IMAP sessions (patched gromox-imap, see `blueprints/build/gromox/patches/`). Measured: `docs/status/lifecycle-gaps-results.md` |
| `idm.user.devices` | low (read only) | the user's ActiveSync devices with wipe status and acknowledgement history |
| `idm.user.enable` | normal | unlock, Keycloak enable, Gromox reactivate + release; the old password is replaced by a random one and a NEW one-time enrollment is issued |
| `idm.user.delete` | **high** (2 approvers) | only after disable; LDAP entry + Keycloak user removed; **mailbox data is retained** (suspended, mode 0000; there is no purge action) so the uid/mail cannot be reused |
| `idm.reconcile` | low (read only) | compares LDAP <-> Keycloak <-> Gromox <-> OpenCloud for every managed user; also runs periodically per stack (`reconcile_interval_seconds`). **Reports only**: destructive drift (a disabled user that still has access, entryUUID swap, ...) is never auto-repaired |

Credentials are never broad: the stack uses `cn=svc-ics` (LDAP: write under `ou=people`, `member` of existing groups only, cannot read `userPassword`) and the Keycloak client `ou-ics` (service account: `manage-users`, `view-users`, `query-clients`; no realm admin). Gromox/OpenCloud are driven by the **node agent** with new fixed runbooks (`gromox.sync_user`, `gromox.kick_user`, `gromox.user_state`, `opencloud.check_user`): params exactly `{user: <lowercase uid>}`, started as `systemctl start --wait ou-rb-<name>@<uid>.service` (template units, root-owned helper that validates again); the polkit rule generated from the root-owned `agent.json` allows exactly those start verbs.
**No initial password exists.** `create`/`enable` issue a one-time enrollment token (24 h, 5 wrong guesses burn it, stored as sha256 + vault ciphertext). Only the plan's REQUESTER can `POST identity/enrollments/{plan_id}/reveal` (once; the ciphertext is wiped); the new user redeems it with `POST identity/enroll {stack, uid, token, password}` (unauthenticated, rate limited, one generic error) and chooses their own password. Tokens/passwords never reach audit, plans or job results (tested).
API additions: `GET identity/stacks|users|reconcile` (viewer), `POST identity/enrollments/{plan_id}/reveal` (operator), `POST identity/enroll`. Plan risk tier `normal` (migration 0005): approval by one approver who is not the requester.
Lab proof: `scripts/lab_user_lifecycle.py {setup|lifecycle|cleanup|all}`.

## Infrastructure (ADR-0009; details and status in `docs/status/provider-proxmox.md`)
`GET endpoints[/{id}]`, `GET infra/summary|clusters|nodes|storage|networks|guests|templates|metrics`, `POST setup/probe` (admin; `stage:'tls'` or full), `GET setup/state` (viewer).
Endpoint settings are typed plans: `endpoint.register|update|remove|disable|enable`. Provider code: `ics/providers/` (mutations only inside job execution), collectors: `ics/inventory/`. Tests use the stateful Proxmox simulator `tests/pve_sim.py` (a test double).

## Not implemented yet
- Any Proxmox mutation / deployment execution (only read-only inventory and dry-run preview exist); no mutation token handling.
- Separate privileged executor process (ADR-0001); the worker is an in-process thread (abandoned timed-out job threads cannot be killed, only prevented from committing).
- Off-host audit head export/checkpoint signing (see above).
- Password change, user disable endpoint, session listing UI; TLS termination (put a proxy in front and then set forwarded-allow-ips deliberately).
- Pin the DNS answer between the destination check and connect (TLS pin / CA+hostname verification covers rebinding for now).
- TOTP still accepts one step of clock skew in both directions.

## Lab demo credentials (review M5, accepted risk)
`scripts/lab_*.py` read the throwaway demo accounts' passwords/TOTP secrets (`lab-op`, `lab-ap1`, `lab-ap2`) from the file named by `OU_DEMO_CREDS`, default `/etc/office-unbound/lab/demo-creds.json` (to be `root:administrator 0640`, directory `root:administrator 0750`). The file is created `0600` atomically by the setup step; the host owner moves an existing `/tmp/ou-demo-creds.json` there. These accounts stay enrolled for approval testing: whoever can read the file can satisfy every two-person rule, so treat it like a root-equivalent secret and delete the accounts before any real use.
