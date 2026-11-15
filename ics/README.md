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
- `GET endpoints`, `GET endpoints/{id}/inventory`, `GET endpoints/{id}/inventory/snapshots` (viewer)
- `POST plans/preview {blueprint_yaml}` (operator) -> `{valid, errors}` or `{valid, plan}`; dry run only
- `GET audit`, `GET audit/verify` (approver)
- `GET /healthz`, `GET /readyz` (booleans only: database, worker heartbeat, audit tail check; 503 when not ready)

## Not implemented yet
- Any Proxmox mutation / deployment execution (only read-only inventory and dry-run preview exist); no mutation token handling.
- Separate privileged executor process (ADR-0001); the worker is an in-process thread (abandoned timed-out job threads cannot be killed, only prevented from committing).
- Off-host audit head export/checkpoint signing (see above).
- Password change, user disable/list endpoints, session listing UI; TLS termination (put a proxy in front and then set forwarded-allow-ips deliberately).
- Pin the DNS answer between the destination check and connect (TLS pin / CA+hostname verification covers rebinding for now).
- TOTP still accepts one step of clock skew in both directions.
