# Office Unbound ICS (backend)

FastAPI + SQLAlchemy 2 + Alembic + PostgreSQL 16. Typed actions -> approval -> durable job -> hash-chained audit (ADR-0001/0002).

## Setup
```
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt   # versions pinned
```
### Postgres (one-time, as postgres superuser; passwords go only in the env file)
Roles `ics_owner` (owns the DB, runs migrations) and `ics_app` (runtime). Databases `ics` and `ics_test`.
```
CREATE ROLE ics_owner LOGIN PASSWORD '...'; CREATE ROLE ics_app LOGIN PASSWORD '...';
CREATE DATABASE ics OWNER ics_owner; REVOKE ALL ON DATABASE ics FROM PUBLIC; GRANT CONNECT ON DATABASE ics TO ics_app;
```
Migrations (as owner): `.venv/bin/alembic upgrade head`. Migration 0001 grants `ics_app` SELECT/INSERT only on `audit_events`
(no UPDATE/DELETE/TRUNCATE) - tested.

### Config: `/etc/office-unbound/ics.env` (root:administrator 0640; override path with `ICS_ENV_FILE`; real env vars win)
| key | meaning |
|---|---|
| `ICS_DATABASE_URL` | runtime URL as `ics_app` (`postgresql+psycopg://...`, scram-sha-256 over 127.0.0.1) |
| `ICS_MIGRATE_DATABASE_URL` | owner URL, used only by Alembic/tests |
| `ICS_VAULT_KEY_FILE` | file with exactly 32 raw bytes (AES-256 key); dev key `/etc/office-unbound/vault.key`. In production make it root-owned and readable only by the ICS service user. Losing it loses all stored secrets. |
| `ICS_COOKIE_SECURE` (default true) | session cookie `Secure`; keep true behind TLS |
| `ICS_WORKER_ENABLED` (default true) | run the in-process job worker thread |

## Run
```
.venv/bin/python -m ics.cli create-admin --username admin      # prompts for password; prints TOTP URI once
.venv/bin/uvicorn ics.main:create_app --factory --host 127.0.0.1 --port 8088
.venv/bin/python -m ics.cli verify-chain                       # exit 1 if the audit chain is broken
```
Interactive OpenAPI: `/docs`. Tests (real Postgres `ics_test`, schema is dropped and rebuilt by the suite): `.venv/bin/pytest`.

## API summary (`/api/v1`, JSON)
Auth is a cookie `ics_session` (HttpOnly, Secure, SameSite=Strict) + `X-CSRF-Token` header (returned by login / `auth/me`) on every non-GET.
Roles: viewer < operator < approver < admin.
- `POST auth/login {username,password,totp_code}`, `POST auth/logout`, `GET auth/me`, `POST users` (admin; returns TOTP URI once)
- `GET actions` (catalog), `POST plans {action,params}` (operator), `POST plans/{id}/approve|reject` (approver, not the requester), `GET plans`, `GET jobs`, `GET jobs/{id}`
  - `endpoint.register` high risk: needs approval. `inventory.refresh` low risk: auto-approved, job queued at once.
- `GET endpoints`, `GET endpoints/{id}/inventory`, `GET endpoints/{id}/inventory/snapshots` (viewer)
- `POST plans/preview {blueprint_yaml}` (operator) -> `{valid, errors}` or `{valid, plan}`; dry run only
- `GET audit`, `GET audit/verify` (approver)
- `GET /healthz`, `GET /readyz` (DB query + worker heartbeat + audit chain tail check; 503 when not ready)

## Not implemented yet
- Any Proxmox mutation / deployment execution (only read-only inventory and dry-run preview exist); no mutation token handling.
- Separate privileged executor process (ADR-0001); the worker is an in-process thread. Jobs left `running` by a crash are not recovered.
- Two-approver rule for high-risk actions (ADR-0002 item 5); currently one approver other than the requester.
- Off-host audit head export/checkpoint signing (tail truncation of the audit table is undetectable from the DB alone).
- Password change/reset, TOTP re-enrollment, user disable/list endpoints, session listing/revocation UI.
- Login rate limit is per username/IP in Postgres; no reverse-proxy `X-Forwarded-For` handling. No TLS termination in the app.
- Plan expiry window, snapshot retention, readiness check of Proxmox endpoints, the UI.
