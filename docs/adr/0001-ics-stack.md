# ADR-0001 ICS implementation stack
Status: Accepted (2026-11-15)
Decision: Python 3.12 + FastAPI + SQLAlchemy 2 + Alembic + PostgreSQL 16 (native, localhost) for the ICS API; small Vue 3 + Vite SPA served by the API. Single repo `office-unbound`, one ICS service process plus a separate privileged-action executor process (later). No Kubernetes, no microservices.
Why: matches Depl0y (FastAPI/SQLAlchemy/proxmoxer) so its read-only inventory code can be adapted; Postgres gives durable jobs/audit; minimal moving parts for an SMB/MSP controller. See docs/status/reuse-audit-ics.md.
