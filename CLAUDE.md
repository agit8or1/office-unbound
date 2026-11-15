# Office Unbound — project instructions (keep short)

Open-source, self-hosted M365/Workspace alternative for MSPs. This host (192.168.22.167, Ubuntu 24.04) is the **ICS** (Infrastructure Control Server).

- Read `docs/status/STATUS.md` first (milestone, next tasks), then the relevant `docs/adr/`.
- Only contact infrastructure listed in `docs/status/authorized-endpoints.md`. No network scanning.
- Record every host-level change in `docs/status/host-changes.md`.
- ICS code: `ics/` (Python 3.12, FastAPI, SQLAlchemy 2, Alembic, PostgreSQL 16). Tests: `cd ics && .venv/bin/pytest`.
- Never print secrets. Never disable TLS verification. No arbitrary command/shell APIs; mutations are typed actions → approval → durable job → hash-chained audit.
- A test/feature is "passing"/"working" only with executed evidence. Use status values from ADR-0000.
- `reference/` holds read-only shallow clones of agit8or1 repos (gitignored). Don't modify them.
