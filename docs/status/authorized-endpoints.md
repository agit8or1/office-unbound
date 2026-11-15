# Authorized endpoints (no secrets here)

| Endpoint | Purpose | Access level | Authorized | Notes |
|---|---|---|---|---|
| localhost (ICS host) | development, PostgreSQL 127.0.0.1:5432 | local | 2026-11-15 | |
| Proxmox (TBD) | read-only inventory | PVEAuditor token | **not yet** | User deferred; build against fixtures |
| Proxmox pool `ou-lab` (TBD) | isolated lab VMs for spikes | pool-scoped VM token | **approved in principle, not configured** | see proxmox-setup.md |

Anything not listed here must not be contacted.
