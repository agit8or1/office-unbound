# Authorized endpoints (no secrets here)

| Endpoint | Purpose | Access level | Authorized | Notes |
|---|---|---|---|---|
| localhost (ICS host) | development, PostgreSQL 127.0.0.1:5432 | local | 2026-11-15 | |
| Proxmox (TBD) | read-only inventory | PVEAuditor token | **not yet** | User deferred; build against fixtures |
| Proxmox pool `ou-lab` (TBD) | isolated lab VMs for spikes | pool-scoped VM token | **approved in principle, not configured** | see proxmox-setup.md |
| Public package/source registries: PyPI, npm registry, deb.debian.org / archive.ubuntu.com, deb.nodesource.com, cli.github.com, github.com (public repos), Collabora/Keycloak/OpenCloud release downloads, OSV/PyPA advisory DB | dependency fetch, release checks, vuln lookups | anonymous read | 2026-11-15 | no credentials sent; lab machines egress via zone `oulab` |
| Lab machines in nspawn zone `oulab` (192.168.202.0/24-ish, ou-* machines on this host) | integration spikes | full (lab) | 2026-11-15 | Proxmox out of scope until owner says otherwise |

Anything not listed here must not be contacted.
