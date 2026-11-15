# Authorized endpoints (no secrets here)

| Endpoint | Purpose | Access level | Authorized | Notes |
|---|---|---|---|---|
| localhost (ICS host) | development, PostgreSQL 127.0.0.1:5432 | local | 2026-11-15 | |
| Proxmox pve06 `https://192.168.22.17:8006` (PVE 9, cert CN pve06.agit8or.net, PVE cluster CA) | inventory + provisioning in pool `officeunbound-pve06`, storage `PVE06-Storage`, VM 126 | token `officeunbound@pam!ics` (privsep; pool/storage/node-scoped ACLs) | **2026-11-15 (owner)** | TLS fingerprint AD:51:9B:27:…:B1:CA pending owner out-of-band confirmation before first authenticated call; no SDN.Use yet; secret root-only at /etc/office-unbound/bootstrap/ — rotate (was pasted in chat) |

| Public package/source registries: PyPI, npm registry, deb.debian.org / archive.ubuntu.com, deb.nodesource.com, cli.github.com, github.com (public repos), Collabora/Keycloak/OpenCloud release downloads, OSV/PyPA advisory DB | dependency fetch, release checks, vuln lookups | anonymous read | 2026-11-15 | no credentials sent; lab machines egress via zone `oulab` |
| Lab machines in nspawn zone `oulab` (192.168.202.0/24-ish, ou-* machines on this host) | integration spikes | full (lab) | 2026-11-15 | Proxmox out of scope until owner says otherwise |

Anything not listed here must not be contacted.
