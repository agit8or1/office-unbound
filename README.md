# Office Unbound

Open-source, self-hosted alternative to Microsoft 365 / Google Workspace for businesses and MSPs — with **zero mandatory third-party licensing cost and no artificial user limits** ([ADR-0007](docs/adr/0007-zero-cost-unlimited.md)).

**Status: alpha (0.10.0 "Juniper", 2026-11-23).** Installable from the release tag and deploys the full stack (sign-in, portal, mail, calendar, contacts, files, documents) onto your own Proxmox VE, reachable from the internet with a trusted certificate; proven on one reference installation. Not for production data: start with the [alpha install guide](docs/admin/alpha-install.md) and the [known limitations](docs/admin/known-limitations.md). Public roadmap & progress: [ROADMAP.md](ROADMAP.md) (machine-readable: [docs/progress.json](docs/progress.json)). Engineering status: [docs/status/STATUS.md](docs/status/STATUS.md). Architecture: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

- `ics/` — Infrastructure Control Server (FastAPI + PostgreSQL + Vue console, node agent)
- `blueprints/lab/` — lab deployment scripts, acceptance tests, backup/restore drills
- `blueprints/build/` — source-build recipes for components we distribute ourselves
- `docs/` — ADRs, evaluations, test evidence, security reviews

## Documentation
- [Alpha install guide](docs/admin/alpha-install.md) (empty host to people signing in) and [known limitations](docs/admin/known-limitations.md)
- [Administrator guide](docs/admin/index.md): [quick start](docs/admin/quick-start.md), install, connect Proxmox, operate, back up and secure the ICS, [glossary](docs/admin/glossary.md) (only procedures executed in the lab; the rest marked Planned / In development)
- [Architecture](docs/ARCHITECTURE.md), [ADRs](docs/adr/), [status](docs/status/STATUS.md)

## License
Office Unbound's own code is licensed under the **GNU Affero General Public License v3.0** ([LICENSE](LICENSE)). Third-party components keep their own licenses; see [docs/status/third-party-inventory.md](docs/status/third-party-inventory.md).
