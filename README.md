# Office Unbound

Open-source, self-hosted alternative to Microsoft 365 / Google Workspace for businesses and MSPs — with **zero mandatory third-party licensing cost and no artificial user limits** ([ADR-0007](docs/adr/0007-zero-cost-unlimited.md)).

**Status: pre-alpha lab work.** Nothing here is production ready. Public roadmap & progress: [ROADMAP.md](ROADMAP.md) (machine-readable: [docs/progress.json](docs/progress.json)). Engineering status: [docs/status/STATUS.md](docs/status/STATUS.md). Architecture: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

- `ics/` — Infrastructure Control Server (FastAPI + PostgreSQL + Vue console, node agent)
- `blueprints/lab/` — lab deployment scripts, acceptance tests, backup/restore drills
- `blueprints/build/` — source-build recipes for components we distribute ourselves
- `docs/` — ADRs, evaluations, test evidence, security reviews

## License
Office Unbound's own code is licensed under the **GNU Affero General Public License v3.0** ([LICENSE](LICENSE)). Third-party components keep their own licenses; see [docs/status/third-party-inventory.md](docs/status/third-party-inventory.md).
