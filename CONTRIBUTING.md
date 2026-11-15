# Contributing

Thanks for your interest. Office Unbound is in early lab development; the architecture and component choices are recorded in `docs/adr/` and `docs/ARCHITECTURE.md`. Please open an issue to discuss larger changes first.

## Ground rules
- **Zero-cost, unrestricted** (ADR-0007): do not add dependencies that require paid licenses, subscriptions, external paid APIs or impose user/connection limits. Every new third-party component needs an entry in `docs/status/third-party-inventory.md` with its actual source license.
- **Evidence over claims**: a feature or test is "working" only with executed evidence. Do not mark tests as passing that were skipped.
- **Security**: no arbitrary command/shell execution paths, no disabled TLS verification, no secrets in code, logs or tests. Report vulnerabilities privately (see `SECURITY.md`).
- Tests: `cd ics && .venv/bin/pytest`; frontend: `cd ics/frontend && npm test && npm run typecheck`.

## Developer Certificate of Origin (DCO)
By contributing you certify the [Developer Certificate of Origin 1.1](https://developercertificate.org/): that you wrote the contribution or otherwise have the right to submit it under the project's license. Sign off every commit:

```
git commit -s -m "Your message"
```
which adds `Signed-off-by: Your Name <you@example.com>`.

## License
Contributions are accepted under the project license, **GNU AGPL-3.0** (`LICENSE`). No CLA is required.
