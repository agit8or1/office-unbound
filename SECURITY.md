# Security policy

Office Unbound is **alpha software** (0.10.0). It is not supported for production use and has no supported releases yet; open findings and their state are in [docs/status/SECURITY-REMEDIATION.md](docs/status/SECURITY-REMEDIATION.md).

## Reporting a vulnerability
Please report vulnerabilities **privately** through GitHub's private vulnerability reporting:
**Security → Report a vulnerability** on this repository (https://github.com/agit8or1/office-unbound/security/advisories/new).

Do not open public issues for security problems. Include affected component/commit, reproduction steps and impact. We aim to acknowledge reports within 5 business days.

## Scope
- Office Unbound's own code: `ics/` (control server, console, node agent), `blueprints/` (deployment, backup/restore, build recipes).
- Vulnerabilities in upstream components (gromox/grommunio, Collabora Online, OpenCloud, Keycloak, OpenLDAP, …) should go to their upstream projects; tell us too if Office Unbound's integration makes them exploitable.

## Our own reviews
Independent security reviews and their remediation status are published in `docs/status/security-review-*.md`. Open findings are listed there — we do not hide them.
