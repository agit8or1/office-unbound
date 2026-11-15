# Office Unbound administrator guide

> **Status: pre-alpha lab software. Not for production use** (see [SECURITY.md](../../SECURITY.md)). Everything in this guide was
> executed in the lab (isolated systemd-nspawn machines on the ICS host, one real Proxmox node, read-only) unless a section says
> **Planned** or **In development**. Each procedure cites the evidence document that records its execution. If a step has no
> evidence, it is marked. Nothing here has been run against a production tenant or a multi-host customer deployment.

Office Unbound is a self-hosted collaboration suite (mail/calendar, files, documents, SSO) with a control plane for MSPs and
businesses. The constraint behind every design choice is ADR-0007: no mandatory third-party licence cost and no artificial user limits.

## Components
| Part | What it does | Lab status (evidence) |
|---|---|---|
| **ICS** (Infrastructure Control Server) | FastAPI + PostgreSQL + Vue console. Operators plan, approve and run typed actions; monitoring, alerts, bounded remediation; customer user lifecycle. Deterministic, no LLM. | Tested (268 passing at last merge per git log; older counts in [STATUS.md](../status/STATUS.md), [ics/README.md](../../ics/README.md)) |
| **Node agent** (`ou-agent`) | Unprivileged daemon on managed nodes; runs only fixed, signed, allow-listed runbooks | Verified in lab ([ics-monitoring-results.md](../status/ics-monitoring-results.md)) |
| **Customer stack** (one isolated stack per customer, ADR-0006) | OpenLDAP + Keycloak (identity/SSO), Gromox stack (mail, own source build), OpenCloud (files), Collabora (documents) | Integrated in lab; Collabora own build still Implementing ([ARCHITECTURE.md](../ARCHITECTURE.md)) |
| **User portal** | Keycloak OIDC launcher, device onboarding | Lab e2e only ([portal-results.md](../status/portal-results.md)) |
| **Migration assessment** | Read-only M365/Google readiness report | Fixture-tested only; never run against a real tenant ([migration-assessment.md](../status/migration-assessment.md)) |

The lab topology is **not** the intended production topology: customer stacks run in nspawn machines on the ICS host, and Proxmox
integration is read-only so far ([Known limitations](known-limitations.md)).

## Pages
1. [Installing the ICS](installing-the-ics.md) - host install, TLS front end, first admin, roles, approvals
2. [Connecting Proxmox](connecting-proxmox.md) - least-privilege roles, fingerprint check, token rotation
3. [Operating the ICS](operating-the-ics.md) - plans, jobs, monitoring, incidents, remediation, maintenance, alerts
4. [Users and access](users-and-access.md) - ICS operators and customer users
5. [Backup and restore](backup-and-restore.md) - the drilled procedures and what they do not cover
6. [Security](security.md) - what is enforced where, secrets, audit verification
7. [Troubleshooting](troubleshooting.md) - real issues found in the lab
8. [Known limitations](known-limitations.md)

Conventions: **Verified** = executed, evidence cited. **Planned** = not implemented, never to be relied on. **In development** = code
exists but is not proven end to end.
