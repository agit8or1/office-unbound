# Office Unbound administrator guide

> **Status: pre-alpha lab software. Not for production use** (see [SECURITY.md](../../SECURITY.md)). Everything in this guide was
> executed in the lab (isolated systemd-nspawn machines on the ICS host, one real Proxmox node) unless a section says
> **Planned** or **In development**. Each procedure cites the evidence document that records its execution. If a step has no
> evidence, it is marked. Nothing here has been run against a production tenant or a multi-host customer deployment.

Office Unbound is a self-hosted collaboration suite (mail/calendar, files, documents, SSO) with a control plane for MSPs and
businesses. The constraint behind every design choice is ADR-0007: no mandatory third-party licence cost and no artificial user limits.

**New here?** Start with the [Quick start](quick-start.md) and keep the [Glossary](glossary.md) open.

## Components
| Part | What it does | Lab status (evidence) |
|---|---|---|
| **ICS** (Infrastructure Control Server) | FastAPI + PostgreSQL + Vue console. Operators plan, approve and run typed actions; monitoring, alerts, bounded remediation; customer user lifecycle; Proxmox inventory. Deterministic, no LLM. | Tested; one-command installer proven on two fresh machines ([ics-installer-results.md](../status/ics-installer-results.md)); test counts in [STATUS.md](../status/STATUS.md) |
| **Node agent** (`ou-agent`) | Unprivileged daemon on managed nodes; runs only fixed, signed, allow-listed runbooks | Verified in lab ([ics-monitoring-results.md](../status/ics-monitoring-results.md)) |
| **Proxmox provider** | Read-only inventory plus scoped VM lifecycle (clone, configure, resize, power, snapshot, destroy) | Lifecycle run once against a real PVE 9.2 node ([provider-proxmox-real.md](../status/provider-proxmox-real.md)); see [Connecting Proxmox](connecting-proxmox.md) |
| **Deployment engine + wizards** | Plans a customer stack, shows it, runs it after approval | **In development**: no real end-to-end deployment yet ([deployment-engine.md](../status/deployment-engine.md)) |
| **Customer stack** (one isolated stack per customer, ADR-0006) | OpenLDAP + Keycloak, Gromox mail (own source build), OpenCloud files, Collabora documents | Integrated in lab; see [Lab-proven components](lab-proven-components.md) |
| **Chat, meetings, telephony, migration** | Matrix/Jitsi, Asterisk softphone, mail migration | Lab prototypes only; not deployable by the ICS ([Lab-proven components](lab-proven-components.md)) |

The lab topology is **not** the intended production topology: customer stacks run in nspawn machines on the ICS host ([Known limitations](known-limitations.md)).

## Pages
1. [Quick start](quick-start.md) - fresh Ubuntu 24.04 host to "Proxmox connected"
2. [Glossary](glossary.md) - plan, approval, job, endpoint, node agent, deployment, profile, drift
3. [Installing the ICS](installing-the-ics.md) - the one-command installer, accounts, upgrade, uninstall
4. [Connecting Proxmox](connecting-proxmox.md) - least-privilege setup, endpoint settings, node allowlist, protected ICS VM
5. [Operating the ICS](operating-the-ics.md) - console tour, plans, deployments, monitoring, remediation, roadmap feed
6. [Users and access](users-and-access.md) - operators, privileged-access workflow, break-glass, customer users
7. [Backup and restore](backup-and-restore.md) - the drilled procedures and what they do not cover
8. [Lab-proven components](lab-proven-components.md) - webmail SSO, chat/meetings, telephony, Office Unbound Docs, migration
9. [Security](security.md) - what is enforced where, secrets, audit verification
10. [Troubleshooting](troubleshooting.md) - real issues found in the lab
11. [Known limitations](known-limitations.md)

Conventions: **Verified** = executed, evidence cited. **Planned** = not implemented, never to be relied on. **In development** = code
exists but is not proven end to end.
