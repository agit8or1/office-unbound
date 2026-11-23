# Office Unbound administrator guide

> **Alpha (0.10.0 "Juniper"). Not for production data** ([SECURITY.md](../../SECURITY.md)). The full stack installs and deploys onto a
> real Proxmox node and is reachable from the internet; this was run on one reference installation. Start with the
> [Alpha install guide](alpha-install.md) and [Known limitations](known-limitations.md). Pages below cite the evidence for each procedure
> and label anything not proven; some older pages describe the lab stage and say so.

This guide is for a new MSP engineer. You do not need the project chat history. Read the pages in the order below; each one says what you need first.

## How features are labelled
The labels are the project's own status values (`docs/progress.json`, [ADR-0000](../adr/0000-status-values.md)). They are the same words as in [ROADMAP.md](../../ROADMAP.md).

| Label | Meaning in this guide |
|---|---|
| **Tested** | Implemented, with automated tests that were executed. This is the "implemented and tested" level. |
| **Integrated in lab** | Run end to end in the lab with evidence, but not on production infrastructure. |
| **Implementing** | Code exists, but it is not proven end to end. Do not rely on it. |
| **Planned** | Not built. Never rely on it. |

"Simulator-proven" means it ran only against a test double of Proxmox. Treat it as **Implementing** until a real cluster run is recorded.

## Reading order
| # | Page | You will be able to | Label of what it covers |
|---|---|---|---|
| 0 | [Alpha install guide](alpha-install.md) | Install the alpha end to end: ICS, Proxmox, image, deployment, public names, certificate, people | Integrated on the reference installation |
| 1 | [Glossary](glossary.md) | Read the rest of the guide (plan, approval, job, endpoint, agent, profile, drift) | n/a |
| 2 | [Quick start](quick-start.md) | Go from a fresh host to "Proxmox connected" in one sitting | Integrated in lab |
| 3 | [Installing the ICS](installing-the-ics.md) | Install, TLS, first login with TOTP, first-run accounts, uninstall (reference) | Integrated in lab |
| 4 | [Connecting Proxmox](connecting-proxmox.md) | Create the Proxmox tokens, choose Mode A or B, choose single-node or whole-cluster scope, rotate tokens, change scope later | Integrated in lab (manual path); Implementing (Mode A/B, scope change, rotation actions) |
| 5 | [Customers and approvals](customers-and-approvals.md) | Create customers, set approval policies, scope operators, invite approvers, use customer approval links | Tested; not run on a real cluster |
| 6 | [Deploying a customer environment](deploying-a-customer.md) | Use the wizard, review the plan, get approvals, understand each step, fix failures | Implementing (one real run in the lab) |
| 7 | [Day-2 operations](day-2-operations.md) | Monitor, handle incidents, run backups and restore drills, manage users, use break-glass | Integrated in lab |
| 8 | [Upgrades and rollback](upgrades.md) | Upgrade the ICS from a release; upgrade and roll back signed packages on a node | Integrated in lab |
| 9 | [ICS recovery and warm standby](ics-recovery-and-standby.md) | Restore the controller, or run a standby and promote it | Restore: Integrated in lab. Standby: integrated in lab |
| 10 | [Security model](security-model.md) | Explain the security design to a customer; do the owner actions | Tested |
| 11 | [Known limitations](known-limitations.md) | Know what not to promise | n/a |

Reference pages (use when needed): [Operating the ICS](operating-the-ics.md) (console, plans, monitoring checks, remediation, removal actions),
[Users and access](users-and-access.md) (operator accounts, customer users and revocation gaps), [Backup and restore](backup-and-restore.md) (per-tier scripts and the backup product),
[Security (technical)](security.md), [Troubleshooting](troubleshooting.md), [Lab-proven components](lab-proven-components.md), [Mail migration](migration.md).
Runbooks: [ICS recovery](../runbooks/ics-recovery.md), [provider access recovery](../runbooks/provider-access-recovery.md). Release procedure: [RELEASING.md](../RELEASING.md).

## The parts of the product
| Part | What it does | Label |
|---|---|---|
| **ICS** (Infrastructure Control Server) | Web console and API. You plan, approve and run typed actions. Monitoring, alerts, bounded self-healing, customer user lifecycle, Proxmox inventory. No LLM. | Tested ([ics-installer-results.md](../status/ics-installer-results.md)) |
| **Node agent** (`ou-agent`) | Small unprivileged service on managed machines. Runs only fixed, signed, allow-listed runbooks. | Integrated in lab |
| **Proxmox provider** | Reads inventory and runs scoped VM actions (clone, configure, resize, power, snapshot, destroy) | Integrated in lab ([provider-proxmox-real.md](../status/provider-proxmox-real.md)) |
| **Deployment engine and wizards** | Builds a customer plan, shows it, runs it after approval | Implementing ([deployment-engine.md](../status/deployment-engine.md), [first-real-deployment.md](../status/first-real-deployment.md)) |
| **Customer stack** (one isolated stack per customer, [ADR-0006](../adr/0006-deployment-model.md)) | OpenLDAP + Keycloak, Gromox mail, OpenCloud files, Collabora documents | Integrated in lab; isolation of two stacks tested ([tenant-isolation-results.md](../status/tenant-isolation-results.md)) |
| **Chat, meetings, telephony** | Matrix/Jitsi, Asterisk softphone | Integrated in lab; not deployable by the ICS |
| **Mail migration** | Read-only assessment, IMAP mailbox mover | Implementing (assessment), Integrated in lab (mover, command line) |

## Rules that apply everywhere
- Every change is **typed action, plan, approval, single-use job, audit**. There is no free-form command box. High-risk plans need two approvers, and the requester is never one of them ([ADR-0002](../adr/0002-ics-security-model.md)).
- Never paste a secret (token, password, key) into chat, tickets or shell history. Enter secrets only in the console forms.
- Take a backup before any upgrade or restore ([Backup and restore](backup-and-restore.md)).
- Check this folder's links and cited commands with `python3 scripts/check_doc_links.py` (also run in CI).
