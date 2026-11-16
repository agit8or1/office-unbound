# Day-2 operations

Label: **Integrated in lab** (monitoring, incidents, remediation, backup and restore drills, user lifecycle), unless a row says otherwise. Not run against production.
This page is a checklist that points to the detailed pages. Read [Operating the ICS](operating-the-ics.md) once for the console and the plan flow.

## Daily and weekly routine
| When | Do | How |
|---|---|---|
| Daily | Look at the Overview dashboard: health, incidents, pending approvals | Console **Overview**; `GET /readyz` reports database, worker heartbeat and audit tail |
| Daily | Decide pending plans (do not let them expire: 7 days) | **Approvals** |
| Weekly | Verify the audit chain | `cd /opt/office-unbound/ics && sudo -u ics .venv/bin/python -m ics.cli verify-chain` (exit 1 means a break). There is no built-in scheduler; use your own cron |
| Weekly | Confirm a recent ICS backup exists and copy it off the host | `sudo ics/deploy/backup/ics-backup.sh` |
| Monthly | Restore drill for at least the ICS and one customer tier | [section 3](#3-backups-and-restore-drills) |
| After any exposure of a secret | Rotate it | [Connecting Proxmox](connecting-proxmox.md), [Security model](security-model.md) |

## 1. Monitoring and incidents
Checks are typed plans (`check.create`): kinds `http`, `tcp_tls`, `imap_login`, `smtp_banner`, `ews_getfolder`, and `backup` kinds. One incident is open per check; it opens on the first non-ok state and closes on recovery. Acknowledge with `incident.ack`. Alerts go to the channels you created with `alert_channel.create` (email with verified TLS and signed webhooks work; Pushover and SMS are disabled by design, ADR-0007). Test a channel with `alert_channel.test`.
Planned maintenance: `maintenance.create` (one check and up to 60 minutes is low risk; global or longer is high risk). Details, limits and the remediation safety rules: [Operating the ICS](operating-the-ics.md). Evidence: [ics-monitoring-results.md](../status/ics-monitoring-results.md).
Self-healing is bounded: only `service.restart`, `service.status` and `disk.usage` runbooks, only on units in the node's root-owned allowlist, with attempt limits and terminal escalation to a human. If an incident says "escalated", a person must act; the ICS will not try again.
Proxmox drift and token failures raise alerts once per transition ([Connecting Proxmox](connecting-proxmox.md)). Credentials raise an alert 14 days before expiry.

## 2. Node agents
Enrolling a node is a high-risk plan (`node.enroll`). On the node, as root: `sh ics/agent/deploy/install-agent.sh <bind-ip> <hostname>`, then `ou-agent init` prints a one-time token and two fingerprints for the plan. Keep node clocks in sync: requests outside their validity window are rejected. Retire a node with `node.decommission`. Rotating the ICS signing key means re-enrolling agents.

## 3. Backups and restore drills
Four tiers exist. Scripts, timings and what each drill proved are in [Backup and restore](backup-and-restore.md).
| Tier | Backup | Label |
|---|---|---|
| ICS controller | `sudo ics/deploy/backup/ics-backup.sh` | Integrated in lab (restored to a fresh machine, audit chain verified) |
| Identity | `blueprints/lab/backup/id-backup.sh <machine>` | Integrated in lab |
| Files | `blueprints/lab/backup/files-backup.sh <machine>` | Integrated in lab |
| Groupware | `blueprints/lab/backup/gw-backup.sh <machine>` | Integrated in lab |
| Scheduled, encrypted, verified backups (the backup product, ADR-0010) | `backup.policy.create` plan, runner node `ou-backup` | Integrated in lab (the ICS tier itself was not run) |
A backup is not real until it was restored. Restore to a **new** machine (the scripts refuse an existing one), then check the counts in the MANIFEST and log in. The lab scripts act on the lab's nspawn machines; production per-customer backup orchestration does not exist yet (**Planned**).
Keep an offline copy of `vault.key`: without it every stored secret is lost, even though the backups themselves restore. The backup product also has an offline recovery key procedure (step 4 of "Operating it" in [Backup and restore](backup-and-restore.md)).
Evidence: [restore-drill-results.md](../status/restore-drill-results.md), [backup-product-results.md](../status/backup-product-results.md).

## 4. Upgrades and rollback
See [Upgrades and rollback](upgrades.md). Always take and verify a backup first.

## 5. User lifecycle
| Population | Create | Remove access | Label |
|---|---|---|---|
| ICS operators | `user.invite`, then `issue-enrollment` on the host ([Customers and approvals](customers-and-approvals.md)) | `user.disable` (plan), `user.revoke_sessions` | Tested |
| Customer users (mail, files, SSO) | `idm.user.create` (no initial password; one-time enrollment token) | `idm.user.disable` (locks LDAP, ends Keycloak sessions, suspends the mailbox, then probes every path), later `idm.user.delete` | Integrated in lab |
Use the ICS action to disable a customer user, never only an LDAP lock: an LDAP lock alone did not end Keycloak sessions for more than 7 minutes. Read the "Known revocation gaps" in [Users and access](users-and-access.md) before promising a customer instant revocation. Mailbox purge and export are **Planned**.

## 6. Break-glass: disable an operator when approvals cannot work
Use only when the normal `user.disable` plan cannot be approved (no second approver, a compromised approver). Needs root on the ICS host:
```
cd /opt/office-unbound/ics && sudo -u ics .venv/bin/python -m ics.cli disable-user --username <name> --reason "<why, at least 10 characters>"
```
It refuses to disable the last active admin, ends the account's sessions, and records `user.disabled.break_glass` (actor `cli`) in the audit chain. Re-enable through the normal `user.enable` plan. Other host-root recovery commands:
| Need | Command |
|---|---|
| Login throttled | `cd /opt/office-unbound/ics && sudo -u ics .venv/bin/python -m ics.cli unlock --username <name>` |
| Lost password or authenticator | `... -m ics.cli issue-enrollment --username <name>` (resets password, TOTP and sessions) |
| No admin left | `... -m ics.cli create-admin --username <name> --role admin` |
All of these are audited as actor `cli`. Anyone with root on the ICS host can do them; that cannot be prevented ([Security model](security-model.md)).
If access to a customer's Proxmox breaks (expired token, revoked access, lost vault key): [provider access recovery](../runbooks/provider-access-recovery.md).

## 7. When the ICS itself is down
Customer stacks do not depend on the ICS at runtime: mail, files, editing and SSO keep working. Only management pauses. Follow [ICS recovery and warm standby](ics-recovery-and-standby.md).
