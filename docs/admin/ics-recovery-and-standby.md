<!-- pending: ics/deploy/standby/ics-standby-prepare-primary.sh, ics/deploy/standby/ics-promote.sh, ics/deploy/standby/ics-standby-status.sh, docs/adr/0012-ics-warm-standby.md, docs/status/ics-standby-results.md, controller-status -->
# ICS recovery and warm standby

The ICS is not on the customers' data path: mail, files, editing and SSO keep running while it is down. Only management (approvals, monitoring, deployments) pauses. You still must be able to replace it. There are two ways.
| Method | Data loss (RPO) | Time to take over | Label |
|---|---|---|---|
| **Restore from backup** to a new host, then a deliberate cut-over | age of the last backup | minutes to rebuild, plus your decision time | Integrated in lab (restored on two machines, audit chain verified) |
| **Warm standby** with fenced promotion | replication lag (under 1 ms observed in the lab) | 3.1 s to promote, 4.4 s to the first signed request through the new primary (lab, one node) | **On branch `integration-6`, pending merge into main.** Integrated in lab on that branch. Not available in a main-branch install yet |
Replication copies corruption and deletions too. Keep the backups even with a standby.

## 1. Back up the controller
```
sudo ics/deploy/backup/ics-backup.sh
```
Contents: the database (`pg_dump`) and the two database roles, `/etc/office-unbound/` env files and the three keys (`vault.key`, `audit.key`, `ics-signing.key`), the TLS directory, the firewall file, the systemd units, the nginx site and the deployed release. The output is root-only and holds **every ICS secret**; treat it like a key. Without `vault.key` stored secrets cannot be recovered; without `audit.key` the audit chain cannot be verified or extended. Encrypting backups to an offline key, copying them off the host and scheduling them are **Planned** for this tier (the TODO is in the script header).

## 2. Restore from backup
Full procedure and the evidence are in the runbook [ICS recovery](../runbooks/ics-recovery.md) and [Backup and restore](backup-and-restore.md). Summary:
1. On a new host, as root: `ics/deploy/backup/ics-restore.sh <backup_dir> <new_machine>` (lab form) or run `ics/deploy/backup/ics-restore-inner.sh` on a real host. It verifies checksums, restores keys and database, rebuilds the code environment from hash-pinned requirements, and starts the ICS **passive** (`ICS_WORKER_ENABLED=false`, `ICS_MONITOR_ENABLED=false`). `/readyz` shows `ready:false` meanwhile; that is expected.
2. Verify: `cd /opt/office-unbound/ics && sudo -u ics .venv/bin/python -m ics.cli verify-chain` (checked count equals the manifest `audit_events`, head equals `audit_head_hash`), an operator logs in, no job is running.
3. **Cut over deliberately.** Stop the old controller first (two active controllers would both act on the nodes). Move the console IP or DNS, the nginx site, firewall and TLS from the backup, set both flags to `true`, restart `ics`, watch the first monitoring cycle. Agents keep working because the signing key was restored.
4. Record the recovery in the audit log and your incident record.
Not exercised: moving the console to a different IP/CA name (the installer refuses a name outside the CA's constraints by design; the manual cut-over is the path) and agents accepting a restored controller in a full drill.

## 3. Warm standby (pending merge)
Design: [ADR-0012](../adr/0012-ics-warm-standby.md). Lab results: [ics-standby-results.md](../status/ics-standby-results.md). These files exist only on branch `integration-6`; check `git branch --contains` or the file list before you rely on them.
**How it works, in plain language.** A second ICS host copies the primary's database continuously (PostgreSQL streaming replication over verified TLS) and holds the same keys, transferred once, encrypted, and audited. It runs passive: it refuses every change and every signed request to agents. Promotion is always a human decision (never automatic, because a network split would look like a dead primary). On promotion the controller **epoch** goes up by one. Every signed request to an agent carries the epoch, and agents refuse any lower one. A resurrected old primary can therefore not drive agents that have seen the new epoch; it marks itself `fenced` the first time an agent refuses it.

**Set up (once per standby).**
1. On the primary, as root: `sudo ics/deploy/standby/ics-standby-prepare-primary.sh --primary-ip <ip> --standby-ip <ip>`. It turns on PostgreSQL TLS for the standby address only, creates a replication-only role and a bounded slot, and writes an encrypted key bundle plus a separate passphrase file. Send the two by **different channels**.
2. On a fresh Ubuntu 24.04 host: `sudo ics/deploy/bootstrap.sh --standby-of <primary-ip> --key-bundle <file> --bundle-passphrase-file <file> --listen-ip <ip> --allow-cidr <cidr>`.
3. Re-run step 1 after every key rotation (`rewrap-master` or a signing key change), and re-bundle.
**Watch it.** Standby `/readyz` shows `role`, `epoch` and a `replication` check (503 when the heartbeat is over 60 s old). On either host: `sudo ics/deploy/standby/ics-standby-status.sh`. `cd /opt/office-unbound/ics && sudo -u ics .venv/bin/python -m ics.cli controller-status` prints role, epoch and replication position. Alert on the standby's `/readyz`.

**Promote (operator decision).**
1. Confirm the primary is really down, or stop it (`systemctl stop ics postgresql`). If it is still streaming, promotion refuses unless you give `--fence-old-dsn-file`.
2. On the standby as root: `sudo ics/deploy/standby/ics-promote.sh` and type `promote <hostname>`. It records the replay position, promotes the database, raises the epoch, audits `controller.promoted`, verifies the whole audit chain (it will not start the ICS if that fails), switches the role to primary, restarts, and sends one read-only runbook to every enrolled agent so they learn the new epoch. Read the `announce:` lines. A node that says `unreachable` is not yet protected against the old primary; **keep the old primary off** until it has been reached.
3. Move the console address or DNS and the firewall allow-list to the new primary. Verify: `controller-status` (epoch +1), `verify-chain`, `/readyz`, and a harmless `service.status` on one node.
4. Bring the old primary back only as a **new standby**: prepare on the new primary for the old host's address, then on the old host `bootstrap.sh --standby-of <new primary> ... --rebuild` (this destroys its local database; copy anything you need for the incident report first). Never "unfence" it.

**Not proven.** Network partition behaviour, agents unreachable during promotion (they learn the epoch late), a console banner, an operator login on the promoted controller beyond `/readyz`, key re-bundle, and automatic failover (designed, disabled, not implemented).

## 4. Other recovery cases
| Case | Page |
|---|---|
| Lost or expired Proxmox token, disabled service account, customer revoked access, lost vault key | [provider access recovery](../runbooks/provider-access-recovery.md) |
| Locked-out operator | [Day-2 operations](day-2-operations.md), break-glass table |
| A customer tier (identity, files, groupware) | [Backup and restore](backup-and-restore.md) |
