# Backup and restore

Evidence: [restore-drill-results.md](../status/restore-drill-results.md) (files, identity, ICS controller and groupware drills, 2026-11-15, lab), [ics-installer-results.md](../status/ics-installer-results.md) (controller restore re-run on a fresh installer-built host), [docs/runbooks/ics-recovery.md](../runbooks/ics-recovery.md).
All scripts run as root on the ICS host against **nspawn lab machines**; they are drill tooling, not a product backup service. Backups hold secrets: output is root-only (0700/0600).
Default destination `/var/backups/office-unbound/lab/<machine>/<UTC timestamp>`. Executables are never restored from backup: they are re-fetched/rebuilt from pinned, hash-checked sources.

## Summary
| Tier | Backup | Restore to a NEW machine | Measured | Verified by |
|---|---|---|---|---|
| Files (OpenCloud) | `blueprints/lab/backup/files-backup.sh <machine>` (brief stop of opencloud + collaboration) | `files-restore.sh <backup_dir> <new_machine>` | 18 s | current content and prior version byte-identical (sha256) |
| Identity (OpenLDAP + Keycloak + PostgreSQL) | `id-backup.sh <machine>` (online, no downtime) | `id-restore.sh <backup_dir> <new_machine>` | 73-79 s | logins via restored Keycloak and LDAP, DB-only canary, identical realm key ids and entryUUIDs |
| Groupware (Gromox) | `gw-backup.sh <machine>` (online, read-only on the node, 7.4 s) | `gw-restore.sh create|restore|all <backup_dir> <machine>` | 19 s restore plus 18.5 min source build | 23 mailboxes / 148 messages counts enforced; 16-17 protocol checks |
| ICS controller | `ics/deploy/backup/ics-backup.sh [dest_root]` (online pg_dump) | `ics/deploy/backup/ics-restore.sh <backup_dir> <new_machine>` | 75 s, starts passive | `verify-chain` ok (526 events), operator login |

Each restore script refuses an existing machine and verifies the archive checksum against its `MANIFEST` first. Use `blueprints/lab/backup/*.sh` paths as given; the `*-inner.sh` helpers run inside the machine.

## Files tier
Backup preserves `user.oc.*` xattrs (a plain copy loses file ids and versions). Restore runs `files-restore.sh`; the xattr count after extract must equal the manifest (enforced). Production would use a filesystem snapshot instead of a brief stop; **Planned**.

## Identity tier
Backup is `slapcat` of config and data plus `pg_dump` of Keycloak plus config/TLS (CA private key excluded). Restore asserts an `ldaps` listener exists (a missed `/etc/default/slapd` once brought slapd up with plaintext on all interfaces).
The Keycloak tarball is verified by SHA-1 only (all upstream publishes), a supply-chain item.

## Groupware tier
```
sudo blueprints/lab/backup/gw-backup.sh ou-gw1
sudo blueprints/lab/backup/gw-restore.sh create  <backup_dir> <new_machine>    # clone base, start detached source build
sudo blueprints/lab/backup/gw-restore.sh restore <backup_dir> <new_machine>    # after the build finished OK
```
(`all` does both; the end-to-end `all` path was **not** run in the drill.) The drill (source node read-only, restore to a new node): 23 mailboxes / 148 messages restored with counts enforced, canary mail byte-identical, 17 checks passed across IMAP, EWS, CalDAV, ActiveSync and MAPI/HTTP; a re-run by the lead showed 16/1 where the failure was test mail delivered after the manifest comparison, not a restore defect. The final restore ran on a machine reset by hand after earlier failed attempts, not a pristine clone. Test the restored node by IP; it answers for the production names itself and must not get them in DNS until a cut-over is intended. A failed restore cannot be retried on the same machine (it refuses); reset or use a fresh clone.
Quarantined (suspended) mailboxes are mode 000 and are handled specially; the restore refuses a backup flagged `incomplete`.

## ICS controller (procedure from the runbook)
1. Back up: `sudo ics/deploy/backup/ics-backup.sh` (contents: DB, `ics.env`, `ics-migrate.env`, `vault.key`, `audit.key`, `ics-signing.key`, TLS dir, firewall file, units, nginx site, deployed release). Without `vault.key` secrets are unrecoverable; without `audit.key` the chain cannot be verified.
2. Restore (drill form): `sudo ics/deploy/backup/ics-restore.sh <backup_dir> <new_machine>`. On a real host run `ics-restore-inner.sh` as root.
3. **The restored controller starts passive** (`ICS_WORKER_ENABLED=false`, `ICS_MONITOR_ENABLED=false`); `/readyz` shows `ready:false` meanwhile, as expected. This prevents two controllers remediating the same nodes.
4. Verify: `sudo -u ics .venv/bin/python -m ics.cli verify-chain` (count equals MANIFEST `audit_events`, head equals `audit_head_hash`); an operator logs in; no queued/running jobs; no connections to agents (:8443).
5. **Cut-over** (deliberate, never rushed): stop the old controller first; move the console IP/DNS, nginx site, firewall and TLS from the backup; set both flags to `true`; restart `ics`; watch the first monitoring cycle. Agents keep working because the signing key is restored.
   After a restore on a host built by the installer, `sudo ics/deploy/bootstrap.sh --skip-tls ...` adopts it (keeps keys, database and the passive setting; proven, second run reports no changes). A restored host whose IP differs from the CA's name constraints makes `bootstrap.sh` refuse by design: the cut-over onto a new IP/CA is still the manual runbook step.
6. Record the recovery in the audit log/incident.
Customer stacks do not depend on the ICS at runtime, so they keep running while it is down.

## Not yet covered
- No encryption of backups, off-host copy, scheduling, retention, or measured RPO (all **Planned**; the scripts say so).
- Restore of a whole customer stack together, with DNS/MX cut-over: not drilled. Collabora editing against a restored files node: not proven. The portal is not in the backup set.
- Groupware logical export is not point-in-time across mailboxes; only IPM_SUBTREE content is exported (no archive stores, search index, rules, OOF, delegates); ActiveSync device state and the postfix queue are not backed up (devices fully resync); large attachments untested.
- The ICS cut-over (nginx/IP move) and agents accepting the restored controller were **not exercised** in either drill. The installer drill restored a controller with one operator and verified `verify-chain` (head equal to the manifest) and a login with the original password and TOTP.
- Backup of the lab machines runs from the ICS host; production per-customer backup orchestration does not exist.
