# Backup and restore

Evidence: [restore-drill-results.md](../status/restore-drill-results.md) (files, identity, ICS controller and groupware drills, 2026-11-15, lab), [ics-installer-results.md](../status/ics-installer-results.md) (controller restore re-run on a fresh installer-built host), [docs/runbooks/ics-recovery.md](../runbooks/ics-recovery.md).
All scripts run as root on the ICS host against **nspawn lab machines**; they are drill tooling and tier hooks; the **backup product** (ADR-0010) is described in [the product section](#backup-product-adr-0010) and [backup-product-results.md](../status/backup-product-results.md). Backups hold secrets: output is root-only (0700/0600).
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

## Backup product (ADR-0010)
Lab-proven (2026-11-15): policies per deployment and tier, restic 0.19.1 repositories on a rest-server (`ou-bkp1`), typed actions, scheduler, checks, automated restore verification with measured RTO.

**Operating it** (all mutations are plans; read views `GET /api/v1/backups/policies|runs|verifications`):
1. Enroll the runner node (`node.enroll`) with an agent config enabling `backup.run/verify/prune` for the tiers (`ics/agent/deploy/agent-backup.json`), install `/etc/ou-backup/<tier>.json` on it (root-owned; source machine, repository URL, credential directory, scratch machine, canary pattern; see `blueprints/lab/backup/lab-runner-setup.sh` for the lab values).
2. `backup.policy.create` (normal, one approver): tier, deployment label, schedule (`every_hours` or `daily_at`), retention (`last/daily/weekly/monthly`), RPO and RTO targets, repository URL + certificate SHA-256, verification cadence. The repository password is generated server-side and kept only in the vault.
3. Provision the node (host root, once per tier): `sudo -u ics python -m ics.cli backup-node-secret --policy P | sudo ou-backup --direct provision <tier>` then `sudo ou-backup --direct init <tier>`. The value is never printed to a terminal log by ICS (the command writes JSON to the pipe; the audit log records the export with a fingerprint only).
4. **Offline recovery key (owner procedure).** `sudo ou-backup --direct recovery-key <tier> /root/recovery-<tier>.txt` adds a second, independent restic key and writes it to a 0600 file once; it prints only a 16-hex fingerprint. Print or copy the file to offline media (safe, sealed envelope, second site), verify the fingerprint on the copy, then `shred -u` the file and run `sudo -u ics python -m ics.cli backup-recovery-ack --policy P --fingerprint <fp>` (ICS then reports `recovery_key.exported`). With this key, `restic -r <repo> snapshots` works without the ICS vault: losing the vault key (see the ICS controller backup above) does not lose the backups. Rotate by adding a new key, then `restic key remove` the old one.
5. Watch the four states (never one flag): `backup_success`, `replication`, `recovery_readiness`, `verified_restore`. Create `kind: backup` checks (`age`, `repo_check`, `restore`, `growth`) with `check.create` to alert through the existing channels.
6. A restore verification failing, a canary mismatch, a failed repository check or a RPO breach are incidents like any other check; retention reductions are high-risk plans (two approvers) because the next prune deletes history.

**Real recovery** (not the verification): `restic -r rest:https://<target>:8000/<tier> restore <snapshot> --target /restore`, then feed the directory (`MANIFEST` + archive) to the tier restore script exactly as in the drills above (`files-restore.sh`, `id-restore.sh`, `gw-restore.sh`; the archive is `files.tar` for online-mode backups).

### Per-customer isolation (ADR-0010 section 6; lab-proven by T20, [backup-isolation-results.md](../status/backup-isolation-results.md))
A customer's backups are a separate security domain from every other customer's. Never put two customers into one repository, one password or one REST credential.
1. **Policy bound to the customer**: `backup.policy.create` takes `customer_id`. The ICS derives the customer's *profile* `c-<32 hex of the customer id>` and requires the repository URL to be `https://host:port/<profile>/<tier>`. The restic repository password is vault-encrypted with the customer id in its AAD (relabelling the row to another customer makes it undecryptable). One repository belongs to exactly one policy (unique URL).
2. **Operators**: an operator scoped to customers sees only their policies/runs/verifications and can plan `backup.run|verify|prune|policy.update` only on their own policies; anything else answers 404 exactly like a missing policy. `backup.run`, repository checks and policy management are not "infrastructure changes" (no customer approval, allowed for monitoring-only customers); `backup.prune` and restore verification keep the usual gates.
3. **Repository host**: `blueprints/lab/backup/bkp-customer-setup.sh <profile>...` starts two `rest-server --private-repos` listeners on a store of their own: `:8010 --append-only` (runner) and `:8011` (maintenance). The REST user is the profile name, so the credential only reaches `/<profile>/...`; backup and maintenance passwords differ per customer and per listener. In production prefer a separate store (or instance) per customer and S3 credentials scoped to one bucket/prefix.
4. **Runner**: one profile directory per customer on the runner, `/etc/ou-backup/<profile>/<tier>.json` with its own credentials directory and staging directory (`blueprints/lab/backup/lab-customer-runner-setup.sh`); the agent allowlist names the profiles (`"customers": [...]` next to `"tiers"`). The root helper refuses a profile config that points outside the customer's repository namespace, credentials or staging directory, whose REST user is not the profile, or whose source/scratch machine is also configured for another profile. Give every customer its own scratch machine for restore verification.
5. Provision per customer: `ics.cli backup-node-secret --policy P | ou-backup --direct --customer <profile> provision <tier>`, then `init` and `recovery-key` with the same `--customer`.

### ICS controller tier (policy tier `ics`, lab-proven against a DEV ICS)
`ics-backup.sh` archives the controller (pg_dump, roles, `ics.env`, `ics-migrate.env`, vault/audit/signing keys, units, TLS dir, deployed release) and the runner puts it **only into the encrypted restic repository**; the plain archive exists in the root-only staging directory for the run. Production: policy `tier=ics`, `/etc/ou-backup/ics.json` with `"login_canary_file"` (a *viewer* operator account whose credentials sit in the root-only creds directory) and a scratch machine. Dev/lab: `backup_env` points the hook at a dev tree and database (`blueprints/lab/backup/lab-ics-tier-setup.sh`). Never target the production service from a lab.
**Offline recovery key** (the vault key is inside the backup, so the vault cannot be the only way in): `sudo ou-backup --direct recovery-key ics /root/recovery-ics.txt` once after `init`; print/copy it offline, shred the file, `ics.cli backup-recovery-ack --policy P --fingerprint <16 hex>`. To recover with nothing else: `RESTIC_PASSWORD=<key from the file> restic -r rest:https://<target>:<port>/<repo> restore latest --target /restore`, then `ics-restore-inner.sh` as in the runbook.
**Restore verification** (`backup.verify level=restore`, scheduled like the other tiers): the helper restores the snapshot, checks the archive checksum, runs the passive restore (`ics-restore.sh` with `OU_INTO_EXISTING=1`) into the scratch machine, then checks `verify-chain` ok, the backup-time audit head event present with the same hash, schema at the backed-up alembic head, worker/monitor disabled (not ready), and an operator can log in (password + TOTP + vault key + audit key). The scratch machine is powered off afterwards.

## Not yet covered
- Product gaps: ICS controller tier lab-proven only against a dev ICS (never run against the production ICS), second-copy replication, S3 backends, production runner topology, filesystem-snapshot consistency for files (see backup-product-results.md).
- Restore of a whole customer stack together, with DNS/MX cut-over: not drilled. Collabora editing against a restored files node: not proven. The portal is not in the backup set.
- Groupware logical export is not point-in-time across mailboxes; only IPM_SUBTREE content is exported (no archive stores, search index, rules, OOF, delegates); ActiveSync device state and the postfix queue are not backed up (devices fully resync); large attachments untested.
- The ICS cut-over (nginx/IP move) and agents accepting the restored controller were **not exercised** in either drill. The installer drill restored a controller with one operator and verified `verify-chain` (head equal to the manifest) and a login with the original password and TOTP.
- Backup of the lab machines runs from the ICS host; production per-customer backup orchestration does not exist.
