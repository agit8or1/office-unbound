# Runbook: recover the ICS controller

Customer stacks do **not** depend on the ICS at runtime (mail, files, editing, SSO keep working while it is down). Recovery is therefore restore → verify → deliberate cut-over, never a rushed hot start.

## What a backup must contain (`ics/deploy/backup/ics-backup.sh`)
PostgreSQL `ics` (pg_dump -Fc) + roles `ics_owner`/`ics_app`; `/etc/office-unbound/{ics.env, ics-migrate.env, vault.key, audit.key, ics-signing.key, tls/, ics-admin-fw.nft}`; systemd units; nginx site; the **deployed release** (code that matches the DB schema — the venv is rebuilt from `requirements.lock --require-hashes`). Without `vault.key` the stored secrets are unrecoverable; without `audit.key` the audit chain can no longer be verified or extended.
Backups hold every ICS secret: root-only 0600. **TODO before production:** encrypt to an offline recovery key, copy off-host, schedule, measure RPO.

## Restore (`ics/deploy/backup/ics-restore.sh <backup_dir> <machine>` — drill form; on a real host run `ics-restore-inner.sh` as root)
1. Checksums verified (MANIFEST + SHA256SUMS).
2. Packages, service user `ics`, config/keys restored; ownership re-applied **by name** (numeric gids differ between hosts).
3. Roles + DB restored with ON_ERROR_STOP; release + hash-pinned venv; `ics-migrate` (no-op if schema already at head) then `ics`.
4. **Starts PASSIVE**: `ICS_WORKER_ENABLED=false`, `ICS_MONITOR_ENABLED=false`. The restored controller holds the agent-signing key and node registry; if the original is still alive, two active controllers would both remediate nodes (split brain). `/readyz` reports `ready:false` (worker) while passive — expected.

## Verify before cut-over
- `sudo -u ics .venv/bin/python -m ics.cli verify-chain` → ok, `checked` == MANIFEST `audit_events`, head == `audit_head_hash`.
- An operator logs in (proves password hashes + vault key decrypting TOTP secrets + audit HMAC key appending).
- `SELECT count(*) FROM jobs WHERE status IN ('queued','running')` and no outbound connections to agents (:8443).

## Cut-over (operator, deliberate)
1. Make sure the old controller is **stopped** (`systemctl stop ics` or host down) — never run two active controllers.
2. Move the front end: assign the console IP (or update DNS) to the new host, install nginx site + `ics-admin-fw`, TLS from the backup.
3. Set `ICS_WORKER_ENABLED=true`, `ICS_MONITOR_ENABLED=true`, restart `ics`; `/readyz` → ready.
4. Watch the first monitoring cycle; confirm agents accept requests (their pinned ICS public key comes from the restored signing key — no re-enrollment needed).
5. Record the recovery in the audit log / incident.

## Warm standby and fenced promotion (ADR-0012; lab-proven, [results](../status/ics-standby-results.md))
Use this instead of restore when a standby exists: takeover in seconds with no data older than the replication lag (sub-millisecond observed), instead of "restore last backup" (RPO = backup age). The restore path above stays the answer for a lost standby+primary or a corrupted database (replication copies corruption too: keep the backups).

**Set up (once per standby).** On the primary (needs the TLS install): `sudo ics/deploy/standby/ics-standby-prepare-primary.sh --primary-ip <ip> --standby-ip <ip>`. It enables PostgreSQL TLS + a hostssl-only line and a firewall rule for the standby address, creates role `replicator` and a bounded slot, and writes the **encrypted key bundle** plus a passphrase file (audited as `standby.keys_exported`). Hand the two files over by different channels. On the standby (fresh Ubuntu 24.04): `sudo ics/deploy/bootstrap.sh --standby-of <primary-ip> --key-bundle B --bundle-passphrase-file P --listen-ip <ip> --allow-cidr <cidr>`. Re-run the prepare script after any key rotation (`rewrap-master`, signing key) and re-bundle.
**Watch it.** Standby `/readyz` -> `{"role":"standby","checks":{"replication":{"ok","heartbeat_age_seconds","replay_delay_seconds","replay_backlog_bytes"}}}` (503 when the heartbeat is older than 60 s: stream broken or primary down). Primary: `ics-standby-status.sh` (pg_stat_replication lag, slot). Alert on the standby readyz; a dead standby makes the slot retain WAL up to `max_slot_wal_keep_size` (2 GB) then the slot is dropped (primary never blocks).

**Promote (operator decision; never automatic).**
1. Confirm the primary is really down, or stop it: `systemctl stop ics postgresql` there. Do not promote on a network blip: if the primary is up and streaming, promotion refuses unless you give `--fence-old-dsn-file` (URL of its app role), which marks it `fenced` in its own database first.
2. On the standby as root: `sudo ics/deploy/standby/ics-promote.sh` (type `promote <hostname>`). It records the replay position, `pg_promote`s, bumps the **controller epoch**, audits `controller.promoted`, verifies the whole audit chain (rc 3 and no start if it fails), sets `ICS_ROLE=primary`, restarts ics (worker/monitor start) and sends one read-only runbook to every enrolled agent so they learn the new epoch now. Read the `announce:` lines: a node that shows `unreachable` has NOT yet been fenced against the old primary - keep the old primary off until it has been reached.
3. Move the console address / DNS (and the firewall allow-list) to the new primary; run the verification below; record the incident.

**Fencing guarantee.** Every signed agent request carries the epoch; agents persist the highest epoch and refuse lower ones (`stale_epoch`) and epoch-less ones. A resurrected old primary keeps the signing key but cannot drive any agent that has seen the new epoch; on the first refusal it fences itself (`/readyz` red, `controller_state.role=fenced`). Never "unfence" it: **rebuild it as a standby of the new primary**: on the new primary run the prepare script for the old host's address, then on the old host `bootstrap.sh --standby-of <new primary> ... --rebuild` (destroys its local database: first copy anything you want to keep, e.g. audit rows written after the split, for the incident report).
**Verify after promotion.** `ics.cli controller-status` (epoch +1, role primary), `ics.cli verify-chain` ok and `checked` >= standby's audit_rows_at_promotion, `/readyz` ready with `epoch`, a harmless `service.status` on a node answers `agent_epoch` = new epoch, old primary (if started) is rejected.
**Automatic failover** is intentionally not provided (partition = split brain). A witness-based mode is designed in ADR-0012 and disabled.

## Not yet covered
Encrypted off-host backups and schedule; automated cut-over of the front-end address; witness-based automatic failover; agent behaviour when the ICS is unreachable for long periods (agents are passive: they only act on signed, unexpired ICS requests).
