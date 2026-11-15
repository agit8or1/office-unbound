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

## Not yet covered
HA/standby controller; encrypted off-host backups and schedule; automated cut-over; agent behaviour when the ICS is unreachable for long periods (agents are passive: they only act on signed, unexpired ICS requests).
