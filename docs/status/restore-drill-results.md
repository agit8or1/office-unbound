# Restore drill — files tier (OpenCloud), 2026-11-15 (lead)

Acceptance item 17 (restore to a separate machine), **files tier only**. Identity (OpenLDAP/Keycloak/Postgres) and groupware (gromox export/import already proven in place, GW07) drills to separate machines are still open.

| Step | Result |
|---|---|
| Canary | `restore-drill-canary-*.docx` (user bob), 2 versions written via WebDAV; sha256 of v1/v2 recorded before backup |
| Backup | `blueprints/lab/backup/files-backup.sh ou-files1` → `/var/backups/office-unbound/lab/ou-files1/20261115T172712Z` (root 0700). Brief stop of opencloud+collaboration; tar with `user.*` xattrs + ACLs, numeric owners. MANIFEST: binary sha256 = pinned 183d95c3…777e, OpenCloud 9.1.0, uid/gid 996, **143 xattr entries**, archive sha256 + size (≈17 MB) |
| Restore | `files-restore.sh <backup> ou-files-r1` onto a NEW machine cloned from the clean base image. Binary re-downloaded from the pinned release and verified against versions.env **and** MANIFEST (executables are never restored from backup). Archive checksum verified; xattr count after extract = 143 (enforced). **18 s** wall-clock to running services |
| Verify (against the restored machine's IP, real TLS name `cloud.ou-lab.internal`, OIDC token from the same Keycloak) | current content HTTP 200, **sha256 == v2**; version list 207 with 1 prior version, **prior version sha256 == v1**; `/app/list` lists CollaboraOnline; ready 1 s after restore script returned |

## Findings (fixed)
1. First attempt: `/root/ou-restore.tgz: Permission denied` — nspawn `PrivateUsers=pick` UID shift; restore now chowns to the container's shifted root.
2. First successful extract → OpenCloud **panic: inotifywait is not installed**. The restore re-derived the package list and missed `inotify-tools`. Fix: single runtime package list `blueprints/lab/common/packages.env` sourced by install AND restore.
3. Backup initially omitted the system-trust copy of the lab CA (`/usr/local/share/ca-certificates/ou-lab-ca.crt`) needed for OIDC/LDAP TLS; added before the drill backup was taken.

## Not proven
- Collabora editing against the restored instance (WOPISrc/hostnames still resolve to ou-files1 from the office machine; would need a DNS cut-over drill).
- No-downtime backup (production: filesystem snapshot), retention, off-host copy, encryption at rest of backups, measured RPO.
- Identity + groupware restores onto separate machines; full customer-stack restore.
