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

# Restore drill — identity tier (OpenLDAP + Keycloak 26.8.2 + PostgreSQL 16), 2026-11-15 (lead)

| Step | Result |
|---|---|
| Canaries (before backup) | LDAP user `drillcanary` (entryUUID 3e495542-…0c1d) via ldap-user.sh; Keycloak realm role `drill-canary-<ts>` created via admin API — exists ONLY in the DB (not in the realm import file, so a restore that silently re-imports would fail this check) |
| Backup | `id-backup.sh ou-id1` → `/var/backups/office-unbound/lab/ou-id1/20261115T174040Z`. **Online, no downtime**: slapcat -n0 (13 config entries) + -n1 (19 data entries), pg_dumpall --globals-only, pg_dump -Fc keycloak, config tar (Keycloak env/conf/import, TLS for Keycloak + slapd, slapd listener defaults, CA trust, unit, lab secrets). CA private key excluded. Root-only 0600 |
| Restore | `id-restore.sh <backup> ou-id-r1` onto a NEW Ubuntu 24.04 machine; packages from common/packages.env; Keycloak re-fetched from the pinned release (SHA-1 = only upstream-published hash); slapadd config+data; roles + DB restored with ON_ERROR_STOP; `kc.sh build` with install-time build options. **73–79 s** to running services, Keycloak ready ≤5 s later. Restore node answers for auth./ldap.ou-lab.internal itself |
| Verify (TLS name auth.ou-lab.internal → restored IP) | drillcanary + bob **log in via restored Keycloak → restored LDAP** (password grant), `iss` unchanged, `uuid` claim == original entryUUID; DB-only role HTTP 200; **realm signing key ids identical** to the original (existing clients/tokens remain valid); 19 LDAP entries; listeners ldaps :636 + ldap 127.0.0.1:389 only (== original) |

## Findings (all fixed in the scripts)
1. slapd TLS material lives in /etc/ldap/tls — not in the first backup set (found by inspecting olcTLS* before restoring).
2. Globals restore ran as postgres against a root-only file and the error was suppressed → `role keycloak does not exist`. Now piped via stdin with ON_ERROR_STOP=1 (only the pre-existing `postgres` role is skipped).
3. umask 077 + root tar kept upstream numeric owners → kc.sh not executable. Fixed; ownership mirrors install-kc.sh (whole dist owned by keycloak). **Hardening TODO:** root-owned distribution, build as root, only data/ writable by the service.
4. **Security-relevant:** /etc/default/slapd not backed up → restored slapd came up with the package default `ldap:///` on ALL interfaces (plaintext) and no LDAPS; Keycloak federation failed. Now backed up, and restore asserts an ldaps listener exists.

## Still not proven
Groupware tier restore to a separate machine (in-place export/import proven in GW07); a whole customer stack restored together with DNS cut-over; backup encryption, off-host copies, retention, measured RPO; Keycloak tarball verified only by SHA-1 (upstream publishes no SHA-256/signature) — supply-chain item.
