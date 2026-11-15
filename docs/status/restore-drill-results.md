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

# Restore drill — ICS controller, 2026-11-15 (lead)
Backup `ics/deploy/backup/ics-backup.sh` (online pg_dump; 552 KB) → `/var/backups/office-unbound/ics/20261115T180734Z`: schema 0005, 526 audit events, 4 operator accounts, keys, deployed release (sha256 e08f4997…4e29). Restore `ics-restore.sh` onto NEW Ubuntu 24.04 machine `ou-ics-r1`: **75 s**, PASSIVE.

| Check on restored ICS | Result |
|---|---|
| `verify-chain` (restored audit HMAC key) | ok, checked=526, 0 problems, head d8f8f6c5bf84… == MANIFEST |
| Operator login `lab-ap1` (password hash + vault-decrypted TOTP secret) | HTTP 200, session issued |
| Audit append after login, re-verify | ok, checked=527 |
| Passive: jobs queued/running; connections to node agents | 0; 0 (`/readyz` ready:false because worker off — expected) |

Findings fixed: (1) restore numeric gid of `ics` differs on a new host → ownership re-applied by name; (2) `umask 077` made the release/venv unreadable for the service user (`status=203/EXEC Permission denied`) → release + venv under umask 022, secrets stay 077. Design decision recorded: restores start passive to prevent split-brain remediation. Runbook: docs/runbooks/ics-recovery.md.
Not proven: cut-over of the console IP/nginx; agents accepting requests from the restored controller (expected: same signing key) — not exercised to avoid two controllers talking to live nodes.

# Restore drill — groupware tier (source-built Gromox on Debian 12), 2026-11-15 (groupware engineer)

Acceptance 22 (clean-room repeatable install) + acceptance 17, groupware tier. Source node `ou-gw1` (live, ICS-monitored, another agent working on it): **read-only** for the whole drill. Restore target `ou-gw-r1`, a NEW machine cloned from `ou-base-bookworm`, zone oulab, `PrivateUsers=pick`, `MemoryMax=3G`, `JOBS=3`.

## A. Clean-room build (committed `spike-groupware/build-from-source.sh`, all 8 stages)
| Item | Result |
|---|---|
| Run | detached in the machine (`systemd-run -M ou-gw-r1 --unit=ou-build`, log `/root/build.log`), polled; `EXIT=0`, **no stage had to be patched during the run** |
| Wall time | **1108 s (18 m 28 s)**: deps 1m20, libHX 0m20, wmime 5m02, gromox 10m31, mapihdr/sync/dav 0m07, web 1m10 |
| Memory | cgroup `memory.peak` **3072 MiB = the 3G cap** (includes page cache; `memory.events`: max hit 4835x, **oom_kill 0**). 3G is the practical floor for `JOBS=3`; do not go lower while a Collabora build competes for RAM |
| Pins | the 7 source SHAs (libhx v4.28, wmime-1.2.0, gromox-3.13 8b620206…, mapi-header-php 2.4, sync 2.7, dav 1.9, web-5.2) are identical to the original node; build writes `/usr/src/ou/PINS`. The `gromox-http` **binary sha256 is identical to ou-gw1's** (same toolchain: the build is bit-reproducible here, not guaranteed across toolchains) |
| Disk | image 3.3 GB, `/usr/src/ou` 1.2 GB (deletable) |

Fixes made to the committed scripts (all folded in; this is the point of the exercise):
1. **Packages**: `composer` (used by stages sync/dav) and every runtime package (mariadb-server, nginx, php-fpm + curl/mbstring/mysql/sqlite3/xml/zip/redis/soap/intl, postfix(-mysql), redis-server, ldap-utils, python3-ldap3/pymysql) had only ever been installed by hand on ou-gw1; the script's deps stage only had build deps. Now `GW_BUILD_PKGS` + `GW_RUN_PKGS` = `GW_PKGS` in `common/packages.env`, used by `build-from-source.sh` stage deps (found by diffing `apt-mark showmanual` on ou-gw1 *before* the run, so the run itself passed first time; any further gap would only show on another fresh machine).
2. `build-from-source.sh` sources `../common/packages.env`, appends `PIN` lines to `$SRC/PINS`.
3. The base image has no `/etc/hosts`, and gromox needs **`::1 localhost`**: the exmdb provider binds `[::1]:5000` only and clients resolve `localhost` (see restore finding 1). Written by `gw-restore.sh create`.
Not re-tested from pristine: machine creation was done by the same commands by hand before the script existed; afterwards `gw-restore.sh create` was exercised with `GW_STAGES=deps` on a throwaway machine (OK, removed) and refuses an existing machine; the full `all` path (create + 18 min build + restore in one call) was not run end to end.

## B. Backup (online, `blueprints/lab/backup/gw-backup.sh ou-gw1`)
Canary first (`tests/gw_09_restore_drill.py seed`): unique-token mail with random body to `grace@gw1.ou-lab.internal` (SQL user), `alice@ou-lab.internal` (LDAP user) and `support@gw1.ou-lab.internal` (shared); CalDAV event for the LDAP user alice and the SQL user bob.
- No stop/reload/config edit on ou-gw1. The inner script is streamed over stdin and the tar comes back on stdout; scratch only in tmpfs `/run/ou-gwbk.*` (removed on exit). (During debugging I wrote and removed one 564-byte file in `/tmp` of ou-gw1 and ran sqlite3 read-only queries against the stores.)
- Content: `mysqldump --single-transaction --skip-extended-insert` of `email`; config tar (gromox, lab TLS **without the CA key**, ldap_adaptor + bind secret, nginx, php-fpm pools, postfix, mailname, sync/dav/web `config.php`); per mailbox `gromox-exm2mt -u U -ars IPM_SUBTREE` + the store's ACL rows; public stores via sqlite online backup; MANIFEST with the 7 source SHAs, package versions, per-mailbox message counts (total / inbox / calendar, SQL on the store **before and after** each export: a mismatch would be logged as "changed during export"), export sha256, `SHA256SUMS` inside the tar verified after transfer. Root-only 0700/0600.
- Result `/var/backups/office-unbound/lab/ou-gw1/20261115T182544Z`: **7.4 s**, 1.9 MB, 28 user rows, **23 mailboxes / 148 messages** saved (22 logical exports + 1 raw), 2 public stores, 5 empty quarantined stores recorded, incomplete=0.

## C. Restore (`gw-restore.sh restore <backup> ou-gw-r1`)
**19 s** from command to all 13 services active (+ node already built). Steps: archive/manifest/pin checks → config → accounts/dirs → MariaDB db+users+dump → stores recreated from DB rows (`mkprivate`, `mkmidb`, public store copied in) → services → `gromox-import -x -c` per mailbox → ACL rows → restart gromox frontends → `sync-midb` → postfix/nginx last → **every mailbox's restored counts (total/inbox/calendar) == manifest, enforced** (`VERIFIED: 23 mailboxes, 148 messages`). Node has its own `/etc/hosts` (gw1/mail/autodiscover names -> itself, ldap/auth -> ou-id1 192.168.186.241); the ICS `/etc/hosts` was not touched. LDAP auth goes to ou-id1 with the restored read-only svc-gromox bind.

## D. Verification on the restore, by IP (`OU_GW1_RESOLVE=192.168.186.107 gw_09_restore_drill.py verify`; TLS verified against the lab CA by name; nginx on r1 logged 14 EWS/11 DAV/7 EAS/4 MAPI requests; the same device id grep on ou-gw1 = 0 hits)
**17 PASS, 0 FAIL** (`/tmp` scratchpad evidence `verify2.txt`):
| Check | Result |
|---|---|
| IMAP INBOX count == MANIFEST | grace (SQL) 20==20, alice@ou-lab.internal (LDAP) 1==1, bob (SQL) 6==6 |
| Canary | present exactly once in grace and LDAP alice, subject + body sha256 equal the pre-backup value, original Message-ID kept |
| EWS FindItem | finds the canary for grace and LDAP alice |
| Shared mailbox support@ | canary visible to alice via EWS (ACL restored), TotalCount 4==4 manifest, carol still `ErrorAccessDenied`, direct login refused |
| CalDAV | pre-backup events present for the LDAP user and bob (GET 200, summary equal) |
| LDAP user | logs in over IMAP/EWS/DAV/EAS through the restored gromox -> OpenLDAP |
| ActiveSync | FolderSync (LDAP user) 200, 574 bytes WBXML, 14 folders; unmodified `gw_03` 7 PASS |
| MAPI/HTTP | unmodified `gw_02` 12 PASS incl. Connect `X-ResponseCode: 0`, StatusCode/ErrorCode 0, Disconnect; `gw_04` DAV 10 PASS; `gw_05` shared 4 PASS |
`gw_lab.py` got one env override (`OU_GW1_RESOLVE=<ip>`: connect to the IP, keep name for SNI/Host/cert verification, like `curl --resolve`) so the existing gw_* tests run against the restore unforked.

## E. Findings (all fixed in the scripts unless noted)
1. **`localhost` must resolve to `::1`** (nspawn base has no /etc/hosts): first import failed `PF-1047 ... allocate_message_id RPC failed` because exmdb listens on `[::1]:5000` only.
2. `tar --numeric-owner` stored **no owner names**: on the new node group `postfix` has another gid, so `mysql-vmbox.cf` came back `root:redis` (postfix lookups would fail). Backup now stores names; restore maps by name.
3. `postfix check` fails (silently, rc=1) without `/etc/mailname`: now in the backup.
4. **Quarantined (suspended by the lifecycle tooling) mailboxes have store dir mode 000**; `gromox-exm2mt` runs as `gromox` and cannot read them: it exits 1 after writing a 564-byte empty header, which a naive backup would have stored as a "successful" export. Now detected; empty store -> noted, store with content (kicktest2, 3 messages) -> raw sqlite online-backup + `cid/` tar, restored before daemons start. Quarantine is **filesystem-only state** (not in MariaDB): recorded as `dirmode|` and re-applied (a restore would otherwise silently un-quarantine). Restore refuses a backup flagged `incomplete`.
5. `exm2mt` cannot export public stores -> sqlite `.backup` copy (consistent while in use); restored by copying in over a fresh `gromox-mkpublic`.
6. ACLs are not in the export: dumped as `INSERT OR REPLACE ... permissions(folder_id,username,permission)` (the dump with `member_id` collides with default rows) and re-applied.
7. Live churn on ou-gw1 (lifecycle agent adds users mid-backup): the user list is now restricted to users present in the DB dump, so MANIFEST `users_rows` always equals the dump.
8. A failed restore cannot be retried on the same machine (refuses: db exists / `ou-restore.done`); for these iterations I reset by hand (drop db/user, remove /var/lib/gromox) and re-ran. **The final restore ran on that reset machine, not on a pristine clone**; the build itself and every pre-restore state were fresh.

## F. Not proven / limits
- Logical export is **not point-in-time consistent across mailboxes** and each export reads sqlite stores while gromox writes them; per-mailbox before/after counts catch only added/removed messages, not modified ones. Production needs filesystem/LVM/ZFS snapshots (`gromox-snapshot` not exercised).
- Archive stores, search index, read/flag state fidelity, categories, rules, OOF, free/busy, folder views, `NON_IPM_SUBTREE`, delegates beyond folder ACLs, send-as, anything outside IPM_SUBTREE: not exported, not verified. Message *content* equality was proven for the canaries only (body sha256), other messages by count.
- Large attachments (`cid/` blobs) only covered for the raw fallback; the logical path re-creates them from the stream, untested at size.
- **ActiveSync device state** (grommunio-sync state in redis/`/var/lib/grosync`) is not backed up: after a restore every device does a full resync (FolderSync SyncKey 0 works). `grommunio-dav` and web session state likewise. Real clients (Outlook profile, phones, DAV apps) not tested.
- Mail arriving at the original while the backup runs is lost for the restore (RPO = backup time); postfix queue is not backed up; no DNS/MX cut-over drill; restore target uses gw1's TLS server key (the CA key is deliberately not in the backup, so a re-issue needs the CA).
- Backup is plaintext on the ICS (root 0600), no encryption/retention/off-host copy; MariaDB root/db password lives in the config tar.
- Machine restore is NOT idempotent (see E8); LDAP users depend on ou-id1 being reachable at restore time only for logins, not for import.

### Lead re-verification (groupware tier), 2026-11-15
Re-ran `gw_09_restore_drill.py verify` against the restored node: **16 PASS / 1 FAIL** — shared mailbox TotalCount 5 vs manifest 4. Cause established from the restored node's postfix log: at 18:30 the node delivered locally-submitted test mail (bob→alice, alice→carol, erin→support) — the existing gw_* suites the drill agent ran against the restore *after* the manifest comparison. Not a restore defect and not leakage from ou-gw1 (no inbound relay; queue empty). Finding: `verify` is not idempotent once other tests write to the restored node → change it to verify immediately after restore, or compare `>= manifest` plus canary identity. Canaries, EWS, CalDAV, shared-mailbox ACL, MAPI/HTTP and ActiveSync checks all passed again.
