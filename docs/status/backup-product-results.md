# Backup product results (agent AB, 2026-11-15, lab)

Roadmap P5.3 ("backups are not complete until recovery is tested"). Design and tool decision: [ADR-0010](../adr/0010-backup-product.md). Operator procedures: [docs/admin/backup-and-restore.md](../admin/backup-and-restore.md).
Status values (ADR-0000): policy/run/verification/monitoring path **Lab-proven**; production runner topology, S3 repositories and second-copy replication **Planned**.

## What was built
| Piece | Where |
|---|---|
| Policy model, retention math, RPO/RTO evaluation, four states, verification state machine (pure) | `ics/ics/backups/policy.py` |
| Typed actions `backup.policy.create/update`, `backup.run`, `backup.verify`, `backup.prune`; executors, scheduler, monitoring evaluation, read models | `ics/ics/backups/ops.py`, wired in `actions.py`; tables via migration `0008_backups.py` |
| Agent runbooks `backup.run {tier}`, `backup.verify {tier, level, [percent], [snapshot]}`, `backup.prune {tier, last, daily, weekly, monthly}` (closed shapes, per-node tier allowlist, fixed template unit, polkit rule) | `ics/agent/ou_agent/runbooks.py`, `agent/deploy/runbooks/ou-rb-backup@.service`, `render_polkit.py` |
| Root helper that runs the existing online tier scripts, restic, scratch restore and canary comparison | `ics/agent/deploy/runbooks/ou-backup`, `ou-backup-canary.py` |
| API (viewer): `GET /api/v1/backups/policies`, `/runs`, `/verifications` | `ics/ics/main.py` |
| Monitoring: check kind `backup` (aspects `age`, `repo_check`, `restore`, `growth`) through the normal check/incident/alert pipeline | `ics/ics/checks.py`, `monitor.py` |
| Own worker lane for `backup.*` jobs (budget 3600 s) so a restore verification cannot block remediation | `actions.claim_job(backup_lane)`, `worker.py` |
| Lab: target machine `ou-bkp1`, runner install, runner agent, drill driver | `blueprints/lab/backup/bkp-target-setup.sh`, `lab-runner-setup.sh`, `lab-agent-setup.sh`, `ics/scripts/lab_backup_product.py` |
| Tier scripts: online mode (`OU_ONLINE=1`, no stop, uncompressed tar for dedup) and `OU_INTO_EXISTING=1` (restore data into an already built scratch machine) | `files-backup.sh`, `files-restore.sh`, `id-restore*.sh`, `gw-restore.sh` |

Tool: **restic 0.19.1** (BSD-2) + **rest-server 0.14.0** (BSD-2), both pinned by SHA-256 in `blueprints/lab/common/versions.env`; the runner refuses a restic binary whose SHA-256 differs from its root-owned config. Evaluation of restic / borg / kopia in ADR-0010. The PGP signature of the release `SHA256SUMS` was not verified (no trusted keyring); the pin is the anchor.

## Lab topology
`ou-bkp1` (new nspawn machine, Debian 12, zone oulab, **MemoryMax=1G**; `memory.peak` 818 MiB after the drill, page cache included) runs two rest-server listeners over one repository store `/srv/restic`: `:8000 --append-only` (what the runner uses) and `:8001` full access (prune only). TLS: self-signed certificate with SAN IP/DNS, pinned by the clients (`RESTIC_CACERT`). Credentials: bcrypt htpasswd in the machine; plaintext only in root-only files on the runner (rest-server 0.14 rejected `$apr1$` hashes: "Invalid htpasswd entry", fixed to bcrypt).
Source machines unchanged and never stopped: `ou-files1`, `ou-id1`, `ou-gw1`. Scratch machines `ou-files-r1`, `ou-id-r1`, `ou-gw-r1` (existing images) are powered on only during verification and powered off afterwards (verified: none running after the run).
The runner is the ICS host (the only place that can reach the nspawn machines): a **second, separate** agent instance `ou-agent-bkplab` (own state dir, port 18443 on the oulab bridge, allowlist `backup.*` only). The ICS side was a **throwaway ICS instance on a test database** driven in-process by `ics/scripts/lab_backup_product.py` with its own temporary vault/audit/signing keys; the production `ics` service and database were not touched. Enrollment was a real `node.enroll` plan with two approvers.

## Drill (through typed plans -> approval -> jobs -> signed agent request -> helper -> restic -> ou-bkp1)
Host load average during the drill was 6-10 (other agents running suites and lab machines), so wall-clock numbers are pessimistic.

Backups (two rounds, `backup.run`, job wall-clock including agent round trip):
| Tier | Source processed (uncompressed archive) | Round 1: new data / job time | Round 2: new data / job time | Repository on disk after 2 rounds | Phases of round 2 |
|---|---|---|---|---|---|
| files (OpenCloud, online, no stop) | 806 MB then 959 MB | 648 MB / 35.8 s | 665 MB / 44.1 s | 1.3 GB | canary 2.5 s, source export 31.4 s, restic 6.0 s |
| identity (slapcat + pg_dump + config) | 0.6 MB | 0.6 MB / 10.3 s | 0.6 MB / 9.9 s | 1.5 MB | 1.3 / 1.2 / 1.6 s |
| groupware (mysqldump + mailbox exports) | 184 MB | 184 MB / 64.8 s | 74 MB / 65.6 s | 122 MB | 0.8 / 58.2 / 2.5 s |
A later direct run of the files tier (same data, little churn) stored 35 MB of 970 MB: deduplication works; the first two rounds saw heavy churn on `ou-files1` by other agents (+150 MB growth between the two rounds). Identity and groupware dumps contain compressed members and timestamps, so they dedup poorly; fine at these sizes.

Repository check (`backup.verify level=check`, 25 % of the data read): files 6.2 s, identity 4.7 s, groupware 3.8 s, all passed. Prune with the policy retention (`last 2, daily 7, weekly 4, monthly 6`): 2.4-3.2 s per tier, nothing removed (2 snapshots each).

**Restore verification into the scratch machines** (`backup.verify level=restore`; restic restore -> archive checksum -> power on scratch -> data restore -> canary comparison -> services active -> power off):
| Tier | Canary compared | restic restore | scratch power-on | data restore | **RTO** (restic + data + canary, excl. power-on) | target | result |
|---|---|---|---|---|---|---|---|
| files | canary .docx bytes (sha256 + size) + sha256 of its stored prior version (xattr node id -> `.REV.` blob) | 8.0 s | 7.1 s | 20.7 s | **29.1 s** | 900 s | passed |
| identity | LDAP canary entry (`entryUUID`) + Keycloak realm role that exists only in the database | 3.1 s | 2.4 s | 30.1 s | **33.9 s** | 900 s | passed |
| groupware | mailbox `alice@gw1`: message count 22 + sha256 over the sorted subject list (message ids change on import, subjects do not) | 3.1 s | 3.0 s | 123.1 s | **126.7 s** | 1800 s | passed |
Services checked active on the restored machine: opencloud, opencloud-collaboration, nginx / slapd, postgresql, keycloak / mariadb, gromox-http, gromox-imap, nginx, postfix. (Service "active" is not an application login; the drill-1 style login probes are not part of the automated verification.) Power-on of a scratch machine is not part of the RTO because a real recovery provisions a new machine (the drills measured: files 18 s, identity 73-79 s, groupware 18.5 min source build on top).

**Measured RPO.** A snapshot reflects the source at the start of its export (canary read first; groupware mailboxes are exported one after another over about 58 s, not point-in-time across mailboxes). Worst-case data-loss window = schedule interval + run duration: with the lab policy `every_hours: 12` and RPO target 24 h that is 12 h + 36-66 s (files 44 s, identity 10 s, groupware 66 s). `age` checks read 7-8 min right after the drill (RPO 1440 min).

## The four states (policy view from `GET /backups/policies` after the drill)
| Policy | backup_success | replication | recovery_readiness | verified_restore |
|---|---|---|---|---|
| lab-files / lab-identity / lab-groupware | ok (7-8 min old) | ok (1 of 1 copies) | ready (check passed, recovery key recorded, fresh snapshot) | verified (RTO 29 s / 34 s / 127 s) |
Before the drill steps each state was distinct: after the first backups `verified_restore` was `never_verified` and `recovery_readiness` `not_ready` (no check, no key) while `backup_success` was already `ok` (covered by tests). `replication` with `copies_required: 2` shows `degraded` (there is one repository).

Monitoring checks created and evaluated through `check.create` plans (12 checks): all `ok` except `*-growth` for files and groupware, which stayed `unknown` (flap damping: not yet `fail_threshold` results) because the growth estimate extrapolated minutes to days (150 GB/day); fixed afterwards: no growth rate with less than 6 h between samples.

## Negative tests (real, lab)
| Test | Result |
|---|---|
| Append-only: runner credential tries `DELETE /identity/config` | HTTP 403; `restic forget` with the runner credential leaves both snapshots in place |
| Wrong repository password | `wrong password or no key found` |
| Corrupted pack (bytes overwritten in a copy of the identity repository) | `restic check --read-data` exits 1: `repository contains errors`, damaged pack reported |
| Canary missing at backup time (canary pattern pointed at nothing): backup still succeeds (`canary_recorded=false`), restore verification | `match=false`, problem "no canary was recorded at backup time": a restore without a canary is never "verified" |
| Offline recovery key (second restic key, 256 bit) | opens the repository with no access to the vault password (`key list` shows both keys); file written 0600, shredded after the test |
| Secret non-leakage (unit tests) | repository password absent from audit entries, plans, jobs, runs, API output; vault ciphertext bound to policy id + repository URL (wrong URL / policy id cannot decrypt) |

## Tests
`ICS_TEST_ENV_FILE=... pytest tests/test_backups.py tests/test_backups_restic.py`: 86 unit/integration tests (policy validation, retention math, runbook parameter validation in ICS **and** agent, polkit rule, verification state machine, canary judgement, four states, executors through a real agent with a stubbed `systemctl`, secrets, scheduler incl. failure backoff, lane isolation, monitoring aspects) plus 6 cases that compare the retention math with the real `restic forget --dry-run` on synthetic snapshot histories. The cross-check found one rule the first version missed: when a `--keep-*` rule is not used up, restic also keeps the oldest snapshot ("oldest monthly snapshot"); fixed and now equal in all cases.

## Findings fixed during the drill
1. rest-server 0.14 refuses `$apr1$` htpasswd entries (bcrypt works).
2. The scratch id machine boots with PostgreSQL still starting: the reset in `id-restore-inner.sh` now waits for it.
3. `restic restore latest` reported no snapshot id: the runner resolves the id first and reports it.
4. An empty canary (nothing found) must not equal an empty canary: treated as "no canary", verification fails.
5. The `checks.kind` CHECK constraint rejected the new kind (migration 0008 widens it).
6. Test suite shares one test database name with other agents' runs; concurrent suites make each other wait on locks (tests took minutes instead of 20 s). Not a product issue.

## Limits and open items
- **Runner credentials**: the repository password and REST credentials are provisioned on the runner by a host-root step (`ics.cli backup-node-secret | ou-backup --direct provision <tier>`); the agent protocol deliberately carries no secrets. A compromised runner can read its repository password (it must, to back up) and write snapshots; with the append-only listener it cannot delete history. In the lab the maintenance credential sits on the same runner (so the separation is not demonstrated end to end); production should prune from the repository host or a separate maintenance node.
- **Files tier is crash-consistent per file, not quiesced** (no stop, tar tolerates "file changed"): the manifest says `consistency=online-crash-consistent`; a filesystem snapshot is still needed for guaranteed consistency (existing Planned item). The xattr count check brackets before/after counts.
- **ICS controller tier** is supported by the model and runner (`ics-backup.sh`), but was **not run**: it reads the production ics database, which this drill must not touch. Restore verification is not defined for it yet (the existing `ics-restore.sh` creates a new machine).
- Restore verification proves data and services come back and the canary matches; it does not run user-visible login/protocol probes (drill scripts do), and the identity canary does not exercise Keycloak token issuance.
- The agent serialises runbooks (one at a time): a 2-minute restore verification delays other runbooks on the same runner agent; use a dedicated runner node.
- `replication` is computed from one repository; `restic copy` to a second target is Planned. S3/MinIO/Garage backends use the same restic code path but were not exercised.
- The scheduler runs inside the ICS worker; it was exercised in tests (and via plans in the drill), not left running unattended for days. No long-term RPO statistics yet.
- 2 s scratch power-on assumes the scratch image is current; a stale scratch image (old packages) is not detected.
