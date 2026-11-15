# Mail migration

Both tools run from the repository's `migration/` package on a workstation or server with network access to the source and the target. **Lab-proven only**: neither has touched a real Microsoft 365 or Google tenant, and neither is controlled by the ICS (no plan, approval or audit; ICS orchestration is **Planned**, design in [migration-ics-contract.md](../status/migration-ics-contract.md)). Pre-alpha.

## 1. Assess first (read-only)
Evidence: [migration-assessment.md](../status/migration-assessment.md): 52 fixture tests pass; the collectors were never run against a real tenant, and the fixtures prove our parsing against documented API shapes only.
```
cd migration
python -m ou_migration assess --provider m365 --out ./report        # or --provider google
```
Options: `--checkpoint FILE` (resume), `--bandwidth-mbps N` (transfer-time estimate), `--deep` (opt-in sampled per-user counts, needs extra permissions), `--dns-resolver IP`, `--no-dns`. Credentials come only from environment variables or `*_FILE` secret files (regular, mode 0600, no symlink); nothing secret is written to the reports.
Output: `assessment.json` and a self-contained `assessment.html`. Every field is tagged verified, estimated or assumption; a stage that fails is recorded in the coverage section and lowers the confidence instead of stopping the run. It lists users, groups, mailbox sizes, DNS posture (MX, SPF, DKIM, DMARC), features Office Unbound cannot reproduce, a proposed identity mapping, a transfer-time range and a risk score with every fired rule.

## 2. Migrate one mailbox over IMAP
Evidence: [migration-engine-results.md](../status/migration-engine-results.md): `cd migration && pytest` passed 80 tests; one real lab run moved 337 messages and then 562 into a new Gromox mailbox. Code: `migration/ou_migration/engine/`.
Prepare the target user first (an LDAP/directory user with a Gromox mailbox, see [Users and access](users-and-access.md)). Put the two passwords in 0600 files, then:
```
export OU_SRC_PASSWORD_FILE=/path/src.pw OU_DST_PASSWORD_FILE=/path/dst.pw
python -m ou_migration mail-migrate --src-host SRC --src-ca ca.pem --src-user USER \
   --dst-host gw1.ou-lab.internal --dst-ca gw1-ca.crt --dst-user USER@domain \
   --state job.db --out report/ --dry-run            # counts per folder, writes nothing
python -m ou_migration mail-migrate ... (same flags without --dry-run)
python -m ou_migration mail-verify ... (same flags without --state) --sample 50
```
(Flags as in section 5 of the results document: also `--max-msgs-per-sec`, `--exclude REGEX`, `--map SRC=DST`.) Exit code 0 = complete, 1 = incomplete or verification mismatch, 2 = usage, credential or fatal error.
- **Source is read-only**: only read commands are possible (`BODY.PEEK`, no store, expunge, delete); the lab source's unseen count and server log confirmed nothing changed. TLS is always verified.
- **Incremental and resumable**: re-run the same command with the same `--state` file to copy only new mail. The lab run copied 25 new messages in a delta, then zero on an immediate re-run; a run killed with SIGKILL resumed and adopted the one message that had been appended but not recorded, ending with 562 of 562 and no duplicates.
- **Verify** compares counts, fingerprints, flags and full-body hashes of a sample (lab: all 337 bodies identical, flags equal).
- Folder names are mapped to the Gromox standard folders (Sent to Sent Items, Trash to Deleted Items, Junk to Junk Email, and so on); unicode folder names worked in the lab. For Gmail, exclude `[Gmail]/All Mail` when labels are the real structure, or mail is duplicated.

**Not carried or not proven** (migration-engine-results.md sections 2, 3, 6): IMAP keywords/Gmail labels, MAPI-only properties, deletions or flag changes made at the source after copying; calendars, contacts, tasks, shared mailboxes, public folders, files, rules and aliases (not started); OAuth2 against Google and Microsoft 365 (unit tests against stubs only; throttling handled generically); very large mailboxes; one mailbox per process, about 19 messages per second in the lab. Nothing is ever deleted at either side.
