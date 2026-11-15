# Migration engine (Phase 7, step 2): IMAP -> Gromox mail mover

Date: 2026-11-15. Code: `migration/ou_migration/engine/` (extends agent I's assessment package, same conventions: secrets via env / 0600 files, no
secret logging, state + resume). Status words follow ADR-0000: **Tested** = executed in this session, output quoted; everything under section 6 is **not** tested.
Evidence: `cd migration && pytest` -> 80 passed (52 existing + 28 engine) and the real lab run in section 4.

## 1. What it does
`python -m ou_migration mail-migrate | mail-verify` moves ONE mailbox from any IMAP source (legacy server, Google Workspace via IMAP + XOAUTH2, Microsoft 365 via IMAP + XOAUTH2)
into a Gromox mailbox over IMAP APPEND.

| Feature | Implementation |
|---|---|
| Source is read-only | Connection-level command allow-list (`imapx.py`): the source can only run CAPABILITY LOGIN/AUTHENTICATE LIST EXAMINE STATUS UID FETCH/SEARCH NOOP LOGOUT; FETCH must be `BODY.PEEK` (a plain `BODY[]`/`RFC822` raises `GuardViolation` before anything is sent). STORE/EXPUNGE/DELETE/COPY/MOVE/RENAME/SELECT are unreachable on source AND target (target adds only CREATE, APPEND). Unit-tested against a recording fake server; confirmed on the real source (UNSEEN count unchanged, Dovecot log `deleted=0 expunged=0`). |
| Folder mapping | `mapping.py`: RFC 6154 special-use wins (\Sent->`Sent Items`, \Drafts->`Drafts`, \Trash->`Deleted Items`, \Junk->`Junk Email`, \Archive/\All->`Archive`), name hints for servers without special-use (Sent/Gesendet/Spam/Papierkorb...), `INBOX.` namespace prefix dropped, custom hierarchy kept with `/`, segments sanitised (control chars, `* % \ "`, trailing dots/spaces, length 120), modified-UTF-7 decoded/re-encoded (unicode names), virtual views (\Flagged/\Important, Gmail Starred) and \Noselect skipped, `--exclude` regex, `--map SRC=DST`. Two source folders mapping to the same target merge (dedupe makes that safe). If the target advertises special-use itself those names win (Gromox 3.13 on ou-gw1 advertises none, so the built-in Gromox table is used). |
| Message fidelity | `BODY.PEEK[]` -> `APPEND` with the original INTERNALDATE string and flags \Seen \Flagged \Answered \Draft (\Deleted, \Recent and keywords are deliberately not carried). Bytes are the raw RFC822 bytes. |
| Idempotent + incremental | SQLite state (`state.py`, 0600, bound to source/target identity, one fsync'd transaction per message): per folder UIDVALIDITY + UID high-water mark; per message uid + fingerprint. Fingerprint = sha256(Message-ID + INTERNALDATE + size) (no Message-ID: hash of Date/From/To/Subject headers); only digests are stored, never identifiers or content. Before copying, the target folder is scanned and a multiset of fingerprints is compared with what the state already accounts for, so mail that exists on the target without a state record is **adopted**, not re-copied: crash between APPEND and commit, lost APPEND acknowledgement, deleted/lost state file, UIDVALIDITY change, mail the user already has there (dual delivery during coexistence). Genuine identical duplicates in the source are preserved (multiset, not set). |
| Throttle / backoff | `Throttle` (msgs/s, bytes/s); reconnect + exponential backoff with jitter on connection loss and throttle-like responses (`[UNAVAILABLE]`, `Too many`, `[LIMIT]`...); `[OVERQUOTA]`/`[NOPERM]` and TLS verification failures are fatal. An APPEND whose answer is lost is never blindly retried (target re-scanned first). |
| Resume | Kill at any point, re-run the same command with the same `--state`. |
| Dry run | `--dry-run`: counts and bytes per folder (+ what would be adopted if a target is given); writes nothing to either side. |
| Verification | `mail-verify`: per target folder source vs target counts, fingerprint multiset difference (missing/extra, which covers INTERNALDATE + size), \Seen/\Flagged/\Answered per matched message, seeded random sample (or all, `--sample N`) of full-body SHA-256 comparisons. Exit 1 on any mismatch. |
| Auth | LOGIN (over TLS) and XOAUTH2 through the `TokenProvider` interface (`--src-auth xoauth2` static short-lived token from env/file; `xoauth2-google` = service account + domain-wide delegation reusing `auth.GoogleAuth`, scope `https://mail.google.com/`; `xoauth2-m365` = client credentials, scope `https://outlook.office365.com/.default`). Rejected token -> one forced refresh. TLS always verified (system CAs or `--src-ca`/`--dst-ca` pinning the lab CA / a self-signed cert); plaintext only to loopback (tests). |

## 2. Fidelity limits of IMAP APPEND vs a Gromox-native import (`gromox-import` / `exm2mt` / MAPI)
Measured on Gromox 3.13: APPEND preserved the bytes exactly (sha-256 equal for all 562 migrated messages), INTERNALDATE (to the second, with source offset) and the four flags.
Not preserved / different from a native import: IMAP keywords and Gmail labels (flags other than the four above), MAPI-only properties (categories, importance set by the client, reminders, follow-up
flags beyond \Flagged), conversation/thread index, per-folder special properties, folder `\Archive`/`\All` semantics (mapped to a plain `Archive` folder), receive time vs. submit time distinction,
messages > `--max-message-bytes` (default 64 MiB; reported, never silently dropped), and sequential single-connection throughput (below). A native import would avoid per-message IMAP round trips and
keep MAPI properties but needs a PST/EML/mbox staging step on the Gromox host and cannot be incremental; for staged coexistence + final delta APPEND is the practical choice, native import stays an option for bulk first pass.
Gmail: "All Mail" (\All) is mapped to `Archive`, which duplicates labelled mail that also sits in other folders; exclude it (`--exclude '\[Gmail\]/All Mail'`) when the labels are the real structure.

## 3. Not done on purpose
Nothing is ever deleted at the source or the target (no EXPUNGE/DELETE code path exists). Deletions and flag changes made at the source AFTER a message was copied are not propagated (v1): the delta run copies new mail only.
If a user deletes a migrated message on the target, a re-run does not bring it back (state remembers it).

## 4. Real lab test (executed)
Machines: source `ou-msrc1` (clone of `ou-base-bookworm`, zone oulab, PrivateUsers=pick, MemoryMax=384M, DHCP 192.168.186.22, Dovecot 2.3.19 IMAPS only, `ssl=required`, self-signed ECDSA cert with SAN pinned via `--src-ca`;
special-use Sent/Drafts/Trash/Junk/Archive configured). Target: Gromox 3.13 on `ou-gw1`, **new** directory user `migcarol@ou-lab.internal` created with `ldap-user.sh add migcarol -` on ou-id1 and
`gw-ldap-sync.py --user migcarol@ou-lab.internal` on ou-gw1 (output: `created ... externid=18c7e1ae-...`), IMAPS verified against `gw1-ca.crt`. No gw1 configuration was changed.
Source corpus (`migration/tools/seed_imap_mailbox.py`, deterministic): 337 messages in INBOX 175, Sent 70, Archive/2025 55, `Projekte/Übersicht & Pläne/日本語` 22, Drafts 5, Trash 5, Junk 5; text/HTML/multipart, attachments 20-250 KB, one 5 MB PDF-like attachment, ~20% unseen, ~9% flagged, ~8% answered, dates 2024-2025.

| Step | Result |
|---|---|
| Dry run | `INBOX 175 msgs 10.95 MiB`, `Sent 70 / 1.40`, `Archive/2025 55 / 1.54`, unicode folder 22 / 0.17, Drafts/Trash/Junk 5 each; TOTAL candidates=337 copied=337 (nothing written: target message counts 0) |
| Migration | `migrate: complete`, copied=337 failed=0, 17.7 s wall (~19 msg/s, ~0.7 MB/s; bound by Gromox per-message APPEND) |
| Folder mapping on Gromox | Sent->`Sent Items`, Trash->`Deleted Items`, Junk->`Junk Email`, Drafts->Drafts, `Archive/2025` created under `Archive`, unicode path `Projekte/&ANw-bersicht &- Pl&AOQ-ne/&ZeVnLIqe-` (mUTF-7 on the wire, nested 3 levels) |
| Verification | `verify: OK source=337 target=337`; with `--sample 1000` all 337 bodies hashed, 0 mismatches; 0 missing, 0 extra, 0 flag mismatches; INBOX UNSEEN 35 on both sides; source UNSEEN unchanged (80 after later additions = expected) |
| Delta | +25 new INBOX messages -> second run `candidates=25 copied=25`; third run immediately after: `candidates=0 copied=0` |
| Kill + resume | +200 messages, `kill -KILL` of the running process after ~4 s: state had 449 messages recorded (INBOX hwm 287) while Gromox INBOX already held 288 = one message appended but not yet committed (the worst window). Re-run: `candidates=113 copied=112 adopted=1`, then `verify: OK source=562 target=562`, INBOX 400/400, 562 bodies hashed, 0 bad, 0 extra: no duplicates |

Final state of `migcarol@ou-lab.internal`: 562 messages. The lab machine `ou-msrc1` was powered off afterwards (image kept).
Engine behaviours that are covered by unit tests only (fake IMAP server, `migration/tests/test_engine.py`, no live evidence): lost APPEND acknowledgement, connection drop before APPEND, UIDVALIDITY change,
oversize messages, throttled login with backoff, XOAUTH2 token refresh, state-file/identity binding, credentials absent from output/logs/state.

## 5. How to run (lab)
```
export OU_SRC_PASSWORD_FILE=/path/src.pw OU_DST_PASSWORD_FILE=/path/dst.pw     # 0600 files
python -m ou_migration mail-migrate --src-host H --src-ca ca.pem --src-user carol \
   --dst-host gw1.ou-lab.internal --dst-ca gw1-ca.crt --dst-user migcarol@ou-lab.internal \
   --state job.db --out report/ [--dry-run] [--max-msgs-per-sec 20] [--exclude REGEX]
python -m ou_migration mail-verify <same flags without --state> --sample 50
```
Exit codes: 0 complete, 1 incomplete (failures / oversize skipped) or verify mismatch, 2 usage/credential/fatal.

## 6. Pending (not tested)
* **OAuth2 against real tenants**: Google (domain-wide delegation, `https://mail.google.com/`) and Microsoft 365 (`IMAP.AccessAsApp`, Exchange service principal + mailbox permission) token providers exist and are unit-tested against stubs only; XOAUTH2 framing was tested against the fake server and never against Gmail/Exchange Online. Provider-specific throttling (Gmail daily IMAP bandwidth caps, Exchange `Server Busy`) is handled only generically by the backoff classifier.
* Calendars, contacts, tasks, shared mailboxes, public folders, files (Drive/OneDrive/SharePoint -> OpenCloud), mail rules, delegates, aliases/forwarding: not started.
* Flag/deletion sync of already-copied messages, folder renames after the first run, per-mailbox parallelism and ICS orchestration (jobs, approvals, audit) are not implemented; one mailbox per process.
* Not run live: `--src-security starttls`, servers without UIDPLUS, UTF8=ACCEPT, very large mailboxes (the target folder is fully scanned once per run; memory holds one message at a time, state grows ~100 B/message), Gmail label semantics, source servers that renumber UIDs without changing UIDVALIDITY.
* Gromox-native import path (`gromox-import`/`exm2mt`) for bulk first pass: not exercised for foreign mail.
