# Migration assessment (Phase 7, step 1): read-only pre-migration assessment

Date: 2026-11-15. Component: `migration/` (Python 3.12, stdlib + `cryptography`). ADR-0000 status: **Implementing** (code + fixture tests exist;
nothing has ever run against a real Microsoft 365 or Google Workspace tenant, so nothing here is "Tested" in the ADR-0000 sense).
No data movement exists or is planned in this step. No real tenant credentials were used or are available to the author.

## 1. What exists

| Area | Where | Evidence (executed 2026-11-15, `cd migration && .venv/bin/pytest` -> 52 passed) |
|---|---|---|
| HTTP client: TLS always verified, 429/5xx + `Retry-After` (seconds or date) + exponential backoff with jitter, Google 403 `rateLimitExceeded`/`userRateLimitExceeded` retry, redirects never auto-followed, `http://` refused except loopback in tests, size cap, no headers/bodies/query in logs | `ou_migration/http.py` | `tests/test_http_secrets.py` |
| Credentials: env or `*_FILE` only; secret file must be a regular 0600 file (no symlink); `Redacted` wrapper; tokens in memory only, cached until 60 s before expiry | `secrets.py`, `auth.py` | same + `test_m365.py::test_token_*`, `test_google.py::test_google_auth_from_env_*`; log and output scans for secret/token strings |
| Microsoft 365 collector (Graph v1.0, application permissions): organization, domains, users (+proxyAddresses aliases, licences, guests), groups (distribution / mail-security / M365 / Team / dynamic / security), member counts, mailbox + OneDrive + SharePoint usage reports (302 -> pre-authenticated URL fetched WITHOUT bearer), opt-in sampled `$count` of events/contacts | `sources/m365.py` | `tests/test_m365.py` (paging, 429/503, partial failure, concealed names, resume, deep counts, endpoint allow-list: no `/messages`, `/mailFolders`, `/events` items, `/drive`, `/sites`, content) |
| Google collector (Directory, Reports, optional Gmail metadata + Drive metadata via domain-wide delegation, RS256 JWT) | `sources/google.py` | `tests/test_google.py` (JWT signature verified by the fake token endpoint, scope allow-list failure, Reports date look-back, 403 throttle, resume, sampled deep scan with fields-mask check, suspended users not impersonated) |
| Checkpoint/resume: per-stage completion, paging cursor, collected metadata; atomic 0600 write; bound to provider+tenant; contains no tokens/keys | `checkpoint.py`, `sources/base.py` | resume tests in both collectors; tenant-mismatch refusal |
| Partial failure policy: a failed/forbidden stage is recorded in `coverage`/`warnings`, the run continues, the risk score gets an "incomplete assessment" penalty and lower confidence | `sources/base.py`, `scoring.py` | `test_partial_failure_*`, `test_missing_scope_*`, `test_score_band_and_coverage_penalty` |
| DNS posture per verified domain (MX, SPF, DKIM, DMARC) with a stdlib UDP/TCP DNS client | `dns_check.py` | wire-format parsing incl. compression + loop guard; fake UDP DNS server on loopback |
| Assessment model, every field tagged `verified` / `estimated` / `assumption` (estimates and assumptions must carry a `basis`) | `model.py`, `assess.py` | `test_every_tagged_field_has_valid_tag...` |
| Unsupported-feature mapping against target capability facts (`capabilities.py` mirrors `groupware-lab-results.md`, `ARCHITECTURE.md`, `collaboration-eval.md`) | `capabilities.py` | `test_feature_mapping_uses_target_facts` |
| Identity mapping proposal (UPN/primaryEmail -> LDAP uid/mail, aliases, groups, collisions, guests, disabled, dynamic groups) | `identity.py` | `test_identity_mapping_*` |
| Transfer-time estimate (bandwidth x volume with stated throughput assumptions, range) | `estimate.py` | `test_estimate_formula` |
| Additive complexity/risk score; every fired rule listed with points, evidence, tag | `scoring.py` | `test_score_*` |
| Report: `assessment.json` + self-contained `assessment.html` (inline CSS, no JS, no external assets, escaped, files 0600) | `report.py` | `test_html_is_self_contained_and_escaped`, `test_write_reports_private`, `test_cli_run_end_to_end_*` |
| CLI | `python -m ou_migration assess --provider m365\|google --out DIR [--checkpoint F] [--bandwidth-mbps N] [--deep] [--dns-resolver IP]` | `test_cli_*` |

Fixtures (`migration/tests/fixtures/`, mapping to doc pages in its README) are hand-authored from the official reference examples. They prove our
parsing, paging, throttling and failure handling against the DOCUMENTED shapes; they do not prove the real services behave exactly like their docs.

## 2. Awaiting a real tenant (unverified)

- That each Graph/Google call returns what the docs say for a real tenant, including: report CSV column order/BOM, `$count` on `/members` and `/events` with `ConsistencyLevel: eventual`, `proxyAddresses` availability in `$select`, shape of `assignedPlans[].service` names used in `PLAN_SIGNALS` (e.g. `TeamspaceAPI`, `ProcessSimple` were taken from the doc example/knowledge and are unconfirmed for current plans), Google Reports `accounts:*` availability by date, Gmail `getProfile` under the `gmail.metadata` scope, Drive `files.list` fields mask behaviour for `permissions(type)` (permissions lists can be truncated for heavily shared files).
- Real throttling behaviour and throughput at scale (no throughput was measured; the estimate uses assumptions). Large-tenant memory: users/groups are held in memory and in the checkpoint JSON (fine for tens of thousands; not tested beyond fixtures).
- The Google fixtures were written from the documented resource representations without re-fetching every reference page in this session (only scopes and `accounts:*` parameter names were checked directly); re-validate on first real run.
- DNS checks against real public DNS (the test resolver is a loopback fake; the code has never queried a real resolver).
- Concealed-name detection heuristic (`"@" not in name`), shared-mailbox heuristic, and group `has_team` detection.
- Whether `Mail.ReadBasic.All` folder counts or Exchange Online PowerShell should supply per-mailbox item counts (not implemented: item counts come from `--deep` (Google) or are estimated from bytes (M365)).

## 3. Required permissions (minimum, read-only) and sources

Verified against Microsoft Learn / Google developer pages fetched 2026-11-15 unless marked.

### Microsoft 365 (Entra app registration, application permissions, admin consent, client credentials)
| Need | Endpoint | Application permission | Source |
|---|---|---|---|
| tenant, verified domains, assigned plans | `GET /organization` | `Organization.Read.All` (least privileged application permission; `User.Read` returns only id/displayName/verifiedDomains and is delegated-only) | https://learn.microsoft.com/en-us/graph/api/organization-list?view=graph-rest-1.0 |
| domains, verification state, supported services | `GET /domains` | `Domain.Read.All` (least privileged) | https://learn.microsoft.com/en-us/graph/api/domain-list?view=graph-rest-1.0 |
| users, aliases, licences, type | `GET /users` | `User.Read.All` (least privileged application permission) | https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0 |
| groups / DLs | `GET /groups` | `Group.ReadBasic.All` listed as a lower-privileged alternative to `Group.Read.All` | https://learn.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0 (permission table lists `Group.ReadBasic.All`, `GroupMember.Read.All`, `Group.Read.All`, `Directory.Read.All`) |
| group member counts | `GET /groups/{id}/members/$count` | `GroupMember.Read.All` (listed for group list; for the members endpoint confirm on a real tenant: UNVERIFIED) | same page; members reference not fetched |
| mailbox size, item count, archive flag | `GET /reports/getMailboxUsageDetail(period='D30')` | `Reports.Read.All` (only application permission offered) | https://learn.microsoft.com/en-us/graph/api/reportroot-getmailboxusagedetail?view=graph-rest-1.0 |
| OneDrive bytes, file count | `GET /reports/getOneDriveUsageAccountDetail(period='D30')` | `Reports.Read.All` | https://learn.microsoft.com/en-us/graph/api/reportroot-getonedriveusageaccountdetail?view=graph-rest-1.0 |
| SharePoint bytes, file count, template | `GET /reports/getSharePointSiteUsageDetail(period='D30')` | `Reports.Read.All` | https://learn.microsoft.com/en-us/graph/api/reportroot-getsharepointsiteusagedetail?view=graph-rest-1.0 |
| (opt-in `--deep`) event / contact counts | `/users/{id}/events/$count`, `/contacts/$count` | `Calendars.Read`, `Contacts.Read` (UNVERIFIED in this session; these can read content tenant-wide, so scope them with an Exchange application access policy / RBAC for Applications, not verified here) | not fetched |

Requested set (core): `User.Read.All, Group.ReadBasic.All, GroupMember.Read.All, Organization.Read.All, Domain.Read.All, Reports.Read.All`.
Deliberately NOT requested: `Mail.*`, `MailboxSettings.Read`, `Sites.Read.All`, `Files.Read.All` (all can read content or are not needed because usage reports give volumes without reading content). Consequence: no delegations/permissions, no per-site list/page/workflow inventory, no per-file sharing, no retention/eDiscovery state (all reported as limits / "not assessed", never silently zero).
Report notes (same Learn pages): the three report endpoints answer `302 Found` to a pre-authenticated URL valid for minutes that needs no `Authorization` header (implemented and tested); not available in US Gov / China clouds per the page's table; usage reports honour the tenant setting that conceals user/site names (detected and flagged; ask the admin to switch it off for the duration of the assessment). Throttling: 429 with `Retry-After` per https://learn.microsoft.com/en-us/graph/throttling (that page recommends Graph Data Connect for bulk extraction; not used, it needs Azure resources). Auth flow: client credentials, `scope=https://graph.microsoft.com/.default` (https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow, not re-fetched).

### Google Workspace (service account + domain-wide delegation; admin allow-lists the scopes)
| Need | API | Scope |
|---|---|---|
| customer id / primary domain | Directory `customers.get` | `https://www.googleapis.com/auth/admin.directory.customer.readonly` |
| domains + aliases | Directory `domains.list` | `.../admin.directory.domain.readonly` |
| users, aliases, admin flag, suspended | Directory `users.list` | `.../admin.directory.user.readonly` |
| groups + member counts | Directory `groups.list` | `.../admin.directory.group.readonly` |
| room/resource calendars (optional) | Directory `resources.calendars.list` | `.../admin.directory.resource.calendar.readonly` |
| per-user Gmail/Drive storage | Reports `usage/users/all/dates/{date}` parameters `accounts:gmail_used_quota_in_mb`, `accounts:drive_used_quota_in_mb`, `accounts:used_quota_in_mb` | `.../admin.reports.usage.readonly` |
| (opt-in `--deep`) message count | Gmail `users.getProfile` | `.../gmail.metadata` (UNVERIFIED that getProfile is allowed under metadata scope) |
| (opt-in `--deep`) file count, size buckets, shared/anyone-link counts, Forms/Sites/Script counts | Drive `files.list` with `fields=nextPageToken,files(size,shared,mimeType,permissions(type))` (no names/content) | `.../drive.metadata.readonly` |

Sources fetched this session: scope URLs https://developers.google.com/workspace/admin/directory/v1/guides/authorizing ; report parameter names https://developers.google.com/workspace/admin/reports/v1/reference/usage-ref-appendix-a/users-accounts ; quota/backoff guidance https://developers.google.com/workspace/admin/directory/v1/limits (cited by `http.py`; not re-fetched). Reports data lags days; the collector walks back from today-2 up to 6 days. Not collected: shared drives, Vault holds, Calendar/Contacts counts (no content-free API; Calendar/People need `calendar.readonly`/`contacts.readonly`), sharing of Drive beyond the sample.

## 4. Data handling
Stored: ids, logins/emails/aliases, display names, group names/mail, site URLs, sizes and counts, DNS records, sampled counts. Never stored: message/event/contact/file content, file names, tokens, secrets, private keys. Reports and checkpoints contain directory identities and site URLs (personal data): both are written 0600, report is for the MSP/customer only. `--deep` impersonates sampled users via DWD (visible in Google admin audit logs) and, for M365, requires content-capable permissions: use only with customer consent.

## 5. Limits (also embedded in every report)
Reports are 1-3 days stale snapshots; mailbox item counts are estimated unless `--deep`; delegations, shared-mailbox type (heuristic only), retention/legal hold/Vault, mail-flow rules, connectors, per-site lists/pages/workflows and per-file permissions are not assessed; transfer times use operator assumptions (defaults: 100 Mbit/s, 70% efficiency, 4 streams x 1.5 MB/s), range 0.6x-2.5x, initial sync only; target capability statuses are lab facts dated 2026-11-15 (`unproven` = untested, not unsupported). The score measures effort/risk, not suitability. Single-threaded collection (simple, throttle-friendly; slow for >50k users).

## 6. Next
ICS integration contract: `docs/status/migration-ics-contract.md` (design only; nothing wired). First real-tenant run (an MSP test tenant) is the gate to move this component to "Integrated in lab"/"Tested".
