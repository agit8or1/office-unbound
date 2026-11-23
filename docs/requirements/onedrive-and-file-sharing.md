# OneDrive parity: personal drives, sharing, desktop sync and collaborative documents

**Status: PLANNED / NOT IMPLEMENTED (planning only).** Requirements document (2026-11-23). Not authorized for development; the
current roadmap and the beta directive keep priority until the owner explicitly authorizes this work. Rows marked
`integrated_lab` describe a lab-proven primitive only (linked evidence); everything else does not exist in Office Unbound today.
Status values follow [ADR-0000](../adr/0000-status-values.md).

Requirement prefix: **ODB-**. Related documents (other owners, cross-referenced by prefix): SPO- team libraries and sites
([sharepoint-and-team-libraries.md](sharepoint-and-team-libraries.md)); GRP- unified groups, F2 authorization and revocation
([unified-groups-and-permissions.md](unified-groups-and-permissions.md)); ENT- identity and desktop sign-in ([entra-identity-parity.md](entra-identity-parity.md)); MDM- enrollment and
mobile apps ([intune-and-mobile-mdm.md](intune-and-mobile-mdm.md)); WIPE- revoke/selective/full wipe ([mobile-remote-wipe-security.md](mobile-remote-wipe-security.md)); EXO- mail and
calendar ([calendar-and-mailbox-delegation.md](calendar-and-mailbox-delegation.md)); everything else ([m365-feature-parity.md](m365-feature-parity.md)). Priority tags: **A** business-ready
collaboration, **B** mobile security, **C** Entra/Intune expansion, **D** wider Microsoft 365. PDF Studio (P9) stays last.

## 1. Scope

Functional and workflow parity with OneDrive for Business and the document-collaboration parts of Microsoft 365 (not protocol
compatibility): personal drives, sharing, the desktop sync client, mobile file access and browser co-editing. Out of scope here:
team/department libraries and sites (SPO-), group objects and the central authorization API (GRP-), device enrollment and wipe
(MDM-, WIPE-), PDF editing (P9), advanced Office fidelity ([P10.8](../roadmap/post-core-expansion.md#p108-advanced-office-document-functionality-word--excel--powerpoint--xl-continuous)).

Principles:

1. **Reuse before build.** OpenCloud is the only file store ([ADR-0005](../adr/0005-files-documents.md)); Collabora (own build,
   "Office Unbound Docs") is the only editor, reached over WOPI. Upstream OpenCloud features are configured first; custom code
   only fills documented gaps, preferably as upstream-friendly patches or as separate services that call OpenCloud's APIs.
2. **One identity.** OpenLDAP is authoritative, Keycloak issues tokens; OpenCloud reads LDAP read-only
   (`OC_LDAP_SERVER_WRITE_ENABLED=false`, no autoprovisioning). Guests are directory objects created by the ICS, not a second store.
3. **Server-side authorization.** Every permission, policy and link restriction is enforced by OpenCloud (or by an Office
   Unbound service through F2), never only in a UI.
4. **Per-customer stacks.** Tenant isolation is by separate deployment ([tenant-isolation-results.md](../status/tenant-isolation-results.md));
   cross-tenant sharing is off unless explicitly authorized.
5. **Honest limits.** View-without-download, revocation of already-downloaded copies and placeholder behaviour differ by
   platform and are documented, never overstated.

## 2. Existing-state audit

Upstream OpenCloud capabilities listed as "upstream, not verified" come from OpenCloud/oCIS documentation and release notes
([files-identity-eval.md](../status/files-identity-eval.md)); no Office Unbound test has exercised them.

| Capability | What exists today (evidence) | Status |
|---|---|---|
| Personal drive per user | OpenCloud personal space, visible after ICS user create (`opencloud.visible` step, [user-lifecycle-results.md](../status/user-lifecycle-results.md)); Graph `/me/drive` used by the portal ([portal-results.md](../status/portal-results.md)) | integrated_lab |
| Upload/download, folders, rename, delete (WebDAV) | T02 11/0: MKCOL, PUT/GET with sha256 identity (incl. a large file), PROPFIND, MOVE, delete, data survives restart ([identity-files-lab-results.md](../status/identity-files-lab-results.md)) | integrated_lab |
| Version history and restore | T05 9/0: list, restore, restore is itself versioned; Collabora save creates a version (T04) | integrated_lab |
| Backup/restore of the files tier incl. versions | Restore to a separate machine, content and version history byte-identical ([restore-drill-results.md](../status/restore-drill-results.md)); restic per-customer encrypted repositories ([backup-product-results.md](../status/backup-product-results.md), [backup-isolation-results.md](../status/backup-isolation-results.md)) | tested (whole tier, lab) |
| Browser editing (DOCX/XLSX/PPTX) via WOPI | T03 28/0, T04 13/0 headless; own unlimited build, 60 sessions on one document loaded, 30 documents ([docengine-build-results.md](../status/docengine-build-results.md)); multi-user co-editing, browser UI not tested | integrated_lab |
| Web file manager with SSO | Portal launcher opens OpenCloud Web without second login; recent files via search by mtime (no Graph "recent" endpoint in 9.1) ([portal-results.md](../status/portal-results.md)) | integrated_lab |
| Internal user share | Graph `invite` with a viewer role between two users of one tenant (control step F06 of `blueprints/lab/tests/t20_tenant_isolation.py`) | integrated_lab (API only) |
| Project space creation | Graph `POST /drives` (t20 seed) | integrated_lab (API only) |
| Password-protected public link | Graph `createLink` type view + password; OpenCloud enforces link passwords; cross-tenant use refused (t20 F-section) | integrated_lab (API only) |
| Cross-tenant denial (files) | 42 PASS / 0 FAIL: foreign drive/space/file ids, public-link tokens, share-into-other-tenant all refused ([tenant-isolation-results.md](../status/tenant-isolation-results.md)) | tested (lab, identity+files tier) |
| Disabled user loses file access | Old access token refused 5-13 s after disable; app tokens revoked by ICS; Keycloak refresh tokens need explicit revoke (KI-2) ([lifecycle-gaps-results.md](../status/lifecycle-gaps-results.md)) | integrated_lab |
| Desktop sync engine | T07 11/0 with `opencloudcmd` 4.0 (Linux, headless, app token): two-way, offline reconcile, conflict copy, delete; GUI client, OIDC login, VFS, Windows/macOS not tested | integrated_lab |
| Desktop/mobile discovery | WebFinger client ids configured in the OpenCloud env; OIDC clients registered (T01); never exercised from a GUI client | planned |
| Guest role | LDAP group `opencloudGuest` maps to OpenCloud guest role (T01: user dave) | integrated_lab (role only) |
| Upstream, not verified: space quotas, trash bin per space, search service (+Tika content), tags, thumbnails, antivirus (ClamAV/ICAP), postprocessing, activity log, notifications (email), audit service, link types (view/edit/upload/create-only/blocks-download), share expiration, "shared with me / with others / via link" views, Windows VFS in the desktop client, Android/iOS apps, OCM federation, email-based guest access (9.0) | none | researching |
| Not deployed: ClamAV, Tika, thumbnails service | [known-limitations.md](../admin/known-limitations.md), identity-files §6 | planned |
| Per-user storage quota admin | Labelled Planned: no OpenCloud admin identity for the ICS ([org-admin-results.md](../status/org-admin-results.md)) | planned |
| File migration from OneDrive | Not started (assessment collects usage only, [migration-engine-results.md](../status/migration-engine-results.md)) | planned |

## 3. Requirements

Column "Implementation" says which component and whether the work is **configure** (upstream feature, settings and tests),
**integrate** (upstream component added to the stack) or **build** (Office Unbound code or upstream patch).

### 3.1 Personal drives (ODB-D)

| ID | Requirement | Microsoft equivalent | Proposed Office Unbound implementation | Status | Priority | Dependencies | Acceptance criteria |
|---|---|---|---|---|---|---|---|
| ODB-D01 | Every user (any number, no cap) gets a personal drive automatically at account creation | OneDrive provisioning | OpenCloud personal space; ICS lifecycle create already verifies visibility. Configure | integrated_lab | A | - | Creating 50 users through the ICS yields 50 personal drives reachable by their owners only; no per-user setting needed |
| ODB-D02 | Storage quotas: tenant default, per-user override, usage visible to user and admin, warnings at thresholds | OneDrive storage quota | OpenCloud space quota; ICS typed action `files.quota.set` through a dedicated least-privilege OpenCloud service identity. Configure + build (ICS action) | planned | A | ODB-A01 | Upload that would exceed quota is refused server-side with a clear error and leaves no partial file; usage shown in web UI and ICS within 5 min; 80/95 % warnings delivered |
| ODB-D03 | Web file manager, Office Unbound branded, reached from the portal with SSO | OneDrive web | OpenCloud Web with theme; portal launcher. Configure | integrated_lab | A | - | Browser test: portal → files with no second login; branding shows no upstream name on main views |
| ODB-D04 | Browser upload and download of files and whole folders, drag and drop from the OS | OneDrive web upload | OpenCloud Web (upstream). Configure + browser tests | researching | A | ODB-D05 | Playwright test drags a folder of 200 files incl. sub-folders; all arrive with identical hashes; folder download arrives as archive |
| ODB-D05 | Large and resumable transfers (at least 50 GB file; resume after network loss) on web, desktop, mobile | Large file upload | OpenCloud TUS uploads; gateway/nginx body and timeout limits removed for upload paths. Configure | researching | A | - | 50 GB upload interrupted twice resumes without restarting from zero; final sha256 matches; same over the public gateway |
| ODB-D06 | Folder operations: create, rename, move, copy, delete | OneDrive folder ops | OpenCloud (WebDAV verified). Configure | integrated_lab | A | - | T02 extended with COPY and move across spaces; UI test for each operation |
| ODB-D07 | Bulk operations: multi-select move, copy, delete, download, share | OneDrive multi-select | OpenCloud Web multi-select, archiver service. Configure | researching | A | ODB-S01 | Select 500 items, move them, then delete them; all succeed or the UI reports each failure; trash contains all 500 |
| ODB-D08 | Previews and thumbnails: images, PDF, office documents, video poster frames | OneDrive previews | OpenCloud thumbnails service (integrate); office previews via Collabora convert-to. Integrate | planned | A | - | Thumbnails for jpg/png/pdf/docx/xlsx/pptx render in list and grid view; previews respect permissions (no thumbnail URL works for a non-member) |
| ODB-D09 | Recent files | OneDrive Recent | Portal search by mtime (exists); OpenCloud Web view. Configure | integrated_lab | A | - | File edited by the user appears first in Recent within 1 min; files the user cannot access never appear |
| ODB-D10 | Favorites (star) | OneDrive favourites | Verify OpenCloud Web favourites; otherwise portal-side favourites stored per user. Configure or build | researching | A | - | Starred file shows in Favorites across web sessions and devices; unstarring removes it |
| ODB-D11 | Pinned items (pinned to top of a folder or to the portal home) | Pinned / Quick access | Portal feature storing pins per user (build) | planned | D | ODB-D10 | User pins 3 items; they show on the portal home; an item the user lost access to disappears |
| ODB-D12 | Search by name, metadata and content (Office, PDF, text), permission-trimmed | OneDrive search | OpenCloud search service + Apache Tika for content (integrate); cross-application search later via F4. Integrate | researching | A | ODB-D13 | A word that occurs only inside a DOCX is found by its owner and by a user it is shared with, and not by any other user, via UI and API |
| ODB-D13 | Metadata and tags on files and folders, searchable | OneDrive tags / properties | OpenCloud tags (upstream); custom columns are SPO-L. Configure | researching | A | - | Tag set in web is visible on other devices, searchable, and removable; tags of foreign items never appear in tag suggestions |
| ODB-D14 | Version history and restore, version retention policy (count/age) | Version history | OpenCloud versions (verified); retention settings to verify. Configure | integrated_lab | A | ODB-A03 | T05 plus UI test: restore of version N keeps current as a version; retention policy of 50 versions prunes the 51st oldest, and that pruning is logged |
| ODB-D15 | Recycle bin: user restore, configurable retention (default 93 days), permanent purge by owner/admin | Recycle bin (two stages) | OpenCloud trash per space (upstream); retention purge job if not upstream. Configure, build if needed | researching | A | ODB-A03 | Deleted folder restored with its tree and versions; items older than retention purged automatically; purge audited |
| ODB-D16 | Admin-assisted recovery: an admin restores a user's deleted item, folder or whole drive to a point in time | Admin restore / OneDrive restore | ICS typed action restoring from trash, versions or restic snapshot into the original or a recovery folder; item-level restore from backup is new. Build | planned | A | ODB-A01, ODB-A05 | Admin restores one folder deleted 10 days ago (past trash) from backup into a recovery folder; hashes match; audit shows requester, approver, items |
| ODB-D17 | Ownership transfer of files/folders between active users | Move files / transfer | Copy-and-reassign into the target's drive or a space via ICS typed action (OpenCloud has no owner-change primitive, to verify). Build | planned | A | ODB-A01 | Transfer of a 1,000-file folder keeps content, versions (or documents their loss), shares are re-created or reported; source owner loses access only if requested |
| ODB-D18 | Former-employee retention: drive kept for a tenant-defined period after offboarding; manager or delegate gets access via an audited action; deletion at period end | OneDrive retention for deleted users, manager access | ICS offboarding step: disable user (existing), move the personal drive content into an "Archive – user" project space with the delegate as manager, schedule deletion. Build | planned | A | ODB-D17, GRP- | Acceptance test ODB-AT-02 passes; no item that others shared with the leaver becomes visible to the delegate |
| ODB-D19 | Access from desktop and mobile | OneDrive apps | Desktop client (ODB-C), mobile apps (ODB-M). Configure | integrated_lab (desktop engine only) | A | ODB-C01, ODB-M01 | see ODB-C and ODB-M rows |
| ODB-D20 | Malware scanning of uploads (all paths: web, sync, mobile, public upload links) with quarantine and owner notice | Defender for Office 365 / built-in malware detection | OpenCloud antivirus + postprocessing services with ClamAV (integrate, own build per ADR-0007). Integrate | planned | A | - | EICAR file uploaded through each path is blocked or quarantined, never downloadable, uploader and admin notified; clean files unaffected; signature updates monitored by ICS |
| ODB-D21 | Ransomware recovery: detect mass modification/deletion, alert, restore a drive to a point in time | OneDrive files restore | Detection from OpenCloud events (activity/audit stream, rate of renames/rewrites per user), ICS alert; restore through versions/trash or restic. Build | planned | A | ODB-D16, ODB-A05 | ODB-AT-11 passes |
| ODB-D22 | Retention policies and legal hold: keep content for N years, block or record deletion | Microsoft Purview retention | F5 hooks in OpenCloud (deny delete or copy to immutable store), defined in P10.5. Build (upstream patch) | planned | D | F5, P10.5 | Item under hold: user delete appears to succeed or is refused per policy, but content remains retrievable by compliance admin; hold release re-enables purge |
| ODB-D23 | Activity and access history per item (created, viewed, edited, downloaded, shared) for owner and admin | File activity / access stats | OpenCloud activity log (upstream, verify scope; view/download events may need a patch). Configure + build | researching | A | ODB-A04 | Owner sees who edited and shared an item; admin sees who downloaded it; events of other tenants never appear |
| ODB-D24 | Encryption in transit everywhere (browser, sync, mobile, WOPI, internal hops) | TLS | TLS 1.2+ at gateway and between tiers (lab CA verified, Let's Encrypt at the gateway). Configure | integrated_lab | A | - | TLS scan of every exposed and internal files endpoint: no plain HTTP except loopback; certificate verification never disabled |
| ODB-D25 | Encryption at rest for file data and backups, keys per customer | Service encryption | Encrypted VM data disk (LUKS) or encrypted ZFS dataset on Proxmox (decision); backups already per-customer restic encryption. Configure | planned | A | - | Raw disk image of the files VM contains no readable file content; restic key of A cannot open B (already proven for backups) |
| ODB-D26 | Auditable access: tenant-visible, exportable, tamper-evident log of file access, sharing and admin actions | Unified audit log | OpenCloud audit service → per-tenant log store with hash chain (ICS pattern); export CSV/JSON. Integrate + build | planned | A | ODB-A04 | Log of a test session contains every action of ODB-AT-01 with actor, item, time, IP; altering one record is detected by verification |

### 3.2 Sharing (ODB-S, mandatory)

All rules are evaluated by OpenCloud's share manager and frontend capabilities (server-side); Office Unbound policy settings are
pushed as OpenCloud configuration or enforced by an Office Unbound policy service in front of the share API only where OpenCloud
lacks the rule (gap noted per row).

| ID | Requirement | Microsoft equivalent | Proposed Office Unbound implementation | Status | Priority | Dependencies | Acceptance criteria |
|---|---|---|---|---|---|---|---|
| ODB-S01 | Share a file or folder with one internal user | Share with people | OpenCloud Graph `invite` (verified in t20). Configure | integrated_lab | A | - | ODB-AT-01 steps 1-3 |
| ODB-S02 | Share with several users in one action | Share with multiple people | OpenCloud invite with several recipients. Configure | researching | A | ODB-S01 | One share action with 5 recipients creates 5 grants and 5 notifications |
| ODB-S03 | Share with groups (directory groups and unified groups); membership changes apply automatically | Share with M365 group / security group | OpenCloud group shares over LDAP `groupOfNames`; unified groups from GRP-. Configure | researching | A | GRP- | User added to the group gains access within 5 min, removed user loses it within 5 min (server denies) |
| ODB-S04 | Share with the whole organisation ("people in your organisation" link) | Organisation link | OpenCloud internal link type (requires sign-in, tenant only). Configure | researching | A | - | Link opens for any signed-in tenant user, not for anonymous users nor users of another tenant |
| ODB-S05 | Share with external guests by e-mail; guest signs in with an account Office Unbound creates (directory guest, MFA or e-mail one-time code) | B2B guest sharing | ICS guest invitation action creates an LDAP guest (role `opencloudGuest`) and sends the invite; evaluate OpenCloud 9 e-mail guest service against the single-store rule. Build (ICS + invite page) | planned | A | ENT-, ODB-S25, ODB-S26 | Guest receives mail, sets credentials/MFA, sees only the shared item, cannot browse the directory or see other users' names beyond the share |
| ODB-S06 | Cross-tenant sharing between two Office Unbound tenants when both admins authorize it | Cross-tenant access settings | OCM federation (OpenCloud upstream, to verify) with explicit per-tenant trust allowlist; default off. Configure + build (trust policy in ICS) | researching | D | ODB-S24 | Without trust: share to the other tenant refused (t20 already proves). With mutual trust: share works and is revocable; third tenant still refused |
| ODB-S07 | Anonymous public links where tenant policy allows | Anyone link | OpenCloud public links (password-protected link verified). Configure | integrated_lab | A | ODB-S24 | With policy "off" the API refuses link creation (not only hidden in UI); with "on" link works without sign-in |
| ODB-S08 | Named-recipient links: only the named person can open (internal sign-in or external verified by e-mail code) | Specific people link | Internal: user share + direct link. External: guest account (ODB-S05) or a small verification service issuing short-lived access. Build | planned | A | ODB-S05 | Forwarded link opened by another person is refused; named recipient succeeds |
| ODB-S09 | Permission: view (read-only) | Can view | OpenCloud viewer role. Configure | integrated_lab | A | ODB-S01 | Viewer gets 403 on PUT/DELETE/MOVE via WebDAV, Graph and WOPI (editor opens read-only) |
| ODB-S10 | Permission: view without download where enforceable | Can view, block download | OpenCloud "blocks download" link type / secure-viewer role with Collabora watermark and disabled export/print (upstream, verify). Configure. Documented limit: screenshots and screen capture cannot be prevented | researching | A | ODB-E01 | WebDAV GET, archive download and Collabora export/print/copy are refused; viewer still reads in browser; UI states the limit |
| ODB-S11 | Permission: edit | Can edit | OpenCloud editor role. Configure | researching | A | ODB-S01 | Editor changes content in browser and via sync; cannot change sharing unless allowed by policy |
| ODB-S12 | Permission: upload (folder contributor, can see and add) | Can edit (folder) / add | OpenCloud uploader role. Configure | researching | A | - | Uploader adds files, cannot delete others' files if policy says so |
| ODB-S13 | Upload-only file request: external or internal people drop files, cannot see folder contents | Request files | OpenCloud create-only (file drop) link. Configure | researching | A | ODB-D20 | Dropper uploads 3 files, listing returns nothing, uploaded files are virus-scanned and owner notified |
| ODB-S14 | Expiration on shares and links; tenant default and maximum | Link expiration | OpenCloud expiration on shares/links; tenant max enforced by capabilities or policy service (gap check). Configure, build if needed | researching | A | ODB-S24 | Expired link/share denied at the server within 1 min of expiry; a link with expiry beyond the tenant maximum is refused by the API |
| ODB-S15 | Passwords on links; password policy | Link password | OpenCloud link password enforcement (verified) and password policy settings. Configure | integrated_lab | A | - | Link without password refused when policy requires it; weak password refused; brute force rate-limited at the gateway |
| ODB-S16 | Notifications: recipients get e-mail and in-app notice; optional message; owner informed of access requests | Share notifications | OpenCloud notifications service over Gromox SMTP; Matrix bot optional later. Configure | researching | A | EXO- (mail delivery) | Share creates a mail with item name, sharer and link within 2 min; can be suppressed per share |
| ODB-S17 | Inheritance: a folder share covers its contents, including items added later | Permission inheritance | OpenCloud behaviour. Configure | researching | A | - | File added after sharing the folder is readable by the recipient without a new share |
| ODB-S18 | Overrides: grant more on a sub-item; restrict a sub-item below the inherited level | Stop inheriting / unique permissions | Broadening: separate share (upstream). Narrowing below inherited access is not an OpenCloud concept (to verify): option of moving to a separate space, or upstream patch. Build or decision | researching | A | SPO-P | Broadened sub-item works; restricted sub-item (if adopted) is denied to the parent's recipients via every API |
| ODB-S19 | Prevent reshare (default) and allow reshare where owner/policy permits | Allow editing to share | OpenCloud has no resharing since the oCIS 5 line (to verify): prevent = native; allow = owner adds people, or patch. Configure | researching | A | - | Recipient cannot create shares or links on a shared item by any API when resharing is off |
| ODB-S20 | Revoke a share or link; effective server-side immediately | Stop sharing | OpenCloud share/link delete. Configure | researching | A | - | ODB-AT-01 steps 5-7: next request after revoke is denied (<= 60 s including caches) on web, WebDAV, desktop and mobile |
| ODB-S21 | Who has access: per item list of direct, inherited, group, space and link access; admin view | Manage access | OpenCloud permissions listing (Graph); portal "Manage access" panel aggregates. Configure + build | researching | A | GRP- | List matches the actual effective access computed by a test oracle over 20 sharing combinations |
| ODB-S22 | Shared with me, shared by me, shared via link views | Shared view | OpenCloud Web views (upstream). Configure | researching | A | - | Each view lists exactly the expected items for a seeded scenario |
| ODB-S23 | Access requests: denied user asks for access, owner approves/denies in one click | Request access | Not in OpenCloud (to verify). Build: request page and service recording requests, owner notification, approval calls the share API as the owner | planned | A | ODB-S16, F2 | Request reaches owner; approve grants the chosen role; deny is recorded; requester cannot approve own request |
| ODB-S24 | Sharing policies: owner per-share settings; tenant admin policy (allowed share types, external sharing on/off, link defaults and limits, password rules, default role), enforced server-side | SharePoint admin sharing settings | OpenCloud capabilities/config managed by ICS typed action `files.sharing_policy.set`; gaps filled by an Office Unbound policy service (OpenCloud policies service/OPA to evaluate). Configure + build | planned | A | ODB-A01 | Each policy switch, set in the ICS, changes API behaviour (tested by direct API calls bypassing UI) within 5 min |
| ODB-S25 | External domain allow and block lists | Domain allow/block | Enforced in the ICS guest invitation action and in the link/share policy service. Build | planned | A | ODB-S05 | Invite to blocked domain refused; allowlist mode refuses every other domain |
| ODB-S26 | Guest expiration and periodic review | Guest expiration / access reviews | Guest accounts carry an expiry; ICS reconcile disables expired guests (same disable path as users). Build | planned | A | ODB-S05, GRP- | Guest past expiry denied on all paths within 10 min; owner receives review reminder 14 days before |
| ODB-S27 | Sharing audit: every create/modify/revoke/link use recorded with actor, target, role, expiry | Audit log | OpenCloud audit/events into ODB-D26 store. Integrate | planned | A | ODB-D26 | ODB-AT-15 |
| ODB-S28 | Shared folders and items appear in desktop sync and can be synced | Add shortcut to My files | OpenCloud desktop syncs spaces and the shares space (upstream, verify). Configure | researching | A | ODB-C05 | Folder shared with B appears in B's client; edit permission syncs both ways; view permission is read-only locally |
| ODB-S29 | Admin incident actions: list and bulk-revoke all external shares/links of a user or tenant | Sharing reports | ICS typed action over OpenCloud share APIs. Build | planned | A | ODB-S24 | Report lists every external share; bulk revoke disables all within 5 min; audited |

### 3.3 Share experience (ODB-U)

Required flow (owner, 2026-11-23): **(1)** right-click a folder (or file; on mobile, long-press); **(2)** select **Share**; **(3)** enter a
person, group or external e-mail address (picked from the directory where it is internal); **(4)** select **View**, **Edit** or another
authorized permission (Upload only, View without download where enforceable); **(5)** set optional expiration or restrictions (policy defaults
pre-filled: password, allow reshare, notify); **(6)** click **Share**. The recipient then sees the resource automatically under *Shared with me*
in the appropriate Office Unbound interface. Users never configure WebDAV, LDAP permissions or backend components.

| ID | Requirement | Microsoft equivalent | Proposed Office Unbound implementation | Status | Priority | Dependencies | Acceptance criteria |
|---|---|---|---|---|---|---|---|
| ODB-U01 | The six-step share flow above in the web file manager | Share dialog | OpenCloud Web share panel, adjusted by theme or patch to fit the six steps. Configure, build if needed | planned | A | ODB-S01..S16 | Usability test: 5 non-technical testers share a folder with a colleague with edit rights in <= 6 steps without help |
| ODB-U02 | Same flow from the desktop shell (context menu "Share…", "Copy link", "Version history") | OneDrive shell menu | OpenCloud desktop client shell extension (upstream on Windows/macOS, verify; Linux via Nautilus/Dolphin plugins). Configure, build where missing | researching | A | ODB-C12 | On each OS, right-click → Share opens the six-step dialog (native or web) already signed in |
| ODB-U03 | Same flow from mobile share sheet | OneDrive mobile share | OpenCloud Android/iOS apps (upstream). Configure | researching | B | ODB-M01 | Share from phone creates the same grant as from web |
| ODB-U04 | People picker shows only same-tenant users, groups and existing guests; external e-mail allowed only if policy permits | People picker | OpenCloud user search over the tenant LDAP (per-customer stack). Configure | researching | A | ODB-S24 | Search for a name existing only in another tenant returns nothing |
| ODB-U05 | Plain-language policy errors (e.g. "External sharing is turned off by your administrator") | Policy tips | OpenCloud Web strings/patch. Configure + build | planned | A | ODB-S24 | Every refused share in ODB-AT tests shows a human-readable reason, no HTTP codes |
| ODB-U06 | Zero manual server configuration on any client: onboarding from the e-mail address or a portal link | OneDrive sign-in | WebFinger discovery + OIDC (ODB-C03). Configure | planned | A | ODB-C03 | A tester only enters e-mail and password/MFA on each client |

### 3.4 Desktop sync (ODB-C, Windows, macOS, Linux)

Base: OpenCloud Desktop 4.x (sync engine proven headless as `opencloudcmd`). Placeholder support depends on OS APIs; identical
behaviour across platforms is **not** promised.

| ID | Requirement | Microsoft equivalent | Proposed Office Unbound implementation | Status | Priority | Dependencies | Acceptance criteria |
|---|---|---|---|---|---|---|---|
| ODB-C01 | Signed clients and updates for Windows, macOS, Linux | OneDrive client | Option 1: upstream OpenCloud signed builds (zero cost). Option 2: rebranded build signed by Office Unbound (Authenticode, Apple Developer ID + notarization: costs, section 7). Linux: signed repository / AppImage signature. Configure or build | planned | A | owner decision 1 | Installer passes SmartScreen/Gatekeeper without bypass; signature chain verified in CI; update channel signed |
| ODB-C02 | One-click onboarding: download from the portal, or mass deployment (MSI/PKG) with preset server | OneDrive setup / silent config | Portal download page; MSI properties / config file; mass deployment via rem0te or MDM-. Configure + build (portal page) | planned | A | ODB-C03, MDM- | New user installs and is syncing in < 3 min with only e-mail + password/MFA |
| ODB-C03 | Server discovery from the user's e-mail address or organisation domain | Auto discovery | OpenCloud WebFinger (configured, untested) on the tenant domain via gateway. Configure | planned | A | - | Entering `user@customer.tld` finds the right tenant; no URL typed |
| ODB-C04 | SSO with Keycloak incl. MFA; tokens revocable | Modern auth | OIDC client `OpenCloudDesktop` (registered, T01). Revocation through Keycloak revoke (KI-2) and app-token revoke. Configure | planned | A | ENT- | Login uses browser with MFA; after ICS disable the client stops syncing within 5 min and shows "signed out" |
| ODB-C05 | Two-way sync | Sync | OpenCloud desktop (engine verified T07). Configure | integrated_lab | A | - | T07 on GUI clients of all three OS |
| ODB-C06 | Selective sync (choose folders/spaces) | Choose folders | Upstream. Configure | researching | A | - | Unselected folder never downloaded; reselecting downloads it |
| ODB-C07 | Offline files: mark "always keep on this device" | Always keep on device | Upstream VFS pinning (Windows). Configure | researching | A | ODB-C08 | Pinned files open with network disconnected |
| ODB-C08 | Files On-Demand placeholders | Files On-Demand | Windows: Cloud Files API (cfapi), OpenCloud VFS upstream since 3.0, verify. macOS: File Provider extension, research upstream state. Linux: no OS placeholder API; options (a) full sync only, (b) suffix placeholder files, (c) FUSE mount (e.g. rclone, MIT) as separate optional tool. Research then configure/build | researching | A | ODB-C01 | Windows: 10 GB tree visible using < 100 MB disk, file hydrates on open, "free up space" dehydrates; macOS/Linux: documented behaviour matches tests |
| ODB-C09 | Conflict handling without data loss | Conflict resolution | Upstream conflict copies (verified T07). Configure; UI to resolve | integrated_lab | A | - | Same file edited on two clients offline: both versions kept, user prompted, no silent overwrite |
| ODB-C10 | Repair: re-sync, reset, diagnostics bundle for support | Reset OneDrive | Upstream options; Office Unbound "collect diagnostics" doc. Configure | researching | A | - | Corrupted local journal: repair restores sync without re-downloading unchanged files or losing local changes |
| ODB-C11 | Tray status (synced, syncing, error, signed out, quota) | Tray icon | Upstream. Configure | researching | A | - | Each state reproducible and shown within 10 s |
| ODB-C12 | Shell integration: status overlays, context menu (Share, Copy link, Version history, Free up space) | Explorer integration | Upstream (Windows/macOS); Linux file-manager plugins to research. Configure, build on Linux | researching | A | ODB-U02 | Overlay icons and menu present on Windows 11, current macOS and Ubuntu LTS GNOME |
| ODB-C13 | Sync of shared items and team libraries (spaces) | Sync SharePoint libraries | Upstream spaces sync. Configure | researching | A | ODB-S28, SPO-L | Library of a team workspace syncs for members only |
| ODB-C14 | Known-folder backup (Desktop, Documents, Pictures) | Known Folder Move | Not in OpenCloud desktop (to verify). Build: client feature or managed folder redirection policy (Windows) via MDM-. Build | planned | C | MDM- | Enabling the policy moves the three folders into the drive; restore on a new PC brings them back |
| ODB-C15 | Locking: open documents locked against conflicting edits; lock visible to others | Co-authoring / check-out | WebDAV locks from client, WOPI locks from Collabora (`SupportsLocks` must be true in production). Configure | researching | A | ODB-E12 | File opened in a desktop editor shows as locked in web; web edit then requires the lock or co-edit path; no lost update |
| ODB-C16 | Bandwidth limits (up/down, automatic) | Network settings | Upstream. Configure | researching | A | - | Limit of 1 MB/s holds within 10 % |
| ODB-C17 | Multiple accounts (several tenants) in one client | Multiple accounts | Upstream multi-account. Configure | researching | A | - | Two tenants sync side by side; no item crosses between them |
| ODB-C18 | Resumable sync of large files after network loss | Resume | Upstream TUS resume (4.0 notes). Configure | researching | A | ODB-D05 | 10 GB upload over a flapping link completes without restarting |
| ODB-C19 | Deprovisioned user/device: sync stops; local copy handled per policy (keep, remove on sign-out, remote wipe on managed device) | Selective wipe | Token revoke (ICS) stops server access; local removal only via client support (research "remove local data on remote logout") or WIPE-/MDM-. Build | planned | B | WIPE-, MDM- | Server denies within 5 min; managed device removes files per policy; unmanaged device behaviour documented as not removable |
| ODB-C20 | Managed client settings (server, allowed tenants, VFS on, bandwidth, KFM) | Group Policy / Intune | Client config file/registry/plist pushed by MDM- or rem0te. Configure | planned | C | MDM- | Policy-set values cannot be changed by user where marked mandatory |

### 3.5 Mobile access (ODB-M)

| ID | Requirement | Microsoft equivalent | Proposed Office Unbound implementation | Status | Priority | Dependencies | Acceptance criteria |
|---|---|---|---|---|---|---|---|
| ODB-M01 | Android and iOS apps: SSO login, browse, upload, download, offline, share | OneDrive mobile | Upstream OpenCloud apps (stores, F-Droid) with WebFinger/OIDC; rebranding is a cost decision. Configure | planned | B | MDM-, owner decision 1 | Login with e-mail + MFA, all operations on a real device of each platform |
| ODB-M02 | Camera/photo upload | Camera upload | Upstream (verify). Configure | researching | D | ODB-M01 | New photos uploaded within 5 min on Wi-Fi |
| ODB-M03 | Open documents in browser editor from the app; app protection (PIN, no copy to unmanaged apps) where platform allows | Office mobile + app protection | Collabora via browser/app; app protection via MDM- (managed app config). Configure | planned | B | MDM-, WIPE- | Document opens and saves; protection policy blocks "open in" to unmanaged app on managed device |

### 3.6 Collaborative documents (ODB-E)

| ID | Requirement | Microsoft equivalent | Proposed Office Unbound implementation | Status | Priority | Dependencies | Acceptance criteria |
|---|---|---|---|---|---|---|---|
| ODB-E01 | Browser editing of DOCX/XLSX/PPTX and ODF | Office for the web | Collabora own build via OpenCloud WOPI (verified headless). Configure | integrated_lab | A | - | Browser UI test (not only headless) edits and saves each format; reopen shows the change |
| ODB-E02 | Real-time co-editing by several users | Co-authoring | Collabora multi-user session (60 sessions on one document loaded; concurrent edits not tested). Configure + test | researching | A | ODB-E01 | ODB-AT-13 |
| ODB-E03 | Presence: who is in the document | Presence avatars | Collabora user list; display names from WOPI CheckFileInfo. Configure | researching | A | ODB-E02 | Both users listed with directory display names |
| ODB-E04 | Cursors and selections of others | Live cursors | Collabora. Configure | researching | A | ODB-E02 | Remote cursor visible in Writer/Calc/Impress within 2 s |
| ODB-E05 | Comments | Comments | Collabora comments stored in the document. Configure | researching | A | - | Comment persists after save/reopen and in desktop LibreOffice/Word |
| ODB-E06 | Comment replies and resolve | Threaded comments | Collabora replies/resolve. Configure | researching | A | ODB-E05 | Thread with 3 replies and resolve state round-trips through DOCX |
| ODB-E07 | @mentions in comments | @mentions | Collabora mention support needs a WOPI-host user lookup; OpenCloud integration to verify; otherwise build a mention endpoint (tenant-scoped people search). Build | researching | A | ODB-E08 | Typing @ shows only same-tenant people with access; mentioned person notified |
| ODB-E08 | Notifications for mentions, replies and shares (mail, in-app, optional chat) | Activity notifications | Mention events from Collabora → notification service (OpenCloud notifications or Office Unbound). Build | planned | A | ODB-S16 | Mention notification arrives < 2 min, links to the comment |
| ODB-E09 | Track changes (record, accept, reject) | Track changes | Collabora. Configure | researching | A | - | Tracked changes made in browser show correctly in Word and back |
| ODB-E10 | Compare versions | Version compare | Collabora/LibreOffice document compare against a stored OpenCloud version (feature in browser to verify); build "compare with previous" action if needed. Research | researching | D | ODB-D14 | Two versions compared show inserted/deleted text |
| ODB-E11 | Restore a previous version from the editor or file view | Version history | OpenCloud versions (verified). Configure | integrated_lab | A | ODB-D14 | Restore while another user has the document open: editor reloads or warns; no lost save |
| ODB-E12 | Locking between browser editor, desktop apps and sync | Co-authoring locks | WOPI locks (enable `SupportsLocks` path in OpenCloud collaboration service, verify), WebDAV locks for desktop apps. Configure | researching | A | ODB-C15 | Desktop edit + browser edit of the same file never produce a silent overwrite |
| ODB-E13 | Share via e-mail from inside the editor | Share from app | Collabora share button opening the six-step dialog (ODB-U01). Configure + build | planned | A | ODB-U01 | Share button in editor shares the open file |
| ODB-E14 | File links in chat and meetings open with the recipient's own permissions | Share in Teams | Links are OpenCloud `/f/<id>` URLs (never public links by default) posted in Matrix/Jitsi; optional preview bot that checks access as the viewer via F2. Build | planned | A | F2, GRP- | Link posted in a room opens for members with access, shows "request access" for others; no preview leaks content |
| ODB-E15 | Open in desktop app (Word/LibreOffice) and save back | Open in desktop app | WebDAV path through desktop client mount/sync, or protocol handler; research. Research | researching | D | ODB-C08 | Open from web in LibreOffice desktop, save, version created |
| ODB-E16 | Autosave and recovery after editor or files restart | AutoSave | Collabora autosave interval; readiness gate after OpenCloud restart (KI-1). Configure | researching | A | - | Kill coolwsd mid-edit: at most the configured autosave interval lost; user informed |

### 3.7 Administration (ODB-A)

| ID | Requirement | Microsoft equivalent | Proposed Office Unbound implementation | Status | Priority | Dependencies | Acceptance criteria |
|---|---|---|---|---|---|---|---|
| ODB-A01 | Least-privilege service identity for the ICS in OpenCloud (quotas, policies, recovery) | Admin roles | Dedicated OpenCloud admin account or machine-auth runbook (pattern of `opencloud.revoke_app_tokens`), secret in the vault, typed actions only. Build | planned | A | - | ICS can set quota and policy; the identity cannot read file content via the ICS API; actions audited in the hash chain |
| ODB-A02 | Storage and sharing reports per tenant (usage per user, external shares, public links) | OneDrive usage reports | ICS reads OpenCloud Graph; console page. Build | planned | A | ODB-A01 | Report totals match storage measured on disk within 1 % |
| ODB-A03 | Tenant policies for version count, trash retention | Versioning settings | OpenCloud settings via ICS. Configure | researching | A | ODB-A01 | Policy change takes effect on next write, verified by test |
| ODB-A04 | Per-tenant audit store with export and retention | Audit search | OpenCloud audit events shipped to a per-customer log store (no shared index across tenants). Build | planned | A | F3 | Tenant admin of A searches and exports only A's events |
| ODB-A05 | Item-level restore from backup snapshots | Restore | restic restore of selected paths into a recovery folder; ICS typed action with approval. Build | planned | A | ADR-0010 | Single file from a 30-day-old snapshot restored in < 10 min |
| ODB-A06 | OneDrive migration: files, folders, versions (latest N), sharing (report or recreate), timestamps | Migration Manager | Migration toolkit extension (Graph collector exists for assessment). Build | planned | A | ODB-S01 | Pilot tenant: 100 % file count and hashes match, shares reported or recreated, re-run is incremental |

## 4. Security and tenant isolation

- **Cross-tenant denial.** Each customer has its own Keycloak, directory, OpenCloud and keys. Tokens, ids, public-link tokens and
  share invitations across tenants are refused (t20: 42/0 files, 56/0 identity). Every new ODB feature adds its own cross-tenant
  probe to `blueprints/lab/tests/t20_tenant_isolation.py`; a FAIL is a release blocker. Cross-tenant sharing (ODB-S06) only
  through an explicit mutual trust, default off. Network isolation between tenants must be proven on real SDN (open item in
  [tenant-isolation-results.md](../status/tenant-isolation-results.md) section 4).
- **Server-side authorization only.** OpenCloud enforces every role; Office Unbound services (portal, access requests, chat
  previews, search) never decide access from cached UI state and call OpenCloud or F2 (GRP-) as the requesting user.
- **Revocation and offline copies.** Revoking a share, a guest or a user stops **server** access (target <= 60 s for shares,
  <= 5 min for users including Keycloak and app-token revoke, KI-2). Files already downloaded or synced to an **unmanaged**
  device cannot be recalled; this is stated in the UI and admin docs. On managed devices the policy can remove local copies
  (WIPE-, MDM-). View-without-download reduces but does not prevent copying (screenshots).
- **Disabled users.** The ICS disable path (directory lock, Keycloak revoke, OpenCloud app-token revoke) is the only path; public
  links created by a disabled user follow a tenant policy (keep, disable, or disable after N days), default: disable external
  links at disable time, keep internal shares until the drive is transferred (ODB-D18).
- **Guests.** Directory guests with the guest role, an expiry and domain policy; no directory browsing; MFA or e-mail code; guest
  activity in the audit log; guest invites only from users allowed by policy.
- **Links.** Public-link tokens are long random values; passwords rate-limited at the gateway; links can be listed and bulk-revoked
  (ODB-S29); upload links are virus-scanned (ODB-D20).
- **Editor isolation.** WOPI tokens are short-lived and file-scoped; Collabora runs with jails in production (KI-3); proof keys
  required (verified T04).
- **Data at rest and backups.** ODB-D25; per-customer restic keys already proven.

## 5. Acceptance tests (for the eventual implementation)

| Test | Scenario | Pass condition |
|---|---|---|
| ODB-AT-01 | User A shares folder F with user B as viewer. B views (web, WebDAV, desktop, mobile). A changes B to editor; B edits and B's client syncs the change both ways. A revokes. | Viewer write attempts denied on every API; editor changes visible to A; after revoke every server request by B for F is denied within 60 s; B's client stops syncing F and removes or keeps the local copy exactly as the tenant offline-copy policy states (managed: removed; unmanaged: documented as kept) |
| ODB-AT-02 | Employee E leaves. ICS offboarding transfers E's drive to manager M with a 90-day retention. E had received shares from C and had shared items with D. | M sees exactly E's own items; nothing shared with E by C becomes visible to M; D's access follows the chosen policy; E denied on all paths; deletion runs at day 90 and is audited |
| ODB-AT-03 | Cross-tenant: tenant A user tries B's drive ids, share ids, link tokens, people picker, search, thumbnails, WOPI and activity APIs | All refused or empty, each with a positive control at home |
| ODB-AT-04 | Disable user U with open web, sync, mobile and editor sessions | All refused within 5 min; editor session cannot save afterwards |
| ODB-AT-05 | Guest G invited from allowed domain, opens shared item, expiry passes | G sees only the item; after expiry denied on all paths; blocked-domain invite refused |
| ODB-AT-06 | Tenant disables public links | Link creation refused by API; existing links handled per policy |
| ODB-AT-07 | View-without-download share | GET/export/print/download refused; browser viewing works |
| ODB-AT-08 | Upload-only request | Uploader cannot list or read; files scanned |
| ODB-AT-09 | Desktop sync matrix (Windows 11, macOS current, Ubuntu LTS): initial sync 5k files, offline edits, two-client conflict, large file, shared folder | No data loss; conflicts surfaced; T07 checks pass on GUI clients |
| ODB-AT-10 | Files On-Demand on Windows | Placeholders, hydrate on open, free up space, pinned offline |
| ODB-AT-11 | Ransomware drill: a sync client rewrites 1,000 files with random bytes | Alert within 10 min; drive restored to T-1h; all hashes equal the pre-attack state |
| ODB-AT-12 | Malware upload (EICAR) through each path | Blocked/quarantined, never served |
| ODB-AT-13 | Two users co-edit one DOCX and one XLSX in browsers; comment, reply, mention | Each sees the other's change in <= 2 s; comments persist; mention notification sent |
| ODB-AT-14 | Search trimming | B cannot find A's unshared file by name, tag or content |
| ODB-AT-15 | Audit completeness and tamper evidence | Every action of AT-01 logged; altering a record detected |
| ODB-AT-16 | Six-step share usability on web, each desktop OS and mobile | Completed by non-technical testers without help |
| ODB-AT-17 | Quota | Over-quota upload refused, no partial file |
| ODB-AT-18 | Admin-assisted recovery from backup | Restored item hashes match, audit complete |

## 6. Phasing proposal (no dates)

1. Configure-and-verify OpenCloud features already in the product (sharing roles, links, expiry, trash, quotas, search+Tika,
   thumbnails, antivirus) with tests and cross-tenant probes; GUI desktop client matrix.
2. Gap builds needed for business use: sharing policy service, guest invitation, access requests, offboarding transfer, item
   restore, audit store, six-step UX polish.
3. Co-editing verification and mention/notification integration; chat link integration.
4. Placeholder research outcome on macOS/Linux; known-folder backup with MDM-; migration.

## 7. Licensing notes

| Component | Use | Licence (verification state) | Cost / note |
|---|---|---|---|
| OpenCloud server | file platform | Apache-2.0 (stated in eval, LICENSE file not yet read; [third-party-inventory.md](../status/third-party-inventory.md) item 10) | none |
| OpenCloud Web | web UI | believed AGPL-3.0 (ownCloud Web lineage), **verify**; AGPL §13 source offer applies if modified | none |
| OpenCloud Desktop | sync client | believed GPL-2.0-or-later (ownCloud client lineage), **verify** | rebranded signed builds cost money (below) |
| OpenCloud Android/iOS | mobile apps | **verify** (inventory: UNVERIFIED) | own store listings: Apple Developer Program annual fee, Google Play one-time fee |
| Collabora Online (own build) | editor | MPL-2.0 (+LGPL-3.0 engine) | trademark removal obligation (ADR-0005) |
| ClamAV | malware scanning | GPL-2.0, **verify**; run as separate service | none |
| Apache Tika | content extraction | Apache-2.0, **verify** | Java runtime memory |
| rclone (optional Linux FUSE) | on-demand mount option | MIT, **verify** | none |
| restic / rest-server | backups | BSD-2 (in use) | none |

**Costs flagged for owner review:** (1) Windows Authenticode code-signing certificate for any Office Unbound–signed client (OV/EV
certificates are paid yearly; free or low-cost routes such as an open-source signing programme must be checked); (2) Apple
Developer Program membership for Developer ID signing and notarization of a macOS client and for an iOS app; (3) Google Play
developer registration for an Android app. All three are avoided if upstream OpenCloud-signed clients are used unbranded.

## 8. Open owner decisions

1. **Clients:** use upstream OpenCloud-signed desktop and mobile apps (zero cost, upstream branding) or ship rebranded,
   Office Unbound–signed clients (costs in section 7).
2. **Six-step share flow:** fixed by the owner (section 3.3); only the exact UI wording remains for the UX review.
3. **Guests:** ICS-created directory guests only, or also OpenCloud 9 e-mail guests (second account source).
4. **Narrowing inheritance (ODB-S18):** accept OpenCloud's model (restrict by moving to a separate space) or fund an upstream patch.
5. **Allow reshare (ODB-S19):** accept "no reshare" as the only mode, or build it.
6. **Offline-copy policy defaults** for disabled users and revoked shares on managed devices.
7. **Default retention:** trash days, version count, former-employee period.
8. **Encryption at rest:** LUKS in the VM or ZFS encryption on Proxmox storage (key custody per customer).
9. **Cross-tenant sharing (OCM):** pursue at all, and at which priority.
10. **Linux Files On-Demand:** accept full sync only, or invest in a FUSE/placeholder option.
