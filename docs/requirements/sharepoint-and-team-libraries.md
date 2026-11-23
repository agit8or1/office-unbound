# SharePoint parity: sites, team workspaces and document libraries

**Status: PLANNED / NOT IMPLEMENTED (planning only).** Requirements document (2026-11-23). Not authorized for development; the
current roadmap and the beta directive keep priority until the owner explicitly authorizes this work. Nothing described here
exists in Office Unbound today except the lab-proven primitives marked `integrated_lab` in section 2. Status values follow
[ADR-0000](../adr/0000-status-values.md).

Requirement prefix: **SPO-**, grouped as SPO-S (sites and workspaces), SPO-P (permissions and external collaboration), SPO-L
(libraries), SPO-C (pages, news, directory, knowledge), SPO-G (governance, search, records, backup, migration, integration).
Related: personal drives, sharing, sync and co-editing are ODB- ([onedrive-and-file-sharing.md](onedrive-and-file-sharing.md));
unified groups, F2 authorization and revocation are GRP- ([unified-groups-and-permissions.md](unified-groups-and-permissions.md)); identity ENT-
([entra-identity-parity.md](entra-identity-parity.md)); workflow/forms/lists are P10.1 and other areas ([m365-feature-parity.md](m365-feature-parity.md)). Priority tags: **A**
business-ready collaboration, **B** mobile security, **C** Entra/Intune expansion, **D** wider Microsoft 365.

## 1. Scope

Workflow parity with SharePoint Online and Teams file storage: organisation and department sites, team workspaces with several
document libraries, controlled permissions, external collaboration, pages and news, employee directory, knowledge base, library
metadata and document control, access-trimmed search, records retention, audit, backup and migration.

This document refines [P10.2 Company Intranet and Knowledge Center](../roadmap/post-core-expansion.md#p102-company-intranet-and-knowledge-center-sharepoint--l)
(recorded as `deferred` in `docs/progress.json`). It splits P10.2 into two layers:

- **Team libraries (priority A):** team workspaces and libraries on OpenCloud project spaces. Needed for business-ready
  collaboration and mostly configuration of existing OpenCloud features plus a thin site registry.
- **Intranet and knowledge (priority D):** pages, news, page builder, knowledge base: the P10.2 module proper.

Whether team libraries move ahead of the deferred P10.2 is an owner decision (section 8).

Principles: **no separate document silo** — every library is an OpenCloud space and every document is edited by Collabora via
WOPI ([ADR-0005](../adr/0005-files-documents.md)); one directory (OpenLDAP) and one SSO (Keycloak); permissions enforced
server-side by OpenCloud, or by Office Unbound services through F2
([foundations](../roadmap/post-core-expansion.md#foundations-the-core-should-provide-identified-now-do-not-expand-current-scope));
search through F4; retention and legal hold through F5; per-customer stacks.

## 2. Existing-state audit

| Capability | What exists today (evidence) | Status |
|---|---|---|
| Project spaces (shared storage outside personal drives) | Graph `POST /drives` creates a project space; cross-tenant access to it refused (`blueprints/lab/tests/t20_tenant_isolation.py`, [tenant-isolation-results.md](../status/tenant-isolation-results.md)) | integrated_lab (API only) |
| Space administration role | LDAP group `opencloudSpaceAdmin` → OpenCloud space-admin role (T01, user carol, [identity-files-lab-results.md](../status/identity-files-lab-results.md)) | integrated_lab (role only) |
| Versions, restore, browser editing in a space | Verified for personal drives (T03/T04/T05); same storage driver for spaces, not separately tested | integrated_lab (personal drive) |
| Directory groups | OpenLDAP `groupOfNames`, memberOf/refint overlays; ICS `update_groups` action ([user-lifecycle-results.md](../status/user-lifecycle-results.md)) | integrated_lab |
| Employee directory data | One directory (OpenLDAP); global address list in grommunio-web ([groupware-lab-results.md](../status/groupware-lab-results.md)) | integrated_lab (mail GAL only) |
| Chat rooms | Matrix/Element with Keycloak SSO, lab prototype ([collaboration-lab-results.md](../status/collaboration-lab-results.md)); not deployed by the ICS | tested (lab prototype) |
| Backup/restore of all file data incl. spaces | Files tier restore with versions ([restore-drill-results.md](../status/restore-drill-results.md), [backup-product-results.md](../status/backup-product-results.md)) | tested (whole tier, lab) |
| Upstream, not verified: space members with Manager/Editor/Viewer roles, group membership of spaces, space quota, space trash, space description/image/readme, space disable/delete/restore, sync of spaces in the desktop client | none ([files-identity-eval.md](../status/files-identity-eval.md)) | researching |
| Not available in OpenCloud (to verify): several libraries inside one space, custom columns, content types, check-in/out with comments, approval, major/minor versions, page builder, news | none | planned |
| SharePoint migration | Assessment collects SharePoint usage reports only; no content mover ([migration-assessment.md](../status/migration-assessment.md), [migration-engine-results.md](../status/migration-engine-results.md)) | planned |
| Intranet / knowledge module (P10.2) | Candidates only: BookStack (MIT), XWiki (LGPL-2.1), Wiki.js (AGPL-3.0), GrapesJS (BSD-3); Outline excluded (BSL) | deferred |

## 3. Model

- **Site** = an Office Unbound object in a small per-tenant **site registry** (portal/tenant database, `customer_id` on every
  row): title, URL slug, type (organisation, department, team), owners, linked unified group (GRP-), linked Matrix room, policy
  (external sharing, guest rules), and an ordered list of libraries.
- **Library** = one OpenCloud project space. Several libraries per site = several spaces registered to the site. Space membership
  is the library permission; the site's group is added as member by default ("inherit from site"), and a library can be set to
  its own membership ("unique permissions") — this gives controlled inheritance at site → library level with OpenCloud doing the
  enforcement.
- **Folder/file permissions** inside a library: OpenCloud shares (broadening). Narrowing below the library level is not an
  OpenCloud concept (ODB-S18); the supported pattern is a separate library.
- **Metadata** that OpenCloud cannot store natively (custom columns, content types, approval state) lives in an Office Unbound
  metadata service keyed by OpenCloud file id, authorized through F2 (the user must be able to read the file in OpenCloud to read
  its metadata). Storage of simple values as WebDAV properties is a research alternative.

## 4. Requirements

### 4.1 Sites and workspaces (SPO-S)

| ID | Requirement | Microsoft equivalent | Proposed Office Unbound implementation | Status | Priority | Dependencies | Acceptance criteria |
|---|---|---|---|---|---|---|---|
| SPO-S01 | Team workspace: one action creates a group, a site, a default library and a chat room | Teams team / group-connected site | Portal/ICS action: unified group (GRP-) + site registry entry + OpenCloud space with the group as member + Matrix room. Build (orchestration), configure (OpenCloud) | planned | A | GRP-, SPO-L01 | Owner creates "Project X"; members see library and room within 5 min; non-members see neither, via UI and API |
| SPO-S02 | Department sites (e.g. Finance, HR) with owners and members | Communication/team site | Same as SPO-S01 with type "department"; optional link to directory department attribute. Build | planned | A | SPO-S01 | Department site lists the department's library; membership follows the group |
| SPO-S03 | Organisation (home) site visible to all employees, editable by designated editors | Home site | Site type "organisation", group "all employees" (dynamic membership from GRP-), library read-only for members. Build | planned | D | SPO-C01, GRP- | All users read, only editors change; guests excluded by default |
| SPO-S04 | Multiple libraries per site | Document libraries | Several OpenCloud spaces per site in the registry. Build | planned | A | SPO-L01 | Site with 3 libraries; each has its own membership option; all appear in the site view and desktop client |
| SPO-S05 | Site ownership: at least two owners recommended, orphan detection when an owner leaves | Site owners / ownerless policy | Registry owners = group owners (GRP-); ICS reconcile flags sites with 0 active owners and notifies admins. Build | planned | A | GRP-, ODB-D18 | Disabling the only owner raises an "ownerless site" finding within one reconcile interval |
| SPO-S06 | Self-service site creation under admin policy (who may create, naming rules, default settings) | Site creation settings | Tenant policy in the ICS; creation refused server-side when not allowed. Build | planned | A | SPO-S01 | User outside the creator group gets a refusal from the API |
| SPO-S07 | Site directory and discovery: sites I belong to, public sites I can join or request | Following / site discovery | Portal page from the registry, filtered by F2. Build | planned | A | F2 | Private site never listed to non-members, not even its title |
| SPO-S08 | Site lifecycle: archive (read-only), delete with restore window, inactivity policy | Site lifecycle management | OpenCloud space disable/delete/restore (upstream, verify) + registry state. Configure + build | researching | A | SPO-G05 | Deleted site restorable within window with libraries, versions and permissions; purged after window |
| SPO-S09 | Site storage quota | Site storage limits | OpenCloud space quota (upstream). Configure | researching | A | ODB-A01 | Upload beyond quota refused; owner warned |
| SPO-S10 | Navigation: site menu, hub/global navigation across sites | Hub sites / global nav | Portal shell navigation from the registry. Build | planned | D | SPO-S07 | Navigation shows only sites the viewer can access |

### 4.2 Permissions and external collaboration (SPO-P)

| ID | Requirement | Microsoft equivalent | Proposed Office Unbound implementation | Status | Priority | Dependencies | Acceptance criteria |
|---|---|---|---|---|---|---|---|
| SPO-P01 | Site-level roles: owner, member (edit), visitor (read) | Owners/Members/Visitors | Mapped to OpenCloud space roles Manager/Editor/Viewer on every inheriting library. Configure + build (mapping) | researching | A | SPO-S04 | Each role tested on every library API (WebDAV, Graph, WOPI): allowed and denied operations as specified |
| SPO-P02 | Group-based permissions (unified groups, security groups) | Group permissions | OpenCloud space membership by group (upstream, verify) fed by GRP-. Configure | researching | A | GRP- | Group membership change applies within 5 min |
| SPO-P03 | Controlled inheritance: site → library inherits by default; library can break inheritance and set its own members; owners see which libraries are unique | Break inheritance | Registry flag per library; inheriting libraries are re-synchronised from the site group; unique ones are not. Build | planned | A | SPO-P01 | Toggling inheritance changes effective access exactly as the who-has-access view reports |
| SPO-P04 | Folder and file permissions inside a library (broaden only), with who-has-access view | Item permissions | OpenCloud shares (ODB-S01..S21). Configure | researching | A | ODB-S21 | Sub-folder shared with an outsider to the library: only that folder visible to them |
| SPO-P05 | External collaboration: guests as site members or per-item shares, controlled per site (off / existing guests / new guests) never broader than tenant policy | Site external sharing | Site policy in registry, enforced by the sharing policy service (ODB-S24) and guest invite (ODB-S05). Build | planned | A | ODB-S05, ODB-S24 | Site with external sharing off: API refuses guest membership and external links in all its libraries |
| SPO-P06 | Guest policies: expiry, domain allow/block, review by site owner | Guest access settings | ODB-S25/S26 applied per site; owner review reminder. Build | planned | A | ODB-S26 | Expired guest removed from site membership and denied |
| SPO-P07 | Access requests to sites and libraries routed to owners | Access requests | Request service (ODB-S23) extended to sites. Build | planned | A | ODB-S23 | Request for a private site reaches its owners; approval adds the requester as member |
| SPO-P08 | Admin view of permissions across all sites (unique permissions, external members, public links) | Site permissions report | ICS/console report over registry + OpenCloud. Build | planned | A | ODB-A02 | Report equals effective access computed by the test oracle |

### 4.3 Libraries and document control (SPO-L)

| ID | Requirement | Microsoft equivalent | Proposed Office Unbound implementation | Status | Priority | Dependencies | Acceptance criteria |
|---|---|---|---|---|---|---|---|
| SPO-L01 | Library = OpenCloud project space with upload, folders, previews, versions, trash, co-editing | Document library | OpenCloud space (same features as ODB-D/ODB-E). Configure | researching | A | ODB-D04..D15, ODB-E01 | ODB-D and ODB-E acceptance tests re-run inside a library pass |
| SPO-L02 | Library sync to desktop and access from mobile | Sync library | OpenCloud desktop spaces sync (ODB-C13), mobile apps. Configure | researching | A | ODB-C13, ODB-M01 | Member syncs library; visitor gets read-only sync; non-member cannot add it |
| SPO-L03 | Custom columns (text, number, date, choice, person, yes/no) shown, edited, sorted and filtered in the library view | Library columns | Metadata service keyed by OpenCloud file id + web extension in OpenCloud Web (extension API, verify) or portal library view. Build | planned | A | F2, SPO-L06 | Column values survive rename/move/version restore; filter by column returns only items the user can read |
| SPO-L04 | Content types: named set of columns + document template, required fields on upload | Content types | Metadata service schema per library; template = file in a hidden library. Build | planned | D | SPO-L03, SPO-L08 | Upload without required field is flagged/blocked per policy; "New > Contract" uses the template |
| SPO-L05 | Approval of documents before they are visible to readers | Content approval | Draft state in metadata service; readers' access granted only to approved items (approved copy published to a reader library, or reader permission granted on approval). Build; workflow engine from P10.1 later | planned | D | SPO-L03, P10.1 | Draft is invisible to visitors via every API including search; approval makes it visible; audit shows approver |
| SPO-L06 | Check-out / check-in with comment; admin can discard a check-out | Check out | Exclusive WebDAV/WOPI lock owned by the user plus comment in metadata service; editor and sync honour the lock. Build (on top of ODB-E12 locks) | planned | A | ODB-E12, ODB-C15 | While checked out, other members cannot save (web, sync, WebDAV); check-in creates a version with comment |
| SPO-L07 | Versions: history, restore, optional major/minor (drafts visible to editors only), version limits per library | Versioning settings | OpenCloud versions (verified on personal drives); major/minor as metadata labels; limits from ODB-A03 per space if supported. Configure + build | researching | A | ODB-D14 | Restore works in a library; version limit per library enforced; minor versions hidden from visitors if adopted |
| SPO-L08 | Document templates per library ("New" menu) | Library templates | OpenCloud/Collabora template support (upstream templates, verify) or portal "New from template". Configure + build | researching | D | - | Template creates a new file with template content and default metadata |
| SPO-L09 | Library views: saved filters/sort/grouping by column | Views | Portal or OpenCloud Web extension. Build | planned | D | SPO-L03 | Saved view reproduces the same result for each user, trimmed to their access |

### 4.4 Pages, news, directory, knowledge (SPO-C)

| ID | Requirement | Microsoft equivalent | Proposed Office Unbound implementation | Status | Priority | Dependencies | Acceptance criteria |
|---|---|---|---|---|---|---|---|
| SPO-C01 | Pages with a drag-and-drop page builder; web parts for documents, news, people, links, embedded file viewer | Modern pages | Native intranet shell (P10.2) with GrapesJS (BSD-3) as builder component; content stored per tenant; files embedded from OpenCloud by id. Build + integrate | planned | D | F2, SPO-S01 | Department publishes a page with a library web part; restricted page invisible to unauthorised users in UI, search and API (P10.2 acceptance) |
| SPO-C02 | Page and site templates (structure: libraries, folders, pages, permissions) | Site templates / site designs | Template definitions applied by the site-creation action. Build | planned | D | SPO-S01, SPO-C01 | Creating a site from template yields the defined libraries, folders, pages and roles |
| SPO-C03 | News and announcements with audience targeting, scheduled publish, e-mail digest | News | Intranet module; audiences = groups; digest via Gromox SMTP. Build | planned | D | SPO-C01, GRP- | News targeted to Finance not shown to others; digest contains only items the recipient may read |
| SPO-C04 | Employee directory with profile, photo, department, manager, org chart, contact actions (mail, chat, call) | People / Delve profile | Read-only view of OpenLDAP (no second store); fields editable per policy through ICS; links to Gromox, Matrix, Asterisk. Build | planned | D | ENT- | Data matches LDAP; hidden users not listed; guests not listed to members unless policy allows; another tenant's people never appear |
| SPO-C05 | Knowledge base / wiki with permissions per space/book, versions, attachments | SharePoint wiki / pages | Integrate BookStack (MIT) or XWiki (LGPL-2.1) behind Keycloak SSO with group mapping, or native pages if permissions/theming do not fit (P10.2 decision). Integrate | planned | D | F2, F4 | Restricted article invisible to non-members in UI, search and API; version restore works; directory data from one directory |
| SPO-C06 | Page approval before publishing | Page approval | Draft/publish state in the intranet module; P10.1 workflow later. Build | planned | D | SPO-C01 | Unapproved page cannot be reached by readers via any URL |

### 4.5 Governance, search, records, integration (SPO-G)

| ID | Requirement | Microsoft equivalent | Proposed Office Unbound implementation | Status | Priority | Dependencies | Acceptance criteria |
|---|---|---|---|---|---|---|---|
| SPO-G01 | Access-enforced search across sites, libraries, pages, knowledge base and metadata | SharePoint search | Library content: OpenCloud search + Tika (ODB-D12); cross-source (pages, wiki, metadata; tagged D in practice): F4 tenant-partitioned, permission-trimmed index. Integrate + build | planned | A | F4, ODB-D12 | Non-member cannot find a private library's file by name, content or column value; no result count or snippet leaks |
| SPO-G02 | Records retention: retention labels per library or item, declare as record (immutable), disposition review | Purview retention / records | F5 storage hooks in OpenCloud; policy in P10.5. Build (upstream-friendly patch) | planned | D | F5, P10.5 | Record cannot be modified or deleted by any user or API; disposition after period requires reviewer approval and is audited |
| SPO-G03 | Audit of site, library, permission and content events per tenant | Audit log | OpenCloud audit events + registry/metadata service events into the per-tenant audit store (ODB-A04). Build | planned | A | ODB-A04 | Every action of SPO-AT-01 appears with actor, object and time; tamper-evident |
| SPO-G04 | Site admin centre for tenant admins: all sites, owners, storage, external sharing state, ownerless/inactive sites | SharePoint admin center | Console pages over registry + OpenCloud. Build | planned | A | SPO-S05, SPO-P08 | Admin view matches registry and OpenCloud state in a seeded tenant |
| SPO-G05 | Backup and restore per site, library or item, point in time | Site restore | restic item/path restore (ODB-A05) mapped to space paths + registry/metadata DB backup. Build | planned | A | ODB-A05 | Deleted library restored from a 14-day-old snapshot with versions, metadata and membership |
| SPO-G06 | SharePoint Online migration: sites, libraries, folders, files, versions (latest N), metadata columns, permissions (mapped or reported), timestamps, authors | SharePoint Migration Tool | Extend migration toolkit: Graph collector (exists for assessment) + mover into spaces and the metadata service; permission mapping report. Build | planned | D | SPO-L03, ODB-A06 | Pilot site: file count and hashes match; columns mapped; each unmapped permission reported; incremental re-run |
| SPO-G07 | Chat and group integration: each team workspace has a room; library files can be linked/shared in the room; room membership follows the group | Teams Files tab | Matrix room created with the workspace (SPO-S01), membership synced from GRP-, file links per ODB-E14. Build | planned | A | GRP-, ODB-E14 | Removing a member removes room access and library access within 5 min |
| SPO-G08 | Lists (structured data with columns) | Microsoft Lists | Out of scope here: P10.1 ([m365-feature-parity.md](m365-feature-parity.md)) | deferred | D | P10.1 | n/a |

## 5. Security and tenant isolation

- **Cross-tenant denial.** The site registry and metadata service live inside each customer stack (no shared database); every row
  carries `customer_id` (F1). New probes in `blueprints/lab/tests/t20_tenant_isolation.py`: foreign site ids, library (space)
  ids, metadata ids, page ids, search queries and directory lookups from the other tenant must be refused or empty, each with a
  positive control.
- **Server-side authorization.** OpenCloud enforces library access; registry, metadata, pages and search call F2 as the
  requesting user for every read. A page or search result never reveals the existence of a private site or file (no titles,
  counts or snippets).
- **Membership revocation.** Removing a user from a site group removes library, room and page access on the server (target 5 min);
  synced copies on unmanaged devices remain (ODB section 4); managed devices follow WIPE-/MDM- policy.
- **Disabled users and owners.** Disable path as in ODB; sites whose last owner is disabled are flagged (SPO-S05), never left
  editable only by nobody; former-employee content in team libraries stays with the library (it belongs to the site, not the user).
- **Guests.** Site-level external policy can only be narrower than tenant policy; guests never see the site directory or the
  employee directory unless policy allows; guest expiry removes membership everywhere.
- **Integrated knowledge base.** If BookStack/XWiki is adopted it runs per customer, behind Keycloak, with group mapping and its own
  cross-tenant probes; it is not shared across tenants.

## 6. Acceptance tests (for the eventual implementation)

| Test | Scenario | Pass condition |
|---|---|---|
| SPO-AT-01 | Owner A creates team workspace "Project X" with member B and visitor C; B uploads and edits, C reads; A removes B | B edits, C cannot write via any API; after removal B is denied by the server within 5 min on web, WebDAV, desktop sync and room; B's synced copy handled per offline-copy policy |
| SPO-AT-02 | Site with 3 libraries, one with unique permissions | Effective access equals the who-has-access view for 20 seeded users |
| SPO-AT-03 | Former employee E owned the "Contracts" library and created files in it | Library and files stay with the site; ownership moves to the remaining owner or admin; E's personal drive transfer (ODB-AT-02) exposes nothing from other sites |
| SPO-AT-04 | Cross-tenant: tenant A tries B's site, library, metadata, page, search and directory endpoints | All refused or empty, positive control at home |
| SPO-AT-05 | External guest added to site with external sharing on; site switched to off | Guest works, then is denied; external links in the site disabled per policy |
| SPO-AT-06 | Check-out by B | C cannot save by any path; check-in creates a version with comment |
| SPO-AT-07 | Approval: draft document and draft page | Invisible to visitors (UI, API, search) until approved |
| SPO-AT-08 | Search trimming with custom columns | Value of a column on a private file never returned to non-members |
| SPO-AT-09 | Restore a deleted library from backup | Files, versions, metadata and membership restored |
| SPO-AT-10 | Migration of a pilot SharePoint site | Counts and hashes match; permission report complete |
| SPO-AT-11 | Record declared | Modify/delete refused for all users including owners; disposition audited |

## 7. Licensing notes

| Component | Use | Licence (verification state) | Note |
|---|---|---|---|
| OpenCloud server | library storage | Apache-2.0 (LICENSE file not yet read) | existing |
| BookStack | knowledge base candidate | MIT (P10.2 desk review), **verify** | PHP/MySQL; per-customer instance |
| XWiki | knowledge base candidate | LGPL-2.1, **verify** | Java; heavier, strong permissions model |
| Wiki.js | candidate | AGPL-3.0, **verify** | AGPL §13 source offer if modified |
| Outline | excluded | BSL 1.1 | not open source |
| GrapesJS | page builder component | BSD-3-Clause, **verify** | front-end library |
| Flowable / Node-RED | approval workflows (P10.1) | Apache-2.0, **verify** | chosen in P10.0 |

No component above has a mandatory licence fee or user cap. No code-signing costs arise here beyond those of the ODB clients.

## 8. Open owner decisions

1. **Order:** move team libraries (SPO-S01..S09, SPO-P, SPO-L01..L03, L06, L07) to priority A ahead of the deferred P10.2, keeping
   pages/news/knowledge (SPO-C) in P10.2.
2. **Site model:** site registry with one space per library (section 3), or one space per site with folders as "libraries".
3. **Metadata storage:** separate metadata service (recommended) or WebDAV properties in OpenCloud.
4. **Approval mechanism:** separate reader library vs permission grant on approval (SPO-L05).
5. **Knowledge base:** BookStack, XWiki or native pages.
6. **Narrowing permissions below library level:** not supported (use another library) or fund an upstream patch.
7. **Migration priority** (SPO-G06): D as tagged, or A because it gates customer adoption.
