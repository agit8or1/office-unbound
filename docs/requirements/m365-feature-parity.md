# Microsoft 365 feature parity: master matrix

> **Status: planning document. Parity is not claimed for any feature.** Written 2026-11-23 against 0.10.0 "Juniper" (alpha: the full
> stack deploys through the ICS onto one reference Proxmox install; not for production data). Nothing in this file changes a status in
> [`docs/progress.json`](../progress.json), which stays the only source of truth for item status. A row moves only when test evidence
> is recorded in `docs/status/` (ADR-0000, [status values](../adr/0000-status-values.md)).

## Goal and rules

The owner's goal is to get as close as is technically and legally possible to a complete Microsoft 365 replacement: **functional and
workflow parity**, not compatibility with proprietary protocols or objects. Where parity is impossible, this document records the
limitation and the closest alternative.

Rules that apply to every row:

- **Zero mandatory licence cost, no caps** on users, mailboxes, storage objects or connections ([ADR-0007](../adr/0007-zero-cost-unlimited.md)).
- **Tenant isolation** is a gate for every feature (F1, [tenant-isolation-results.md](../status/tenant-isolation-results.md)).
- **Honest status.** "Exists" means a linked test result. Feature presence in an upstream component we ship is *not* evidence until
  we have tested it. No completion percentages.
- **Infrastructure authority stays in the ICS** and is never merged with tenant administration or device management
  ([ADR-0002](../adr/0002-ics-security-model.md), foundation F8 in [post-core-expansion.md](../roadmap/post-core-expansion.md)).
- **PDF Studio (P9) stays the very last implementation priority**, after every P10 module too (see [Priority order](#proposed-priority-order)).

## How to read the matrix

| Column | Meaning |
|---|---|
| ID | Stable requirement ID. Prefixes owned here: **TMS** Teams, **APP** business apps, **CMP** security and compliance, **MIG** Migration Center, **ADM** tenant administration, **MSP** MSP management, **UX** unified experience. Rows named `ODB-…`, `SPO-…`, `EXO-…`, `GRP-…`, `ENT-…`, `MDM-…`, `WIPE-…` are **summary pointers**; the detailed, numbered requirements live in the linked documents. |
| Microsoft product | The Microsoft 365 product whose function is meant (for orientation only; no affiliation). |
| Office Unbound equivalent | The planned or existing function, by its own name. |
| Existing component | What we ship or have in the lab today, or `—`. |
| Status | ADR-0000 value for the Office Unbound function, taken from `docs/progress.json` where an item exists. `planned` with no roadmap item means "identified here, not yet on the roadmap". |
| Gap | What is missing between today and the acceptance criteria. |
| Priority | **A** business-ready collaboration · **B** mobile security · **C** Entra/Intune-equivalent identity and devices · **D** wider Microsoft 365. |
| Dependencies | Other rows, roadmap items (P*x.y*) or foundations (F1–F8, defined in [post-core-expansion.md](../roadmap/post-core-expansion.md)). |
| Difficulty | S weeks · M 1–2 months · L a quarter · XL several quarters (relative, not a commitment). |
| Acceptance criteria | What a test must show before the row may move to `tested`. |
| Evidence | Link to executed results, or `—`. |

Detailed requirement documents written alongside this one (the matrix links to them; check the lead's integration if a link is missing):

| Prefix | Document | Scope |
|---|---|---|
| ODB | [onedrive-and-file-sharing.md](onedrive-and-file-sharing.md) | personal drives, sharing, desktop sync, co-editing |
| SPO | [sharepoint-and-team-libraries.md](sharepoint-and-team-libraries.md) | team libraries, sites, metadata |
| EXO | [calendar-and-mailbox-delegation.md](calendar-and-mailbox-delegation.md) | mail, calendar, contacts, shared mailboxes, delegation, Outlook parity |
| GRP | [unified-groups-and-permissions.md](unified-groups-and-permissions.md) | unified groups, F2 authorisation, revocation |
| ENT | [entra-identity-parity.md](entra-identity-parity.md) | identity, Windows/macOS/Linux sign-in |
| MDM | [intune-and-mobile-mdm.md](intune-and-mobile-mdm.md) | device management, mobile apps |
| WIPE | [mobile-remote-wipe-security.md](mobile-remote-wipe-security.md) | selective and full remote wipe |

Existing related requirement: [office-unbound-connect.md](office-unbound-connect.md) (P10.12 desktop sign-in).

---

## Parity summary by product area

No area has parity today. Each line says what exists with evidence, what is planned, and the main gap.

**Exchange Online / Outlook.** *Exists:* our own Gromox source build with MAPI/HTTP, EWS, ActiveSync, Autodiscover, IMAP/SMTP, CalDAV/CardDAV
and webmail; 57 automated protocol checks in the lab, including a shared mailbox ([groupware-lab-results.md](../status/groupware-lab-results.md));
deployed by the ICS on the reference install with all health checks green ([groupware-deploy-results.md](../status/groupware-deploy-results.md));
shared-mailbox lifecycle, aliases and quotas through the ICS ([mailbox-admin-results.md](../status/mailbox-admin-results.md)); send-as /
send-on-behalf fixed by a groupware patch ([gw-client-fixes-results.md](../status/gw-client-fixes-results.md)); Thunderbird and Evolution
tested automatically ([client-compat-results.md](../status/client-compat-results.md)). *Planned:* calendar delegation, shared calendars and
contacts, resource booking, anti-spam/antivirus, archiving (EXO document). *Main gaps:* no real Outlook, Apple or phone client tested; internet mail
(MX, SPF/DKIM/DMARC) not verified end to end; new Outlook and Outlook mobile can only use IMAP/SMTP against any non-Microsoft server
(Microsoft limitation, [known-limitations.md](../admin/known-limitations.md)).

**OneDrive.** *Exists:* OpenCloud personal files, WebDAV, version history and restart persistence; the desktop sync engine (`opencloudcmd`)
passed upload, download, offline, conflict and delete tests ([identity-files-lab-results.md](../status/identity-files-lab-results.md));
storage quotas through the ICS. *Planned:* sharing dialog, links with expiry, packaged desktop clients, Files On-Demand-style placeholders
(ODB document). *Main gaps:* sharing and the GUI desktop clients are not tested by the project; no tenant-wide sharing policy.

**SharePoint.** *Exists:* nothing tested beyond the OpenCloud file store underneath. *Planned:* team libraries on OpenCloud spaces (SPO
document) and the intranet / knowledge centre (P10.2, deferred). *Main gap:* team libraries, metadata and site permissions are all untested.

**Teams.** *Exists:* lab prototype of chat (Synapse + MAS + Element, Keycloak SSO only) and meetings (Jitsi with SSO-issued room-scoped tokens),
P6.2 `integrated_lab` ([collaboration-lab-results.md](../status/collaboration-lab-results.md)); telephony prototype on Asterisk, P6.3
([telephony-lab-results.md](../status/telephony-lab-results.md)). *Planned:* team workspaces bound to unified groups, files in chat, group
calendars, recording, transcripts, whiteboard, webinars (P10.7). *Main gaps:* the ICS does not deploy chat or meetings; no binding between a
chat room, a group, a library and a calendar; Teams objects cannot be migrated as Teams objects.

**Entra ID.** *Exists:* OpenLDAP as the one directory, Keycloak SSO for every app, MFA, measured revocation on deprovisioning
([user-lifecycle-results.md](../status/user-lifecycle-results.md), [sso-rollout-results.md](../status/sso-rollout-results.md)).
*Planned:* conditional access, device-based access, PAM, access reviews, app registration (P10.10), desktop sign-in (P10.12) (ENT document).
*Main gaps:* no device posture signal (F6); no Windows/macOS/Linux sign-in. Entra join state and Entra-specific tokens cannot be reproduced.

**Intune.** *Exists:* nothing; device onboarding profiles are unsigned and untested ([known-limitations.md](../admin/known-limitations.md)).
*Planned:* P10.6 endpoint management with a device agent separate from the ICS agent; MDM and wipe (MDM, WIPE documents). *Main gaps:* everything;
Apple MDM needs an Apple Push certificate (free, external).

**Microsoft 365 Groups.** *Exists:* directory groups in OpenLDAP and group-membership changes as typed ICS actions
([user-lifecycle-results.md](../status/user-lifecycle-results.md)). *Planned:* one group object that grants mailbox, calendar, library and
chat in one step; the F2 authorisation API (GRP document). *Main gap:* each application keeps its own permissions today (F2 is a gap).

**Business apps (Planner, To Do, Lists, Forms, Bookings, OneNote, Power Automate / Apps).** *Exists:* tasks only through the groupware task
folders (not separately tested). *Planned:* P10.1 (workflow, forms, lists, tasks) and P10.8 (advanced documents), both deferred.
*Main gaps:* all rows in the APP section.

**Security and compliance (Purview, Defender, audit, search).** *Exists:* hash-chained audit for administrative actions in the ICS
([security-review-ics-2026-11-15.md](../status/security-review-ics-2026-11-15.md)); service monitoring and incidents for infrastructure
(P1.2). *Planned:* F4 unified search, F5 legal-hold hooks, P10.4 and P10.5. *Main gaps:* no DLP, retention, legal hold or eDiscovery; F5 is the
largest architecture risk.

**Migration.** *Exists:* read-only readiness assessment for Microsoft 365 (Graph) and Google (fixture-tested, P7.1 `implementing`,
[migration-assessment.md](../status/migration-assessment.md)); IMAP mail mover, incremental and resumable, lab-proven for one mailbox
(P7.2, [migration-engine-results.md](../status/migration-engine-results.md)). *Planned:* every other MIG row. *Main gaps:* never run against
a real tenant; no calendar, contact, file, permission or group migration (calendar/contacts frozen as WIP after failed verification).

**Administration (Microsoft 365 admin center).** *Exists:* Organization Admin in the portal on a separate tenant API, customer-bound, with
users, groups, branding, DNS check, aliases, shared mailboxes and quotas (P4.2, [org-admin-results.md](../status/org-admin-results.md)).
*Planned:* service health, message centre, reports, update approvals for the tenant. *Main gap:* reports, health and audit views for the tenant.

**MSP (Partner Center / GDAP / Lighthouse).** *Exists:* versioned MSP provisioning API with HMAC signing, idempotency, permission sets and signed
webhooks (P4.3, [msp-api-results.md](../status/msp-api-results.md)); two isolated customer stacks with denial tests (P4.1). *Planned:*
MSP Control Center console, delegated technician roles, cross-customer reporting. *Main gap:* the MSP Control Center console is not started.

**Desktop and mobile experience.** *Exists:* unified portal with SSO ([portal-results.md](../status/portal-results.md)); one look across
portal, sign-in, Files and webmail (P3.4 `implementing`). *Planned:* guided desktop and mobile onboarding (P3.3), unified navigation,
search and notifications (UX rows). *Main gaps:* no Office Unbound mobile app; no tested phone client; no cross-application search or
notifications.

*Owner direction (2026-11-23):* chat is delivered two ways. (1) The **Office Unbound desktop app** for Windows and macOS combines file sync
(ODB-sync) and chat (TMS-02) in one signed application. (2) On the web, chat is always at hand: the portal's chat bubble keeps chat running in
the background on every page, with a pop-out window (portal 0.3.3, 0.11.0). Requirement UX-CHAT-1: the same chat session and unread state in
both; the desktop app is Planned (costs: Windows code signing, Apple Developer Program, flagged in the ODB and ENT documents).

---

## Matrix

### Summary pointers to the detailed documents

| ID | Microsoft product | Feature | Office Unbound equivalent | Existing component | Status | Gap | Priority | Dependencies | Difficulty | Acceptance criteria | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|---|
| EXO-mail (see [EXO](calendar-and-mailbox-delegation.md)) | Exchange Online | Mailboxes, webmail, desktop protocols | Gromox groupware + webmail | Gromox 3.13-ou build, grommunio-web | integrated_lab (P1.3) | Internet mail not verified; real Outlook untested | A | P1.11, P8.1 | L | Defined in EXO document | [groupware-deploy-results.md](../status/groupware-deploy-results.md) |
| EXO-shared-mailbox (see [EXO](calendar-and-mailbox-delegation.md)) | Exchange Online | Shared mailboxes, send-as, send-on-behalf | Shared mailbox through tenant admin | `idm.shared_mailbox.*` actions | integrated_lab (P4.2) | SMTP send-as not offered (EWS only) | A | P4.2 | M | Defined in EXO document | [mailbox-admin-results.md](../status/mailbox-admin-results.md), [gw-client-fixes-results.md](../status/gw-client-fixes-results.md) |
| EXO-calendar (see [EXO](calendar-and-mailbox-delegation.md)) | Exchange / Outlook | Calendars, shared calendars, free/busy, rooms | Groupware calendars, CalDAV | Gromox, grommunio-dav | integrated_lab (protocol only) | Sharing, rooms, free/busy in Outlook untested | A | EXO-mail | L | Defined in EXO document | [client-compat-results.md](../status/client-compat-results.md) |
| EXO-delegation (see [EXO](calendar-and-mailbox-delegation.md)) | Exchange / Outlook | Mailbox and calendar delegation | Delegate access via folder rights | Gromox `delegates.txt` | planned | No admin or user UI; untested in clients | A | EXO-calendar, GRP-groups | M | Defined in EXO document | — |
| EXO-contacts (see [EXO](calendar-and-mailbox-delegation.md)) | Exchange / Outlook | Personal and shared contacts, GAL | Groupware contacts, CardDAV, LDAP directory | Gromox, OpenLDAP | integrated_lab (personal) | Shared contacts untested | A | EXO-mail | M | Defined in EXO document | [client-compat-results.md](../status/client-compat-results.md) |
| ODB-files (see [ODB](onedrive-and-file-sharing.md)) | OneDrive | Personal cloud storage, versions | OpenCloud personal space | OpenCloud 9.1 | integrated_lab (P1.5) | Retention/trash policy | A | — | M | Defined in ODB document | [identity-files-lab-results.md](../status/identity-files-lab-results.md) |
| ODB-sync (see [ODB](onedrive-and-file-sharing.md)) | OneDrive | Desktop sync, offline, placeholders | OpenCloud desktop client | `opencloudcmd` sync engine | integrated_lab (engine) | GUI clients and placeholders untested | A | ODB-files | M | Defined in ODB document | [identity-files-lab-results.md](../status/identity-files-lab-results.md) |
| ODB-sharing (see [ODB](onedrive-and-file-sharing.md)) | OneDrive | Share with people, links, expiry | OpenCloud shares | OpenCloud 9.1 | planned | Not tested by the project; no tenant policy | A | GRP-revocation | M | Defined in ODB document | — |
| ODB-coedit (see [ODB](onedrive-and-file-sharing.md)) | Office for the web | Co-editing in the browser | Collabora via WOPI | Own Collabora build | integrated_lab (P1.6, P1.7) | Multi-user concurrency not measured | A | ODB-files | M | Defined in ODB document | [docs-reliability-results.md](../status/docs-reliability-results.md) |
| SPO-libraries (see [SPO](sharepoint-and-team-libraries.md)) | SharePoint | Team document libraries | OpenCloud project spaces | OpenCloud 9.1 | planned | Spaces untested; no group binding | A | GRP-groups | L | Defined in SPO document | — |
| SPO-sites (see [SPO](sharepoint-and-team-libraries.md)) | SharePoint | Sites, pages, intranet, metadata | Intranet and knowledge centre | — | deferred (P10.2) | Everything | D | F2, F4 | L | Defined in SPO document | — |
| GRP-groups (see [GRP](unified-groups-and-permissions.md)) | Microsoft 365 Groups | One group for mail, calendar, files, chat | Unified group object | OpenLDAP groups, `idm.user.update_groups` | planned | No cross-application group | A | F2 | L | Defined in GRP document | [user-lifecycle-results.md](../status/user-lifecycle-results.md) |
| GRP-authz (see [GRP](unified-groups-and-permissions.md)) | Entra / Graph | Central "can U do A on O" check | F2 authorisation API | — | planned (P10.0 design) | Gap F2 | A | F1 | L | Defined in GRP document | — |
| GRP-revocation (see [GRP](unified-groups-and-permissions.md)) | Entra / Exchange / OneDrive | Access removal everywhere, quickly | ICS deprovisioning with VERIFY | `idm.user.disable` | integrated_lab (P1.8) | App-token resurrection, ActiveSync wipe | A | — | M | Defined in GRP document | [user-lifecycle-results.md](../status/user-lifecycle-results.md) |
| ENT-sso (see [ENT](entra-identity-parity.md)) | Entra ID | SSO, MFA, one directory | Keycloak + OpenLDAP | Keycloak 26.8.2 | integrated_lab (P1.4) | Passkeys/policy UI | A | — | M | Defined in ENT document | [identity-files-lab-results.md](../status/identity-files-lab-results.md) |
| ENT-conditional-access (see [ENT](entra-identity-parity.md)) | Entra ID | Conditional and device-based access | Keycloak flows with device signals | — | deferred (P10.10) | F6 gap | C | F6, MDM-enroll | XL | Defined in ENT document | — |
| ENT-desktop-login (see [ENT](entra-identity-parity.md)) | Entra join | Windows/macOS/Linux sign-in | Office Unbound Connect | — | deferred (P10.12) | Everything; Entra join itself cannot be reproduced | C | P10.6, P10.10 | XL | Defined in ENT document and [office-unbound-connect.md](office-unbound-connect.md) | — |
| MDM-enroll (see [MDM](intune-and-mobile-mdm.md)) | Intune | Device enrollment and inventory | Endpoint management (P10.6) | — | deferred (P10.6) | Everything | C | F8 | XL | Defined in MDM document | — |
| MDM-mobile-apps (see [MDM](intune-and-mobile-mdm.md)) | Intune / Outlook mobile | Mobile app protection policies | App protection for Office Unbound apps | — | planned | No Office Unbound mobile app | B | UX-mobile | XL | Defined in MDM document | — |
| WIPE-selective (see [WIPE](mobile-remote-wipe-security.md)) | Intune | Selective (account/app) wipe | Account wipe via ActiveSync and app sign-out | — | planned | ActiveSync wipe gap in lifecycle | B | GRP-revocation | M | Defined in WIPE document | [user-lifecycle-results.md](../status/user-lifecycle-results.md) (gap noted) |
| WIPE-full (see [WIPE](mobile-remote-wipe-security.md)) | Intune | Full wipe of managed devices | Full wipe for eligible enrolled devices | — | planned | Needs MDM enrollment | B | MDM-enroll | L | Defined in WIPE document | — |

### TMS — Teams

| ID | Microsoft product | Feature | Office Unbound equivalent | Existing component | Status | Gap | Priority | Dependencies | Difficulty | Acceptance criteria | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|---|
| TMS-01 | Teams | Team workspace (one place per team: chat, files, calendar, members) | Team workspace bound to a unified group | — | planned | No binding between Matrix space, OpenCloud space, group calendar and group | A | GRP-groups, SPO-libraries, TMS-02 | L | Creating a team creates group, chat space, library and calendar in one approved action; removing a member removes all four accesses within the revocation target; cross-tenant test passes | — |
| TMS-02 | Teams | Persistent chat, channels, threads, direct messages | Matrix (Synapse + MAS) with Element Web | Synapse 1.165, MAS 1.29, Element 1.12 (lab) | integrated_lab (P6.2) | Not deployed by the ICS; no catalog tier; not restyled | A | P2.2 catalog, P3.4 | M | ICS deploys the chat tier; SSO-only login; channel/thread/DM tests pass on a deployment; history survives restart and restore | [collaboration-lab-results.md](../status/collaboration-lab-results.md) |
| TMS-03 | Teams | Files in chat and channels stored in the team library | Matrix attachments saved to the team's OpenCloud space (not only Matrix media store) | Matrix authenticated media (lab) | planned | Attachments live in the Matrix media store only | A | TMS-01, ODB-sharing | M | A file posted in a channel appears in the team library with the same permissions; removing the member removes access to both | [collaboration-lab-results.md](../status/collaboration-lab-results.md) (media only) |
| TMS-04 | Teams / Exchange | Group calendar and channel meetings | Group calendar in groupware, meeting link from Jitsi | Gromox calendars, Jitsi (lab) | planned | No group calendar; no meeting link in invitations | A | GRP-groups, EXO-calendar, TMS-05 | M | Scheduling from the group calendar sends invitations with a working, room-scoped meeting link | — |
| TMS-05 | Teams | Video meetings with SSO, lobby, guests by link | Jitsi with SSO-issued room tokens | Jitsi stable, token service (lab) | integrated_lab (P6.2) | Not deployed by the ICS; lobby and moderator rights untested | A | P2.2 | M | ICS-deployed meeting tier; signed-in join; room token does not admit another room; moderator and lobby tests | [collaboration-lab-results.md](../status/collaboration-lab-results.md) |
| TMS-06 | Teams | Screen sharing | Jitsi screen share | Jitsi (lab) | planned | Not tested | A | TMS-05 | S | Screen share from Chromium and Firefox seen by a second participant (automated) | — |
| TMS-07 | Teams | Guest access to teams and meetings | External guest accounts with expiry | Keycloak guest role (`opencloudGuest` in lab) | planned | No guest lifecycle across chat/files/meetings | A | ENT-sso, GRP-revocation | M | Guest joins with an expiring link, sees only shared content, loses access at expiry | — |
| TMS-08 | Teams | Presence and notifications | Matrix presence, unified notifications | — | planned | No cross-application presence | D | UX-notify | M | Presence visible in chat and contact card; calendar-busy reflected | — |
| TMS-09 | Teams | Meeting recording and recording library | Jibri recording to OpenCloud | — | deferred (P10.7) | Everything | D | TMS-05, ODB-files | M | Recorded meeting lands in the organiser's library with permissions of attendees | — |
| TMS-10 | Teams | Transcripts and captions | whisper.cpp, local only | — | deferred (P10.7) | Everything | D | TMS-09, CMP-01 | M | Transcript produced without internet access, searchable only by permitted users | — |
| TMS-11 | Whiteboard | Whiteboard | Excalidraw, saved as a file | — | deferred (P10.7) | Everything | D | ODB-files | S | Whiteboard saved to the library and reopened | — |
| TMS-12 | Teams Live Events / Webinars | Webinars and town halls | Jitsi/LiveKit + RTMP/HLS relay | — | deferred (P10.7) | Everything; scale unmeasured | D | TMS-05 | L | Webinar with N viewers measured and published | — |
| TMS-13 | Teams | Chat history retention and export | Matrix retention policy + export | — | planned | No retention policy; no export | D | CMP-03, CMP-05 | M | Retention deletes on schedule with audit; per-room export in an open format | — |
| TMS-14 | Teams Phone | Calling and PSTN | Asterisk + browser softphone; optional user-supplied SIP trunk | Asterisk (lab) | integrated_lab (P6.3) | Not deployed by the ICS; emergency calling not possible without a certified trunk | D | Legal review | L | Internal calls on a deployment; trunk calls in lab; emergency-calling limits documented per jurisdiction | [telephony-lab-results.md](../status/telephony-lab-results.md) |
| TMS-15 | Teams | Teams-to-Office-Unbound interop during migration | Mail/calendar coexistence only | — | planned | Teams chats and meetings cannot be federated; history migrates as export, not as Teams objects | A | MIG-17 | M | Coexistence limits documented and tested in MIG dry runs | — |

### APP — Business applications

| ID | Microsoft product | Feature | Office Unbound equivalent | Existing component | Status | Gap | Priority | Dependencies | Difficulty | Acceptance criteria | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|---|
| APP-01 | To Do | Personal tasks synced to mail clients | Groupware task folders (CalDAV VTODO / EAS tasks) | Gromox | planned | Not tested in any client | A | EXO-mail | S | Task created on web appears in Thunderbird and over ActiveSync, and back | — |
| APP-02 | Planner | Team task boards, assignments, due dates | Integrated task app (Vikunja/Taiga, chosen in P10.0) | — | deferred (P10.1) | Everything | D | GRP-groups, F2 | L | Board per group; assignment notifies; removed member loses access | — |
| APP-03 | Lists | Structured lists and custom data models | Native data models on tenant database | — | deferred (P10.1) | Everything | D | F1, F2 | L | Non-developer creates a list with typed columns, views and permissions | — |
| APP-04 | Forms | Forms and quizzes | Native forms | — | deferred (P10.1) | Everything | D | F2 | M | Form shared internally and by link; responses exported as CSV | — |
| APP-05 | Forms | Surveys with anonymous responses | Native forms, anonymous mode | — | deferred (P10.1) | Everything | D | APP-04 | S | Anonymous survey stores no identity; verified in storage | — |
| APP-06 | Bookings | Public appointment booking | Booking pages on groupware calendars | — | planned | Everything | D | EXO-calendar | M | External visitor books a free slot; event lands in staff calendar; no double booking | — |
| APP-07 | OneNote | Notes and notebooks | Notebook app (candidate evaluated in P10.0) on OpenCloud | — | planned | No candidate chosen; OneNote format cannot be edited natively | D | ODB-files | L | Shared notebook with sections, images and co-editing; import path for exported OneNote content documented | — |
| APP-08 | Approvals | Approval requests | Workflow approvals | ICS approval engine (infrastructure only, not reused for tenant data) | deferred (P10.1) | Everything | D | P10.1 engine | M | Approval request routed, decided and audited | — |
| APP-09 | Power Automate | Workflow automation with triggers | Node-RED or Flowable behind a native designer | — | deferred (P10.1) | Everything | D | F3, F2 | XL | Mail/file trigger runs a flow under the user's permissions, every run audited | — |
| APP-10 | Power Apps | Low-code app builder | Native builder on APP-03 | — | deferred (P10.1) | Everything | D | APP-03 | XL | Non-developer builds a form-over-data app; export/import works | — |
| APP-11 | Office templates | Document, sheet and presentation templates per tenant | Template store on OpenCloud | — | deferred (P10.8) | Everything | D | ODB-files | S | Tenant admin publishes a template; users create from it | — |
| APP-12 | Word / Excel / PowerPoint | Advanced document fidelity | Own Collabora build; replaceable WOPI engine | Collabora own build | integrated_lab (P1.7); fidelity programme deferred (P10.8) | No fidelity corpus or scores | A | ODB-coedit | XL | Published fidelity scores on a real-world DOCX/XLSX/PPTX corpus | [docengine-build-results.md](../status/docengine-build-results.md) |
| APP-13 | Excel / Word | Macros (VBA) | LibreOffice Basic; VBA only where the engine supports it | — | deferred (P10.8) | Full VBA compatibility is not achievable | D | APP-12 | XL | A defined macro set runs; unsupported macros are reported, not silently dropped | — |
| APP-14 | Clipchamp / Stream / Sway | Video and media pages | — (not planned) | — | deferred | Out of scope until owner decides | D | — | — | Owner decision recorded | — |

### CMP — Security, compliance, search, analytics, APIs

| ID | Microsoft product | Feature | Office Unbound equivalent | Existing component | Status | Gap | Priority | Dependencies | Difficulty | Acceptance criteria | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|---|
| CMP-01 | Microsoft Search | Universal search across mail, files, chat, people, permission-trimmed | F4 unified search index | Per-app search (Gromox, OpenCloud) | planned (P10.0 design) | Gap F4 | A | F2, F4 | L | A user finds only what they can open (red-team test); tenant-partitioned index | — |
| CMP-02 | Purview DLP | Data loss prevention on mail and files | Native policy engine + Presidio | — | deferred (P10.5) | Everything | D | F3, CMP-06 | L | Test card number blocked or flagged on send and share | — |
| CMP-03 | Purview retention | Retention policies | Retention service with storage hooks | — | deferred (P10.5) | Gap F5 | D | F5 | L | Retention deletes on schedule with audit record | — |
| CMP-04 | Purview legal hold | Legal hold on mailboxes and files | F5 hooks in Gromox and OpenCloud | — | deferred (P10.5) | Gap F5 (largest architecture risk) | D | F5 | XL | Deletion attempts on held items fail at store level | — |
| CMP-05 | Purview eDiscovery | Search, hold, export with manifest | eDiscovery on F4 with EML/MBOX, ICS/VCF, files + hash manifest | Mailbox export/import (restore drills) | deferred (P10.5) | Everything beyond restore export | D | CMP-01, CMP-04 | L | Export complete and hash-manifested for a case | [restore-drill-results.md](../status/restore-drill-results.md) (restore only) |
| CMP-06 | Purview Information Protection | Classification and sensitivity labels | Labels as metadata enforced by F2 | — | deferred (P10.5) | No encryption-bound labels; Microsoft labels cannot be read as protected content | D | F2 | L | Labelled file cannot be shared externally; label survives copy | — |
| CMP-07 | Purview | Sensitive data discovery | Presidio + Tika scans | — | deferred (P10.5) | Everything | D | F4 | M | Seeded PII found in mail and files; report per tenant | — |
| CMP-08 | Purview Audit | User-data audit log (who opened, shared, deleted) | Per-application audit feeding a tenant audit view | ICS admin audit (hash-chained) | planned | No user-data audit | A | F3 | M | Share, download and delete events visible to the tenant admin, not to other tenants | [security-review-ics-2026-11-15.md](../status/security-review-ics-2026-11-15.md) (admin audit) |
| CMP-09 | Compliance Manager | Compliance reports | Configurable reports; no certification claimed | — | deferred (P10.5) | Everything | D | CMP-08 | M | Report generated from audit data; wording claims no certification | — |
| CMP-10 | Intune compliance | Device compliance status | Posture signals (F6) | — | deferred (P10.6) | Everything | C | MDM-enroll | L | Non-compliant device reported and usable by ENT-conditional-access | — |
| CMP-11 | Defender for Endpoint | Endpoint security, EDR, isolation | Wazuh + rem0te | — | deferred (P10.4) | Everything | D | MDM-enroll | XL | Test endpoint isolated after approved response and restored | — |
| CMP-12 | Defender for Office 365 | Anti-spam, antivirus, phishing | rspamd + ClamAV; MailThreatZero later | — | planned | Not deployed by the ICS | A | EXO-mail | M | Spam and EICAR test mail quarantined on a deployment | — |
| CMP-13 | Defender / Sentinel | Security incidents for the tenant | Incidents routed into the ICS incident model per customer | ICS incidents (infrastructure) | planned | Tenant-facing security incidents missing | D | CMP-11, F3 | L | Simulated phishing becomes an incident visible only to that customer and its MSP | [ics-monitoring-results.md](../status/ics-monitoring-results.md) (infrastructure) |
| CMP-14 | Power BI | BI and analytics | Superset with per-tenant row-level security | — | deferred (P10.9) | Everything | D | F7 | L | Tenant dashboard on its own data only | — |
| CMP-15 | Admin usage reports | Usage analytics (active users, storage, mail volume) | Tenant reports from service metrics | ICS monitoring metrics | planned | No tenant reports | A | ADM-08 | M | Tenant admin sees its own usage; MSP sees aggregated per customer | — |
| CMP-16 | Microsoft Graph | User-data APIs and SDKs | Versioned tenant API, OpenAPI, SDKs | MSP API conventions (ADR-0013) | planned | No user-data API | D | F2, F3 | XL | Third-party app registered with scoped consent reads only consented data | [msp-api-results.md](../status/msp-api-results.md) (conventions) |
| CMP-17 | Graph change notifications | Webhooks for user-data events | F3 signed events | MSP signed webhooks (plan/job/incident) | planned | Not for user-data events | D | F3 | M | File and mail events delivered signed, retried, tenant-scoped | [msp-api-results.md](../status/msp-api-results.md) |
| CMP-18 | Copilot | AI assistance | Optional AI workspace, local or bring-your-own models, off by default | — | deferred (P10.3) | Everything; optional only | D | F2, F4 | L | Every feature works with AI disabled; no output from documents the user cannot open | — |

### MIG — Migration Center

The Migration Center moves **data and the access it implies**, not Microsoft objects. It never promises: proprietary sharing links that keep
working (old links point at Microsoft), Teams objects as Teams objects, Entra join state, Intune enrollment, Microsoft-encrypted content
without the keys, or Loop/Whiteboard/Planner objects in their native form. Each such item is listed in the compatibility report (MIG-30).

| ID | Microsoft product | Feature | Office Unbound equivalent | Existing component | Status | Gap | Priority | Dependencies | Difficulty | Acceptance criteria | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|---|
| MIG-01 | Entra ID | Users with aliases and attributes | Directory import into OpenLDAP via ICS actions | Assessment collector (users, proxyAddresses) | implementing (P7.1) | Inventory only; no import | A | ADM-02 | M | Users created with aliases; counts and attributes reconcile | [migration-assessment.md](../status/migration-assessment.md) |
| MIG-02 | Entra / M365 Groups | Groups, distribution lists, memberships, owners | Unified groups | Assessment collector (groups, members) | implementing (P7.1) | No import | A | GRP-groups | M | Memberships and owners reconcile per group | [migration-assessment.md](../status/migration-assessment.md) |
| MIG-03 | Exchange Online | Mail with folder hierarchy, flags | IMAP mover (Graph/EWS later) | `ou_migration` mail-migrate | integrated_lab (P7.2) | One mailbox per process; never against a real tenant; OAuth2 stubs only | A | — | M | Real-tenant mailbox migrated; counts, folder map and spot hashes verified | [migration-engine-results.md](../status/migration-engine-results.md) |
| MIG-04 | Exchange Online | Shared mailboxes and their grants | Shared mailbox + full access/send-as grants | `idm.shared_mailbox.*` | planned | Not started | A | EXO-shared-mailbox, MIG-03 | M | Grants reproduced; delegate opens the migrated shared mailbox | — |
| MIG-05 | Exchange Online | Calendars incl. recurrences and attendees | Groupware calendars | — | planned (frozen WIP) | Verification did not pass; frozen until after alpha | A | EXO-calendar | L | Recurrence, exceptions, attendees and time zones verified | — |
| MIG-06 | Exchange Online | Shared calendars and their permissions | Calendar folder rights | — | planned | Not started | A | MIG-05, EXO-delegation | M | Shared calendar visible to the same people with the same rights | — |
| MIG-07 | Exchange Online | Contacts and shared contact folders | Groupware contacts | — | planned (frozen WIP) | Frozen with MIG-05 | A | EXO-contacts | M | Contact counts and fields verified | — |
| MIG-08 | Exchange Online | Mailbox delegations (full access, send-as, on behalf, calendar delegate) | Folder rights, `sendas.txt`, `delegates.txt` | — | planned | Not started | A | EXO-delegation | M | Each source delegation reproduced or listed as unsupported | — |
| MIG-09 | Exchange Online | Resource and room calendars | Resource mailboxes | — | planned | Not started | A | EXO-calendar | M | Rooms bookable with the same policy | — |
| MIG-10 | Exchange Online | Inbox rules and forwarding | Sieve/Gromox rules | — | planned | Not started; some rule conditions have no equivalent | A | EXO-mail | M | Supported rules reproduced; unsupported ones listed per user | — |
| MIG-11 | OneDrive | Personal files with versions and timestamps | OpenCloud personal space | — | planned | Not started | A | ODB-files | L | Byte-identical content; version count and modified times preserved where the target allows | — |
| MIG-12 | SharePoint | Document libraries, folder hierarchy | OpenCloud project spaces | — | planned | Not started | A | SPO-libraries | L | Tree and content reconcile per library | — |
| MIG-13 | SharePoint / OneDrive | Ownership and sharing permissions (people and groups) | OpenCloud shares and space membership | — | planned | Not started; anonymous links not carried, re-created on request | A | ODB-sharing, MIG-35 | L | Effective access matches the source for every mapped principal; differences reported | — |
| MIG-14 | SharePoint | Metadata columns and content types | Metadata on files (where supported) | — | planned | Target metadata model undecided (SPO document) | D | SPO-sites | L | Supported columns preserved; others exported to a sidecar manifest | — |
| MIG-15 | SharePoint / OneDrive | Version history | OpenCloud versions | — | planned | Not started | A | MIG-11 | M | Last N versions migrated with authors and dates | — |
| MIG-16 | Teams | Team memberships and channels | Team workspace, chat rooms | — | planned | Not started | A | TMS-01 | M | Members and channels reproduced | — |
| MIG-17 | Teams | Chat and channel history | Read-only archive (export) | — | planned | History is imported as an archive, not as live Teams objects | D | TMS-02 | L | History searchable read-only by former members only | — |
| MIG-18 | Teams / SharePoint | Files in team channels | Team library | — | planned | Not started | A | MIG-12, TMS-03 | M | Channel files land in the team library | — |
| MIG-19 | Purview | Retention labels and hold metadata | Exported as metadata for CMP-03 | — | planned | No target until F5 | D | CMP-03 | M | Retention metadata preserved in manifest; holds flagged in compatibility report | — |
| MIG-20 | Entra ID | Identity mapping (UPN, aliases, object IDs → new accounts) | Mapping table used by every mover | — | planned | Not started | A | MIG-01 | M | Every source principal maps to one target or is reported | — |
| MIG-21 | Google Workspace | Gmail, Calendar, Contacts, Drive, shared drives | Same movers with Google collectors | Google collector, IMAP XOAUTH2 path | implementing (P7.1) | Labels not carried; Drive not started | A | MIG-03, MIG-11 | L | Same verification as Microsoft rows | [migration-assessment.md](../status/migration-assessment.md) |
| MIG-30 | — | Readiness assessment and compatibility report | Read-only assessment with unsupported-item list | Assessment package | implementing (P7.1) | Never run against a real tenant | A | — | M | Report on a real tenant lists counts, sizes and every unsupported object type | [migration-assessment.md](../status/migration-assessment.md) |
| MIG-31 | — | Inventory and storage estimates | Assessment `--deep`, bandwidth estimate | Assessment package | implementing (P7.1) | Unverified on real data | A | MIG-30 | S | Estimate within a stated tolerance of the actual migration | [migration-assessment.md](../status/migration-assessment.md) |
| MIG-32 | — | Dry run | Mover in no-write mode with full report | — | planned | Not started | A | MIG-30 | M | Dry run writes nothing (verified) and predicts the error list | — |
| MIG-33 | — | Coexistence (mail routing, free/busy) | Split delivery; free/busy limits documented | — | planned | Not started; cross-platform free/busy may not be achievable | A | EXO-mail | L | Mail flows both ways during coexistence; limits documented | — |
| MIG-34 | — | Incremental sync and resume | State file, delta runs | Mail mover state/resume | integrated_lab (mail only) | Files, calendars not covered | A | MIG-03 | M | Delta copies only changes; kill/resume without duplicates | [migration-engine-results.md](../status/migration-engine-results.md) |
| MIG-35 | — | Permission mapping review | Admin reviews mapped permissions before cutover | — | planned | Not started | A | MIG-20 | M | Every unmapped or widened permission is shown before cutover | — |
| MIG-36 | — | Cutover wizard (MX, Autodiscover, DNS, final delta) | Wizard in Migration Center, approval-gated | — | planned | Not started | A | MIG-33, P2.12 | L | Guided cutover on a lab tenant with checklist and final verification | — |
| MIG-37 | — | Post-migration verification | Count/hash reconciliation per object type | Mail verify | integrated_lab (mail only) | Other types | A | all MIG movers | M | Signed verification report per tenant | [migration-engine-results.md](../status/migration-engine-results.md) |
| MIG-38 | — | Rollback | Source untouched (read-only); rollback = revert DNS | Read-only source guard | integrated_lab (guard) | No rollback runbook | A | MIG-36 | M | Rollback drill restores service on the source without data loss | [migration-engine-results.md](../status/migration-engine-results.md) |
| MIG-39 | — | Error reports and retries | Per-item error list with retry | Mover logs | planned | No consolidated report | A | MIG-37 | S | Every failed item listed with reason and retry outcome | — |
| MIG-40 | — | Migration Center UI (tenant and MSP) | Migration Center in tenant admin and MSP console | — | planned | CLI only ([migration.md](../admin/migration.md)) | A | UX-shell | L | A tenant admin runs assessment → dry run → migrate → verify in the UI | — |

### ADM — Tenant administration (Microsoft 365 admin center equivalent)

| ID | Microsoft product | Feature | Office Unbound equivalent | Existing component | Status | Gap | Priority | Dependencies | Difficulty | Acceptance criteria | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|---|
| ADM-01 | M365 admin center | Tenant admin console separate from infrastructure | Organization Admin in the portal, tenant API | `/api/v1/tenant/*`, portal admin | integrated_lab (P4.2) | Not every lifecycle step run on agents | A | — | M | Tenant admin cannot reach any ICS route; cross-tenant denial tests pass | [org-admin-results.md](../status/org-admin-results.md) |
| ADM-02 | M365 admin center | Users: create, edit, disable, delete, reset credentials | Tenant user management through ICS actions | `idm.user.*` | integrated_lab (P1.8, P4.2) | Bulk import (CSV) | A | — | M | Lifecycle with verified revocation; CSV import of 500 users | [user-lifecycle-results.md](../status/user-lifecycle-results.md) |
| ADM-03 | M365 admin center | Groups and memberships | Group management | `idm.user.update_groups` | integrated_lab | Unified group type | A | GRP-groups | M | Group change reflected in every app | [user-lifecycle-results.md](../status/user-lifecycle-results.md) |
| ADM-04 | M365 admin center | Domains and DNS check | DNS check, setup guidance | `dnscheck.py` | integrated_lab (P4.2) | DNS automation planned | A | P2.12 | S | Missing MX/SPF/DKIM/DMARC reported correctly | [org-admin-results.md](../status/org-admin-results.md) |
| ADM-05 | Exchange admin center | Aliases, shared mailboxes, quotas | Tenant mail settings | `mailadmin.py` | integrated_lab (P4.2) | — | A | — | S | Already defined in mailbox-admin results | [mailbox-admin-results.md](../status/mailbox-admin-results.md) |
| ADM-06 | M365 admin center | Admin roles (user admin, helpdesk, security reader) | Tenant RBAC roles | `org-admin` realm role | planned | Single role only | A | F2 | M | Each role can do only its listed actions (negative tests) | — |
| ADM-07 | M365 admin center | Service health for the tenant | Health view fed by ICS monitoring, tenant-scoped | ICS monitoring | planned | Not exposed to tenant | A | P1.2 | M | Tenant sees its own service states, never another tenant's | [ics-monitoring-results.md](../status/ics-monitoring-results.md) |
| ADM-08 | M365 admin center | Usage and storage reports | Tenant reports | — | planned | Everything | A | CMP-15 | M | Reports match measured usage | — |
| ADM-09 | Message center | Update notices and approval windows | Tenant update approvals within MSP policy | Patch rings (P5.1, infrastructure) | planned | No tenant-facing update approvals | A | P5.1 | M | Tenant approves or defers within the MSP's allowed window | — |
| ADM-10 | Security settings | MFA enforcement, session policies | Keycloak policies managed per tenant | Keycloak | planned | No tenant UI | A | ENT-sso | M | Enforced MFA blocks a non-enrolled user after grace | — |
| ADM-11 | Audit | Tenant admin audit log view | Tenant-scoped view of admin audit | ICS hash-chained audit | planned | Not exposed to tenant | A | CMP-08 | S | Tenant sees its own admin events only | — |
| ADM-12 | Branding | Organisation branding and app switches | Tenant branding | Portal admin branding | integrated_lab (P4.2) | — | D | — | S | Branding applies to portal, sign-in and Files | [org-admin-results.md](../status/org-admin-results.md) |
| ADM-13 | Data export | Tenant data export (portability) | Full tenant export in open formats | Per-tier backups | planned | No tenant-initiated export | A | F7 | L | Export of all mail, calendars, contacts and files in open formats, with manifest | [backup-product-results.md](../status/backup-product-results.md) (backups only) |
| ADM-14 | Backup | Tenant backup and restore (user and item level) | Per-tier backup with item restore | restic tiers | integrated_lab (P5.3) | Not wired into rebuild; no item-level self-service | A | P5.3 | M | Restore of one mailbox folder and one file version by the tenant admin | [backup-product-results.md](../status/backup-product-results.md) |

### MSP — Delegated management and provisioning

| ID | Microsoft product | Feature | Office Unbound equivalent | Existing component | Status | Gap | Priority | Dependencies | Difficulty | Acceptance criteria | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|---|
| MSP-01 | Partner Center | Provisioning API for customers and stacks | Versioned MSP API (OpenAPI 3.1, HMAC, idempotency) | `ics/ics/msp` | integrated_lab (P4.3) | Not run against a real MSP system | A | — | M | Reference client provisions a customer end to end | [msp-api-results.md](../status/msp-api-results.md) |
| MSP-02 | GDAP | Delegated, scoped technician access per customer | Technician roles scoped to customers, approval for high risk | MSP client permission sets (API) | planned | No technician console role model | A | MSP-03 | L | Technician sees only assigned customers; every action audited with technician identity | — |
| MSP-03 | Lighthouse | MSP Control Center console (all customers) | MSP Control Center | — | planned (P4.2 MSP half not started) | Everything | A | UX-shell | L | MSP sees all its customers' health, users, updates; no cross-MSP visibility | — |
| MSP-04 | Lighthouse | Cross-customer reporting | Aggregated reports per customer | MSP metering (`metering.py`) | planned | No reports | A | CMP-15 | M | Monthly report per customer generated from metering | [msp-api-results.md](../status/msp-api-results.md) |
| MSP-05 | Lighthouse | Baseline policies across customers | Policy templates applied per customer | — | planned | Everything | D | ADM-10 | M | Template applied to N customers with a diff preview | — |
| MSP-06 | Partner Center | Signed webhooks for MSP systems (PSA/RMM) | MSP webhooks | Signed webhook outbox | integrated_lab (P4.3) | User-data events (F3) | A | F3 | S | Events delivered signed, retried, SSRF-guarded | [msp-api-results.md](../status/msp-api-results.md) |
| MSP-07 | — | Customer isolation on shared infrastructure | Per-customer stacks and SDN | Two-stack denial tests; SDN implementing | integrated_lab (P4.1) / implementing (P2.10) | Not proven on real Proxmox | A | P2.10 | L | Denial tests on two real-Proxmox customers with SDN | [tenant-isolation-results.md](../status/tenant-isolation-results.md) |
| MSP-08 | — | Customer onboarding wizard (domain, users, migration) | Guided onboarding in MSP console | Deployment wizards (infrastructure) | planned | Tenant onboarding steps | A | MSP-03, MIG-40 | M | New customer onboarded from the console without the CLI | — |
| MSP-09 | — | Billing-neutral metering (no licence enforcement) | Usage metering for MSP invoicing; never a cap | `metering.py` | integrated_lab (P4.3) | Report UI | D | MSP-04 | S | Metering never blocks usage (test) | [msp-api-results.md](../status/msp-api-results.md) |

### UX — Unified experience (concept and mockup requirements only)

These rows define what concepts and mockups must show; they do not authorise implementation. Four admin surfaces stay separate: **user
portal**, **tenant admin**, **MSP admin**, **ICS**. The ICS keeps infrastructure authority and is never merged with tenant or device management.

| ID | Microsoft product | Feature | Office Unbound equivalent | Existing component | Status | Gap | Priority | Dependencies | Difficulty | Acceptance criteria | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|---|
| UX-shell | M365 app launcher | One navigation frame across apps | One top bar and app rail | Portal + restyled apps | implementing (P3.4) | Webmail, chat, meetings not in one frame | A | — | L | Concept shows every app in one frame; usability review with 5 users | [portal-results.md](../status/portal-results.md) |
| UX-search | Microsoft Search | One search box across mail, files, people, chat | Search bar backed by CMP-01 | — | planned | F4 | A | CMP-01 | M | Mockup shows grouped, permission-trimmed results | — |
| UX-notify | M365 notifications | Cross-app notifications | Notification centre (F3 events) | ICS alert channels (infrastructure) | planned | Everything for users | D | F3 | M | Mockup and event list defined | — |
| UX-share | OneDrive share dialog | One sharing dialog for files, folders, libraries, calendars | Shared sharing component | — | planned | Each app has its own | A | ODB-sharing, F2 | M | Mockup covers people, groups, links, expiry, revoke, "who has access" | — |
| UX-pickers | People / file pickers | One people picker and one file picker | Shared pickers on directory and OpenCloud | — | planned | Everything | A | GRP-groups | S | Mockup used in mail, chat, sharing, admin | — |
| UX-settings | Settings | One user settings area (profile, MFA, devices, language) | Portal account pages | Portal account and devices pages | integrated_lab (P3.2) | Not unified with app settings | A | — | M | All user settings reachable from one place | [portal-results.md](../status/portal-results.md) |
| UX-theme | — | One theme, light/dark, accessibility | Office Unbound look | look-0.9.3 | implementing (P3.4) | WCAG audit | A | — | M | Axe clean on all primary pages | [ui-verification-main.md](../status/ui-verification-main.md) |
| UX-errors | — | Consistent errors with next steps | Shared error pattern | — | planned | Upstream texts visible | A | — | S | Every error page names cause, effect, next step | — |
| UX-onboarding | — | Guided desktop and mobile onboarding | Onboarding in the portal | — | planned (P3.3) | Profiles unsigned, untested | A | ODB-sync, EXO-mail | M | New user connects phone mail and desktop sync from the guide on real devices | — |
| UX-mobile | Outlook / Teams / OneDrive mobile | Mobile experience | Responsive web + standard clients; own app only if owner approves | Responsive portal | planned | No own app; no tested phone client | B | P1.11 | XL | Mail, calendar, files and chat usable at 390 px; tested phone clients listed | — |
| UX-portal | Office.com | User portal surface | Portal (user) | Portal | integrated_lab (P3.2) | — | A | — | — | Remains a separate surface from the three admin surfaces | [portal-results.md](../status/portal-results.md) |
| UX-tenant-admin | M365 admin center | Tenant admin surface | Organization Admin | Portal admin area | integrated_lab (P4.2) | See ADM rows | A | — | — | Never shows infrastructure | [org-admin-results.md](../status/org-admin-results.md) |
| UX-msp-admin | Lighthouse | MSP admin surface | MSP Control Center | — | planned | See MSP rows | A | — | — | Concept separate from ICS and tenant admin | — |
| UX-ics | — | Infrastructure surface | ICS console | ICS console v3 | integrated_lab (P3.1) | — | A | — | — | Only infrastructure authority; no tenant data or device management | [console-v3-results.md](../status/console-v3-results.md) |

**Row counts:** pointers 21 · TMS 15 · APP 14 · CMP 18 · MIG 32 · ADM 14 · MSP 9 · UX 14.

---

## Proposed priority order

Proposed for owner review; it does not change the current alpha → beta queue ([ALPHA-EXECUTION-QUEUE.md](../status/ALPHA-EXECUTION-QUEUE.md)).

1. **A — business-ready collaboration.** What an office needs to switch on day one: mail, calendars (shared and delegated), contacts, shared
   mailboxes, personal and shared files, team libraries, sync, editing, groups, revocation, tenant admin, migration, MSP basics. *Rationale:*
   it is what customers notice first, most of the components already exist in the lab, and every later priority depends on its directory,
   groups and permissions.
2. **B — mobile security.** Account protection on phones, selective wipe, full wipe for eligible managed devices. *Rationale:* the first
   question an MSP asks after mail works on phones is "what happens when a phone is lost"; selective wipe builds on the revocation work in A.
3. **C — Entra/Intune-equivalent identity and devices.** Enrollment, device compliance, conditional access, desktop sign-in (P10.6, P10.10,
   P10.12). *Rationale:* needs the F6 device signal and a separate device agent (F8); highest effort and lowest dependency from A.
4. **D — wider Microsoft 365.** Business apps, intranet, compliance suite, SecOps, BI, advanced meetings, advanced documents, optional AI.
   *Rationale:* valuable, but each module is L/XL and most need F2/F4/F5 first.
5. **P9 PDF Studio — absolutely last**, after every P10 module.

Recommendation carried over from [post-core-expansion.md](../roadmap/post-core-expansion.md): design F2 (authorisation), F4 (search) and F5
(legal-hold hooks) early, because A-level sharing and groups already need F2, and retrofitting F5 into Gromox and OpenCloud is the largest risk.

## Readiness gates

Features and maturity are separate gates. A gate is passed only when **both** parts are met with recorded evidence; having a feature never
implies production maturity.

### Gate 1 — functional business beta

*Features (each with tested evidence on an ICS deployment, not only the lab):* users and groups · SSO · mail, calendar and contacts · shared
calendars · basic delegation · shared mailboxes · personal files · shared files and folders · team libraries · desktop sync · document
editing · version recovery · access revocation · tenant admin · backup and restore · monitoring.

Rows: ENT-sso, ADM-02, ADM-03, GRP-groups, EXO-mail, EXO-calendar, EXO-contacts, EXO-delegation, EXO-shared-mailbox, ODB-files, ODB-sharing,
SPO-libraries, ODB-sync, ODB-coedit, GRP-revocation, ADM-01, ADM-14, ADM-07.

*Maturity:* no open Critical/High security findings ([SECURITY-REMEDIATION.md](../status/SECURITY-REMEDIATION.md)); public signed
artifacts and an installer an outsider can run; in-place upgrade with rollback that keeps data; tenant isolation proven on real Proxmox
with SDN; restore drill of a full deployment; documented recovery runbooks; internet mail verified end to end; at least classic Outlook and one
phone client tested.

### Gate 2 — mobile security beta

*Features:* Gate 1, plus WIPE-selective, WIPE-full, MDM-mobile-apps (scope defined in the MDM document), UX-mobile, ADM-10.
*Maturity:* wipe tested on real Android and iOS devices; wipe actions are approval-gated and audited; no wipe path reachable across tenants.

### Gate 3 — advanced enterprise readiness

*Features:* MDM-enroll, CMP-10, ENT-conditional-access, ENT-desktop-login, CMP-01, CMP-04, CMP-05, CMP-08, MSP-02, MSP-03.
*Maturity:* independent security review; F5 holds proven by deletion attempts; HA or warm-standby controller drilled; signed releases with SBOM
for every component; published upgrade and rollback record over several releases.

## Licensing and architecture rules

These extend [ADR-0006](../adr/0006-deployment-model.md), [ADR-0007](../adr/0007-zero-cost-unlimited.md),
[ADR-0018](../adr/0018-gateway-certificates-dns.md) and [ADR-0019](../adr/0019-network-deployment-modes.md).

1. **Zero mandatory licence cost and no caps.** No per-user, per-mailbox, per-device or per-connection fee or limit in any mandatory component.
2. **No mandatory external paid APIs or cloud services.** Every core function works fully self-hosted; external services are opt-in.
3. **Self-hosted and MSP-hosted** on **Proxmox VE** first, through the ICS provider adapter.
4. **One public IP gateway** by default, **central certificates** held by the ICS (ACME), other network modes per ADR-0019.
5. **Single-tenant and multi-tenant modes** with one isolated stack per customer and `customer_id` on every record (F1).
6. **Data portability:** open formats for every export (EML/MBOX, ICS, VCF, files plus manifest); no lock-in to Office Unbound itself.
7. **Signed releases and SBOM** for packages and images ([ADR-0008](../adr/0008-build-release-pipeline.md), [ADR-0015](../adr/0015-artifact-distribution.md)).
8. **Backup and restore** for every new data store, drilled before a feature leaves the lab.
9. **Upgrades and rollback** for every component, with pre-upgrade backup.
10. **MSP APIs** follow [ADR-0013](../adr/0013-msp-provisioning-api.md); new features emit signed events where cheap (F3).
11. **AI is optional only**: every feature works with AI off; local models supported; external providers per tenant opt-in.
12. **No compatibility claims without tests**: "compatible with Outlook/Office/Teams" only with a linked client test.

### External dependencies and costs (for owner review)

| Dependency | Needed for | Cost | Mandatory? | Note |
|---|---|---|---|---|
| Public DNS and a domain | Every deployment | Registrar fee (customer's own) | Yes (customer-supplied) | Not an Office Unbound licence |
| Let's Encrypt (ACME) | Certificates | Free; rate limits | Default, replaceable by own CA/certs | 5 duplicate certificates per week ([known-limitations.md](../admin/known-limitations.md)) |
| Apple Push Notification certificate | Apple MDM, full wipe on Apple devices | Free, needs an Apple ID; yearly renewal | Only for Apple MDM | External dependency, documented in MDM/WIPE |
| Apple Developer Program | Signed/notarised macOS and iOS apps (Connect, own mobile app) | USD 99 per year | Only if we ship own Apple apps | Owner decision |
| Google Play developer account | Publishing an own Android app | USD 25 once | Only for an own Android app | F-Droid/APK as free alternative |
| Firebase Cloud Messaging / APNs | Push notifications on phones (chat, mail apps) | Free, external Google/Apple service | Only for push on stock phones | UnifiedPush/ntfy as self-hosted alternative where clients support it |
| Windows code-signing certificate | Signed Windows installers (sync client branding, Connect) | Roughly USD 200–700 per year (vendor-dependent) | Only for own Windows binaries | Owner decision |
| Android Management API | Android Enterprise MDM | Free, Google-hosted | Not acceptable as mandatory | Self-hosted alternative to be chosen in MDM document |
| SIP trunk | PSTN calling | Per-provider usage fees | Optional | Emergency-calling legal review required |
| Microsoft Graph / Google APIs | Migration from the source tenant | Free with the customer's existing subscription | Only during migration | Uses customer credentials, read-only |
| External AI providers | Optional AI | Provider fees (customer's key) | Never | Local models (Ollama, vLLM) are the default |
| Legal counsel | GPL-2.0-only gromox files, trademarks, AGPL §13, fonts | Professional fees | Before beta | Open items in [third-party-inventory.md](../status/third-party-inventory.md) |

## Top 20 missing high-impact features

Ordered by impact on a business switching from Microsoft 365 (priority A first).

1. ODB-sharing — tested sharing with people, groups and expiring links
2. SPO-libraries — team libraries bound to groups
3. GRP-groups — one unified group for mail, calendar, files and chat
4. EXO-calendar — shared calendars, free/busy and rooms tested in clients
5. EXO-delegation — mailbox and calendar delegation with UI
6. GRP-authz — F2 central authorisation (prerequisite for sharing, search, compliance)
7. MIG-05 / MIG-07 — calendar and contact migration (frozen WIP)
8. MIG-11 / MIG-12 / MIG-13 — OneDrive and SharePoint files with permissions
9. MIG-36 — cutover wizard with coexistence (MIG-33)
10. CMP-12 — anti-spam and antivirus on deployments
11. TMS-01 — team workspace tying chat, files, calendar and members
12. TMS-02 / TMS-05 — chat and meetings deployed by the ICS
13. ADM-06 — tenant admin roles
14. ADM-13 — tenant data export in open formats
15. MSP-03 / MSP-02 — MSP Control Center with delegated technician access
16. CMP-01 — permission-trimmed universal search (F4)
17. WIPE-selective — account wipe on lost phones
18. CMP-08 — user-data audit log
19. MDM-enroll — device enrollment and inventory
20. ENT-conditional-access — device-based conditional access

## Owner decisions requested

1. Confirm the priority order A → B → C → D, with P9 last, and whether early F2/F4/F5 design inside A is approved.
2. Whether to ship own mobile and desktop apps (needs Apple Developer Program, Windows code signing, store accounts) or rely on standard clients.
3. Whether chat and meetings (TMS-02, TMS-05) enter the Gate 1 feature list or stay after the business beta.
4. Notes app (APP-07) and Bookings (APP-06): keep on the roadmap or defer indefinitely; APP-14 (video/media pages) out of scope?
5. Teams history migration as a read-only archive (MIG-17): acceptable as the closest alternative?
6. Accept the external-dependency list above, in particular the Apple Push certificate for Apple MDM.
