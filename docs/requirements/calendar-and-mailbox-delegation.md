# Calendar sharing, meeting scheduling, shared mailboxes and delegation (Exchange Online parity)

**Status: PLANNED, planning only, not authorized for development.** Requirements document (2026-11-23, alpha 0.10.0). The
current roadmap and the beta directive keep priority until the owner explicitly authorizes this work. Rows marked
`integrated_lab` point at recorded lab evidence; everything else is planned or under research and must not be described
to customers as available. Status values follow [ADR-0000](../adr/0000-status-values.md).

Related requirement sets (other documents, cross-referenced by prefix): `GRP-` (unified-groups-and-permissions.md: group
mailbox and group calendar provisioning, distribution and security groups), `ENT-` (entra-identity-parity.md), `MDM-`
(intune-and-mobile-mdm.md), `WIPE-` (mobile-remote-wipe-security.md), `ODB-` / `SPO-` (files and team libraries; calendar
attachments and team sites). This document owns `EXO-`.

Priority tags: **A** business-ready collaboration, **B** mobile security, **C** Entra/Intune, **D** wider M365.

## 1. Scope

In scope: functional and workflow parity with Exchange Online and Outlook for calendars, meetings, resources, shared
mailboxes, delegation, contacts and the everyday Outlook feature set, delivered by the existing Gromox groupware stack and
administered through the ICS (typed actions, approvals, hash-chained audit) and the portal.

Not in scope: Microsoft protocol certification, Exchange hybrid, Microsoft Graph API compatibility, Teams calendar
integration (Matrix/Jitsi meeting links are an optional extension, EXO-MTG-14), eDiscovery and compliance suites beyond the
retention and audit rows below.

Principles (owner): zero mandatory licence cost, no user or mailbox caps, strict tenant isolation, authorization enforced on
the server (never only in a client UI), honest status.

Architecture preserved: OpenLDAP (directory) -> Keycloak (SSO/MFA) -> Gromox (own source build `3.13-ou3`, with
grommunio-web webmail, grommunio-sync ActiveSync, EWS, MAPI/HTTP, Autodiscover, IMAP/SMTP, CalDAV/CardDAV via
grommunio-dav). Mutations go through the ICS; no admin-api (licence module, 5-user cap, see
[groupware-ldap-results.md](../status/groupware-ldap-results.md)).

## 2. Existing-state audit

Two kinds of evidence are separated: **Office Unbound evidence** (executed in our lab, recorded in `docs/status/`) and
**upstream capability** (present in the Gromox/grommunio source under `reference/upstream/`, read-only, which is newer than
our installed 3.13-ou3 build). Upstream capability is not a claim that the feature works in Office Unbound.

### 2.1 What Office Unbound has proven

| Capability | What exists today (evidence) | Status |
|---|---|---|
| Groupware protocols (EWS, MAPI/HTTP connect, Autodiscover, EAS, IMAP/SMTP, CalDAV/CardDAV, webmail login) | 57 checks PASS, GW01-GW08 ([groupware-lab-results.md](../status/groupware-lab-results.md) section 3, rerun with ou3 in [gw-client-fixes-results.md](../status/gw-client-fixes-results.md) section 3); deployed by the engine ([groupware-deploy-results.md](../status/groupware-deploy-results.md)) | integrated_lab |
| Shared mailbox create / delete (retain data) / grant / revoke | Typed actions `idm.shared_mailbox.*` ([mailadmin.py](../../ics/ics/mailadmin.py)); store with `address_status=4`, no direct login; portal `/admin/shared`; 32/32 lab proof ([mailbox-admin-results.md](../status/mailbox-admin-results.md) sections 1-3); GW05 4 PASS | integrated_lab |
| Shared mailbox full access | Folder rights `1531` (0x5FB, `rightsAll`) written on root, IPM subtree and every non-search folder; grantee reads via EWS, non-grantee `ErrorAccessDenied`, revoke effective ([mailbox-admin-results.md](../status/mailbox-admin-results.md)) | integrated_lab |
| Send As / Send on Behalf (EWS) | `sendas.txt` -> `From: mailbox`, no `Sender`; `delegates.txt` -> `From: mailbox` + `Sender: delegate`; requires Gromox patch 0004; `gw_sendas_test.py` 5/5 PASS ([gw-client-fixes-results.md](../status/gw-client-fixes-results.md) section 2.3). Full-access holders can still send as the store (store-owner rule). SMTP send-as is deliberately refused (`reject_sender_login_mismatch`) | integrated_lab |
| Aliases | `idm.user.set_aliases`, Postfix virtual alias map, uniqueness across the customer ([mailbox-admin-results.md](../status/mailbox-admin-results.md)). Aliases for shared mailboxes not covered | integrated_lab |
| Mail quota | Store properties, receive/send limits enforced ([mailbox-admin-results.md](../status/mailbox-admin-results.md)) | integrated_lab |
| Free/busy of another user | Evolution-EWS `get_free_busy_sync` and raw EWS `GetUserAvailability` agree ([client-compat-results.md](../status/client-compat-results.md) section 4.2) | integrated_lab |
| Meeting invitation and accept (EWS) | Invite delivered as `IPM.Schedule.Meeting.Request`; `AcceptItem` creates the entry, HTTP 200 after the `outgoing_smtp_url` fix; no automatic tentative entry on delivery ([client-compat-results.md](../status/client-compat-results.md) section 4.3, finding 3) | integrated_lab |
| Own calendar and contacts over CalDAV/CardDAV and EWS | Thunderbird 12 PASS, Evolution calendar/contacts PASS ([client-compat-results.md](../status/client-compat-results.md)); cross-protocol visibility GW04 | integrated_lab |
| Mailbox isolation between users | erin gets 404 for dave's event (GW04); carol `ErrorAccessDenied` on support@ (GW05) | integrated_lab |
| Tenant isolation for groupware | Each customer gets its own stack; isolation proven for identity + files only, "Mail (Gromox) in particular must be tested the same way" ([tenant-isolation-results.md](../status/tenant-isolation-results.md)) | planned |
| User disable -> mailbox suspended, IMAP sessions closed, EAS wipe | [user-lifecycle-results.md](../status/user-lifecycle-results.md), [lifecycle-gaps-results.md](../status/lifecycle-gaps-results.md); grants held by a disabled user are not removed (gap, EXO-SEC-03) | integrated_lab (lifecycle); planned (grant clean-up) |
| Follow-up flag / categories | EWS `PidTagFlagStatus` <-> IMAP `\Flagged` both ways ([gw-client-fixes-results.md](../status/gw-client-fixes-results.md) section 4) | integrated_lab (flag); planned (categories) |
| Backup of mailbox content | `gromox-exm2mt` / `gromox-import` restore; **ACLs and rules are not exported** ([groupware-lab-results.md](../status/groupware-lab-results.md) section 4) | integrated_lab (content); planned (ACLs, rules) |
| Real Outlook / Apple / phone clients | Not tested; requires owner devices and licences ([client-compat-results.md](../status/client-compat-results.md) section 6, [MANUAL-CHECKLIST.md](../../blueprints/lab/tests/MANUAL-CHECKLIST.md) B1-B6; progress item P1.11 `implementing`) | planned |
| Internet mail (MX, SPF/DKIM/DMARC, rspamd/ClamAV) | Not verified end to end; "Stage 3, needs the owner's public IP and domain" ([groupware-deploy-results.md](../status/groupware-deploy-results.md)) | planned |

### 2.2 Upstream capability (source read, not exercised by Office Unbound)

| Capability | Where upstream | Notes for planning |
|---|---|---|
| Folder permissions with Outlook profiles (Reviewer, Author, Editor, Owner, ...) and free/busy bits | `gromox/include/gromox/mapidefs.h` (rights enum); grommunio-web `hierarchy/dialogs/FolderPropertiesPermissionTab.js`, `PermissionProfiles.js` | Per-folder ACLs in the store `permissions` table (the shared-mailbox runbook already writes them) |
| Delegates (user-managed) | grommunio-web `common/delegates`, `SettingsDelegateCategory.js`; Gromox `delegates.txt` / `write_delegates` | Delegate list = send on behalf + folder rights + meeting forwarding |
| Meeting forwarding to delegates | Gromox changelog "Development 3.13.16": TwoStep rule processor supports `OP_DELEGATE`; delegate responses recorded | Not in our 3.13-ou3 build; needs upgrade evaluation |
| Meeting request autoprocessing, room/equipment booking | `exmdb_local.4gx` `lda_mrautoproc` ("room and equipment mailboxes accept or decline them according to their booking settings"), default on only in the development branch | Our build showed no auto-processing (client-compat finding 3) |
| Room and equipment mailboxes | `doc/user_properties.rst` display types `DT_ROOM` (7), `DT_EQUIPMENT` (8), `PR_EMS_AB_ROOM_CAPACITY` (informational) | No ICS action, no portal page |
| Out of Office | `doc/outlook_oof_spec.rst`; grommunio-web `SettingsOutOfOfficeCategory.js`; grommunio-sync `Settings` OOF (EAS); Gromox OOF replies only when the address is in To/Cc/Bcc | Not tested by any client |
| Server-side rules | `doc/outlook_rule_spec.rst`; TwoStep processor (`lda_twostep_ruleproc`, development branch default) | Rules not in backup (GW07 finding) |
| Public folders | `gromox-mkpublic` (run per domain in the lab, [groupware-lab-results.md](../status/groupware-lab-results.md) section 2); restore by sqlite copy ([restore-drill-results.md](../status/restore-drill-results.md)) | No ICS management, no client test |
| GAL / address book | MAPI NSPI (`/mapi/nspi/` answers 401 only, not queried), EWS `OABUrl` advertised, grommunio-dav `GalAddressBook*.php` (CardDAV GAL), Evolution saw a "Global Address List" source | Directory-sourced via the LDAP sync; content and hiding rules unverified |
| Distribution lists | grommunio-dav `DistList.php`; Gromox mailing lists | Group provisioning belongs to `GRP-` |
| CalDAV scheduling / iMIP | grommunio-dav `GrommunioSchedulePlugin.php`, `GrommunioIMipPlugin.php` | iTIP via CalDAV not exercised (Thunderbird NOT SUPPORTED row) |
| Categories | Gromox 3.13 changelog: "Full synchronization of IMAP keywords from and to MAPI categories" | Not tested |
| Protocol audit logging | Gromox 3.13 changelog: audit logging in emsmdb and zcore at `log_level >= 5` | Not wired into the ICS audit |
| Archive mailbox, retention policies, litigation hold | No equivalent found in the upstream docs read | Gap; build or defer |

## 3. Permission levels: mapping and client support

Bits from `mapidefs.h`: ReadAny 0x1, Create 0x2, EditOwned 0x8, DeleteOwned 0x10, EditAny 0x20, DeleteAny 0x40,
CreateSubfolder 0x80, Owner 0x100, Contact 0x200, Visible 0x400, FreeBusySimple 0x800, FreeBusyDetailed 0x1000; Gromox
extras reported by `get_mbox_perm`: SendAs 0x4, StoreOwner 0x2000.

| Level (Outlook name) | Gromox / MAPI representation |
|---|---|
| None | 0 |
| Free/busy time only | 0x800 on the Calendar folder |
| Limited (free/busy, subject, location) | 0x1800 on the Calendar folder |
| Full details / Reviewer | `rightsReviewer` 0x401, plus 0x1800 on calendars |
| Author | `rightsAuthor` 0x41B |
| Editor | `rightsEditor` 0x47B (plus 0x1800 on calendars) |
| Publishing editor | `rightsPublishingEditor` 0x4FB |
| Owner | `rightsAll` 0x5FB plus Contact 0x200 (0x7FB) |
| Delegate | Editor on Calendar (optionally Tasks, Inbox, Contacts) **plus** an entry in `delegates.txt` (send on behalf) **plus** a delegate rule (`OP_DELEGATE`) for meeting messages, with an option for "delegate only" or "copy to principal" and "can see private items" |
| Full access (mailbox) | 0x5FB on root, IPM subtree and every folder (current shared-mailbox runbook) |
| Send As | line in `sendas.txt` (reported as 0x4) |

Which clients honour each level. **Untested** = expected from the protocol and the upstream source but needs real-client
validation (EXO-OLK-20); **N/S** = the protocol cannot express it; **PASS** = executed in our lab.

| Level | grommunio-web | Classic Outlook (MAPI/HTTP) | Outlook for Mac (EWS) | New Outlook / Outlook mobile | Thunderbird (CalDAV) | Evolution (EWS) | iOS/Android EAS | CalDAV clients (Apple, DAVx5) |
|---|---|---|---|---|---|---|---|---|
| Free/busy | Untested | Untested | Untested | N/S (IMAP only, no calendar) | Untested (CalDAV free-busy query) | PASS (free/busy lookup) | Untested (EAS ResolveRecipients availability) | Untested |
| Limited | Untested | Untested | Untested | N/S | Untested (likely not distinguished) | Untested | N/S | Untested |
| Reviewer | Untested | Untested | Untested | N/S | Untested (other principal's calendar not exposed, research) | Untested | N/S (EAS exposes only the own mailbox) | Untested |
| Author / Editor | Untested | Untested | Untested | N/S | Untested | Untested | N/S | Untested |
| Owner (manage permissions) | Untested (permission tab) | Untested | Untested | N/S | N/S (no ACL UI over CalDAV) | Untested | N/S | N/S |
| Delegate | Untested (delegate settings) | Untested | Untested | N/S | N/S | Untested | N/S | N/S |
| Full access (mailbox) | Untested (open shared store) | Untested (auto-mapping not built) | Untested | N/S | N/S (IMAP shared namespace not offered) | PASS at EWS level (raw EWS, GW05 / mailbox-admin) | N/S | N/S |
| Send As / on Behalf | Untested | Untested | Untested | N/S | N/S over SMTP (refused by design) | PASS at EWS level (`gw_sendas_test.py`) | N/S | N/S |

Server-side enforcement is the source of truth: every level must also be tested with raw protocol requests (EWS, MAPI ROP
where possible, CalDAV) that try to exceed it (EXO-SEC-01).

## 4. Requirements

Columns: ID | Requirement | Microsoft equivalent | Proposed implementation (component; configure / build; admin UI: **TA** tenant admin
portal, **UP** user portal or webmail self-service) | Status | Priority | Dependencies | Acceptance criteria.

### 4.1 Calendar sharing

| ID | Requirement | Microsoft equivalent | Proposed implementation | Status | Pri | Dependencies | Acceptance criteria |
|---|---|---|---|---|---|---|---|
| EXO-CAL-01 | Multiple personal calendars per user | Outlook "Add calendar" | Gromox calendar subfolders; configure (exists in store model); UP: webmail/Outlook | planned | A | EXO-OLK-20 | Second calendar created in grommunio-web appears in classic Outlook, EWS and CalDAV with its items |
| EXO-CAL-02 | Share a personal calendar internally at a chosen level | Calendar sharing / folder permissions | Folder ACL (section 3); configure; UP: grommunio-web permission tab and Outlook | planned | A | EXO-PERM-01, EXO-SEC-01 | Owner grants Reviewer; grantee sees details; a raw EWS write by the grantee is refused |
| EXO-CAL-03 | View other people's calendars side by side | Open shared calendar, overlay | Client capability over EWS/MAPI; configure | planned | A | EXO-CAL-02 | In grommunio-web and classic Outlook a user opens two colleagues' calendars and sees items per granted level |
| EXO-CAL-04 | Departmental calendar (owned by a department, not a person) | Shared mailbox calendar / group calendar | Shared mailbox with calendar + ACLs; group calendar provisioning from `GRP-` (unified-groups-and-permissions.md); build ICS action `idm.calendar.grant`; TA | planned | A | GRP-, EXO-SMB-01 | Department members (group) get Editor via one action; removing a member from the group removes access within the sync interval |
| EXO-CAL-05 | Group calendar for a team | Microsoft 365 group calendar | Provisioned by `GRP-`; this document requires the permission semantics of EXO-PERM | planned | A | GRP- | As GRP- acceptance; members see and edit the group calendar in webmail and Outlook |
| EXO-CAL-06 | External sharing of a calendar (free/busy or details) to a named outside address | Share calendar with external user | Build: per-tenant policy + signed, revocable ICS (read-only) URL or invitation; webmail/portal UI; UP with TA policy | planned | D | EXO-CAL-09, EXO-SEC-05 | Disabled by default; when the tenant allows it, the outside party receives a link that works until revoked and shows only the permitted level |
| EXO-CAL-07 | Subscribe to internet calendars (ICS URL) | Add calendar from internet | Client feature (Outlook, Thunderbird, Apple); server-side subscription in webmail is research | researching | D | - | A public holiday ICS feed displays in grommunio-web or the documented client list |
| EXO-CAL-08 | Publish a calendar (anonymous web/ICS) subject to tenant policy | Calendar publishing (Anonymous / Organization policy) | Build: publish endpoint behind the gateway, levels free/busy or details, per-tenant on/off; TA policy, UP publish | planned | D | EXO-SEC-05, gateway | Policy off: publish action refused server-side; policy on: URL serves only the chosen level; revoke makes the URL 404 within 60 s |
| EXO-CAL-09 | Revoke any share (internal, external, published) | Remove permission | Remove ACL row / token; build ICS action and audit; TA can revoke any, UP own | planned | A | EXO-SEC-02 | After revoke, grantee's next EWS/MAPI/CalDAV request is refused; audit record exists |
| EXO-CAL-10 | Delegate editing of a calendar | Delegate with Editor | Delegate model (section 3); configure upstream feature, build ICS view | planned | A | EXO-PERM-07 | See acceptance test AT-1 |
| EXO-CAL-11 | Delegate receives and accepts/declines invitations for the principal | Delegate meeting handling | Gromox `OP_DELEGATE` + delegate response handling (development branch); requires Gromox upgrade beyond 3.13-ou3 | planned | A | EXO-MTG-12, Gromox upgrade | Invitation to the executive reaches the assistant; assistant accepts; organizer sees "accepted by assistant on behalf of executive" |
| EXO-CAL-12 | Create and change meetings on behalf of the principal | Send on behalf | `delegates.txt` + Editor on Calendar; EWS/MAPI | planned | A | EXO-SMB-04 | Invitation shows `Sender: assistant`, `From: executive`; item lives in the executive's calendar |
| EXO-CAL-13 | Recurring meetings incl. exceptions and cancelled occurrences, consistent across protocols | Recurring series | Gromox oxcical (3.13 fixed EXDATE/RDATE inversion); configure + test | planned | A | EXO-OLK-20 | Series with one moved and one cancelled occurrence is identical in webmail, Outlook, EWS, CalDAV and EAS |
| EXO-CAL-14 | Private items hidden from delegates and reviewers unless allowed | Private appointment, "delegate can see private items" | Gromox sensitivity handling; research then test | researching | A | EXO-PERM-07 | A private item shows as "Private appointment" to a Reviewer and to a delegate without the flag, in every client listed in section 3 |

### 4.2 Permission levels

| ID | Requirement | Microsoft equivalent | Proposed implementation | Status | Pri | Dependencies | Acceptance criteria |
|---|---|---|---|---|---|---|---|
| EXO-PERM-01 | Named levels None, Free/busy, Limited, Reviewer, Author, Editor, Owner mapped to fixed bit sets (section 3) | Calendar permission levels | ICS closed enum -> bits; build typed action `idm.folder.set_permission` (user, mailbox, folder class, level); TA and UP | planned | A | EXO-SEC-01 | Unit test: each level writes exactly the documented bits; arbitrary bit values are rejected |
| EXO-PERM-02 | Free/busy only | Free/busy time | 0x800 | planned | A | EXO-MTG-02 | Grantee sees busy blocks without subject in web and Outlook; EWS `GetItem` refused |
| EXO-PERM-03 | Limited details | Free/busy, subject, location | 0x1800 | planned | A | EXO-PERM-02 | Grantee sees subject and location, not body or attendees |
| EXO-PERM-04 | Reviewer (read all) | Reviewer | 0x401 (+0x1800) | planned | A | - | Read allowed, create refused on every protocol |
| EXO-PERM-05 | Editor | Editor | 0x47B | planned | A | - | Create/edit/delete any item allowed; permissions change refused |
| EXO-PERM-06 | Owner | Owner | 0x7FB | planned | A | - | Grantee can change folder permissions; cannot grant beyond tenant boundary (EXO-SEC-01) |
| EXO-PERM-07 | Delegate (composite) | Delegate access | Atomic ICS action `idm.delegate.set` writing folder ACLs + `delegates.txt` + delegate rule; rollback on partial failure; UP (principal) and TA | planned | A | EXO-CAL-11 | One action creates all parts; removal deletes all parts; state shown identically in webmail delegate settings |
| EXO-PERM-08 | Client-honour matrix maintained with real-client evidence | - | Test plan section 5; update section 3 cells only with recorded runs | planned | A | owner devices | Every "Untested" cell is replaced by PASS/FAIL/N/S with a status-doc link |

### 4.3 Meeting scheduling and resources

| ID | Requirement | Microsoft equivalent | Proposed implementation | Status | Pri | Dependencies | Acceptance criteria |
|---|---|---|---|---|---|---|---|
| EXO-MTG-01 | Scheduling assistant (attendee and room availability grid) | Scheduling Assistant | Client feature backed by EWS `GetUserAvailability` / MAPI free/busy; configure, test | planned | A | EXO-MTG-02 | grommunio-web and classic Outlook show busy blocks for 3 attendees and 1 room |
| EXO-MTG-02 | Free/busy availability for all internal users | Free/busy | Exists at EWS level (Evolution PASS); extend to MAPI, CalDAV, EAS | integrated_lab (EWS); planned (other) | A | - | Same busy slot returned by EWS, MAPI client, CalDAV free-busy query |
| EXO-MTG-03 | Invitations, responses, updates and cancellations | Meeting requests | EWS path works after `outgoing_smtp_url` fix; automatic tentative entry needs `lda_mrautoproc` (upgrade) | integrated_lab (EWS accept); planned (autoprocess) | A | Gromox upgrade | Invite, accept, update, cancel round-trip between two users on web, Outlook, EAS phone and CalDAV client; organizer tracking shows responses |
| EXO-MTG-04 | Recurrence in meetings (see EXO-CAL-13) incl. per-occurrence responses | Recurring meeting | as EXO-CAL-13 | planned | A | EXO-CAL-13 | Attendee declines one occurrence; organizer sees it; others unchanged |
| EXO-MTG-05 | Room mailboxes | Room resource | Gromox `DT_ROOM` user with capacity, location; build ICS action `idm.resource.create` (room/equipment), GAL room list; TA | planned | A | EXO-CON-05 | Room appears in the room finder / GAL with capacity; can be invited |
| EXO-MTG-06 | Equipment mailboxes | Equipment resource | `DT_EQUIPMENT`; same action | planned | A | EXO-MTG-05 | Projector bookable like a room |
| EXO-MTG-07 | Resource calendar automatic processing | Calendar Attendant / Resource Booking Attendant | `lda_mrautoproc` with booking settings (development branch); upgrade + configure | planned | A | Gromox upgrade | Free slot auto-accepted, conflicting slot auto-declined, organizer receives response mail |
| EXO-MTG-08 | Booking approval (delegate approver for a resource) | Resource delegates / booking requests | Resource delegate + `OP_DELEGATE`; research whether upstream supports "approval required" | researching | A | EXO-MTG-07, EXO-PERM-07 | Request stays tentative until the approver accepts; approver decision is audited |
| EXO-MTG-09 | Booking restrictions (window, max duration, working hours, allowed bookers, recurrence allowed) | `Set-CalendarProcessing` | Research upstream booking settings; build ICS typed settings if store properties suffice; TA | researching | A | EXO-MTG-07 | Each restriction rejects an out-of-policy request with a readable reason |
| EXO-MTG-10 | Conflict prevention for resources | AllowConflicts false | Part of booking settings | researching | A | EXO-MTG-07 | Two overlapping requests: first accepted, second declined, across EWS and MAPI submitters |
| EXO-MTG-11 | Time zones incl. DST transitions and organizer/attendee in different zones | Time zone support | Gromox oxcical; test matrix | planned | A | EXO-OLK-20 | Meeting created in Europe/Berlin shows correct local time in America/New_York on all clients, across a DST change |
| EXO-MTG-12 | Delegated scheduling (see EXO-CAL-10..12) | Delegate scheduling | as referenced | planned | A | EXO-PERM-07 | AT-1 |
| EXO-MTG-13 | Reminders that fire consistently | Reminders | Client-side; verify EAS/CalDAV VALARM <-> MAPI reminder mapping | planned | A | EXO-OLK-20 | Reminder set in one client fires in web, Outlook and phone |
| EXO-MTG-14 | Online meeting link (Jitsi) in invitations | Teams meeting button | Optional build: grommunio-web plugin `meet` exists upstream (research) or invitation template; links to existing Jitsi | researching | D | Jitsi tier | Invitation contains a room-scoped Jitsi link; only invitees with a token join |
| EXO-MTG-15 | Cross-organization scheduling (invite external people, receive external invites) | External meetings, iMIP | iMIP over internet mail; external free/busy is out of scope initially | planned | A | EXO-DEP-01..04 | Invite to a Gmail/M365 address is received and the reply updates the organizer's tracking |
| EXO-MTG-16 | Cross-organization free/busy (federation) | Organization relationships | Research; likely deferred | deferred | D | EXO-CAL-06 | Decision recorded |

### 4.4 Shared mailboxes, groups and mail flow

| ID | Requirement | Microsoft equivalent | Proposed implementation | Status | Pri | Dependencies | Acceptance criteria |
|---|---|---|---|---|---|---|---|
| EXO-SMB-01 | Shared mailbox lifecycle, multiple users | Shared mailbox | Exists: `idm.shared_mailbox.*`, portal `/admin/shared`; TA | integrated_lab | A | - | Already met in lab ([mailbox-admin-results.md](../status/mailbox-admin-results.md)); repeat on a deployed stack |
| EXO-SMB-02 | Full access grant/revoke | FullAccess | Exists (0x5FB ACLs) | integrated_lab | A | - | As above |
| EXO-SMB-03 | Send As | SendAs | Exists at EWS level with patch 0004; full-access holders can also send as (document or restrict) | integrated_lab | A | EXO-OLK-20 | AT-2 in classic Outlook, grommunio-web; send-as revoked -> refused unless full access policy says otherwise |
| EXO-SMB-04 | Send on Behalf | SendOnBehalf | Exists (`delegates.txt`) | integrated_lab | A | - | Delivered headers show `Sender:`; verified in at least two clients |
| EXO-SMB-05 | Sent items of the shared mailbox (copy to the shared mailbox Sent Items per policy) | `MessageCopyForSentAsEnabled` | Research Gromox behaviour; build a tenant setting if needed; TA | researching | A | EXO-SMB-03 | Policy on: sent item in shared Sent Items (and sender's, per setting) |
| EXO-SMB-06 | Shared mailbox in clients without manual setup | Outlook auto-mapping | Research Autodiscover `AlternativeMailbox` in Gromox; build if missing | researching | A | EXO-OLK-20 | Classic Outlook shows the shared mailbox automatically after grant, removes it after revoke |
| EXO-SMB-07 | Delegated inbox (principal's inbox to a delegate) | Delegate with Inbox rights | Delegate composite with Inbox level | planned | A | EXO-PERM-07 | Delegate reads and files mail in the principal's Inbox; not other folders |
| EXO-SMB-08 | Per-folder permissions inside shared and personal mailboxes | Folder permissions | `idm.folder.set_permission` (EXO-PERM-01) | planned | A | EXO-PERM-01 | Member gets Reviewer on one folder only; other folders refused |
| EXO-SMB-09 | Search inside shared mailboxes | Search | Client/EWS search; grommunio-index (upstream) is research | researching | A | - | Search for a token finds it in the shared mailbox in web and Outlook |
| EXO-SMB-10 | Aliases for shared mailboxes | Proxy addresses | Extend `idm.user.set_aliases` to shared mailboxes (gap listed in mailbox-admin finding 6) | planned | A | EXO-SMB-01 | Mail to the alias is delivered to the shared mailbox |
| EXO-SMB-11 | Distribution groups | Distribution list | Owned by `GRP-` (unified-groups-and-permissions.md); Gromox mailing lists | planned | A | GRP- | As GRP- acceptance |
| EXO-SMB-12 | Mail-enabled security groups granting mailbox/calendar access | Mail-enabled security group | `GRP-` provisions the group; this doc requires grants by group with expansion on membership change | planned | A | GRP-, EXO-SEC-03 | Removing a user from the group removes their effective access within the sync interval |
| EXO-SMB-13 | Server-side rules (move, forward, reply) | Inbox rules | Gromox rules; TwoStep processor in development branch; test via web and Outlook | planned | A | Gromox upgrade | Rule created in web runs while all clients are offline |
| EXO-SMB-14 | Automatic replies (OOF), internal/external text, schedule | Automatic replies | Gromox OOF; UP via webmail, Outlook, EAS; TA can set for a leaver | planned | A | EXO-DEP-01 | OOF set from a phone (EAS) is shown in web and answers each sender once per period |
| EXO-SMB-15 | Forwarding policy (allow/deny external auto-forward) | Outbound spam policy auto-forward | Build: Postfix/Gromox check of forwarded mail to external domains; tenant setting; TA | planned | A | EXO-DEP-01 | Default deny: rule forwarding to an external address does not send and the user sees why; allow-list works |
| EXO-SMB-16 | Archive mailbox (online archive) | Online archive | No upstream equivalent found; options: second store or archive folder tree with retention move; research | researching | D | EXO-SMB-17 | Decision record; if built, items older than N days move automatically and stay searchable |
| EXO-SMB-17 | Retention policies (delete or keep after N days per folder) | Retention policies | Build: ICS-scheduled `gromox-mbop`-based job or upstream feature if present | researching | D | - | Policy applied to a test mailbox removes only matching items, audited |
| EXO-SMB-18 | Mailbox auditing (who accessed or sent as which mailbox) | Mailbox audit log | Enable Gromox emsmdb/zcore audit logging (3.13) and EWS logging; ship to the ICS monitoring with tenant tags | planned | A | ICS monitoring | AT-2: the send-as by user A appears in the audit with actor, mailbox, time |
| EXO-SMB-19 | Recovery of deleted items and deleted mailboxes | Recoverable Items, soft-deleted mailbox | Retained data on delete exists (shared mailbox retained); deleted-item recovery: research Gromox soft delete; TA restore action | researching | A | backup product | User restores an item deleted 7 days ago; TA restores a deleted shared mailbox's grants |
| EXO-SMB-20 | Backup and restore of ACLs, delegates and rules | Native data protection | Extend backup (GW07 found ACLs not exported): snapshot sqlite stores or export ACL/rule tables | planned | A | backup product | After restore, permissions, delegates and rules match the pre-backup state |
| EXO-SMB-21 | Public folders (optional, for migration customers) | Public folders | Gromox public store exists per domain; build ICS permission action; research client support | researching | D | EXO-PERM-01 | A public folder with Reviewer for all is visible in Outlook and web |

### 4.5 Contacts and directory

| ID | Requirement | Microsoft equivalent | Proposed implementation | Status | Pri | Dependencies | Acceptance criteria |
|---|---|---|---|---|---|---|---|
| EXO-CON-01 | Personal contacts synced across clients | Contacts | Exists for CardDAV/EWS (Thunderbird, Evolution PASS); extend to Outlook, EAS | integrated_lab (CardDAV/EWS); planned (other) | A | EXO-OLK-20 | Contact created on phone appears in web, Outlook, Thunderbird |
| EXO-CON-02 | Shared contact folders with levels | Shared contacts | Folder ACLs (EXO-PERM-01) | planned | A | EXO-PERM-01 | Reviewer reads, Editor edits, outsider refused |
| EXO-CON-03 | Department / organisation contact list (not GAL users) | Shared mailbox contacts, org contacts | Shared mailbox contacts or public folder; TA | planned | A | EXO-SMB-01 | Department list visible to members in web and Outlook |
| EXO-CON-04 | Mail contacts (external people in the GAL) | Mail contact | Build: directory entry type synced to Gromox; TA | planned | A | GRP-, ENT- | External contact found in GAL search, not a login |
| EXO-CON-05 | Global Address List from the directory, with hide-from-GAL | GAL, HiddenFromAddressListsEnabled | LDAP sync -> Gromox users; validate NSPI, EWS ResolveNames, CardDAV GAL, EAS search; build hide flag | planned | A | EXO-OLK-20 | Users, shared mailboxes, rooms and groups appear; hidden entries do not; no other tenant's entries ever appear |
| EXO-CON-06 | Contact groups (personal distribution lists) | Contact group | Client/store feature (DistList); test across clients | planned | A | - | Group created in web expands when used in Outlook and phone |
| EXO-CON-07 | Delegated contact editing | Delegate on Contacts | Delegate composite with Contacts level | planned | A | EXO-PERM-07 | Assistant edits executive's contacts |
| EXO-CON-08 | Directory search from mobile (EAS GAL search) | GAL search on mobile | grommunio-sync search; test | planned | A | EXO-OLK-20 | Native iOS/Android client finds a colleague by name |

### 4.6 Outlook feature parity

| ID | Requirement | Microsoft equivalent | Proposed implementation | Status | Pri | Dependencies | Acceptance criteria |
|---|---|---|---|---|---|---|---|
| EXO-OLK-01 | Categories (names and colours) synced | Categories | IMAP keyword <-> MAPI category (3.13); master category list in web/Outlook | planned | A | EXO-OLK-20 | Category set in Outlook visible in web and Thunderbird |
| EXO-OLK-02 | Flags and follow-up with due dates | Follow up flag | Flag mapping proven (EWS<->IMAP); due dates/reminders untested | integrated_lab (flag); planned (dates) | A | - | Follow-up with date set in Outlook shows in web and phone |
| EXO-OLK-03 | Tasks (own and shared) | To Do / Outlook tasks | Gromox Tasks folder (CalDAV VTODO collection found by Thunderbird); test EAS/Outlook | planned | A | EXO-OLK-20 | Task created in web syncs to Outlook and a CalDAV client |
| EXO-OLK-04 | Rules (see EXO-SMB-13) | Rules | as referenced | planned | A | EXO-SMB-13 | - |
| EXO-OLK-05 | Signatures, roaming between web and Outlook; optional tenant-managed signature | Roaming signatures, transport disclaimers | Web signatures exist upstream; tenant disclaimers via Postfix milter (build) | planned | D | EXO-DEP-01 | Signature defined in web appears in web; disclaimer appended once |
| EXO-OLK-06 | Search folders | Search folders | Gromox search folders (store model); test | planned | D | - | Search folder "unread from boss" works in Outlook |
| EXO-OLK-07 | Conversation threading | Conversation view | Client feature; verify headers/ConversationIndex | planned | A | - | Thread grouping correct in web and Outlook |
| EXO-OLK-08 | Offline / cached mode | Cached Exchange mode | Classic Outlook OST over MAPI/HTTP (untested; ROP sync not proven) | planned | A | EXO-OLK-20 | Outlook works offline, changes reconcile on reconnect |
| EXO-OLK-09 | Import/export (PST, ICS, VCF) | PST import/export | Upstream tools (`gromox-pff2mt`, `gromox-exm2ical`, `gromox-exm2vcf`, import); build ICS action for admin import; user-side via Outlook | planned | A | migration engine | PST imported into a test mailbox keeps folders, calendar and contacts |
| EXO-OLK-10 | Mobile mail/calendar/contacts with native clients | Exchange ActiveSync | grommunio-sync (lab EAS PASS with scripted client); device policies are `MDM-`, wipe is `WIPE-` | planned | B | MDM-, WIPE- | Native iOS and Android clients sync all three and OOF |
| EXO-OLK-11 | New Outlook for Windows and Outlook mobile | Native | These clients reach non-Microsoft servers by IMAP/SMTP only: mail only, no calendar, contacts or delegation. Document as limitation, recommend classic Outlook / webmail / native mobile | planned | A | - | Limitation stated in customer docs; mail works over IMAP |
| EXO-OLK-20 | Real-client test programme (section 5) | - | Lab runs with recorded evidence | planned | A | owner devices and licences | Every client in section 5 has a results document |

### 4.7 Security and tenant isolation

| ID | Requirement | Microsoft equivalent | Proposed implementation | Status | Pri | Dependencies | Acceptance criteria |
|---|---|---|---|---|---|---|---|
| EXO-SEC-01 | Delegation and sharing never cross tenants; grants only to principals of the same customer | Tenant boundary | ICS validates grantee belongs to the same customer and stack (as alias uniqueness does); node helper re-validates against Gromox domain list; refuse foreign addresses | planned | A | tenant isolation test | Grant to another customer's user refused by ICS (422) and by node helper; GAL of tenant A shows nothing of tenant B |
| EXO-SEC-02 | Authorization on the server, never only in client UI | - | All checks in Gromox exmdb/EWS (3.13 tightened meeting-item rights); raw-protocol negative tests | planned | A | - | Raw EWS/CalDAV requests beyond the granted level are refused for every level in section 3 |
| EXO-SEC-03 | Revocation when a delegate or grantee is removed, disabled or leaves a group | Access removal | Extend `idm.user.disable`/`delete`: remove or suspend that user's ACL rows, delegate entries, `sendas.txt` lines in every mailbox; re-enable restores only via explicit action | planned | A | user lifecycle | After disable, the former delegate cannot open the executive's calendar or send on behalf; listed in the job verdict |
| EXO-SEC-04 | Audit of every grant, revoke and delegate change (ICS audit) and of use (EXO-SMB-18) | Unified audit log | ICS hash-chained audit already records `idm.shared_mailbox.*`; extend to new actions; user self-service changes made in clients must be detected (periodic ACL reconcile) | planned | A | EXO-PERM-07 | Change made in grommunio-web appears in the ICS audit view after the next reconcile |
| EXO-SEC-05 | Tenant policy for external sharing and publishing, default off | Sharing policies | ICS tenant setting checked by publish/share endpoints | planned | D | EXO-CAL-06, EXO-CAL-08 | With policy off no external link can be created by any route |
| EXO-SEC-06 | Approval for high-risk changes (single-admin mode, ADR-0017) | - | Full access / send-as grants on executive mailboxes = high risk per policy | planned | A | ADR-0017 | Grant is planned, approved, executed, audited |

### 4.8 Dependencies (internet mail, not verified end to end)

| ID | Requirement | Microsoft equivalent | Proposed implementation | Status | Pri | Dependencies | Acceptance criteria |
|---|---|---|---|---|---|---|---|
| EXO-DEP-01 | Public MX and inbound mail from foreign MTAs | Exchange Online Protection inbound | Postfix on the gateway; owner public IP and domain | planned | A | owner public IP | Mail from an external provider reaches a mailbox |
| EXO-DEP-02 | SPF, DKIM signing, DMARC policy and reports | EOP authentication | Postfix + DKIM signer, DNS records via ADR-0018 gateway/DNS work | planned | A | EXO-DEP-01 | External receiver reports SPF/DKIM/DMARC pass |
| EXO-DEP-03 | Anti-spam and anti-virus (rspamd, ClamAV) | EOP / Defender | Configure rspamd + ClamAV in the mail path | planned | A | EXO-DEP-01 | GTUBE and EICAR rejected or quarantined; ham delivered |
| EXO-DEP-04 | Outbound relay and reputation | Outbound delivery | Direct or relay; owner decision | planned | A | EXO-DEP-01 | Invitation to an external address lands in inbox, not spam |

## 5. Real-client test plan

Per-client support target (what we expect to support; every cell needs evidence before it is claimed):

| Area | grommunio-web | Classic Outlook Win | Outlook Mac | New Outlook / Outlook mobile | iOS Mail/Calendar (EAS) | Android (EAS app) | Thunderbird | DAVx5 (Android) |
|---|---|---|---|---|---|---|---|---|
| Mail, flags, categories, search | yes | yes (MAPI/HTTP) | yes (EWS) | mail only (IMAP) | yes | yes | yes (IMAP, PASS) | n/a |
| Calendar, invitations, recurrence | yes | yes | yes | no | yes | yes | yes (CalDAV, PASS for own events) | yes |
| Shared calendars, permission levels | yes | yes | likely | no | no (own mailbox only) | no | research | research |
| Delegation | yes | yes | likely | no | no | no | no | no |
| Shared mailbox | yes | yes | likely | IMAP only if offered | no | no | no | no |
| Contacts, GAL | yes | yes (NSPI unproven) | yes | partial | yes | yes | CardDAV, GAL research | CardDAV |
| Tasks | yes | yes | partial | no | partial | partial | CalDAV VTODO | via jtx/OpenTasks |
| Rules, OOF | yes | yes | yes | no | OOF only | OOF only | no | no |
| Offline | no | cached mode | yes | n/a | yes | yes | yes | yes |
| Import/export | ICS/VCF | PST | OLM/PST | no | no | no | ICS/VCF | no |

Test steps per client: account set-up via Autodiscover/autoconfig, the section 3 permission matrix with raw-protocol
cross-checks, AT-1, AT-2, recurrence/time-zone set (EXO-MTG-11), rooms (EXO-MTG-05..10), OOF, rules, offline reconnect, and
revocation (EXO-SEC-03) observed in the client. Results go to a new status document per client with versions and counts.

What each client needs (costs flagged for owner review; no purchase without owner approval):

| Client | Needs | Cost flag |
|---|---|---|
| Classic Outlook for Windows (Microsoft 365 Apps or Outlook 2024) | Windows 11 VM, Office licence, lab CA, hosts entries, MAPI/HTTP trace tool | **Licence cost** (Windows + Office); a time-limited Microsoft trial may cover a test window, owner to decide |
| Outlook for Mac | Mac hardware, Office licence | **Hardware + licence cost** |
| New Outlook for Windows | Windows device, free Microsoft account | Windows licence only; result expected to be IMAP-only |
| Outlook iOS/Android | Phone, free Microsoft account; note that Microsoft's cloud relays IMAP for these apps (privacy note for customers) | **Device cost** |
| iOS Mail/Calendar/Contacts | iPhone (and Mac for configuration profiles); signed `.mobileconfig` would need a signing certificate | **Device cost**; signing certificate is an optional cost |
| Android native EAS app / Gmail app with Exchange | Android phone | **Device cost** (low; a used device suffices) |
| Thunderbird (incl. its native EWS account type) | none; existing `ou-desk2` harness | none |
| DAVx5 | Android phone; DAVx5 is open source (paid in Play store, free on F-Droid) | none beyond the Android device |
| grommunio-web | browser automation with JS execution (only HTTP login tested so far) | none |

## 6. Acceptance tests

| ID | Scenario | Pass condition |
|---|---|---|
| AT-1 | Executive delegates the calendar to an assistant (Editor + delegate, receive meeting copies). Assistant creates a meeting on behalf, modifies it, accepts an incoming invitation for the executive. Repeat with the assistant on grommunio-web, classic Outlook and one more supported client | Items live in the executive's calendar; attendees see "assistant on behalf of executive"; changes are identical in every supported client; removing the delegate (or disabling the assistant) ends access at the next request; every step is in the ICS audit |
| AT-2 | Two employees have full access to a shared mailbox; employee A sends as it, employee B sends on behalf | Recipient sees `From: shared` (A) and `From: shared` + `Sender: B` (B); copies in Sent Items per the tenant policy (EXO-SMB-05); mailbox audit shows actor and action (EXO-SMB-18); after revoking A's send-as, A's attempt is refused (or the documented full-access rule applies) |
| AT-3 | Permission matrix: for each level in section 3, raw EWS and CalDAV operations just above the level | All refused; operations at the level succeed |
| AT-4 | Tenant boundary: two customer stacks; attempt grant, GAL lookup, free/busy and invitation-based access across them | Grants refused; GAL and free/busy show nothing of the other tenant; cross-tenant invitations travel only as external mail |
| AT-5 | Room booking: free slot, conflicting slot, outside booking window, recurring request | Accept / decline / decline / per-policy, with responses to the organizer |
| AT-6 | Leaver: disable a user who is delegate on two calendars and holds send-as on a shared mailbox | All grants gone or suspended, listed in the job verdict; re-enable does not silently restore them |
| AT-7 | Backup and restore of a mailbox with ACLs, delegates and rules | All three restored (EXO-SMB-20) |

## 7. Top gaps

1. No real Outlook, Apple or phone client has been tested; every Outlook-parity claim depends on EXO-OLK-20.
2. Meeting autoprocessing, delegate meeting forwarding and room booking need a Gromox version newer than 3.13-ou3
   (features listed under the upstream development branch); upgrade path not evaluated.
3. No ICS actions or portal pages for folder permissions, delegates, rooms/equipment or OOF; only shared mailboxes exist.
4. Revocation of a disabled or removed user's grants across other mailboxes, and backup of ACLs/rules, are missing.
5. Groupware tenant isolation and internet mail (MX, SPF/DKIM/DMARC, rspamd/ClamAV) are not proven end to end.

## 8. Decisions requiring owner approval

1. Authorize this work and its order relative to the beta directive.
2. Budget for test clients: Windows + Microsoft Office licence, Mac + Office, iPhone, Android device (section 5).
3. Gromox upgrade beyond 3.13-ou3 to obtain meeting autoprocessing, `OP_DELEGATE` and the TwoStep rule processor.
4. Send-as semantics: whether full-access holders may send as the mailbox (current Gromox store-owner rule) or whether
   Office Unbound must restrict it.
5. External calendar sharing and publishing: offer at all, and the tenant default (proposed: off).
6. Archive mailbox and retention: build, or defer and document as a limitation.
7. Positioning of New Outlook and Outlook mobile as mail-only (IMAP) clients in customer documentation.
