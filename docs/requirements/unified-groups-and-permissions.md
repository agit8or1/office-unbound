# Unified groups and permissions (Microsoft 365 Groups equivalent)

**Status: PLANNED / NOT IMPLEMENTED. Planning document only (2026-11-23 roadmap revision). Not authorized for development.**
Nothing in this document exists unless the audit table (section 2) links repository evidence for it. Status values follow
[ADR-0000](../adr/0000-status-values.md). Stage: alpha 0.10.0. No completion percentages are given.

Requirement prefix: **GRP-**. Related documents (other prefixes, owned elsewhere): ODB- [onedrive-and-file-sharing.md](onedrive-and-file-sharing.md),
SPO- [sharepoint-and-team-libraries.md](sharepoint-and-team-libraries.md), EXO- [calendar-and-mailbox-delegation.md](calendar-and-mailbox-delegation.md), ENT- [entra-identity-parity.md](entra-identity-parity.md),
MDM- [intune-and-mobile-mdm.md](intune-and-mobile-mdm.md), WIPE- [mobile-remote-wipe-security.md](mobile-remote-wipe-security.md). Priority tags: **A** business-ready collaboration,
**B** mobile security, **C** Entra/Intune, **D** wider M365.

This document extends foundation **F2** (service-to-service authorisation API) in the
[post-core expansion plan](../roadmap/post-core-expansion.md#foundations-the-core-should-provide-identified-now-do-not-expand-current-scope).
It is not a second permission system: F2 is the one interface; this document defines what F2 must answer for groups and how each
service enforces the answer itself.

## 1. Goal and worked example

Functional parity with Microsoft 365 Groups (not protocol compatibility). Example:

1. A tenant administrator creates the group **Finance**, assigns owners (Alice) and members (Bob, Carol).
2. One action provisions: a shared mailbox and group address (`finance@customer`), a shared calendar, a shared files library
   (OpenCloud Space), a chat space with a default room (Matrix), a shared task list, optionally a site (SPO- document), and the
   group's security policies (guests allowed or not, external sharing, expiry/review).
3. Adding Dave to Finance grants Dave access to all of these, without any per-service step by the administrator.
4. Removing Dave revokes that access server-side in every service, within documented, measured limits (section 6).

## 2. Existing-state audit (evidence only)

| Area | What exists today | Status | Evidence |
|---|---|---|---|
| Single directory | OpenLDAP authoritative, `ou=groups` (`groupOfNames`), overlays memberof, refint, ppolicy; Keycloak READ_ONLY federation; OpenCloud reads the same LDAP read-only | integrated_lab | [identity-files-lab-results.md](../status/identity-files-lab-results.md) section 2, [ADR-0004](../adr/0004-identity.md), progress P1.4 |
| Stable identifiers | `entryUUID` as immutable user id; Keycloak `uuid` claim; Gromox `externid == entryUUID`; ICS idm user id | integrated_lab | [user-lifecycle-results.md](../status/user-lifecycle-results.md) sections 2 and 4 |
| Group -> Keycloak | `role-ldap-mapper` over `groupOfNames` turns LDAP groups into realm roles (`roles` claim) | integrated_lab | [identity-files-lab-results.md](../status/identity-files-lab-results.md) section 4 |
| Group -> OpenCloud | Groups used only as **roles** (`opencloudAdmin`, `opencloudSpaceAdmin`, `opencloudUser`, `opencloudGuest`) via the OIDC role driver; no group-based Space membership configured or tested | integrated_lab (roles only) | [identity-files-lab-results.md](../status/identity-files-lab-results.md) section 2, [files-identity-eval.md](../status/files-identity-eval.md) |
| Group -> Gromox | Only the entitlement group `mail-users` is read; other groups unused; the Gromox bind cannot see `ou=groups`; shared/group mailboxes and distribution lists from LDAP groups not tested | integrated_lab (entitlement only) | [groupware-ldap-results.md](../status/groupware-ldap-results.md) |
| Group -> Matrix | None. LDAP group sync into rooms/spaces is "original work via Synapse admin API driven by ICS" | planned | [collaboration-eval.md](../status/collaboration-eval.md), [collaboration-lab-results.md](../status/collaboration-lab-results.md) |
| Membership changes | `idm.user.update_groups` typed action (existing groups only); privileged groups raise the plan to high risk | integrated_lab | [user-lifecycle-results.md](../status/user-lifecycle-results.md) section 4, progress P1.8 |
| Group creation | Not possible by design: the ICS LDAP identity may not create groups; tenant admin "creating/renaming groups" is planned | planned | [user-lifecycle-results.md](../status/user-lifecycle-results.md) section 1, [org-admin-results.md](../status/org-admin-results.md) |
| Delegated admin | Tenant admin (`org-admin` realm role) via `/api/v1/tenant/*`; per-user app toggles = membership of MSP-mapped groups only; privileged groups never assignable by a tenant admin | integrated_lab | [org-admin-results.md](../status/org-admin-results.md), progress P4.2 |
| Approval model | Typed action -> plan -> approval -> job -> hash-chained audit; single-admin mode | integrated_lab | [ADR-0002](../adr/0002-ics-security-model.md), [ADR-0017](../adr/0017-single-admin-approval-mode.md) |
| Cross-service user revocation | `idm.user.disable`: LDAP lock, Keycloak revoke, Gromox suspend + IMAP kick + quarantine, OpenCloud app-token revoke; worst measured 10.2 s | integrated_lab | [user-lifecycle-results.md](../status/user-lifecycle-results.md) section 3, [lifecycle-gaps-results.md](../status/lifecycle-gaps-results.md) |
| Group-removal revocation | Not measured for any service | planned | none |
| Tenant isolation | Two customer stacks, identity + files tier: 153 PASS / 1 FAIL (backup encryption); groupware/chat not built per customer | integrated_lab (identity, files) | [tenant-isolation-results.md](../status/tenant-isolation-results.md), progress P4.1 |
| F2 authorisation API, F4 search, F5 legal hold | Gaps in the foundation table | planned | [post-core-expansion.md](../roadmap/post-core-expansion.md#foundations-the-core-should-provide-identified-now-do-not-expand-current-scope) |

## 3. Unified authorization architecture (extension of F2)

### 3.1 Principles

1. **One directory.** OpenLDAP per tenant stack is the only authoritative store of users, groups and memberships. No group
   database in Keycloak, Matrix, OpenCloud or the ICS that can disagree with it. Other stores hold derived, reconcilable copies.
2. **Stable identifiers.** Users and groups are referenced by `entryUUID` everywhere (never by `cn`, display name or mail, which can
   be renamed). Globally (MSP API, audit) a principal is `(customer_id, entryUUID)`.
3. **Every change is a typed ICS action** (`idm.group.*`), approved and audited; services never accept group changes from their own
   UIs for unified groups (their native UIs are disabled or read-only for those objects).
4. **Server-side enforcement per service.** Each service enforces access with its own native mechanism; F2 answers questions and
   drives reconciliation, it is not a proxy in the data path. A failure of F2 must fail closed for new grants and never re-open revoked access.
5. **Reconcile, do not trust.** The existing `idm.reconcile` pattern (report drift, never silently fix) is extended to groups: for each
   group, expected state (from LDAP) vs. actual state in each service.

### 3.2 Components

| Component | Role | Placement |
|---|---|---|
| OpenLDAP group entry | Authoritative membership, owners, group type and policy attributes | Tenant stack (existing directory) |
| Group schema extension | `ouGroupType` (unified, security, distribution), `ouOwner` (DN list), `ouVisibility`, `ouGuestsAllowed`, `ouExpiry`, `ouResourceIds` | Requires an ADR (schema change); custom auxiliary objectClass |
| ICS `idm.group.*` actions | create, update, set_owners, add/remove members, archive, delete, restore; membership expiry | ICS (existing engine) |
| Group provisioner | Per-service adapters (runbooks on node agents) that create the group's resources and apply membership | Node agents (existing pattern, polkit-restricted) |
| F2 decision API | `check(principal, action, resource)`, `list_principals(resource)`, `effective_groups(user)` | Inside the tenant stack (never in the ICS data path), read-only on LDAP and on service ACLs |
| Reconciler | Periodic + event-triggered drift detection per group and service | ICS (existing `idm.reconcile` extended) |
| Event emitter (F3) | `group.member.added/removed`, `group.created/deleted`, `access.revoked` | ICS signed events, later the F3 bus |

F2 candidates for the policy evaluation layer (if a dedicated engine is warranted): OpenFGA (Apache-2.0), Cerbos (Apache-2.0),
OPA (Apache-2.0). Recommendation: start without one; F2 v1 is a thin service computing effective membership from LDAP and asking each
service's own ACL. A relationship store (OpenFGA) would be a derived cache only and must not become a second authoritative directory.

### 3.3 How each service consumes groups

| Service | Mechanism today | Proposed for unified groups | Enforcement point | Verify |
|---|---|---|---|---|
| Keycloak | `role-ldap-mapper` -> realm roles in tokens | Add a `group-ldap-mapper` (READ_ONLY) emitting a `groups` claim of group `entryUUID`s **only for groups marked token-relevant** (roles, app entitlements); content-access groups are not put in tokens (token size, staleness) | Keycloak token issuance; resource servers | Claim size limits; refresh-time re-evaluation of LDAP groups |
| Gromox (mail, calendar, contacts, tasks) | `mail-users` entitlement via LDAP | Group mailbox as a Gromox store (shared mailbox) whose folder permissions (owner, editor, reviewer) are set by the provisioner from LDAP membership; group address as a mailing list or alias; calendar and tasks are folders of that store | Gromox exmdb folder ACLs per request | Gromox CLI/API for permission writes (`gromox-mbop` or exmdb); mlist from LDAP; EXO- doc owns delegation details |
| OpenCloud (files) | Groups as roles only | One project Space per group; Space members = the LDAP group (OpenCloud's Graph reads groups from LDAP); owners = Space managers; members = editors | OpenCloud per request (resolves user and groups from LDAP) | Group membership in Spaces with a read-only LDAP group backend on 9.1; group cache TTL (user cache measured ~5-13 s) |
| Matrix (Synapse + MAS) | Users via MAS JIT from Keycloak | One Matrix space + default room per group, invite-only, history visibility "joined"; provisioner (Synapse admin API, ICS-driven) joins/kicks members and sets power levels for owners | Synapse room membership | Admin API join without consent; kick latency; E2EE implications (section 6.3) |
| Collabora | Via OpenCloud WOPI | Inherits OpenCloud permission at each WOPI CheckFileInfo/PutFile | OpenCloud | Open editing sessions after revocation (WOPI token lifetime) |
| Jitsi | Room-scoped JWT from Keycloak (120 s) | Group meeting rooms: JWT issued only after an F2 check | Token service | n/a until meetings use groups |
| Tasks | No product | Gromox task folder in the group store for v1; P10.1 (Planner) later | Gromox | Client support for shared task folders |
| Site | No product | SPO- document | n/a | n/a |
| Portal / tenant admin | Mapped groups only | Group management pages; group owners manage membership of their own groups only | ICS tenant API (re-checks live role) | n/a |
| rem0te / device policy | n/a | Group-targeted device policies via MDM- documents | MDM | n/a |
| Search (F4) | none | Index stores principal `entryUUID`s per item; query-time trimming with F2 effective membership | F4 query path | section 7 |

### 3.4 Inheritance and nesting

OpenLDAP `groupOfNames` may contain groups, but the `memberof` overlay and the services' LDAP group readers do not reliably expand
nested groups. Recommendation: allow nesting in the model, but have the ICS **materialise effective (flattened) membership** into a
derived attribute or a derived group used by services, recomputed on every change; services never resolve nesting themselves. Resource
inheritance (folder -> subfolder) stays native to each service. Dynamic (rule-based) groups: see ENT- dynamic groups; OpenLDAP
`dynlist` is a candidate.

## 4. Requirements

| ID | Requirement | Microsoft equivalent | Proposed implementation | Status | Priority | Dependencies | Acceptance criteria |
|---|---|---|---|---|---|---|---|
| GRP-01 | One authoritative store for groups and memberships per tenant | Entra ID groups | OpenLDAP `ou=groups`; every other store derived and reconciled | integrated_lab (store); planned (unified groups) | A | ADR-0004 | Reconcile reports zero drift after every GRP action; no service has a writable group UI for unified groups |
| GRP-02 | Stable group and user identifiers, rename-safe | Object ID | `entryUUID` referenced by every adapter, MSP API and audit | integrated_lab (users); planned (groups) | A | GRP-01 | Renaming a group changes no resource binding; audit shows the same id before and after |
| GRP-03 | Create a unified group with owners and members in one action | M365 Group creation | `idm.group.create` typed action; ICS LDAP ACL extended to create entries in `ou=groups` (today refused by design) | planned | A | ADR for schema + ACL change | One approved plan creates the LDAP group and all selected resources; failure of any step rolls back or reports a partial state loudly |
| GRP-04 | Group shared mailbox and address | Group mailbox | Gromox shared store + alias/mlist, folder ACL from membership | planned | A | EXO- doc, Gromox permission API | Member opens the group mailbox in webmail and Outlook-compatible clients; non-member is refused |
| GRP-05 | Group shared calendar | Group calendar | Calendar folder of the group store, ACL from membership | planned | A | GRP-04, EXO- | Member creates and sees events; removed member gets 403/NO on next request |
| GRP-06 | Group files library | Group SharePoint library | OpenCloud project Space bound to the group `entryUUID` | planned | A | SPO-, ODB- docs | Member reads/writes via web, WebDAV, desktop sync; non-member 404 |
| GRP-07 | Group chat space and default room | Teams channel | Matrix space + room, membership driven by provisioner via Synapse admin API | planned | A | MAS/Synapse admin API | Member sees the room without an invite click; removed member is kicked and cannot rejoin |
| GRP-08 | Group shared tasks | Planner plan | v1 task folder in the group store; P10.1 later | planned | D | GRP-04, P10.1 | Member creates and completes a task visible to other members |
| GRP-09 | Optional group site | Group SharePoint site | See SPO- document | planned | D | SPO- | Defined in SPO- |
| GRP-10 | Membership change propagates to every bound resource | Group membership | Event-triggered provisioner + periodic reconcile | planned | A | GRP-03..07 | Add: access everywhere within a target bound measured per service; remove: section 6 targets met |
| GRP-11 | Group owners manage their group's membership | Group owners | Portal pages; tenant API checks `ouOwner` live; owners cannot change policy attributes | planned | A | P4.2 tenant admin | Owner adds/removes members of own group only; other groups 403; audited with owner `sub` |
| GRP-12 | Delegated administration scopes | Administrative units / group admin roles | Tenant admin (org-admin) for all tenant groups; MSP operators scoped per customer (existing scoping) | integrated_lab (users); planned (groups) | A | P4.2 | Scoped MSP operator of A sees no group of B (404) |
| GRP-13 | Guests as group members | B2B guests in groups | Guest accounts in a separate LDAP subtree, `opencloudGuest` role, allowed only where `ouGuestsAllowed=true` | planned | A | ENT- guests | Guest reaches group files/chat only; cannot see directory or other groups; guest in a no-guest group refused at plan time |
| GRP-14 | Expiring membership and group expiry | Access reviews, group expiration | Membership expiry kept by the ICS; reconcile job removes expired members through the normal action; group expiry warns owners then archives | planned | C | ENT- access reviews | Expired member loses access at the next reconcile run; removal is audited as system-initiated |
| GRP-15 | Ownership continuity | Ownerless group policy | At least one owner enforced; leaver's owned groups reported to tenant admin on disable | planned | A | P1.8 lifecycle | Disabling the last owner raises a plan-time warning and a task for the tenant admin |
| GRP-16 | Security groups distinct from unified groups | Security groups | `ouGroupType=security`: access/role only, no resources | planned | A | GRP-01 | Security group creates no mailbox/space/room |
| GRP-17 | Distribution lists | Distribution groups | `ouGroupType=distribution`: Gromox mlist from membership | planned | A | Gromox mlist | Mail to the list reaches every member; removed member stops receiving |
| GRP-18 | F2 decision API for groups | Graph permission evaluation | `check`, `list_principals`, `effective_groups`; read-only; per tenant stack | planned | A | F2 | Answers match each service's actual enforcement in a differential test over all bound resources |
| GRP-19 | Cross-service revocation on group removal | Remove member | Provisioner removes ACLs/space membership/room membership; Keycloak claim staleness bounded by access-token lifetime | planned | A | GRP-10 | Section 6 table: every path measured, worst case documented |
| GRP-20 | Cross-service revocation on user termination | User block/delete | Existing `idm.user.disable` + group cleanup + offline-copy policy | integrated_lab (disable); planned (group cleanup, offline policy) | A | P1.8, WIPE-, MDM- | Owner test OT-3 passes |
| GRP-21 | Group deletion and restore | Soft-delete, 30-day restore | Archive (read-only, members removed, resources retained) then delete after retention; restore within retention | planned | A | F5 for retention | Restored group regains resources with the same `entryUUID`; deleted group's resources not reachable by former members |
| GRP-22 | Permission-aware search over group content | Microsoft Search security trimming | F4 index with principal ids; query-time F2 trimming | planned | D | F4, GRP-18 | Removed member's search returns no group item immediately after removal (no re-index needed) |
| GRP-23 | Central audit of every authorization change | Entra audit log | ICS hash-chained audit for changes; F3 events; service access logs referenced by correlation id | integrated_lab (ICS audit); planned (group events) | A | F3 | Every GRP action has one audit entry with actor, group id, before/after membership, no secrets |
| GRP-24 | Tenant-aware authorization everywhere | Tenant boundary | Per-customer stack; every ICS group object carries `customer_id`; F2 refuses principals of another tenant | integrated_lab (identity, files); planned (groups) | A | F1, P4.1 | Owner test OT-4 passes for all listed cases |
| GRP-25 | Group membership visible to users | My groups | Portal "My groups" from F2 `effective_groups` | planned | A | GRP-18 | User sees exactly their groups; hidden-membership groups shown only to owners |
| GRP-26 | Privileged groups protected | Role-assignable groups | Existing high-risk tier for privileged groups; never assignable by tenant admins; unified groups can never be privileged | integrated_lab (high tier); planned (rule) | A | ADR-0017 | Plan adding a member to a privileged group requires the high tier; tenant admin refused |
| GRP-27 | Drift detection for groups | n/a (Microsoft internal) | `idm.reconcile` extended per group and service | planned | A | GRP-10 | Injected out-of-band room join / space share is reported critical and not silently fixed |

## 5. Lifecycle flows

- **Join:** `idm.user.update_groups(add Finance)` -> LDAP member added -> event -> adapters: Gromox folder ACL, OpenCloud (no step if Space
  membership is the LDAP group itself; otherwise add), Matrix join, Keycloak none (claim on next token) -> reconcile verifies.
- **Leave:** reverse order of exposure: Matrix kick, Gromox ACL removal, OpenCloud membership, then LDAP member removal, then verify probes
  (canary-style, as `idm.user.disable` already does).
- **Termination:** `idm.user.disable` (existing) first, then group cleanup, ownership hand-over, device actions per MDM-/WIPE-.

## 6. Cross-service revocation behaviour

### 6.1 User disable (measured, lab, 2026-11-15)

From [user-lifecycle-results.md](../status/user-lifecycle-results.md) section 3, [lifecycle-gaps-results.md](../status/lifecycle-gaps-results.md),
[identity-files-lab-results.md](../status/identity-files-lab-results.md) section 3.3 and [collaboration-lab-results.md](../status/collaboration-lab-results.md):

| Path | Refused after | Mechanism | Caveat |
|---|---|---|---|
| Keycloak password login | 0.1 s | LDAP lock | |
| Keycloak SSO and offline refresh tokens | 2.0 s | ICS Keycloak revoke + disable | An LDAP-only lock leaves them valid indefinitely (KI-2, >420 s observed) |
| OpenCloud access token (Graph, WebDAV) | 5.1 s (canary 10.2 s) | OpenCloud re-resolves user in LDAP | JWT itself valid 300 s for any consumer not re-resolving |
| OpenCloud app tokens | revoked ~1 s after approval | `opencloud.revoke_app_tokens` | User already locked out-of-band cannot be resolved -> not revoked |
| IMAP fresh login / open session | 2.0 s | suspend; USER-KICK patch closes sockets | Patched binary lab-only; POP3 not covered |
| EWS, EAS, MAPI requests | 2.0 s | suspend (per-request auth) | Running long requests (EWS streaming, EAS Ping) until timeout, not probed |
| Matrix | 1 s with Keycloak back-channel logout to MAS | MAS `logout_all` | Without back-channel/MAS lock: indefinite |
| ActiveSync device wipe | 2.2 s request-to-delivery (scripted client) | grommunio-sync Provision | No real device tested; offline device never wipes; acknowledgement is the client's statement, not proof of erasure; mail-account path only, not MDM |
| Worst measured end-to-end | 10.2 s | | lab, single runs |

### 6.2 Group removal (not measured; expected behaviour to verify)

| Path | Expected | Bound |
|---|---|---|
| Gromox folder ACL | Next request after ACL write refused | Gromox caches (verify) |
| OpenCloud Space | Next request after group cache refresh | Group cache TTL (unknown; user cache ~5-13 s) |
| Matrix room | Kick is immediate for new events | Already-synced history stays on the device |
| Keycloak `groups`/`roles` claim | Stale until the access token expires | 300 s (lab default); refresh re-evaluates (verify) |
| Collabora open document | Until the WOPI session ends | WOPI token lifetime (verify) |
| Jitsi group room | New joins refused; ongoing call continues | JWT 120 s, then session lifetime |

### 6.3 Offline copies, issued tokens and existing sessions

- **Offline copies cannot be revoked by the server.** Files already synced by the desktop client, mail cached by IMAP/EAS clients and Matrix
  history decrypted on devices remain on those devices. Policy options: (a) accept and document; (b) device wipe of managed devices
  (WIPE-, MDM-; EAS wipe lab-proven with a scripted client only); (c) selective wipe of the sync folder by a managed agent (MDM-, not built).
  This is never described as "revoked".
- **Issued access tokens:** bounded by token lifetime (300 s) unless the consumer re-resolves the user per request. Requirement: every
  resource server either re-resolves identity per request or accepts at most the access-token lifetime as revocation delay, documented.
- **Existing sessions:** must be ended explicitly per service (Keycloak sessions, MAS sessions, IMAP sockets, app tokens), as `idm.user.disable` does.
- **Matrix E2EE:** removing a member rotates the room's outbound session for future messages; past keys already held remain usable for past history.

## 7. Permission-aware search (F4 dependency)

Index items with the principal `entryUUID`s allowed at index time, but **trim at query time** using F2 `effective_groups(user)` and, for
high-sensitivity sources, a final per-hit F2 `check`. Revocation is therefore effective without re-indexing. Tenant partitioning: one index
(or index namespace) per tenant stack; no cross-tenant query path exists. Search is P10/F4 scope; GRP-22 only fixes the contract.

## 8. Central audit events

Every `idm.group.*` action is audited in the ICS hash-chained log (existing). Proposed event types: `group.created`, `group.updated`,
`group.owner.set`, `group.member.added`, `group.member.removed` (reason: admin, owner, expiry, termination), `group.archived`,
`group.deleted`, `group.restored`, `access.revocation.verified` (per service, with measured seconds), `reconcile.drift`. Service access logs
(Keycloak events, Gromox, OpenCloud, Synapse) are correlated by job id, not copied wholesale into the ICS.

## 9. Security and tenant isolation

- One stack per customer (ADR-0006); groups, F2 and indexes live inside the stack. The ICS holds only group ids and metadata needed for
  plans and audit, scoped by `customer_id` (F1).
- Adapters run as node-agent runbooks with exact parameters (`{group_uuid, user_uuid}`), validated twice (agent and root helper), as today.
- Fail closed: an adapter failure on **add** leaves access not granted; on **remove** the job fails loudly, retries, and the reconcile
  reports critical drift. Revocation never waits on an unreachable service before locking what it can.
- Tenant admins cannot touch privileged groups; group owners cannot change policy attributes or add guests to no-guest groups.
- The ICS LDAP identity gains only `ou=groups` create/delete rights; it still cannot read `userPassword` or touch `ou=system`.

## 10. Owner acceptance tests

| ID | Test | Pass condition |
|---|---|---|
| OT-1 | New employee joins Finance | Within the measured bound, without any per-service step: Finance files (web + WebDAV + desktop sync), calendar, chat room and shared mailbox all accessible |
| OT-2 | Employee removed from Finance | Every OT-1 path refused server-side; times recorded per path; Matrix kicked; no rejoin; search returns no Finance item |
| OT-3 | Employee terminated | Login, Keycloak sessions, refresh/offline tokens, app tokens, IMAP sockets, EAS/EWS, Matrix sessions, group resources all refused (section 6.1 targets); offline copies handled per the configured policy and reported, not claimed revoked |
| OT-4 | Cross-tenant denial | For tenant A vs B, both directions, with a paired positive control each: an authorization change in A has no effect in B; a user removed in A cannot reach B; a group of A cannot be referenced by a plan in B (404); a guest of A cannot see B; a disabled account of A is refused at B (as already for tokens in P4.1) |
| OT-5 | Disabled account in a group | Group membership does not grant anything to a disabled user; re-enable does not resurrect app tokens or sessions |
| OT-6 | External guest | Guest reaches only the groups that allow guests; cannot list the directory |
| OT-7 | Drift | Out-of-band share/room join is reported critical by reconcile |

## 11. Licensing notes

| Component | Licence | Note |
|---|---|---|
| OpenLDAP | OpenLDAP Public License 2.8 | Existing; text re-read by counsel still open ([third-party-inventory.md](../status/third-party-inventory.md)) |
| Keycloak | Apache-2.0 | Existing |
| Gromox | AGPL-3.0 (verify per component) | Existing; grommunio-admin-api has a licence module with a user cap ([groupware-source-eval.md](../status/groupware-source-eval.md)), so group sync must not depend on it |
| OpenCloud | Apache-2.0 | Existing |
| Synapse, MAS | AGPL-3.0 (Element relicensing; verify current LICENSE) | Existing; admin API use only |
| OpenFGA, Cerbos, OPA | Apache-2.0 | Optional F2 candidates; verify before adoption |

No component in this design has a licence fee or user cap. No cost flagged.

## 12. Open owner decisions

1. Approve an ADR for the OpenLDAP group schema extension and for widening the ICS LDAP identity to create/delete groups.
2. Nesting: allow nested groups (flattened by the ICS) or flat groups only for v1.
3. Which group resources are created by default (mailbox, calendar, Space, chat, tasks) and which are opt-in.
4. Offline-copy policy on removal/termination: accept, wipe managed devices, or selective wipe (depends on MDM-/WIPE-).
5. Group-removal revocation target (proposal: 60 s, same as user disable) and whether the 300 s access-token lifetime is acceptable for claim-based checks.
6. Whether F2 v1 uses a policy engine (OpenFGA/Cerbos/OPA) or stays a thin LDAP + service-ACL facade.
7. Group expiry and access-review defaults (off, or yearly with owner confirmation).
