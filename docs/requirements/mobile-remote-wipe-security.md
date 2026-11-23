# Mobile and endpoint remote wipe: revocation, selective wipe, full wipe and their authorization

**Status: PLANNED / NOT AUTHORIZED.** Planning document only (stage alpha 0.10.0). Not authorized for development. The only
existing destructive device function is the lab-only ActiveSync wipe described in section 2; everything else here is planned.
Status words follow [ADR-0000](../adr/0000-status-values.md). No completion percentages are given.

Requirement prefix: **WIPE-**. Device management, enrollment modes and platform capabilities are in
[intune-and-mobile-mdm.md](intune-and-mobile-mdm.md) (prefix **MDM-**; supported mechanisms per platform in its section 5.5).
The cross-service revocation architecture lives in GRP- ([unified-groups-and-permissions.md](unified-groups-and-permissions.md)); device sign-in in ENT-
([entra-identity-parity.md](entra-identity-parity.md)) and [office-unbound-connect.md](office-unbound-connect.md#11-offline-access-and-recovery).
Priority tags: **A** core, **B** mobile security, **C** Entra/Intune parity, **D** later.

## 1. Principles

- Three **separate** actions with separate authorization: (1) revoke organisational access, (2) selective corporate-data wipe,
  (3) full-device wipe. One never silently implies another.
- Full wipe only for eligible **company-owned** devices, only through a supported MDM mechanism of that OS; never on BYOD by
  assumption; never by arbitrary shell or script.
- Every destructive action is a typed action through the existing ICS model (plan, hash-bound approval, single-use job,
  hash-chained audit) with the additional protections of sections 8.4 and 8.5. The device channel itself belongs to the endpoint
  service, never to the ICS node agent (rule F8).
- Status is reported as observed. Submitting a command is never "wiped successfully".

## 2. Existing state (audit, 2026-11-23)

| Item | What exists | Status | Evidence | Limits that matter here |
|---|---|---|---|---|
| Access revocation on account disable | `idm.user.disable`: Keycloak sessions, SSO/offline refresh tokens, OpenCloud access and app tokens, IMAP session kill, EWS/EAS refused; VERIFY step measures it | integrated_lab | [user-lifecycle-results.md](../status/user-lifecycle-results.md), [lifecycle-gaps-results.md sections 1-2](../status/lifecycle-gaps-results.md) | Per **user**, not per device; long-running EAS Ping / EWS streaming end at their timeout; data already on devices stays |
| ActiveSync remote wipe | `wipe_devices` option of `idm.user.disable`; runbook `gromox.wipe_devices` marks **all** of the user's EAS devices; grommunio-sync answers `Provision` with `RemoteWipe`; shim `ics/agent/deploy/runbooks/ou-wipe-api`; read-only `idm.user.devices` | integrated_lab | [lifecycle-gaps-results.md section 3](../status/lifecycle-gaps-results.md#3-activesync-remote-wipe-pass-in-the-lab-with-a-scripted-eas-client-no-real-device-tested), `ics/ics/identity.py`, `ics/ics/easprobe.py`, `ics/tests/test_identity_gaps.py` | Proven only with a **scripted EAS client; no real phone validated.** Scripted EAS wipe is **not MDM**. The `wiped_acknowledged` state is reported by the device, **unauthenticated by protocol design, and not proof of erasure**. Offline devices, clients without a policy key (`LOOSE_PROVISIONING`) and devices refused with 401 before calling `Provision` **may never execute it**. Not per-device (all devices of the user). Only full `RemoteWipe` is requested; EAS 16.1 account-only wipe statuses (32/64) are accepted as acknowledgements but not requested (to verify client support). What a client erases is client-defined: on some clients the full phone, **including a personal (BYOD) phone** |
| Approval for the EAS wipe | Plan risk `high` (two approvers in `two_person` mode) | integrated_lab | `ics/ics/identity.py` (risk), `ics/ics/actions.py` (`needed_approvals`) | **In `single_admin` mode (ADR-0017) a high-risk plan needs one approval and the admin may approve their own plan**, so today the EAS wipe can be requested and approved by one person |
| Fresh second-factor step-up | `step_up`: single-use TOTP, shares the replay counter with sign-in, throttled, failures audited | integrated_lab (ICS console) | `ics/ics/auth.py`, used in `ics/ics/deploy/api.py` and `ics/ics/userdir.py` | ICS users only; binds only a purpose string, not tenant + device + operation parameters; not used for any destructive action yet |
| Tenant-admin plans | Customer org-admin (Keycloak JWT) submits plans; `destructive_approval` = `second_admin` or `msp` | integrated_lab | `ics/ics/tenant_admin/service.py`, `ics/ics/tenant_admin/jwtv.py`, [customers-and-approvals.md](../admin/customers-and-approvals.md) | No step-up MFA for tenant admins; no device actions exposed to tenants |
| Hash-chained audit | append-only chained audit | integrated_lab | `ics/ics/audit.py` | One chain; no separate device-command history |
| MDM-based selective or full wipe, lock, lost mode | none | planned | — | Needs the MDM- platform work |

**Consequence:** the existing EAS wipe stays an MSP lab capability. It must not be presented to tenants as "selective wipe" or
as MDM, and must not be offered for BYOD phones until WIPE-05 is met.

## 3. Mapping onto the ICS plan / approval / audit model

| Step | Existing ICS mechanism | Addition for device actions |
|---|---|---|
| Request | Typed action with closed parameters, server-side validation | New actions `device.revoke_access`, `device.selective_wipe`, `device.full_wipe`, `device.lock`; parameters: tenant id, device id, device serial/hardware id, enrollment id, reason |
| Plan | Plan with params hash, risk tier, expiry | Plan digest covers tenant, device identity tuple, action, enrollment mode, ownership; eligibility computed server-side from the device record, never from the request |
| Step-up | `step_up` (TOTP, purpose string) | Operation-bound step-up (WIPE-10) for the authorizing tenant admin |
| Approval | `plan_approvals` bound to params hash; customer authority for tenant plans | Independent second approval for full wipe (WIPE-15), never relaxed by `single_admin` without an owner decision |
| Job | Single-use durable job, digest re-checked at execution | Endpoint service receives a signed, single-use command (rem0te signed-plan pattern) and re-verifies tenant, device and validity window |
| Audit | Hash-chained audit | Plus a separate per-device command history (WIPE-21) |

## 4. Requirements

### 4.1 The three actions (8.1 to 8.3)

| ID | Requirement | Microsoft equivalent | Proposed implementation | Status | Priority | Dependencies | Acceptance criteria |
|---|---|---|---|---|---|---|---|
| WIPE-01 | **Revoke organisational access** for one device or one user: SSO sessions, refresh/offline tokens, app tokens and passwords, device certificate and device trust, mail (EAS device block, IMAP/EWS), files (OpenCloud tokens, sync clients), app authorisations. UI and docs state that **data already on the device is not erased** | Revoke sign-in sessions, Entra device disable | Extend the measured `idm.user.disable` revocation to a per-device scope: revoke the device certificate (MDM-06), block the EAS device id, revoke the device's Keycloak sessions/tokens and OpenCloud tokens; GRP- revocation architecture for other services | implementing (per-user path integrated_lab; per-device planned) | B | GRP-, MDM-06 | After revocation every probed path refuses the device within the measured time; other devices of the user keep working (per-device mode); UI shows "access revoked; local data not erased" |
| WIPE-02 | **Selective corporate-data wipe** within what the enrollment mode supports: iOS/macOS remove managed apps, profiles, managed volume (User Enrollment); Android remove work profile; desktop agent removes managed folders (best effort); EAS account-only wipe where the client supports it | Retire / selective wipe, App protection wipe | Endpoint service command per MDM- section 5.5; unsupported modes return "not supported" instead of falling back to full wipe | planned | B | MDM-02, WIPE-10 | On a real BYOD iOS and Android device: corporate data gone, a personal photo and personal app remain; status reflects device report |
| WIPE-03 | **Full-device wipe** only for devices whose record says company-owned and whose enrollment mode supports erase (Apple `EraseDevice`, Android Device Owner `wipeData`, Windows RemoteWipe CSP); never BYOD; never via arbitrary shell | Wipe | Eligibility computed server-side from ownership + enrollment mode + platform; action refused otherwise | planned | B | MDM-01, WIPE-10, WIPE-15 | Request for a BYOD or agent-only device is refused server-side with a logged reason; eligible device is wiped in the lab |
| WIPE-04 | Remote lock and lost-device mode as a separate, non-destructive action | Remote lock, Lost mode | MDM lock commands (MDM-27) | planned | B | MDM-27 | Lock delivered and reported with honest status |
| WIPE-05 | Existing EAS wipe made safe: per-device selection, ownership check, prefer account-only wipe, label "ActiveSync wipe request (unverified)" | Exchange mobile device wipe | Change `gromox.wipe_devices` to a device id; request AccountOnlyRemoteWipe for BYOD/unknown; full `RemoteWipe` only for company-owned devices under WIPE-03 rules | planned | B | WIPE-03 | Real-phone test per supported client records exactly what was erased |
| WIPE-06 | Ownership changes are themselves controlled | Device ownership change | Changing BYOD to company-owned is a high-risk audited action with step-up; cannot be done in the same plan as a full wipe | planned | B | WIPE-10 | Ownership flip followed by immediate wipe in one request is refused |

### 4.2 Fresh MFA step-up and authorization (8.4)

| ID | Requirement | Microsoft equivalent | Proposed implementation | Status | Priority | Dependencies | Acceptance criteria |
|---|---|---|---|---|---|---|---|
| WIPE-10 | Mandatory **fresh** tenant-admin MFA bound to the exact tenant + device + operation. A sign-in MFA, an older step-up, a bearer token or an API key alone never suffices | Entra authentication context, PIM | Preferred: WebAuthn assertion whose challenge is derived from the plan digest (tenant id, device identity tuple, action, params hash, nonce, expiry), the rem0te approver pattern. Fallback: Keycloak step-up (`max_age=0` / ACR with OTP) whose result is recorded server-side as a single-use step-up record bound to that plan digest, valid for minutes | planned | B | Keycloak ACR/LoA, ENT- | Each bypass test in section 6 fails; a step-up for device A cannot authorize device B |
| WIPE-11 | Explicit tenant and device identification on screen and in the plan | Device details blade | Show tenant name, device name, serial/hardware id, platform, ownership, enrollment mode, user, last seen | planned | B | MDM-20 | Plan view contains all fields; they are part of the hashed digest |
| WIPE-12 | Destructive action display and typed confirmation | Wipe confirmation dialog | Plain statement of what will be erased and what will not; admin types the device name (or serial) exactly | planned | B | WIPE-11 | Mismatch blocks submission server-side, not only in the UI |
| WIPE-13 | Mandatory reason | n/a | Free-text reason (bounded length) stored in plan and audit | planned | B | — | Plan without reason refused |
| WIPE-14 | Server-side, action-specific authorization | Intune RBAC (wipe permission) | Separate permissions `device.revoke`, `device.selective_wipe`, `device.full_wipe`, `device.approve_full_wipe`; checked in the API and again at job execution; tenant derived from the authenticated principal, never from the request body | planned | B | Tenant roles | A principal with `device.selective_wipe` only cannot submit or approve a full wipe |

### 4.3 Independent approval for full wipe (8.5)

| ID | Requirement | Microsoft equivalent | Proposed implementation | Status | Priority | Dependencies | Acceptance criteria |
|---|---|---|---|---|---|---|---|
| WIPE-15 | Full wipe needs an independent approval by a **distinct** tenant admin with their own fresh operation-bound MFA, or a defined high-assurance equivalent (owner decision, section 9) | Multi Admin Approval | Plan approval requiring an approver who is not the requester, each with WIPE-10 step-up; the approval binds the plan digest | planned | B | WIPE-10 | Requester self-approval refused; approval for a changed plan refused |
| WIPE-16 | MSP technicians may prepare, never authorize | GDAP | MSP role can draft the plan; it stays `pending authorization` until the customer tenant admin authorizes with fresh MFA | planned | B | Tenant roles | MSP technician alone cannot move a plan past `pending authorization` |
| WIPE-17 | Cross-tenant rejection | Tenant boundary | Device, plan, approver and step-up record must share one tenant id; checked at submit, approve and execute | planned | A | F1 | Any mismatch refused and audited as a security event |
| WIPE-18 | Emergency access process | Break-glass accounts | Documented break-glass: a pre-registered sealed tenant emergency admin (own hardware key) can serve as second approver; every use alerts all tenant admins and the MSP, is audited, and never disables step-up or the audit | planned | B | WIPE-15 | Emergency approval works, raises alerts and is visible in audit; no configuration switch turns protections off silently |
| WIPE-19 | `single_admin` mode must not relax full-wipe approval | n/a | `needed_approvals` keeps the independent-approval rule for `device.full_wipe` (and the existing EAS full wipe) regardless of `ICS_APPROVAL_MODE`, unless the owner decides otherwise (section 9) | planned | B | ADR-0017 | In `single_admin` mode a self-approved full wipe is refused |

**ADR-0017 note (owner decision).** ADR-0017 lets one admin approve their own plan for every risk tier. Today that also covers
the EAS `wipe_devices` option. For full-device wipe this document proposes an exception: the independent approval is a
customer-side control (the device belongs to the customer, not to the MSP), so a single MSP admin's mode should not remove it.
If a customer tenant has only one admin, the equivalent would be WIPE-18 (sealed emergency approver) or a time-delayed
self-approval with notification and cancel window. The owner must decide.

### 4.4 Status model and histories (8.6)

| ID | Requirement | Microsoft equivalent | Proposed implementation | Status | Priority | Dependencies | Acceptance criteria |
|---|---|---|---|---|---|---|---|
| WIPE-20 | Status model: `pending authorization`, `MFA required`, `awaiting secondary approval`, `queued`, `sent`, `device acknowledged`, `verified` (only where possible, e.g. Apple device no longer checks in and re-appears unenrolled via ADE, Android DPC final report before reset; otherwise never set), `failed`, `timed out`, `device offline`, `unknown`. Never "wiped successfully" on submit | Device action status | State machine in the endpoint service; ICS shows it; the existing EAS states map as `wipe_pending`→`queued`, `wipe_delivered`→`sent`, `wiped_acknowledged`→`device acknowledged (unauthenticated)` | planned | B | — | UI and API never show success before a device report; acknowledgement labelled as device-reported |
| WIPE-21 | Separate tamper-evident histories for authorization (requests, step-ups, approvals, rejections) and for device commands (sent, retries, device responses with time and source) | Audit logs | Two hash-chained streams (port the rem0te chain algorithm), cross-referenced by plan id; exportable checkpoints | planned | B | ICS audit | Tampering with one row breaks verification; both histories exportable per tenant |

### 4.5 Offline devices (8.7)

| ID | Requirement | Microsoft equivalent | Proposed implementation | Status | Priority | Dependencies | Acceptance criteria |
|---|---|---|---|---|---|---|---|
| WIPE-30 | Command expiry and retries | Pending device actions | Each command has a validity window; retried on each check-in until expiry; then `timed out`, never silently dropped | planned | B | WIPE-20 | Expired command shows `timed out` and an escalation prompt |
| WIPE-31 | Revocation independent of the device being online | n/a | WIPE-01 is always applied first server-side, so access ends even if the wipe never arrives | planned | B | WIPE-01 | Offline device cannot sync or sign in when it reconnects |
| WIPE-32 | Last-seen and escalation | Device compliance noncompliance | Show last check-in; escalate (notify admins, mark lost) after a configurable time | planned | C | MDM-20 | Escalation fires in a lab test |
| WIPE-33 | Encryption-key revocation | BitLocker key, FileVault | Rotate or revoke escrowed keys where the OS supports it; Linux network-bound unlock (Clevis/Tang, to verify); on-device offline timers only where the OS/DPC or our own app enforce them (Android DPC check-in timeout, app cache expiry). Not erasure; documented as such | researching | C | MDM-21 | Revoked Linux lab device does not auto-unlock; documentation states limits |
| WIPE-34 | Lost or stolen workflow | Lost mode | Guided flow: revoke access (WIPE-01), lock / lost mode, then selective or full wipe per eligibility, with escalation and police-report note field | planned | B | WIPE-01..04 | Workflow completes in lab with each step's status shown |

## 5. Acceptance tests (for the eventual implementation)

1. **BYOD selective wipe:** tenant admin with fresh operation-bound MFA selectively wipes a real BYOD Android (work profile) and
   iOS (User Enrollment) device; corporate apps/data are gone, a personal photo and a personal app remain; status goes
   `queued → sent → device acknowledged` and is never shown as verified unless verification exists.
2. **Company device full wipe:** an eligible company-owned device is fully wiped after the requester's fresh MFA and an
   independent approval by a distinct admin with their own fresh MFA; status is accurate through each state; both histories
   are complete and verify.
3. **MFA bypass attempts that must fail:** (a) stale MFA (sign-in MFA or a step-up older than the window, or used for another
   plan); (b) API key alone; (c) MSP technician without customer tenant authorization; (d) credentials of another tenant's
   admin; (e) replayed approval (same approval re-submitted, or applied to a re-created plan); (f) modified device id after
   step-up or approval (digest mismatch). Each is refused server-side and audited.
4. **Cross-tenant denial:** a tenant A admin cannot list, address, plan, approve or execute anything for a tenant B device,
   through UI or API; the attempt is a security audit event.
5. **Single-admin mode:** with `ICS_APPROVAL_MODE=single_admin`, a self-approved full wipe is refused (unless the owner decides
   otherwise).
6. **Offline device:** a wipe for an offline device ends as `timed out` or stays `device offline`; access revocation took effect.
7. **BYOD full wipe refused:** full wipe of a BYOD or agent-only device is refused server-side.

## 6. Readiness gate: "mobile security beta"

Same gate as [intune-and-mobile-mdm.md section 9](intune-and-mobile-mdm.md#9-readiness-gate-mobile-security-beta); for this
document specifically: supported client compatibility for every wipe mechanism offered (real devices); WIPE-01 revocation
tested; authenticated enrollment where available (MDM-05/06); WIPE-02 tested on real BYOD devices; WIPE-10 to WIPE-19
including all bypass tests; WIPE-21 audited histories; WIPE-20 truthful status; unsupported modes (EAS-only phones, PWAs,
agent-only desktops, Linux wipe) documented to admins.

## 7. Costs and external dependencies

Full and selective wipe on Apple devices need Apple MDM (APNs push certificate, MDM vendor CSR signing; section 8 of the MDM
document). Android without Google uses a custom DPC / Headwind path (no Google cost). Windows RemoteWipe needs Windows MDM
enrollment (Pro or higher). WebAuthn step-up needs no licence. No paid service is required beyond what the MDM document
flags.

## 8. Risks

- Today's EAS wipe can erase a personal phone completely on some clients and is approvable by one person in `single_admin`
  mode.
- Device acknowledgements are unauthenticated in EAS and only partly trustworthy in MDM; "verified" will rarely be achievable.
- Offline or stolen devices may never receive any command; only server-side revocation is certain.
- Operation-bound step-up for tenant admins needs Keycloak ACR/WebAuthn work that does not exist yet.

## 9. Owner decisions

1. Whether `single_admin` mode (ADR-0017) may relax full-wipe independent approval (recommended: no).
2. High-assurance equivalent for single-admin customer tenants: sealed emergency approver, time-delayed self-approval, or
   MSP co-approval.
3. WebAuthn-only step-up for destructive actions, or TOTP fallback allowed.
4. Whether the existing EAS full `RemoteWipe` stays available before WIPE-05 (recommended: MSP lab use only).
5. Default command validity window and offline escalation period.
