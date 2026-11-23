# Intune-style endpoint and mobile device management (MDM)

**Status: PLANNED / NOT AUTHORIZED.** Planning document only (stage alpha 0.10.0). Nothing in this document is authorized for
development, and no endpoint or mobile device management exists in Office Unbound today except the lab-only ActiveSync items in
section 2. Status words follow [ADR-0000](../adr/0000-status-values.md). No completion percentages are given.

Requirement prefix: **MDM-**. Destructive device actions (revocation, selective wipe, full wipe) and their authorization are
specified separately in [mobile-remote-wipe-security.md](mobile-remote-wipe-security.md) (prefix **WIPE-**); this document only
references them. Related planning: [P10.6 Endpoint](../roadmap/post-core-expansion.md#p106-endpoint-and-device-management-intune--xl),
[P10.12 Office Unbound Connect](../roadmap/post-core-expansion.md#p1012-office-unbound-connect-desktop-sign-in-and-device-enrollment--xl)
and its requirements [office-unbound-connect.md](office-unbound-connect.md) (desktop sign-in, enrollment app, device identity;
not repeated here). Cross-references by prefix: ENT- ([entra-identity-parity.md](entra-identity-parity.md), desktop sign-in and Entra parity),
GRP- ([unified-groups-and-permissions.md](unified-groups-and-permissions.md), group assignment and the revocation architecture), ODB- ([onedrive-and-file-sharing.md](onedrive-and-file-sharing.md)),
SPO- ([sharepoint-and-team-libraries.md](sharepoint-and-team-libraries.md)), EXO- ([calendar-and-mailbox-delegation.md](calendar-and-mailbox-delegation.md)).

Priority tags: **A** core product, **B** mobile security, **C** Entra/Intune parity, **D** later.

## 1. Scope and non-negotiable rules

- Platforms: Windows, macOS, Linux, Android, iOS/iPadOS. Each is managed only through the interfaces that OS supports
  (section 5); where an OS offers nothing, the document says so instead of inventing a mechanism.
- **Separation from the ICS (rule F8).** The ICS node agent `ou-agent` manages Office Unbound server VMs only and is never
  installed on an employee device. Endpoint management is a separate service with its own agent(s), credentials, CA and trust
  root. It never gains hypervisor or infrastructure rights. The ICS may *orchestrate* (typed action, plan, approval, audit) a
  request to the endpoint service, but the endpoint service holds the device channel.
- **Zero mandatory licence cost.** Every component in the default path is free and self-hostable. Where a platform makes zero
  cost impossible (Apple developer membership, code signing, Google registration), it is listed in section 8 and flagged for the
  owner; no paid MDM product is a hidden dependency.
- **Tenant isolation.** Every device, enrollment token, certificate, policy, command and audit record belongs to exactly one
  tenant (F1); a per-tenant device CA follows the existing per-tenant CA pattern.
- **Server-side authorization.** Every management action is authorized on the server against the acting principal, tenant and
  device; the console only displays.
- **Honest status.** A command is never reported as done when it was only sent (status model: WIPE-section 8.6).

## 2. Existing state (audit, 2026-11-23)

| Area | What exists | Status | Evidence | Limits |
|---|---|---|---|---|
| ActiveSync (EAS) gateway | grommunio-sync in front of Gromox; OPTIONS, FolderSync, Sync | integrated_lab | [groupware-lab-results.md](../status/groupware-lab-results.md) (GW03) | Scripted protocol tests only |
| EAS device list per user | read-only action `idm.user.devices` / runbook `gromox.devices` (device, last sync, wipe status, history) | integrated_lab | [lifecycle-gaps-results.md section 3](../status/lifecycle-gaps-results.md#3-activesync-remote-wipe-pass-in-the-lab-with-a-scripted-eas-client-no-real-device-tested), `ics/ics/identity.py` | Only devices that synced through EAS; no inventory, no posture |
| EAS remote wipe | `idm.user.disable` with `wipe_devices` (all of the user's EAS devices), shim `ics/agent/deploy/runbooks/ou-wipe-api`, scripted client `ics/ics/easprobe.py`, tests `ics/tests/test_identity_gaps.py` | integrated_lab | [lifecycle-gaps-results.md section 3](../status/lifecycle-gaps-results.md#3-activesync-remote-wipe-pass-in-the-lab-with-a-scripted-eas-client-no-real-device-tested) | **No real phone validated.** Scripted EAS wipe is **not MDM**; the device-reported acknowledgement is unauthenticated and **not proof of erasure**; offline, policy-less or never-provisioning devices never execute it. The client decides what "wipe" means (on some clients a full device erase, also on BYOD); see WIPE-section 2 |
| Access revocation on disable | Keycloak sessions and refresh/offline tokens, OpenCloud access and app tokens, IMAP sessions, EWS, EAS measured as refused after disable | integrated_lab | [user-lifecycle-results.md](../status/user-lifecycle-results.md), [lifecycle-gaps-results.md](../status/lifecycle-gaps-results.md) | Already-running long requests (EAS Ping, EWS streaming) end at their timeout; offline data on devices is untouched |
| Client compatibility | Thunderbird, Evolution tested; Outlook and phones not tested | implementing | [client-compat-results.md](../status/client-compat-results.md) | Real mobile clients need owner devices |
| Fresh second-factor step-up | `step_up` (single-use TOTP, throttled, audited) used to reveal a deployment admin password and an enrollment token | integrated_lab (ICS console only) | `ics/ics/auth.py`, `ics/ics/deploy/api.py`, `ics/ics/userdir.py` | ICS users only; not bound to an operation's parameters; not available to tenant admins |
| Plan / approval / audit model | typed action, plan hash, approval, single-use job, hash-chained audit; tenant-admin plans with customer authority | integrated_lab | `ics/ics/actions.py`, `ics/ics/tenant_admin/service.py`, [customers-and-approvals.md](../admin/customers-and-approvals.md) | Reused for device actions; ADR-0017 relaxations apply (WIPE-section 8.5) |
| Endpoint agent, MDM server, device inventory, enrollment, policies | none | planned | [P10.6](../roadmap/post-core-expansion.md#p106-endpoint-and-device-management-intune--xl) | rem0te is the candidate foundation (design reviewed in [reuse-audit-ics.md](../status/reuse-audit-ics.md)); no code integrated |
| Mobile apps | none of our own; OpenCloud and groupware are reachable by third-party clients | planned | — | Section 7 |

## 3. Target architecture (proposed)

| Layer | Proposed component | Notes |
|---|---|---|
| Device console and policy model | Native Office Unbound service ("device service"), per tenant | New; uses the portal for tenant admins and the ICS console for MSP staff |
| Desktop agent (Windows, macOS, Linux) | rem0te agent (MIT, ours) extended, or fleetd/osquery | Closed, typed command catalog (rem0te pattern: signed plans, journal, no free-text shell) |
| Inventory and compliance queries | osquery | Apache-2.0 / GPL-2.0 |
| Apple MDM | NanoMDM (+ NanoDEP for ADE, KMFDDM for declarative management) | APNs certificate required (section 8) |
| Windows MDM | Windows MDM enrollment (MS-MDE2) + OMA-DM CSPs, from Fleet's MIT core or a native implementation | Pro, Enterprise, Education editions; Home not supported (to verify per build) |
| Android | Headwind MDM community (device owner) and/or a custom DPC for work profile | No Google EMM registration in the default path (section 5.5) |
| Identity and device trust | Keycloak (existing), per-tenant device CA, hardware-backed keys | Device signals to Keycloak policies (F6, ENT-) |
| Orchestration and authorization | ICS typed actions, plans, approvals, hash-chained audit | Destructive actions per WIPE- |
| Remote assistance | rem0te (RustDesk-based) | Consent or approved policy only |

## 4. Requirements

Status for every row is `planned` unless stated. "Microsoft equivalent" names the Intune/Entra feature for orientation only;
Office Unbound is not Intune-compatible.

### 4.1 Enrollment

| ID | Requirement | Microsoft equivalent | Proposed implementation | Status | Priority | Dependencies | Acceptance criteria |
|---|---|---|---|---|---|---|---|
| MDM-01 | Company-owned enrollment per platform | Intune corporate enrollment, Autopilot | Windows MDM enrollment with a provisioning package or enrollment app; macOS/iOS device enrollment or ADE; Android fully managed via QR; Linux agent installer | planned | C | MDM-05, MDM-06 | One device per platform enrolls as company-owned; ownership shown |
| MDM-02 | BYOD enrollment that separates personal data | Intune BYOD, User Enrollment, Work Profile | iOS/macOS account-driven User Enrollment; Android work profile; desktops: agent-only with limited scope (no full wipe) | planned | B | MDM-05, section 8 | BYOD device enrolls; only the corporate container is managed; a personal file is not visible to the console |
| MDM-03 | One-click enrollment, QR codes, enrollment links | Company Portal, QR provisioning | Single-use, short-lived, tenant-bound enrollment tokens rendered as link or QR (Android device-owner QR is an OS feature) | planned | B | MDM-05 | Token is single use, expires, refuses replay and another tenant |
| MDM-04 | Discovery from the organisation address (FQDN) | Enterprise enrollment discovery | Well-known HTTPS documents on the tenant domain: Apple `/.well-known/com.apple.remotemanagement` (account-driven enrollment), Windows `EnterpriseEnrollment` discovery, our own document for the agent (same as Connect section 6) | planned | B | ADR-0018 gateway/DNS | Entering `user@customer.com` finds the right tenant; a wrong domain finds nothing |
| MDM-05 | Authenticated enrollment | Entra-authenticated enrollment | User authenticates in Keycloak with MFA before a device is bound; enrollment token bound to tenant + user + ownership | planned | B | Keycloak, ENT- | Enrollment without valid MFA sign-in fails; audit shows user, device, tenant |
| MDM-06 | Hardware-backed device identity and device certificates | Device identity, Intune certificate | Key generated in TPM / Secure Enclave / Android Keystore (StrongBox where present); CSR signed by the per-tenant device CA; mutual TLS for check-in; ACME device attestation where the OS supports it (Apple managed device attestation, to verify per OS version) | planned | B | Per-tenant CA | Certificate private key is non-exportable where the hardware allows; revoked certificate is refused at next check-in |
| MDM-07 | Ownership, approval policies, quotas | Enrollment restrictions | Per-tenant policy: allowed platforms, ownership types, approval required, pre-approved serials, MSP-set quotas (no product licence limit) | planned | C | MDM-01 | A device outside policy stays "pending approval" and receives no configuration |
| MDM-08 | Group assignment | Dynamic/assigned groups | Policies assigned to Office Unbound groups (GRP-); no second group model | planned | C | GRP- | Moving a user between groups changes the device's assigned policies on next check-in |
| MDM-09 | MSP-assisted onboarding | Partner Center / Autopilot pre-provisioning | MSP technician prepares enrollment profiles and bulk tokens for a customer tenant; customer admin sees and can revoke them | planned | C | Tenant roles | An MSP-prepared token is visible in the customer's audit and works only for that tenant |
| MDM-10 | Enrollment status and repair | Enrollment status page | Per-device status (pending, enrolled, configuring, compliant, error, retired) with plain errors | planned | C | MDM-01 | Each failure path shows an actionable message |
| MDM-11 | Retirement and unenrollment | Retire | Revoke device certificate, remove management profile/agent, remove corporate data per WIPE-02 | planned | B | WIPE-02 | Retired device no longer checks in; history kept |

### 4.2 Management

| ID | Requirement | Microsoft equivalent | Proposed implementation | Status | Priority | Dependencies | Acceptance criteria |
|---|---|---|---|---|---|---|---|
| MDM-20 | Hardware and software inventory, OS version | Intune inventory | osquery (desktop); Apple `DeviceInformation`/`InstalledApplicationList` (supervised or device enrollment; restricted under User Enrollment); Android DPC reports; EAS device list (existing) as a weak source | planned | C | MDM-01 | Inventory matches the device within one check-in interval |
| MDM-21 | Encryption and posture | Compliance: BitLocker, FileVault | BitLocker CSP status, FileVault status via MDM/osquery, Android encryption state, LUKS via osquery; firewall, screen lock, OS patch level | planned | B | MDM-20 | A device with encryption off is reported non-compliant |
| MDM-22 | Compliance policies feeding access | Compliance + Conditional Access | Compliance state signed by the device service, consumed by Keycloak (F6, ENT-); grace periods | planned | B | ENT-, F6 | Non-compliant device is denied app sign-in after grace; compliant device allowed |
| MDM-23 | Configuration policies | Configuration profiles | Apple configuration profiles and declarative management; Windows CSPs (Policy CSP); Android managed device policies; Linux agent-applied config | planned | C | MDM-01 | Policy drift reported (P10.6 acceptance) |
| MDM-24 | App deployment where permitted | Intune apps | Apple Apps and Books (VPP, free apps, via ABM) and custom apps; Windows winget/MSI via agent or `EnterpriseDesktopAppManagement` CSP; Android private APK repository (F-Droid server) without managed Google Play; Linux distro packages | planned | C | section 8 | A package is deployed and removed on each platform where supported |
| MDM-25 | Patching and OS update policies | Windows Update rings, Apple software update | Windows Update CSP / Update policies; Apple software update declarations; Android system-update policy (device owner); Linux unattended-upgrades | planned | C | MDM-23 | An update deferral policy is applied and reported |
| MDM-26 | Wi-Fi, VPN and certificate profiles | Wi-Fi/VPN/SCEP profiles | Apple profiles with ACME/SCEP; Windows WiFi/VPNv2 CSPs; Android work-profile Wi-Fi; per-tenant CA | planned | C | MDM-06 | Wi-Fi profile with certificate auth connects in the lab |
| MDM-27 | Lost-device mode and remote lock | Lost mode, Remote lock | Apple `DeviceLock`, Lost Mode (supervised iOS); Windows `RemoteLock` (limited); Android `lockNow` (device owner/profile owner); desktop agent lock | planned | B | MDM-01, WIPE-04 | Lock is delivered; status honest per WIPE-section 8.6 |
| MDM-28 | Remote assistance | Remote Help | rem0te (RustDesk) with user consent or an approved policy, audited, session recorded where configured | planned | C | rem0te | Session impossible without consent or approved policy; audit entry exists |
| MDM-29 | Account and access revocation | Revoke sessions | Per WIPE-01 | planned | B | WIPE-01, GRP- | See WIPE-01 |
| MDM-30 | Selective wipe | Retire / selective wipe | Per WIPE-02 | planned | B | WIPE-02 | See WIPE-02 |
| MDM-31 | Full wipe for eligible company devices | Wipe | Per WIPE-03 | planned | B | WIPE-03 | See WIPE-03 |
| MDM-32 | Device lifecycle history and audit | Device actions history | Append-only per-device history plus the hash-chained audit | planned | B | ICS audit | Every enrollment, policy change and command has a history row and an audit entry |
| MDM-33 | MSP reporting | Intune reports, Lighthouse | Per-tenant and MSP-wide (only tenants the MSP manages) reports: compliance, OS versions, encryption, last seen, pending commands | planned | C | Tenant roles | MSP sees an aggregate; tenant A's admin sees only tenant A |
| MDM-34 | Tenant isolation of all device data | Tenant boundary | `customer_id` on every model; per-tenant CA; cross-tenant queries rejected server-side | planned | A | F1 | Device in tenant A invisible and unaddressable from tenant B (API test) |
| MDM-35 | Typed command catalog, no arbitrary shell | Intune scripts (deliberately not copied) | Closed catalog of compiled-in actions with closed parameters (rem0te approved-actions pattern); custom scripts out of scope for beta | planned | A | rem0te | A free-text command is refused by API and agent |
| MDM-36 | Separate trust root from the ICS | n/a | Own CA, keys, agent and service account; ICS holds no device credential | planned | A | F8 | ICS node credentials cannot address a device; device credentials cannot address the ICS |

### 4.3 Mobile apps

| ID | Requirement | Microsoft equivalent | Proposed implementation | Status | Priority | Dependencies | Acceptance criteria |
|---|---|---|---|---|---|---|---|
| MDM-40 | Supported client matrix for mail, calendar, contacts | Outlook mobile | Native iOS Mail/Calendar (EAS or IMAP/CalDAV/CardDAV), Android: Thunderbird for Android / K-9, FairEmail, DAVx5; published matrix with tested versions | planned | B | P1.11 | Each listed client tested on a real device and recorded in docs/status |
| MDM-41 | Files: browse, offline, share links | OneDrive mobile | OpenCloud mobile apps (to verify licence, maturity and AppConfig support); WebDAV clients as fallback | planned | B | ODB- | Offline file, share link and upload work on Android and iOS |
| MDM-42 | Document editing | Office mobile | Collabora Office mobile (MPL-2.0, to verify store availability) or browser editing via WOPI | researching | D | P10.8 | A document edited on a phone is saved with version history |
| MDM-43 | Scan to files | Office Lens | OS document scanner + upload, or app feature | planned | D | MDM-41 | Scanned PDF lands in the user's files |
| MDM-44 | Chat, meetings, notifications | Teams mobile | Depends on the chat/meetings choice (ARCHITECTURE item 8, not decided); Android push without Google via UnifiedPush/ntfy; iOS push requires APNs and a signed app | planned | D | section 8 | Notifications arrive on both platforms with no Google dependency on Android |
| MDM-45 | MFA, passkeys, SSO in apps | Authenticator, broker | Keycloak OIDC with system browser (AppAuth pattern), passkeys via platform authenticator, TOTP apps (FreeOTP) | planned | B | ENT- | App sign-in uses MFA and SSO; no password stored by the app |
| MDM-46 | Managed app configuration | App configuration policies | iOS managed app config (AppConfig) via MDM; Android managed configurations via the DPC (requires app support) | planned | C | MDM-24 | Server URL is preconfigured on a managed device |
| MDM-47 | App-level selective removal and revocation processing | App protection policies | Our own apps (if built) delete their local cache on revocation signal or after an offline grace period; third-party apps rely on OS container removal | planned | B | WIPE-02 | Revoked user's app shows signed-out and removes cached data on next start |
| MDM-48 | Device trust in apps | Device-based CA | Device certificate (MDM-06) presented to Keycloak; not available to a PWA | planned | C | MDM-06, ENT- | Unenrolled device denied where policy requires trust |
| MDM-49 | PWA limits documented | n/a | PWA allowed for convenience only; it cannot enroll, receive managed config, attest device identity or be selectively wiped | planned | B | — | Documentation states the limits; no feature claims MDM via PWA |

## 5. Platform evaluation

### 5.1 Apple (iOS, iPadOS, macOS)

- **MDM protocol and APNs.** Apple devices are managed only through Apple's MDM protocol; the server wakes devices through
  APNs. An MDM APNs push certificate is issued by the Apple Push Certificates Portal (free, needs an Apple Account) against a CSR
  signed by an **MDM vendor certificate**. Obtaining a vendor certificate requires an Apple developer organisation account (to
  verify current programme requirements); community users of NanoMDM/MicroMDM historically used the third-party signing service
  mdmcert.download, which is a trust and availability dependency outside our control. The push certificate is renewed yearly.
- **Apple Business Manager (ABM)** is free but needs a legal organisation (D-U-N-S number) per customer or per MSP. It provides
  Automated Device Enrollment (ADE, formerly DEP: supervised, non-removable management), Managed Apple Accounts (required for
  account-driven User Enrollment) and Apps and Books (VPP). ADE needs devices bought through Apple or an authorised reseller, or
  added with Apple Configurator (provisional period applies, to verify).
- **Device Enrollment** (profile install, not ADE) works without ABM; devices are not supervised, so many restrictions and
  Lost Mode are unavailable. **User Enrollment** (BYOD) limits the MDM to a managed APFS volume and managed apps: no device-wide
  inventory, no device erase; unenrollment removes the managed volume (selective removal).
- **Managed apps, selective removal, erase.** Removing the management profile removes managed apps and their data. `EraseDevice`
  is available for device-enrolled devices (not User Enrollment). Declarative Device Management (iOS 15+/macOS 13+) is
  supported by KMFDDM.
- **Platform SSO** (macOS) needs an SSO extension shipped in an app signed by a paid Apple Developer Program member with the
  associated-domains entitlement, delivered by MDM (detail in [office-unbound-connect.md section 4.2](office-unbound-connect.md#42-macos)).
- **Signing.** Any own iOS app, push-capable app or macOS app outside the App Store needs Apple Developer Program signing and
  (macOS) notarisation.

### 5.2 Android

- **Android Enterprise modes:** Fully Managed (Device Owner), Work Profile on personal devices (Profile Owner), COPE (work
  profile on a company-owned device, Android 11+ model), Dedicated devices. Work-profile removal deletes all work data and leaves
  personal data; Device Owner can factory reset (`wipeData`), and enforce factory-reset protection policy.
- **Provisioning:** QR code after factory reset (AOSP feature, Android 7+), NFC (older), `afw#` token and zero-touch (both
  Google-run and require an EMM registered with Google; zero-touch also needs a participating reseller).
- **Google registration.** Managed Google Play and the Android Management API (AMAPI) require a Google-registered EMM and a
  Google account per organisation; AMAPI is a Google cloud service and is not acceptable as a mandatory component (P10.6).
  Google has restricted new custom-DPC EMM registrations in favour of AMAPI (to verify current policy). A custom DPC using public
  `DevicePolicyManager` APIs can still be provisioned as Device Owner by QR and can create a work profile without Google, but
  then app distribution cannot use managed Google Play; apps come from a private repository. Devices without Google Play
  services (for example GrapheneOS, LineageOS) are possible targets for the custom-DPC path (to verify per ROM).
- **Managed configurations** work only for apps that declare them; delivered by the DPC.

### 5.3 Windows

- Built-in MDM client: enrollment per MS-MDE2 (discovery, policy, enrollment web services), management over OMA-DM (SyncML) with
  Configuration Service Providers: Policy, BitLocker, RemoteWipe (`doWipe`, `doWipeProtected`, `doWipePersistUserData`),
  RemoteLock, Update, WiFi, VPNv2, ClientCertificateInstall, EnterpriseDesktopAppManagement, DeviceStatus. MDM enrollment
  needs Pro, Enterprise or Education (Home: to verify, generally unsupported). Push uses WNS (Microsoft service, free, external
  dependency) or periodic polling.
- Autopilot requires Microsoft Entra/Intune; not available. Agent-based management (rem0te, fleetd/osquery, winget) complements
  the CSPs. Installers need Authenticode signing to be usable (section 8).

### 5.4 Linux

- No OS-level MDM protocol. Management is agent-based: osquery/fleetd for inventory and compliance, rem0te agent for typed
  actions, distribution package managers and unattended-upgrades for patching, fwupd for firmware.
- **No supported remote wipe.** The useful substitute is encryption-key revocation: LUKS with network-bound unlock (Clevis
  client + Tang server, both GPL-3.0, to verify) so that a revoked device cannot unlock at next boot when Tang is the only
  unattended unlock path. This is not erasure; see WIPE-section 8.7.

### 5.5 Summary of supported destructive mechanisms

| Platform / mode | Revoke access | Selective removal | Full wipe | Mechanism |
|---|---|---|---|---|
| iOS/macOS User Enrollment (BYOD) | yes (server) | managed volume and apps | **no** | Unenroll / remove managed apps |
| iOS/macOS Device Enrollment | yes | managed apps and profiles | yes | `EraseDevice` |
| iOS/macOS ADE (supervised) | yes | yes | yes | `EraseDevice`, Lost Mode |
| Android Work Profile (BYOD) | yes | work profile | **no** | DPC removes work profile |
| Android COPE | yes | work profile | yes (policy) | DPC |
| Android Fully Managed | yes | managed apps | yes | `wipeData` |
| Windows MDM (company) | yes | per CSP (limited) | yes | RemoteWipe CSP |
| Windows / macOS / Linux agent only | yes | managed folders by agent (best effort) | **no** | Agent typed action |
| Linux company device | yes | agent (best effort) | key revocation only | Clevis/Tang (to verify) |
| EAS-only phone (no MDM) | yes (server) | client-defined | client-defined, not provable | EAS RemoteWipe / AccountOnlyRemoteWipe |

## 6. FOSS components (licences and maintenance; "to verify" = not checked against the upstream repository for this document)

| Component | Role | Licence | Maintenance (as known) | Limits |
|---|---|---|---|---|
| NanoMDM | Apple MDM core | MIT (licence also in [office-unbound-connect.md section 12](office-unbound-connect.md#12-licensing-review-checked-against-the-upstream-license-files-2026-11-21)) | Active (to verify) | Protocol core only; needs NanoDEP (ADE), KMFDDM or NanoCMD (MIT, to verify) and our own console |
| MicroMDM | Apple MDM | MIT | v1 in maintenance mode, NanoMDM recommended upstream (to verify) | Not proposed |
| Fleet | Device management, macOS/Windows MDM, osquery fleet | MIT core; `ee/` separate commercial licence | Active | Use only MIT-core features; check each feature's licence before use |
| osquery | Inventory, compliance queries | Apache-2.0 or GPL-2.0 | Active (Linux Foundation) | Read-oriented |
| rem0te | Desktop agent, remote assistance, approved actions | MIT (ours) | Active (ours) | Windows-first Go agent; macOS/Linux to build |
| MeshCentral | Remote management alternative | Apache-2.0 | Active | Overlaps rem0te |
| Headwind MDM community | Android MDM (device owner, kiosk) | Apache-2.0 (server and launcher, to verify) | Active (to verify); paid enterprise edition exists | Check which features (work profile, remote control) are enterprise-only; do not depend on them |
| Flyve MDM | Android MDM | GPL-3.0 | **Discontinued / archived** (to verify) | Not viable |
| Android TestDPC | Reference DPC | Apache-2.0 | Google sample (to verify) | Reference for a custom DPC, not a product |
| F-Droid server | Private Android app repository | AGPL-3.0 (to verify) | Active | App distribution without managed Google Play |
| Clevis / Tang | Network-bound disk unlock | GPL-3.0 (to verify) | Active | Linux key revocation, not wipe |
| grommunio-sync | ActiveSync | AGPL-3.0 (to verify against [third-party-inventory.md](../status/third-party-inventory.md)) | Active | Existing; EAS policies and wipe only |
| Thunderbird for Android / K-9 Mail | Mail client | Apache-2.0 | Active | No EAS; IMAP |
| FairEmail | Mail client | GPL-3.0 | Active (to verify) | IMAP |
| DAVx5 | CalDAV/CardDAV sync | GPL-3.0 | Active | Store version is paid on Google Play; F-Droid build free |
| ntfy / UnifiedPush | Android push without Google | Apache-2.0 / GPL-2.0 (ntfy dual), UnifiedPush spec Apache-2.0 (to verify) | Active | App must support UnifiedPush |
| FreeOTP | TOTP authenticator | Apache-2.0 | Active (to verify) | — |

Not proposed: Tactical RMM (source-available custom licence, not OSI, to verify), any MDM with per-device fees.

## 7. Mobile app strategy

| Option | Can do | Cannot do | Verdict |
|---|---|---|---|
| Native OS apps (iOS Mail/Calendar, Android system apps) over EAS/IMAP/CalDAV | Mail, calendar, contacts; MDM-pushed account profiles on iOS | No files/chat; wipe semantics defined by the OS client | Beta baseline for mail/calendar |
| Existing FOSS clients (Thunderbird/K-9, FairEmail, DAVx5, OpenCloud apps, Element if chosen) | Most functions per app | No unified SSO broker; managed config only if the app supports it | Beta baseline, documented matrix |
| Licence-compatible forks (rebranded) | Branding, managed config, revocation hooks | Store publishing needs developer accounts and signing (section 8); fork maintenance cost | Later, owner decision |
| Own native app | Full integration (enrollment, device trust, cache wipe on revocation) | Large effort; iOS needs Apple signing and APNs | Deferred |
| PWA | Mail/files UI, web push (iOS 16.4+ only when installed to home screen) | **No MDM, no enrollment, no managed config, no device identity, no selective wipe**; local cache deletion only when the app next runs | Convenience only (MDM-49) |
| Wrappers (WebView shells) | Store presence | Same limits as PWA plus signing costs | Not proposed |

## 8. Costs and external dependencies (flag for owner review)

| Item | Needed for | Cost | Avoidable? |
|---|---|---|---|
| Apple MDM APNs push certificate | Any Apple MDM | Free certificate; needs an Apple Account and a CSR signed by an MDM vendor certificate | No, for Apple MDM |
| MDM vendor CSR signing | Apple push certificate | Apple developer organisation membership (paid annual, to verify which programme) or a third-party signing service | Owner decision |
| Apple Developer Program | Platform SSO extension, own iOS/macOS apps, notarisation, iOS app push | Paid annual membership | Only by not shipping own Apple apps or Platform SSO |
| Apple Business Manager | ADE, Managed Apple Accounts (User Enrollment), Apps and Books | Free; per-organisation D-U-N-S and Apple terms | Optional; without it no ADE and no account-driven User Enrollment |
| Google EMM registration / AMAPI / managed Google Play / zero-touch | Google-run Android Enterprise features | Free but Google-controlled, cloud, account per organisation | Yes: custom-DPC/Headwind path without them (reduced features) |
| Google Play developer account | Publishing own Android app on Play | One-time fee | Yes: F-Droid / private repository |
| Windows Authenticode code signing | Usable Windows agent installer | Normally paid | Owner decision (as in Connect) |
| WNS / APNs / FCM push services | Waking devices | Free, external | WNS and APNs not avoidable for push on those platforms; polling fallback; FCM avoidable via UnifiedPush |

No paid MDM product is part of any proposed path.

## 9. Readiness gate: "mobile security beta"

The mobile security capability may be called beta only when all items have evidence in docs/status:

1. **Supported client compatibility:** published matrix of tested real devices and app versions (MDM-40, MDM-41).
2. **Revocation:** WIPE-01 tested end-to-end on real devices, including offline-device behaviour documented.
3. **Authenticated enrollment where available:** MDM-05 and MDM-06 for each platform listed as supported.
4. **Tested selective removal:** WIPE-02 on a real BYOD iOS and Android device, personal data shown intact.
5. **Tenant-admin MFA:** WIPE-10 to WIPE-14 including all bypass tests in the WIPE document.
6. **Audited management:** MDM-32 and the separate command and authorization histories (WIPE-21).
7. **Truthful status:** WIPE-20 status model; no "wiped successfully" on submit.
8. **Documented unsupported modes:** section 5.5 published to admins, including EAS-only phones, PWAs and Linux wipe.
9. Tenant isolation test (MDM-34) and the F8 separation test (MDM-36) pass.
10. Owner decisions in section 11 recorded.

## 10. Risks

- Apple and Google control critical paths (push, ABM, managed Google Play); programme terms can change.
- The existing EAS wipe can mean a full device erase on some clients, including personal phones; it must not be offered as a
  BYOD tool (WIPE-section 2).
- Custom DPC and Windows MDM server work is security-critical and large; reuse Fleet MIT core or Headwind only where licence and
  maintenance are verified.
- Real-device testing needs owner hardware; until then nothing beyond integrated_lab may be claimed.
- Single-admin approval mode (ADR-0017) weakens destructive-action controls (WIPE-section 8.5).

## 11. Owner decisions

1. Authorize development at all and its order relative to P10.6/P10.12.
2. Apple: obtain a developer organisation membership / MDM vendor signing (zero-cost exception), use a third-party CSR signing
   service, or exclude Apple MDM from the first release.
3. Android: custom-DPC/Headwind path only, or also optional Google AMAPI for tenants that want managed Google Play.
4. Windows code-signing certificate (shared decision with Connect).
5. Mobile app strategy: FOSS clients only for beta, or rebranded forks / own app later.
6. Supported platform and enrollment-mode matrix for the first beta.
7. Whether rem0te or Fleet MIT core is the desktop foundation.
