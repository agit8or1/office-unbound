# Entra ID identity parity

**Status: PLANNED / NOT IMPLEMENTED. Planning document only (2026-11-23 roadmap revision). Not authorized for development.**
Nothing in this document exists unless the audit table (section 2) links repository evidence for it. Status values follow
[ADR-0000](../adr/0000-status-values.md). Stage: alpha 0.10.0. No completion percentages are given.

Requirement prefix: **ENT-**. Related: GRP- [unified-groups-and-permissions.md](unified-groups-and-permissions.md); desktop sign-in and
enrollment [office-unbound-connect.md](office-unbound-connect.md) (referenced, not duplicated); MDM- [intune-and-mobile-mdm.md](intune-and-mobile-mdm.md);
WIPE- [mobile-remote-wipe-security.md](mobile-remote-wipe-security.md); roadmap [P10.10](../roadmap/post-core-expansion.md#p1010-advanced-identity-and-enterprise-integrations-entra-id-advanced--graph--xl)
and [P10.12](../roadmap/post-core-expansion.md#p1012-office-unbound-connect-desktop-sign-in-and-device-enrollment--xl).
Priority tags: **A** business-ready collaboration, **B** mobile security, **C** Entra/Intune, **D** wider M365.

Goal: functional parity with Microsoft Entra ID for the identity needs of small and mid-sized organisations, on the existing
architecture (OpenLDAP authoritative, Keycloak for SSO/MFA, ICS typed actions). **Not** Entra-compatible: no Entra Join, no CloudAP,
no Primary Refresh Token, no Microsoft protocols or signals. **Critical UX rule:** no employee ever configures LDAP, Kerberos, VPN or
certificates by hand.

## 1. Constraints

- No second authoritative directory without an approved ADR (affects Samba AD and hybrid AD, sections 5 and 6).
- Zero mandatory licence cost; where a platform vendor charges (Apple, code signing), it is flagged as an owner decision.
- Every administrative change is a typed ICS action with approval and audit; ICS operators and tenant admins stay separate (ADR-0002).

## 2. Existing-state audit (evidence only)

| Capability | State | Status | Evidence |
|---|---|---|---|
| Directory | OpenLDAP authoritative; ppolicy, memberof, refint; LDAPS only | integrated_lab | [identity-files-lab-results.md](../status/identity-files-lab-results.md), [ADR-0004](../adr/0004-identity.md), progress P1.4 |
| SSO (OIDC) | Keycloak 26.8.2, LDAP READ_ONLY federation; OpenCloud, Matrix (MAS), Jitsi JWT, portal, webmail via Keycloak | integrated_lab | [identity-files-lab-results.md](../status/identity-files-lab-results.md), [collaboration-lab-results.md](../status/collaboration-lab-results.md), [webmail-sso-results.md](../status/webmail-sso-results.md), [sso-rollout-results.md](../status/sso-rollout-results.md) |
| MFA for end users (TOTP) | Keycloak built-in; portal shows MFA status (read side live); tenant-admin "reset 2-step" unit-tested against a fake only; TOTP enrolment not executed live | implementing (not proven live) | [portal-results.md](../status/portal-results.md), [org-admin-results.md](../status/org-admin-results.md) |
| MFA for ICS operators | ICS own argon2id + TOTP, replay-safe | tested | [STATUS.md](../status/STATUS.md), [SECURITY-REMEDIATION.md](../status/SECURITY-REMEDIATION.md) |
| WebAuthn / passkeys | Keycloak feature, not configured or tested | planned | [files-identity-eval.md](../status/files-identity-eval.md) (marked UNVERIFIED) |
| User lifecycle | `idm.user.create/update_groups/disable/enable/delete/reset_credentials/reconcile`; one-time enrollment, no initial passwords | integrated_lab | [user-lifecycle-results.md](../status/user-lifecycle-results.md), progress P1.8 |
| Revocation | Worst measured 10.2 s across Keycloak, OpenCloud, Gromox; KI-2: LDAP-only lock leaves Keycloak refresh tokens valid | integrated_lab | [user-lifecycle-results.md](../status/user-lifecycle-results.md), [lifecycle-gaps-results.md](../status/lifecycle-gaps-results.md) |
| Lockout | ppolicy lock attribute used for disable; failed attempts from a stale device password locked an account during a test run | integrated_lab (disable); not designed (lockout policy) | [lifecycle-gaps-results.md](../status/lifecycle-gaps-results.md) section 3 |
| Delegated admin | Tenant admin (`org-admin` role) through `/api/v1/tenant/*`, live re-check of role | integrated_lab | [org-admin-results.md](../status/org-admin-results.md), progress P4.2 |
| MSP API, service accounts | Versioned MSP API; narrow service identities (`svc-ics`, Keycloak client `ou-ics` client-credentials) | integrated_lab | [msp-api-results.md](../status/msp-api-results.md), [ADR-0013](../adr/0013-msp-provisioning-api.md), [user-lifecycle-results.md](../status/user-lifecycle-results.md) section 1 |
| Tenant isolation | Per-customer Keycloak, LDAP, CA, signing keys; cross-tenant token, refresh, forged-token denials | integrated_lab | [tenant-isolation-results.md](../status/tenant-isolation-results.md), progress P4.1 |
| Admin approval | Typed actions, approvals, single-admin mode | integrated_lab | [ADR-0002](../adr/0002-ics-security-model.md), [ADR-0017](../adr/0017-single-admin-approval-mode.md) |
| Device sign-in (Windows, macOS, Linux) | None | planned | [office-unbound-connect.md](office-unbound-connect.md) |
| SAML, SCIM, federation, hybrid AD, access reviews, PIM, conditional access, sign-in log UI | None | planned | [post-core-expansion.md](../roadmap/post-core-expansion.md#p1010-advanced-identity-and-enterprise-integrations-entra-id-advanced--graph--xl) |

## 3. Capability map: what Keycloak/OpenLDAP give, what to configure, what to build

Legend: **Native** = shipped by upstream, **Configure** = upstream feature we must enable, harden and test, **Build** = Office Unbound code.

| Capability | Native (Keycloak / OpenLDAP) | Configure | Build |
|---|---|---|---|
| SSO (OIDC/OAuth2) | Keycloak OIDC/OAuth2, PKCE, refresh/offline tokens, back-channel logout | Per-app clients, token lifetimes, back-channel logout to every client (MAS proven) | Client registration as typed actions |
| SAML 2.0 | Keycloak SAML IdP and broker | Per-app SAML clients | Admin UI for SAML apps |
| MFA: TOTP | Keycloak OTP | Required action, policy per role (admin mandatory) | Recovery flow through tenant admin (exists, unit-tested) |
| FIDO2 / WebAuthn, passkeys | Keycloak WebAuthn and WebAuthn-passwordless policies; passkey/conditional-UI support per release (verify for 26.8) | RP id per tenant domain, attestation policy, flows | Enrolment UX in portal; recovery |
| Passwordless | WebAuthn passwordless flow | Flow per tenant | Device-bound sign-in with Connect (C7) |
| Recovery codes | Keycloak recovery codes (verify support level in 26.8) | Enable | Portal display |
| Password reset (self-service) | Keycloak "forgot password" (needs SMTP) | Mail via tenant Gromox; but federation is READ_ONLY, so password writes must reach LDAP | Reuse ICS enrollment path (exists for admins); self-service via one-time token |
| Password change by user | Keycloak account console | Requires writable LDAP for the password attribute, or an ICS path; behaviour today unverified | Decide path (owner decision 3) |
| Password policy | Keycloak policies (local creds); OpenLDAP ppolicy (`pwdMinLength`, history, quality via module) | One policy, enforced at the write path | Policy editor for tenant admin |
| Lockout / brute force | Keycloak brute-force detection; ppolicy `pwdMaxFailure` | Choose one primary lockout (avoid double lockout and device-induced lockout DoS) | Unlock action for tenant admin |
| Session controls | Keycloak SSO idle/max, offline idle, per-client lifetimes, sign out everywhere | Tenant defaults (proposal: access 5 min, SSO idle 8-12 h) | Portal session list and revoke (mock-tested) |
| User lifecycle | n/a | n/a | Exists (P1.8); extend for guests, service accounts |
| Group lifecycle | `groupOfNames` | n/a | GRP- document |
| Dynamic groups | OpenLDAP `dynlist` overlay | Rules on attributes (department, title) | Rule editor; materialised membership (GRP- 3.4) |
| Organisational units | LDAP OUs | Per-tenant OU layout | Admin scoping per OU (administrative units) |
| Guests (B2B) | Keycloak users; identity brokering to external IdPs | Guest subtree, `opencloudGuest` role | Invitation flow, sponsor, expiry |
| Service accounts | Keycloak client-credentials; LDAP `ou=system` binds | Narrow roles per account (pattern proven) | Typed actions, secret rotation, expiry |
| App registration, permissions, consent | Keycloak clients, client scopes, consent screen | Scope catalogue | Tenant self-service registration with admin consent (P10.10) |
| SCIM 2.0 (inbound/outbound) | **Not in Keycloak core** | Community extensions exist; licences differ and at least one popular extension moved to a commercial model (verify) | Prefer an ICS-native SCIM server writing LDAP through typed actions |
| Federation with other IdPs | Keycloak identity brokering (OIDC, SAML, social) | Per-tenant brokers, account linking rules | UI |
| Hybrid AD / directory sync | Keycloak LDAP federation to AD; OpenLDAP syncrepl (LDAP-to-LDAP) | n/a | AD-authoritative mode needs an ADR (section 5) |
| Access reviews | None | n/a | ICS campaigns: owners confirm/remove; unanswered -> policy |
| Entitlement management | None | n/a | Access packages = request -> approval -> time-bound group membership |
| PIM / JIT admin | None | n/a | Time-bound privileged group membership via ICS approval engine, auto-expiry |
| Conditional access | Keycloak authentication flows with conditions (role, client, OTP condition) | Per-app flows | Custom authenticators for network and device signals (F6) |
| Device compliance | None | n/a | F6 + MDM- signals into Keycloak authenticator |
| Risk-based policy | Brute-force counters only | n/a | Only reliable signals (failed attempts, new device, unknown network); no GeoIP or "impossible travel" without a reliable data source (owner decision) |
| Sign-in logs | Keycloak login and admin events (DB, with expiry) | Enable, retention | Per-tenant log view, export, F3 events |
| Alerts | n/a | n/a | ICS monitoring alert channels on events (failed-MFA bursts, break-glass use) |
| Admin approval workflows | n/a | n/a | Exists (ICS plans, ADR-0017) |
| Emergency access (break-glass) | Keycloak local (non-LDAP) user | Hardware key, excluded from conditional access | Alert on every use; quarterly test |

## 4. Requirements

| ID | Requirement | Microsoft equivalent | Proposed implementation | Status | Priority | Dependencies | Acceptance criteria |
|---|---|---|---|---|---|---|---|
| ENT-01 | Single sign-on for every Office Unbound app | Entra SSO | Keycloak OIDC per app; back-channel logout to all | integrated_lab | A | ADR-0004 | Every app signs in via Keycloak; one logout ends all app sessions (MAS proven, others to verify) |
| ENT-02 | TOTP MFA, enforceable per role and tenant | Entra MFA | Keycloak OTP required action; mandatory for admins | implementing (not proven live) | A | ENT-01 | Live test: enrol, sign in, reset by tenant admin, enforced for `org-admin` |
| ENT-03 | FIDO2/WebAuthn security keys | FIDO2 method | Keycloak WebAuthn | planned | A | ENT-02 | Security key registered and used as second factor in two browsers |
| ENT-04 | Passkeys and passwordless sign-in | Passkeys, passwordless | Keycloak WebAuthn passwordless | planned | C | ENT-03 | User signs in without a password; recovery path tested |
| ENT-05 | Self-service password reset | SSPR | One-time token via verified mail or MFA; writes LDAP through the ICS path | planned | A | Owner decision 3 | User resets without admin; old password refused everywhere within 60 s (Gromox cache) |
| ENT-06 | Password policy | Password protection | ppolicy at the LDAP write path, mirrored in UI | planned | A | ENT-05 | Weak/reused password refused with a plain message |
| ENT-07 | Lockout and brute-force protection without self-DoS | Smart lockout | Keycloak brute-force detection primary; ppolicy as backstop with higher threshold | planned | A | ENT-06 | 10 wrong passwords lock temporarily; a stale phone password does not lock the account permanently |
| ENT-08 | Session controls and revoke | Sign-in frequency, revoke sessions | Keycloak lifetimes; portal "sign out everywhere" | implementing (mock-tested) | A | ENT-01 | Revoke ends all sessions within the measured bound |
| ENT-09 | User lifecycle across all services | User management | Existing `idm.user.*` | integrated_lab | A | P1.8 | Existing evidence; extend to Matrix lock and guests |
| ENT-10 | Group lifecycle | Groups | GRP- document | planned | A | GRP- | GRP- acceptance |
| ENT-11 | Dynamic groups | Dynamic membership | OpenLDAP `dynlist` or ICS-materialised rules | planned | C | GRP-01 | Changing `department` moves the user between groups within one reconcile run |
| ENT-12 | Organisational units and scoped admins | Administrative units | LDAP OUs + tenant-admin scope per OU | planned | C | P4.2 | OU admin manages only their OU |
| ENT-13 | Guest accounts | B2B collaboration | Guest subtree, invitation, sponsor, expiry | planned | A | GRP-13 | Guest invited by mail, MFA enforced, expires on date |
| ENT-14 | Service accounts | Service principals | Keycloak client-credentials, narrow roles, rotation | integrated_lab (internal); planned (tenant-facing) | C | P4.3 | Tenant creates a scoped account; it cannot exceed its scope (403) |
| ENT-15 | App registration with scoped consent | App registrations, consent | Keycloak clients via typed action; admin consent | planned | C | P10.10 | Third-party app registered; consent shown; scopes enforced |
| ENT-16 | OIDC/OAuth2 for third-party apps | Enterprise apps | Keycloak | planned | C | ENT-15 | Reference app (e.g. a wiki) signs in via OIDC |
| ENT-17 | SAML 2.0 for third-party apps | SAML SSO | Keycloak SAML | planned | C | ENT-15 | Reference SAML SP signs in; signed assertions |
| ENT-18 | SCIM 2.0 provisioning | SCIM | ICS-native SCIM endpoint -> typed actions (inbound); outbound to SaaS later | planned | C | ADR | SCIM create/deactivate reaches LDAP via approved plan; audited |
| ENT-19 | Federation with external IdPs | External identities | Keycloak brokering per tenant | planned | C | ENT-13 | Partner's IdP users sign in as guests |
| ENT-20 | Hybrid AD | Entra Connect | Keycloak LDAP federation or one-way sync; authority per ADR (section 5) | planned | C | ADR | Lab AD users sign in; P10.10 acceptance "AD users sync" |
| ENT-21 | Directory sync from other sources (HR, CSV) | Entra Connect, API-driven provisioning | Migration toolkit + SCIM | planned | D | ENT-18 | CSV import creates users via plans |
| ENT-22 | Access reviews | Access reviews | ICS campaigns to owners | planned | C | GRP-14 | Review removes stale membership (P10.10 acceptance) |
| ENT-23 | Entitlement management | Access packages | Request -> approval -> time-bound membership | planned | C | ENT-22 | Package request approved, expires automatically |
| ENT-24 | PIM / just-in-time admin | PIM | Time-bound privileged membership via ICS approval | planned | C | ADR-0017 | Elevation needs approval and expires (P10.10 acceptance) |
| ENT-25 | Conditional access (app, role, network) | Conditional Access | Keycloak flows + custom authenticators | planned | C | ENT-02 | Policy blocks sign-in from a disallowed network for an app |
| ENT-26 | Device compliance in sign-in | Compliant device | F6 signals from MDM- into a Keycloak authenticator | planned | C | F6, MDM-, Connect C7 | Non-compliant device blocked (P10.10 acceptance) |
| ENT-27 | Risk-based policy on reliable signals | Identity Protection | Failed-attempt bursts, new device; step-up MFA | planned | D | ENT-25 | Burst triggers step-up; no unreliable signal used |
| ENT-28 | Sign-in logs per tenant | Sign-in logs | Keycloak events -> tenant view + export | planned | A | F3 | Tenant admin sees own tenant's sign-ins only |
| ENT-29 | Security alerts | Alerts | ICS alert channels on identity events | planned | C | ENT-28 | Break-glass use and MFA-failure bursts alert within 5 min |
| ENT-30 | Admin approval workflows | Approvals | ICS plans (existing) | integrated_lab | A | ADR-0017 | Existing evidence |
| ENT-31 | Emergency access accounts | Break-glass | Keycloak local account, hardware key, alerting | planned | A | ENT-29 | Break-glass works with LDAP down; use alerts |
| ENT-32 | Windows device sign-in | Entra Join (functional only) | Connect section 4.1 (Samba AD option or local-account bridge) | planned | C | Connect C1-C3 | Connect section 16 |
| ENT-33 | Windows offline sign-in, emergency local admin, profile migration | Cached credentials, LAPS | Connect sections 4.1, 7, 11 | planned | C | ENT-32 | Offline sign-in; LAPS-style rotated local admin retrievable by admin only |
| ENT-34 | macOS sign-in | Platform SSO with Entra | Connect section 4.2 | planned | C | MDM-, Apple membership | Connect section 16 |
| ENT-35 | Linux sign-in | Entra for Linux | Connect section 4.3 | planned | C | Connect C4 | Connect section 16 on the matrix in section 6.3 |
| ENT-36 | Device identity and certificates | Device objects | Connect sections 5-6 (hardware-backed key, per-tenant CA) | planned | C | F1 | Device in tenant A invisible to B |
| ENT-37 | Zero manual employee configuration | Autopilot-like UX | Connect app + discovery document | planned | C | ENT-32..35 | No employee step involves LDAP, VPN or certificates |
| ENT-38 | Tenant isolation for every identity object | Tenant boundary | Per-customer Keycloak/LDAP/CA (existing) | integrated_lab | A | P4.1 | T20 re-run per release; cross-tenant tests for guests, apps, service accounts added |

## 5. Hybrid AD and the one-directory rule

Three modes, each needing an owner decision and, for any authority change, an ADR:

1. **OpenLDAP authoritative (default, existing).** No AD.
2. **Customer AD authoritative, read-only federation.** Keycloak federates the customer's AD; OpenLDAP-based services (Gromox, OpenCloud) need
   an identity source too, so either they read AD (changes ADR-0004 per tenant) or the ICS syncs AD one way into OpenLDAP. Passwords stay in AD.
3. **Samba AD for Windows sign-in** (Connect option 4.1 A). Samba AD keeps its own database; one side must be authoritative
   ([office-unbound-connect.md](office-unbound-connect.md) section 5).

## 6. Platform sign-in (summary; details in Office Unbound Connect)

### 6.1 Windows

See [Connect section 4.1](office-unbound-connect.md#41-windows-11-pro-enterprise-education-versions-verified-in-c2). Options: Samba AD domain
with Kerberos over a KDC proxy (no VPN), or a signed Credential Provider with a local-account bridge. Required: device certificate (TPM),
cached credentials, profile migration, emergency local administrator. **No claim of Entra Join, CloudAP or PRT.** Windows Hello for Business
cloud trust is unavailable; Hello for the local account only (option B) or Hello with AD key trust (option A, to verify).

### 6.2 macOS

See [Connect section 4.2](office-unbound-connect.md#42-macos). Platform SSO + Extensible SSO extension against Keycloak, delivered by MDM
(MDM- document); Secure Enclave key for passwordless, FileVault/Secure Token compatibility and offline recovery follow Apple behaviour.
**Cost flag:** Apple Developer Program membership (paid annually; about USD 99/year at the time of writing, verify) for signing and
associated-domains entitlements. Apple Business Manager (free, requires an organisation identifier such as D-U-N-S) only for automated enrolment.

### 6.3 Linux

See [Connect section 4.3](office-unbound-connect.md#43-linux-ubuntu-debian-fedora-first). PAM + SSSD configured by the installer; cached
credentials; automatic home directories; group mapping; SSH policy (`AllowGroups` from GRP- groups, keys or certificates from the directory);
never public LDAP/Kerberos. Proposed validation matrix (none validated today):

| Distribution | Versions to validate | SSSD path | Status |
|---|---|---|---|
| Ubuntu | 24.04 LTS, 26.04 LTS | LDAP/Kerberos over device-authenticated tunnel or KDC proxy; IdP provider if mature | planned |
| Debian | 12, 13 | same | planned |
| Fedora | current stable | same; newer SSSD | planned |

## 7. Security and tenant isolation

- One Keycloak realm and one directory per customer stack (existing); no Keycloak Organizations for customer separation
  ([files-identity-eval.md](../status/files-identity-eval.md)).
- Deprovisioning always revokes in Keycloak as well as LDAP (KI-2); new consumers must either re-resolve users per request or accept the
  access-token lifetime as revocation delay.
- Password-grant test clients must not exist in production ([tenant-isolation-results.md](../status/tenant-isolation-results.md) section 3).
- Break-glass accounts are excluded from conditional access but every use alerts.
- SCIM, app registration and service accounts are tenant-scoped; cross-tenant tests extended to them (ENT-38).
- Device sign-in security requirements: [Connect section 10](office-unbound-connect.md#10-security-requirements-mandatory).

## 8. Licensing notes

| Item | Licence / cost | Note |
|---|---|---|
| Keycloak | Apache-2.0 | Existing; SSO, MFA, WebAuthn, SAML, brokering included |
| OpenLDAP | OpenLDAP Public License 2.8 | Existing |
| SCIM extensions for Keycloak | Varies; verify each LICENSE | Prefer ICS-native SCIM to avoid a commercial dependency |
| Samba AD, SSSD | GPL-3.0 | Separate programs, never linked into Office Unbound code |
| GeoIP data (risk policy) | Free databases carry EULAs and account requirements (verify) | Owner decision before any use |
| Apple Developer Program | Paid annual membership | Owner decision (zero-cost rule) |
| Windows code signing | Authenticode certificate, normally paid | Owner decision |
| FIDO2 security keys | Hardware bought by customers | Optional; platform passkeys need no hardware |
| SMS OTP | Paid gateways | Not proposed; TOTP, WebAuthn, mail links instead |

Full Connect licensing review: [office-unbound-connect.md section 12](office-unbound-connect.md#12-licensing-review-checked-against-the-upstream-license-files-2026-11-21).
No Microsoft licence is required by any item.

## 9. Open owner decisions

1. Order of identity work for the beta (proposal: ENT-02, 05, 06, 07, 08, 28, 31 first; priority A).
2. Lockout design: Keycloak primary vs ppolicy primary.
3. User password change path with READ_ONLY federation: writable password attribute for Keycloak, or always through the ICS enrollment path.
4. SCIM: ICS-native implementation or a Keycloak extension.
5. Hybrid AD mode(s) to support and the authority ADR (section 5).
6. Apple Developer Program and Windows code-signing costs (shared with Connect decision 4).
7. Whether any risk signal beyond failed attempts and new device is acceptable (GeoIP licensing).
8. Linux distribution matrix for the first release.
