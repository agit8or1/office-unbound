# Office Unbound Connect: cloud identity, desktop sign-in and device management

**Status: PLANNED / NOT IMPLEMENTED.** Planning document only (owner, 2026-11-21). Not authorized for development; the current
roadmap keeps priority until the owner explicitly authorizes this module. Nothing described here exists in Office Unbound today.

Roadmap: [P10.12 in the post-core expansion plan](../roadmap/post-core-expansion.md#p1012-office-unbound-connect-desktop-sign-in-and-device-enrollment--xl),
building on [P10.6 Endpoint](../roadmap/post-core-expansion.md#p106-endpoint-and-device-management-intune--xl) and
[P10.10 Advanced Identity](../roadmap/post-core-expansion.md#p1010-advanced-identity-and-enterprise-integrations-entra-id-advanced--graph--xl).

## 1. Executive summary

Office Unbound Connect would let an organisation's people sign in to their Windows, macOS and Linux computers with the same
organisational identity they already use for Office Unbound mail, files and documents, and let administrators and MSPs enrol,
inventory and revoke those computers centrally. The aim is an experience comparable to Microsoft Entra ID join, fully
self-hosted, with no per-user or per-device licence. It is **not** Entra-compatible: no Entra Join, no CloudAP, no Microsoft
protocols. Each operating system offers a different, limited set of supported integration points (section 4); the plan uses
only those.

## 2. Product objectives

- A technician enrols a computer without configuring LDAP, Kerberos, certificates, VPNs or OS authentication by hand.
- An employee installs a signed app, enters the organisation address (for example `office.customer.com`) and their account,
  completes MFA, and the computer is enrolled and configured.
- The same identity signs in to the computer and (SSO) to Office Unbound apps.
- Password reset, account disable and device revocation apply consistently, within documented offline limits (section 11).
- Administrators and MSPs manage users, devices and access policies centrally, per tenant.

Target end-user screen: "Connect your computer to your organization": Organization, Username, **Connect Device**; then status
lines (connected to organization, device enrolled, sign-in configured, security policy applied, apps connected, last
synchronization) with plain error messages and repair actions. Administrators get a guided setup wizard.

## 3. Entra ID comparison (target, with limitations)

| Entra ID capability | Connect plan | Limitation compared with Entra |
|---|---|---|
| Entra Join / cloud sign-in on Windows | Windows sign-in through a supported mechanism (section 4.1) | Not Entra Join, no Primary Refresh Token, no CloudAP; Windows Hello for Business cloud trust unavailable |
| macOS Platform SSO with Entra | Apple Platform SSO with the Office Unbound identity provider | Requires MDM and an Apple-signed SSO extension (section 12) |
| Linux (Entra via Himmelblau / Intune) | SSSD and PAM, configured by the installer | Distribution and version matrix limited to what is validated |
| Conditional Access | Keycloak policies using verified device signals | Only signals the agent can attest; no Microsoft risk signals |
| Intune device management | P10.6 device console (osquery or Fleet, rem0te) | Actions limited to what each OS and MDM allows |
| Self-service password reset, MFA | Keycloak (existing) | Offline devices learn of changes only when they reconnect |
| Immediate revocation | Revocation on next contact | **Not immediate on disconnected devices** (section 11) |

## 4. Implementation options per platform

### 4.1 Windows (11 Pro, Enterprise, Education; versions verified in C2)

A Credential Provider only collects credentials; Windows still needs an account and an authentication package behind it.
Options to evaluate in C1/C2:

| Option | How it works | For | Against |
|---|---|---|---|
| A. Samba AD domain mode | Device joins a Samba AD domain; Kerberos over HTTPS through a KDC proxy (MS-KKDCP, supported by Windows) so no VPN | Native Windows mechanism: cached logon, Group Policy, profiles, mature | Samba AD becomes a directory (section 5); KDC proxy must be validated; GPL-3.0 server component |
| B. Local-account bridge | Signed Credential Provider plus service maps the organisational identity to a local account, verifies online against Keycloak, keeps the local password in step | No domain; works over plain HTTPS | Security-sensitive custom code; needs a dedicated threat model and security review; Windows Hello only for the local account |
| C. Existing open-source provider | pGina-style plug-in model (BSD-3-Clause), adapted | Prior art for B | Upstream largely inactive; same review burden as B |

Recommendation for C1: evaluate A first (least custom security code), B as the domainless mode. Required in every option: device
key in the TPM, cached offline logon, local emergency administrator, signed installer with staged rollout and rollback,
migration of existing profiles.

### 4.2 macOS

Apple Platform SSO (macOS 13+, extended in 14/15) with an Extensible SSO extension talking to Keycloak. Apple requires the
configuration to be delivered by **MDM**, and the extension to ship in an app signed by a registered Apple developer with the
associated-domains entitlement. Account association, password sync or passwordless (Secure Enclave key), FileVault and Secure
Token compatibility, and offline login follow Apple's Platform SSO behaviour. MDM candidates: NanoMDM / MicroMDM (MIT) or
Fleet (MIT core). Unattended enrollment (Automated Device Enrollment) needs Apple Business Manager; not promised.

### 4.3 Linux (Ubuntu, Debian, Fedora first)

PAM and SSSD (GPL-3.0) configured automatically by the installer: identity and cached credentials from the tenant directory
over an authenticated, encrypted channel (never public LDAP or Kerberos; section 10), automatic home directories, group
mapping, desktop and terminal sign-in, optional SSH integration, MFA where the flow supports it. To verify in C4: SSSD's
OIDC/IdP-based provider maturity per distribution versus LDAP/Kerberos through a tunnel or KDC proxy.

## 5. Proposed identity architecture

Reuse, do not duplicate:

| Function | Component | Note |
|---|---|---|
| 1. User identity and authentication | OpenLDAP (authoritative) + Keycloak (OIDC, MFA, SSO) | Existing; no second user database |
| 2. OS sign-in integration | Per-OS client (section 4) | New, signed, per platform |
| 3. Device identity and trust | Device certificate / key issued at enrollment, hardware-backed | New; per-tenant CA (existing pattern) |
| 4. Device management and policy | P10.6 device console and agent | Separate from the ICS node agent (rule F8) |
| 5. Application SSO | Keycloak (existing) | Device signals feed Keycloak policies (F6) |
| 6. MSP administration | ICS console and portal admin area | Existing tenancy and roles |
| 7. Orchestration | ICS typed actions, approval, audit | Existing |

**Samba AD (option 4.1 A):** Samba AD keeps its own directory database; it cannot run on top of OpenLDAP's data. If offered, a
tenant in AD mode needs one authoritative directory: either Samba AD authoritative (Keycloak federates it, OpenLDAP-based apps
read from it or are synchronised one way), or OpenLDAP authoritative with one-way provisioning into Samba AD (password hashes
cannot simply be copied; password changes must be captured at the source). This boundary is an owner decision (section 17).

## 6. Enrollment workflow

1. MSP provisions the tenant (existing). 2. Administrator creates or imports people (existing People / directory).
3. Administrator enables Connect for the tenant: enrollment policy (approval required or not, company-owned or BYOD, device
quota). 4. Employee installs the signed app, enters the organisation address; discovery uses a well-known HTTPS document on
that name. 5. Browser-based sign-in with MFA (Keycloak). 6. The device generates a hardware-backed key; the server issues a
device certificate bound to tenant, device and user; enrollment tokens are single-use, short-lived and replay-protected.
7. The app configures the OS integration and reports status. Bulk options: enrollment links, QR codes, pre-approved serials.

## 7. User management

Existing People lifecycle (create, role, lock, delete) extended with: device sign-in rights per group, local account mapping,
profile migration from existing local or domain accounts, disablement and deprovisioning propagated to devices on next
contact, audit of every change.

## 8. Device management

Inventory, OS version and health, encryption status, last check-in, agent version, compliance state, policy assignment,
security alerts, update status, unenrolment and removal, lost-device actions limited to what the OS and MDM support. Delivered
through P10.6; Connect adds the identity and enrollment side.

## 9. MSP workflows

Tenant-isolated device administration, an MSP-wide overview, delegated and role-based permissions, enrollment policies per
customer, MSP-configurable device quotas (no product licence limits), bulk operations, API integration with clientst0r and
rem0te, later backup and endpoint modules.

## 10. Security requirements (mandatory)

- LDAP, Kerberos, Samba AD and similar services are never exposed publicly; device traffic uses HTTPS with mutual TLS or an
  equivalent device-authenticated channel.
- OS secure key storage (TPM, Secure Enclave, kernel keyring/TPM on Linux); no plaintext passwords stored anywhere.
- No custom password-verification scheme without a security review; native OS login protections are never bypassed.
- Local emergency administrator on every device; documented recovery when the identity servers are unreachable.
- Protection against device impersonation and enrollment hijacking; credential rotation and revocation.
- Strict tenant isolation; scoped authorization for administrative actions (ICS typed actions, approval, audit).
- Signed installers and updates, staged rollout, rollback.
- No permanent VPN for ordinary operation.
- A threat model is a C1 exit criterion; implementation does not start without it.

## 11. Offline access and recovery

Cached sign-in works offline for a configurable period. Password changes, disablement and revocation reach a device only when
it next contacts the service; until then a disconnected device may still accept the cached credential. This delay is shown to
administrators and is never described as immediate. Recovery: local emergency administrator, re-enrollment, documented
procedure when the identity service is down.

## 12. Licensing review (checked against the upstream LICENSE files, 2026-11-21)

| Candidate | Provides | Licence | Self-hosted / limits | Fit and concerns |
|---|---|---|---|---|
| Keycloak | OIDC, MFA, SSO, policies | Apache-2.0 | Yes / none | Existing; device-signal policies need custom authenticators |
| OpenLDAP | Directory | OpenLDAP Public License 2.8 | Yes / none | Existing authoritative store |
| Samba AD | AD domain controller, Kerberos | GPL-3.0 | Yes / none | Windows option A; its own directory; operate as a separate service, not linked into our code |
| SSSD | Linux identity and cached credentials | GPL-3.0 | Yes / none | Linux client; used as shipped by distributions |
| Linux-PAM | Linux authentication stack | BSD-style, or GPL at the recipient's option | Yes / none | Configured, not modified |
| FreeIPA | LDAP + Kerberos + CA, Linux domain | GPL-3.0 | Yes / none | Would be a second identity system; not proposed as a component |
| authentik | IdP | MIT core; `authentik/enterprise/` under a separate licence | Yes / enterprise features paid | Overlaps Keycloak; not proposed |
| Kanidm | IdP with Unix/PAM client over HTTPS | MPL-2.0 | Yes / none | Would be a second identity system; its HTTPS Unix client is a design reference |
| pGina | Windows credential provider framework | BSD-3-Clause | n/a | Prior art for Windows option B |
| Windows Credential Provider API | Windows sign-in UI integration | Microsoft platform API (Windows SDK) | n/a | Needs code signing for distribution |
| Apple Platform SSO / Extensible SSO | macOS sign-in with an IdP | Apple platform API | n/a | Requires Apple Developer Program (paid annual membership, held by the publisher) and MDM |
| NanoMDM, MicroMDM | Apple MDM | MIT | Yes / none | APNs certificate from Apple (free, external dependency) |
| Fleet | Device management, osquery-based | MIT core; `ee/` under a separate licence | Yes / premium features paid | Use only the MIT core |
| osquery | Device inventory and queries | Apache-2.0 or GPL-2.0 (choice) | Yes / none | P10.6 inventory |
| MeshCentral | Remote management | Apache-2.0 | Yes / none | Alternative to rem0te features |
| Headwind MDM (server) | Android MDM | Apache-2.0 | Yes / none | Mobile only; out of Connect scope |
| Himmelblau | Linux sign-in with Entra ID | GPL-3.0 | n/a | Entra-specific; design reference only |

Findings that need owner decisions: (1) macOS Platform SSO requires a **paid Apple Developer Program membership** and a
code-signed app, which conflicts with the zero-cost rule unless the publisher holds it; (2) Windows binaries need an
Authenticode code-signing certificate (normally paid) for a usable installer; (3) GPL-3.0 server components (Samba, SSSD) are
acceptable as separately run programs, but must not be linked into non-GPL Office Unbound code.

## 13. Development dependencies

People lifecycle and directory runbooks (0.8.0), tenant isolation (F1, per-tenant CAs and secrets), service authorisation API
(F2), event bus (F3), device posture (F6), separate device agent (F8), P10.6 device console, Keycloak conditional-access work
(P10.10), signing infrastructure for installers and updates (extends ADR-0011/0015 artifact signing).

## 14. Phased plan (provisional; not authorization to start)

| Phase | Deliverable |
|---|---|
| C1 | Architecture, licensing, feasibility and security design (threat model, Windows option choice, Apple and signing decisions) |
| C2 | Windows authentication and enrollment proof of concept |
| C3 | Windows device administration and recovery |
| C4 | Linux authentication and enrollment |
| C5 | macOS Platform SSO and management integration |
| C6 | Unified device dashboard and MSP administration |
| C7 | Passwordless, device trust and conditional access |
| C8 | Production hardening, compatibility validation and documentation |

No dates and no completion percentages are assigned.

## 15. Risks and technical limitations

Windows sign-in without a domain needs security-critical custom code (option B); Samba AD adds a second directory engine to
operate (option A); Apple requirements (MDM, developer membership, entitlements) are outside our control; revocation is delayed
on offline devices; OS updates can break credential providers and PAM configurations (staged rollout needed); a wide
distribution matrix on Linux is costly to validate; no Microsoft signals for conditional access.

## 16. Acceptance criteria (for the eventual implementation)

- A Windows 11 Pro, a macOS and an Ubuntu test device enrol through the one-screen flow without manual OS configuration.
- The person signs in to the device and then to Office Unbound apps without a second sign-in.
- Disabling the account or revoking the device blocks the next online sign-in; the offline delay matches the documented policy.
- Cached offline sign-in and the local emergency administrator both work.
- A device in tenant A is invisible to tenant B; every enrollment and administrative change is audited.
- Installers and updates are signed; a staged rollout can be rolled back.
- No LDAP, Kerberos or AD port is reachable from the internet.

## 17. Decisions requiring owner approval

1. Authorize development at all, and its position relative to the current roadmap.
2. Windows approach: Samba AD domain mode, domainless local-account bridge, or both.
3. Authoritative directory for AD-mode tenants (section 5).
4. Apple Developer Program membership and Windows code-signing certificate (zero-cost rule exception or not).
5. Supported OS and distribution matrix for the first release.
6. Default offline sign-in period and revocation policy.

## Cross-references (2026-11-23 roadmap revision)

This document is unchanged otherwise; the identity and device requirements of the 2026-11-23 revision point to it instead of duplicating it.

| Section here | Requirement IDs |
|---|---|
| 3 Entra ID comparison, 5 identity architecture | ENT-32 to ENT-37 in [entra-identity-parity.md](entra-identity-parity.md) |
| 4.1 Windows | ENT-32, ENT-33 |
| 4.2 macOS | ENT-34; MDM- ([intune-and-mobile-mdm.md](intune-and-mobile-mdm.md)) for MDM delivery of Platform SSO |
| 4.3 Linux | ENT-35 |
| 6 Enrollment, 10 security | ENT-36, ENT-37; MDM- enrollment requirements |
| 8 Device management | MDM- ([intune-and-mobile-mdm.md](intune-and-mobile-mdm.md)) |
| 7 User management, 11 offline access and revocation | ENT-09, GRP-20 in [unified-groups-and-permissions.md](unified-groups-and-permissions.md); WIPE- ([mobile-remote-wipe-security.md](mobile-remote-wipe-security.md)) for lost-device and wipe actions |
| 12 Licensing, 17 decisions 4 | ENT owner decision 6 (Apple and code-signing costs) |
