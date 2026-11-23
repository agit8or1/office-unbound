# Office Unbound Desktop Connector: HTTPS mapped drives and OneDrive-style sync

**Status: PLANNED / NOT IMPLEMENTED.** Planning document only (owner, 2026-11-23: "This is a planning and roadmap task only. Do not begin
implementing it yet."). Development starts only after explicit owner approval. Nothing below exists in Office Unbound today unless marked
*exists*. Roadmap: [P11.8](../../ROADMAP.md). Builds on [ODB-C desktop sync](onedrive-and-file-sharing.md#34-desktop-sync-odb-c-windows-macos-linux)
(sync requirements are **not** repeated here) and on [Office Unbound Connect](office-unbound-connect.md) (device enrolment).

## 1. Objective

A remote Windows, macOS or Linux computer reaches its Office Unbound files over HTTPS only, with no VPN and no SMB/NFS exposed to the
internet: as a **mapped drive** (Windows `O:`, Finder volume, Linux mount) and, optionally, as **OneDrive-style sync** (offline, selective,
on-demand, conflicts). One downloadable connector sets both up in one step.

## 2. Current file stack (evaluated 2026-11-23)

| Piece | What exists | Evidence | Consequence for the connector |
|---|---|---|---|
| OpenCloud server (files, spaces, shares) | *exists*; WebDAV at `/remote.php/dav/files/<user>` and spaces WebDAV; Graph API `/graph/v1.0/me` | T02 11/0, [identity-files-lab-results.md](../status/identity-files-lab-results.md) | The drive speaks WebDAV to OpenCloud: no new storage, no new file API |
| Authentication | Keycloak OIDC; OpenCloud accepts bearer access tokens; revoked tokens denied within ~11 s | same, revocation rows | Drive authenticates with OIDC tokens, never a password |
| Desktop sync | OpenCloud Desktop 4.x; engine `opencloudcmd` tested headless (T07: two-way, conflicts); GUI not tested | ODB-C05/C09 | Sync = OpenCloud Desktop, configured by the connector; not rebuilt |
| Files on-demand | Windows: OpenCloud VFS via Cloud Files API (upstream, to verify); macOS/Linux: none verified | ODB-C08 | On-demand on macOS/Linux comes from the mount (VFS cache), not from sync |
| Public entry | Gateway serves `cloud.<domain>` with a trusted certificate (HTTPS only) | [host-changes.md](../status/host-changes.md) 2026-11-21 | Drives use the same public name; nothing else is opened |
| Audit of file access | OpenCloud has an audit service (**not configured**, to verify) | — | Needed before "audit logging" can be claimed (M4) |
| Device inventory / revocation | none | — | New, ICS-side (M2), shared with Connect |

## 3. Options compared

| | Native OS WebDAV (Windows WebClient, Finder "Connect to Server", davfs2) | **rclone mount** (WebDAV backend) + WinFsp / FUSE | Dedicated sync client (OpenCloud Desktop) |
|---|---|---|---|
| Drive letter / volume | Yes | Yes | No (a folder) |
| SSO + MFA | **No**: Basic auth only, needs a password-like secret | **Yes**: `bearer_token_command` gets a fresh OIDC token from the connector | Yes (browser sign-in) |
| Large files | Windows WebClient default limit ~50 MB (registry raises to 4 GB) | Streamed; VFS cache handles large files | Chunked, resumable (TUS) |
| Offline | No | Read cache only (cache mode `full`), no guaranteed offline | Yes |
| Conflicts | Last writer wins | Last writer wins on the server; local cache detects changed remote | Conflict copies (T07) |
| Locking | WebDAV LOCK (client-dependent) | No WebDAV locks (to verify) | To verify (ODB-C15) |
| Windows future | WebClient is deprecated by Microsoft (to verify current state) | WinFsp maintained | Upstream maintained |
| Support cost | Low code, high support (registry tweaks, flaky Finder) | Medium: connector + mount driver per OS | Low (upstream), GUI untested |
| Verdict | Fallback only, not recommended | **Recommended for mapped drives (initial)** | **Recommended for sync** |

**Proposed choice:** mapped drives = rclone mount over WebDAV/HTTPS with an OIDC bearer token; sync = OpenCloud Desktop. The connector is a
small signed app that signs in once and configures both. Final choice after milestone M0 (spike on the real stack).

## 4. Architecture

```
 Computer                                                     Office Unbound deployment
 ┌──────────────────────────────────────┐      HTTPS 443      ┌───────────────────────────────┐
 │ Office Unbound Connector (tray app)  │ ─── OIDC (PKCE, ──▶ │ auth.<domain>  Keycloak        │
 │  · sign-in in the system browser     │     device client)   │  device client, offline token │
 │  · token store: OS keychain          │                      │  per device, revocable        │
 │  · drive manager: rclone mount ──────┼── WebDAV + Bearer ──▶│ cloud.<domain> OpenCloud      │
 │      WinFsp / macFUSE·FUSE-T / FUSE  │                      │  WebDAV, spaces, permissions  │
 │  · sync: configures OpenCloud Desktop│                      │                               │
 │  · status, diagnostics, reconnect    │ ── device API ──────▶│ app.<domain> portal → ICS     │
 └──────────────────────────────────────┘                      │  device register / revoke,    │
                                                               │  drive assignments, audit     │
                                                               └───────────────────────────────┘
```

- **Credentials (requirement 6):** OIDC authorization code with PKCE in the system browser, so MFA always applies; Keycloak issues a
  refresh (offline) token to a dedicated public client `ou-connector`, one session per device. The refresh token sits in the OS keychain
  (Windows Credential Manager/DPAPI, macOS Keychain, Linux Secret Service); access tokens live minutes and are handed to rclone through
  `bearer_token_command`, never written to its config. No password is stored or typed into the connector. Revocation: the portal (user) or
  the ICS (admin) ends the device's Keycloak session; OpenCloud refuses the next request (measured ~11 s for access tokens today).
- **Scope (requirement 8):** the connector lists what the user may see through OpenCloud (personal space, shared with me, project/team
  spaces) via the Graph API and maps only those; permissions are OpenCloud's, unchanged. No admin credential on the device.
- **Tenant isolation (15):** each tenant is its own deployment with its own names; a device signs in to exactly one deployment per account;
  multi-account keeps them in separate mounts, token stores and caches.
- **No SMB/NFS on the internet (15):** only `cloud.<domain>:443` and `auth.<domain>:443`. (macOS FUSE-T and `rclone nfsmount` use NFS on
  the loopback interface only.)

## 5. Recommended FOSS dependencies (licences to verify from the upstream LICENSE files before use)

| Component | Role | Licence (believed) | Note |
|---|---|---|---|
| rclone | WebDAV client, mount, VFS cache, bandwidth limits | MIT | Has an OpenCloud/ownCloud WebDAV vendor mode (to verify for OpenCloud) |
| WinFsp | Windows user-mode filesystem | GPL-3.0 with FLOSS exception; commercial licence available | Fine for an open-source connector; redistribution terms to confirm |
| macFUSE | macOS FUSE (kernel extension) | Freeware, **not open source** since 4.x; redistribution needs permission | Prefer FUSE-T or `rclone nfsmount` if licence or kext approval is a problem |
| FUSE-T | macOS FUSE without kernel extension (local NFS) | Free; licence to verify | Candidate default on macOS |
| libfuse / fuse3 | Linux FUSE | LGPL-2.1 / GPL-2.0 | Distribution packages |
| OpenCloud Desktop | Sync, on-demand on Windows | GPL-2.0-or-later (to verify) | Upstream signed builds avoid signing costs |
| Tray UI | Connector app | Tauri (MIT/Apache-2.0) or Qt (LGPL-3.0) | Decide in M1 |

**Costs flagged for the owner:** Windows code signing and Apple Developer ID notarization for a connector signed by Office Unbound (same
items as ODB section 7). Without them the connector cannot be installed silently on managed Windows/macOS fleets.

## 6. Requirements (all **planned**)

| ID | Requirement (owner list) | Approach |
|---|---|---|
| DC-01 | One-click setup from a downloadable connector (1) | Portal *Set up devices* download; enter work e-mail, sign in, drives appear |
| DC-02 | Windows drive letter, Finder volume, Linux mount (2) | rclone mount via WinFsp / FUSE-T or macFUSE / fuse3 |
| DC-03 | WebDAV over HTTPS with rclone + WinFsp/FUSE as first implementation (3) | Section 3; M0 spike |
| DC-04 | Optional sync: offline, selective, on-demand, conflicts (4) | OpenCloud Desktop configured by the connector (ODB-C05..C09) |
| DC-05 | SSO/MFA, identity, tenant isolation, permissions, shared folders, audit (5) | Section 4; audit needs OpenCloud audit service enabled + ICS log (M4) |
| DC-06 | Device-specific, revocable, scoped credentials; no stored passwords; MFA never bypassed (6) | Section 4 credentials |
| DC-07 | Reconnect at login, recover from network loss, clear status (7) | Login item / service; rclone retries; tray states: connected, reconnecting, signed out, offline, error |
| DC-08 | Personal, shared-with-me, department and company storage per permissions (8) | Graph API listing of drives/spaces |
| DC-09 | Central admin: drive assignments, policies, deployment packages, device revocation (9) | ICS + portal Admin area: device list, revoke, assigned drives (letter, space), policy (allow drives / sync / offline cache) |
| DC-10 | Silent install and mass deployment: GPO/Intune, macOS MDM, Linux scripts (10) | MSI with properties (server, tenant), signed PKG + configuration profile, .deb/.rpm + script; no per-user secret in packages |
| DC-11 | Caching, large files, conflicts, locks/versions, bandwidth, offline recovery (11) | rclone VFS cache `writes`/`full`, chunked upload, `--bwlimit`; versions = OpenCloud versions; locks to evaluate (ODB-C15) |
| DC-12 | Evaluate FOSS clients before custom work (12) | Section 3 and 5; custom code limited to the connector shell |
| DC-13 | Compare native WebDAV, rclone, sync clients incl. support cost (13) | Section 3 |
| DC-14 | Reuse OpenCloud; no new storage (14) | Section 2 |
| DC-15 | TLS everywhere, tenant authz, no SMB/NFS on the internet (15) | Section 4 |
| DC-16 | Diagnostics, connection test, troubleshooting (16) | "Test connection" (DNS, TLS chain, sign-in, WebDAV PROPFIND, write test file), redacted diagnostics bundle, help pages |

## 7. Milestones (no dates; each needs owner approval to start)

| | Scope | Exit |
|---|---|---|
| M0 Spike | rclone mount of a real deployment's personal space on Windows (WinFsp), macOS (FUSE-T and macFUSE), Linux, with a bearer token from a test OIDC client | Measured: open/save of DOCX in LibreOffice and the built-in editor, 2 GB file copy, revoke-to-denied time, behaviour on network loss; licence check of each dependency |
| M1 Connector alpha | Tray app: sign-in (PKCE), keychain, one drive, reconnect, status, test connection | Acceptance 1-4 below on all three systems |
| M2 Devices | `ou-connector` client per deployment; ICS device list + revoke; portal "Your devices" | Acceptance 5 |
| M3 Shares and sync | Shared-with-me and spaces as drives; OpenCloud Desktop configuration from the connector | Acceptance 6-7 |
| M4 Admin and audit | Drive assignments, policies, OpenCloud audit service on, ICS audit of device events | Acceptance 8 |
| M5 Mass deployment | Signed MSI/PKG/deb, Intune/GPO/MDM guides | Acceptance 9 |

## 8. Acceptance criteria

1. A new user installs the connector, enters their work e-mail, signs in with MFA in the browser and sees drive `O:` (Finder volume, Linux
   mount) with their personal files within 60 s; no password is stored anywhere on the computer (keychain holds only the device token).
2. A DOCX opened from the drive in LibreOffice and saved appears in Files with a new version; the earlier version is restorable.
3. Network unplugged for 5 min while idle: the drive shows "reconnecting" and recovers without user action; a save attempted while offline
   is reported, not silently lost.
4. After restart and login the drive is back without signing in again (until the device token expires or is revoked).
5. Revoking the device in the portal or the ICS denies the next file operation within 60 s; other devices of the user keep working.
6. A folder shared with the user appears in "Shared with me" read-only or read-write exactly as shared; a space the user is not a member
   of is never listed.
7. With sync enabled, a file edited offline on two computers produces a conflict copy and no overwrite.
8. Every device sign-in, revocation and drive assignment is in the hash-chained ICS audit log; file access by the device is in OpenCloud's
   audit log.
9. A silent MSI install with a preset server on a managed Windows computer needs only the user's sign-in.
10. An owner-authorised external port check of the deployment's own public address shows only 80/443 (and mail ports); no SMB (445), NFS
    (2049) or WebDAV on other ports.

## 9. Open owner decisions

1. Approve M0 (spike, no product code).
2. Accept signing costs (Authenticode, Apple Developer ID) or ship unsigned community builds first.
3. macOS mount layer: FUSE-T (no kernel extension) vs macFUSE (licence and kernel-extension approval).
4. Drive letter default (`O:`) and whether admins may force letters.
