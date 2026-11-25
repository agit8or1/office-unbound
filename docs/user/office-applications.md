# Choose how you work: office applications and Office Unbound

Your files. Your software. Your choice. Office Unbound includes an office suite in the browser; you may also use other office software on
your own computer with the same files. This page is the reference behind the portal's **Choose how you work** section (Set up devices
page, `portal/app/office_apps.py`); both list the same facts.

Status words follow [ADR-0000](../adr/0000-status-values.md): only what the project has tested is described as working.

## 1. The built-in editor (default)

**Office Unbound Documents** is Office Unbound's own build of the open-source **Collabora Online** code (MPL-2.0; pinned source, built by the
project, [ADR-0005](../adr/0005-files-documents.md), [ADR-0008](../adr/0008-build-release-pipeline.md), catalog component `office`). It opens from Files and from the portal's *Start something new*.

| Capability | State | Evidence |
|---|---|---|
| Edit documents, spreadsheets, presentations in the browser | Works (alpha) | [identity-files-lab-results.md](../status/identity-files-lab-results.md), live deployment 2026-11-21 |
| Saved straight into Files; Files sharing and permissions apply | Works (alpha) | same (WOPI PutFile read back through WebDAV) |
| One sign-in (SSO) for portal, Files, editor | Works (alpha) | [portal-results.md](../status/portal-results.md) |
| Version history | Kept by Files; byte-identical after restore drill. Restoring a version from the web UI: **not tested** | [restore-drill-results.md](../status/restore-drill-results.md) |
| Several people editing one document at the same time | **Not tested** by the project (the engine is built for it) | [docengine-rollout-results.md](../status/docengine-rollout-results.md) "no co-editing" |
| Offline editing | No | — |
| Tenant administration of the editor | Through the ICS (deployment, upgrades) | — |

## 2. Other applications (external, not provided by Office Unbound)

Checked on 2026-11-23 against the publishers' official pages (sources in section 6). None of these is integrated with Office Unbound; they
work with Office Unbound files through the desktop sync app or a file downloaded from Files (section 3). Office Unbound does not host or
redistribute their installers.

| Application | Free | Open source | Windows | macOS | Linux | Offline | Browser editing | Status | Best for |
|---|---|---|---|---|---|---|---|---|---|
| Office Unbound Documents | Included | Yes | Browser | Browser | Browser | No | Yes | Alpha | Integrated cloud experience |
| LibreOffice | Yes | Yes (MPL-2.0) | Yes | Yes | Yes | Yes | No | Stable | Mature free desktop suite |
| ONLYOFFICE Desktop Editors | Yes | Yes (AGPL-3.0) | Yes | Yes | Yes | Yes | Requires server | Stable | Microsoft Office-style workflow |
| Collabora Office (desktop) | Depends on edition | Yes (MPL-2.0) | Yes | Yes | Yes | Yes | Requires server | Stable | Open-source office collaboration |
| MailCraft (mail, calendar, contacts) | Yes | Yes (MIT or Apache-2.0) | Yes | Yes | Yes | Yes | No (its browser build needs JMAP) | Not verified | Outlook-style desktop mail |
| ArtCraft WordCraft, GridCraft, DeckCraft | Yes | Yes (MIT or Apache-2.0) | Yes | Yes | Yes | Yes | Not verified | **Experimental** | Emerging experimental alternatives |

Limitations worth knowing:

- **LibreOffice:** Microsoft Office formatting does not always translate perfectly; some advanced Excel functions and VBA macros may not
  work; no simultaneous cloud co-editing comparable to Microsoft 365.
- **ONLYOFFICE:** three different products. *Desktop Editors* are free desktop applications (listed above). *ONLYOFFICE Docs Community
  Edition* is a self-hosted browser-editing server: it was limited to **20 simultaneous connections before version 9.4**; ONLYOFFICE's 9.4
  release (May 2026) removed that limit. *Commercial editions* of the server are paid. Office Unbound does **not** use any ONLYOFFICE server
  and will not substitute one for its own editor.
- **Collabora:** *Collabora Online* is server software; Office Unbound already runs its own build for you. The free CODE edition is not
  recommended by Collabora for production. *Collabora Office* is the separate desktop suite.
- **MailCraft:** a separate project (github.com/ZIDAN44/mailcraft), not one of ArtCraft's apps. Connect it with IMAP/SMTP and
  CalDAV/CardDAV; not tested with Office Unbound; the publisher states no maturity level.
- **ArtCraft:** in active development (alpha releases); features incomplete; file-format compatibility not evaluated by the project; not
  for business-critical documents; GridCraft does not run VBA macros. Installers existing does not mean production readiness.

Evaluated and **not listed** (2026-11-23): Apache OpenOffice (development far slower than LibreOffice, no added value for users over it);
FreeOffice and WPS Office (proprietary; free tiers carry commercial-use, advertising or account terms that the project has not verified, so
they are not recommended alongside the open-source options). They may be added in a separate "proprietary" group once their current terms
are checked from official sources.

## 3. Using a desktop application with your Office Unbound files (today)

| Way | State | Notes |
|---|---|---|
| Desktop sync app (OpenCloud Desktop, linked from *Set up devices*): open files from the synced folder in any application; changes sync back; Files keeps earlier versions | Sync engine tested headless (T07); GUI clients **not tested** by the project | Conflicts: both versions are kept (conflict copy, T07). No lock is shown to others while a desktop application has the file open |
| Download from Files, edit, upload again | Works | Manual; easy to create duplicates; versions kept when uploading over the same name |
| Mapped drive (O: drive, Finder volume) | **Planned**: [Desktop Connector](../requirements/desktop-connector.md) | — |

No Office Unbound credential is handed to a third-party application: they only see local files. Office Unbound authorisation, audit and tenant
isolation stay with the sync app and Files.

## 4. Roadmap

**Implemented**

- Built-in editor in the browser (section 1, alpha).
- *Choose how you work* section in the portal (portal 0.4.0): comparison, filters by system and type, official links, limitations.

**Planned** (roadmap [P11.8](../../ROADMAP.md))

- Mapped drives and desktop connector ([desktop-connector.md](../requirements/desktop-connector.md)).
- Tenant policies: default document editor, approved and restricted desktop applications (advisory list shown to users), desktop sync
  permission, file download restrictions, external-application access policy, security logging of desktop/sync access, DLP hooks where
  technically feasible ([ODB-A](../requirements/onedrive-and-file-sharing.md) administration rows).
- Locks visible to others while a desktop application edits a file (ODB-C15).

**Under evaluation**

- A per-user preference *Preferred office application* (built-in editor / download for desktop editing / open in an installed application).
  "Open in an installed application" needs custom URI handlers or the sync client's shell integration; not started until security and
  platform behaviour are reviewed.
- WebDAV access for desktop applications that open URLs directly (LibreOffice can): needs device-scoped credentials first (Desktop Connector).
- A proprietary-applications group (section 2).

## 5. Security notes

- External links are marked as such and open the publisher's site; Office Unbound does not proxy, host or install third-party software.
- No application is configured, installed or launched by Office Unbound.
- Desktop editing goes through the sync app, which signs in with the organisation's sign-in (SSO, MFA) and is subject to Files permissions.
  Device-specific, revocable credentials for drives are part of the Desktop Connector plan.

## 6. Sources (checked 2026-11-23)

- LibreOffice: <https://www.libreoffice.org/>, <https://www.libreoffice.org/download/>
- ONLYOFFICE Desktop Editors (AGPL-3.0, Windows/macOS/Linux): <https://www.onlyoffice.com/download-desktop>; source <https://github.com/ONLYOFFICE/DesktopEditors>
- ONLYOFFICE Docs 9.4 (connection limit removed from Community Edition): <https://www.onlyoffice.com/blog/2026/05/onlyoffice-docs-9-4>
- Collabora Office: <https://www.collaboraonline.com/collabora-office/>; CODE not for production: <https://www.collaboraonline.com/code/>
- MailCraft (MIT or Apache-2.0; IMAP/POP+SMTP, JMAP, EWS/Graph, CalDAV/CardDAV): <https://github.com/ZIDAN44/mailcraft>, <https://mailcraft.dev/> (checked 2026-11-25).
- ArtCraft apps (MIT or Apache-2.0, in development): <https://getartcraft.com/apps>. Note: `getartcraft.app` is a different site; link only `getartcraft.com`.
