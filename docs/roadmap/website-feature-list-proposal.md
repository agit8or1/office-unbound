# Website feature list: proposal

> **PROPOSAL — NOT DEPLOYED.** Nothing here is on officeunbound.com. It is draft copy and placement guidance for the owner to review.
> Status labels must be re-checked against [`docs/progress.json`](../progress.json) and the matrix in
> [m365-feature-parity.md](../requirements/m365-feature-parity.md) on the day of publishing.

## 1. What the site shows today (read on 2026-11-23)

Pages read: `/`, `/platform`, `/platform/files-sync`, `/platform/identity-administration`, `/platform/security-controls`,
`/product-concepts`, `/progress`, `/roadmap`, `/why/microsoft-365-alternative` (fetched with curl, read only).

- **Navigation.** Five menus: Platform, Solutions, Migration, Architecture & Security, Project. The Platform menu already lists
  six application pages (email & calendar, documents, files & sync, chat, meetings & calling, security & compliance), the four
  administration interfaces, operations pages and interface concepts. There is **no single feature list**; features are spread across
  those pages and the concepts.
- **Design language.** Navy, copper and paper palette, IBM Plex Sans with Source Serif 4, three-square mark; every concept carries the
  label "Proposed interface concept · Not released · example data"; status chips already exist as CSS classes
  (`status--concept`, `status--evaluation`, `status--planned`, `status--development`, `status--implemented`, `status--tested`,
  `status--production`) on `/why/microsoft-365-alternative`.
- **Tone.** Already honest: "In development. Nothing is production ready yet." and "not a claim to match Microsoft 365 feature for feature".
- **Out of date (re-checked 2026-11-23 after the 0.10.0 release).** The parts read from GitHub already show the new state (header
  `v0.10.0`; `/progress` "Stage: Alpha", "0.10.0 Juniper"; "22 of 24 passing" is the current acceptance count, correct). The **static copy**
  is out of date: see "Static text corrections" below.
- **M365 comparison: no overclaim (corrected 2026-11-23).** An earlier reading of this page was wrong: "shared mailboxes, delegation,
  resource booking" is in the *Microsoft 365 today* column; the *Office Unbound target* entry ("Integrated in lab") names only mailboxes,
  shared mailboxes, calendars and contacts, which matches the evidence. No change needed.

### Static text corrections (ready to apply; the website is not managed from this repository)

| Page | Current text | Replace with |
|---|---|---|
| `/` (open-source foundations) | "Office Unbound's own code is public under AGPL-3.0, as pre-alpha lab work." | "Office Unbound's own code is public under AGPL-3.0. It is an alpha: installable, not for production data." |
| `/` FAQ "Is Office Unbound available today?" | "No. The project is in Phase 1: Control server foundation and core platform proof, with pre-alpha work in its lab. The only tagged build, 0.1.0, is a lab pre-alpha, not production supported, and the screens on this site are design concepts." | "As an alpha, for evaluation. Version 0.10.0 "Juniper" installs from its release tag with the alpha install guide and deploys the full stack onto your own Proxmox VE node; it has been proven on one reference installation. It is not production supported: do not put production data in it, and read the known limitations first. Some screens on this site are still design concepts." |
| `/` (source repository paragraph) | "It holds pre-alpha lab work, not a release. Signed releases and software bills of materials are planned from the first release; neither exists yet." | "It holds the alpha releases (latest 0.10.0) and their evidence. Packages and VM images are signed by the project's release pipeline but not yet publicly downloadable; software bills of materials are planned." |
| `/` (build and release pipeline) | "No build or release has been published yet; the source repository holds pre-alpha lab work." | "Alpha releases are tagged on GitHub (latest 0.10.0); signed artifacts are not yet publicly downloadable." |
| `/` (contact, source repository) | "It is pre-alpha lab work, not a release;" | "It is an alpha, not for production data;" |
| `/progress` intro | "Pre-alpha lab work, in the open: … The only tagged build, 0.1.0, is a lab pre-alpha, not production supported, and the roadmap has no dates." | "Alpha, in the open: every status is backed by recorded evidence in the source repository. The latest release is 0.10.0 "Juniper" (alpha, not production supported); the roadmap has no dates." |
| `/progress` status note | "Pre-alpha: the only tagged build, 0.1.0, is a lab pre-alpha; nothing here is production ready." | "Alpha: installable for evaluation from the latest release; nothing here is production ready." |
| Header status line (all pages) | "Phase 1 · Core Platform Proof" | Keep (P1 is still the current phase in `progress.json`); the version beside it is already read from GitHub. |

Links to use: alpha install guide `docs/admin/alpha-install.md`, known limitations `docs/admin/known-limitations.md`, release
`https://github.com/agit8or1/office-unbound/releases/tag/v0.10.0`.

## 2. Label rules

Only four public labels. Each maps to an existing site chip so no new styling is needed.

| Public label | Use when (ADR-0000 status in `progress.json`) | Existing CSS class |
|---|---|---|
| **Planned** | `planned`, `researching`, `deferred` | `status--planned` |
| **In development** | `implementing` | `status--development` |
| **Tested in lab** | `integrated_lab`, `tested` or `alpha` **and** a linked result with passing tests | `status--tested` |
| **Available** | `beta` or `production` in a release outsiders can install | `status--production` |

Rules:
- **Nothing is labelled Available today.** The alpha runs on one reference installation and signed artifacts are not publicly downloadable.
- Where only part of a capability is tested, label the item by its weakest part and say what is tested in the sentence (e.g. "the sync
  engine is tested; the desktop apps are not yet").
- Never use "replacement", "full parity", "compatible with Outlook/Teams" or "drop-in". Use "designed to replace", "alternative for",
  "planned".
- Every item links to its evidence or to the roadmap.

## 3. Proposed feature list copy

Intro line (above the list):

> **What Office Unbound is being built to do.** Each feature shows its status today. Office Unbound is in alpha: it runs on one reference
> installation and is not ready for production data. It is not yet a complete Microsoft 365 replacement, and some Microsoft features
> will never be reproduced; the [comparison](https://officeunbound.com/why/microsoft-365-alternative) says which.

### Files and storage

| Feature | Copy | Label |
|---|---|---|
| Personal cloud storage | Each person gets their own file space with version history, on storage you choose. | **Tested in lab** |
| Desktop sync | Files sync to the computer and keep working offline, with conflicts kept rather than overwritten. The sync engine is tested; packaged desktop apps for Windows and macOS are not yet. | **Tested in lab** (engine) |
| Shared files and folders | Share a file or folder with people or groups, or by link with an expiry date, and see who has access. | **Planned** |
| Team libraries | A library per team or department, with members managed by group. | **Planned** |
| Documents in the browser | Edit documents, spreadsheets and presentations in the browser, on our own unlimited build of Collabora Online. | **Tested in lab** |

### Mail, calendars and contacts

| Feature | Copy | Label |
|---|---|---|
| Business email | Exchange-compatible mail with webmail and standard desktop protocols. Internet delivery and real Outlook clients are still being tested. | **Tested in lab** |
| Shared mailboxes | Mailboxes such as accounts@ that a team reads and sends from, granted by the administrator. | **Tested in lab** |
| Shared calendars | Team and room calendars that colleagues can see and book. | **Planned** |
| Calendar delegation | Let an assistant manage your calendar and reply to invitations on your behalf. | **Planned** |
| Shared contacts | Contact lists shared across a team, next to the organisation directory. | **Planned** |

### Groups, identity and sign-in

| Feature | Copy | Label |
|---|---|---|
| Single sign-on and MFA | One account and one sign-in for every application, with multi-factor authentication. | **Tested in lab** |
| Unified groups and permissions | One group gives its members the mailbox, calendar, files and chat they need, and removing someone removes all of it. | **Planned** |
| Identity directory (Entra-like) | One organisation directory with roles, policies and fast access removal. Advanced policies (conditional access, privileged access) are planned. | **Tested in lab** (directory, SSO, removal) · **Planned** (advanced) |
| Windows, macOS and Linux sign-in | Sign in to the computer with the organisation account. | **Planned** |

### Devices and security

| Feature | Copy | Label |
|---|---|---|
| Device enrollment | Enrol company computers and phones to see inventory and apply policies. | **Planned** |
| Mobile account protection | Protect company data on phones: require a PIN, block risky devices, sign out remotely. | **Planned** |
| Selective wipe | Remove company mail, files and accounts from a lost or personal phone without touching personal data. | **Planned** |
| Full wipe for managed devices | Erase a company-owned, enrolled device that is lost or stolen. Only for devices enrolled under management. | **Planned** |
| Conditional access | Allow sign-in only from compliant devices and trusted conditions. | **Planned** |

### Administration

| Feature | Copy | Label |
|---|---|---|
| Tenant administration | An organisation admin area for users, groups, domains, shared mailboxes and quotas, separate from the servers underneath. | **Tested in lab** |
| MSP delegated management | Manage many customer organisations with scoped technician access. A versioned provisioning API is tested; the MSP console is not built yet. | **Tested in lab** (API) · **Planned** (console) |

### Migration

| Feature | Copy | Label |
|---|---|---|
| Migration assessment | A read-only report of what a Microsoft 365 or Google Workspace tenant contains and what will not move. | **In development** |
| Mail migration | Copy mailboxes incrementally from Microsoft 365, Google Workspace or any IMAP server, without changing the source. Tested in the lab for one mailbox, not yet against a real tenant. | **Tested in lab** |
| Calendars, contacts, files and permissions | Move calendars, contacts, OneDrive and SharePoint files and their sharing. Microsoft sharing links, Teams objects and device join state do not carry over. | **Planned** |

Evidence links for each "Tested in lab" item (to use as the item's "Evidence" link, pointing at the GitHub copy of the file):
personal storage, sync, documents: [identity-files-lab-results.md](../status/identity-files-lab-results.md);
mail: [groupware-deploy-results.md](../status/groupware-deploy-results.md); shared mailboxes:
[mailbox-admin-results.md](../status/mailbox-admin-results.md); SSO and removal:
[user-lifecycle-results.md](../status/user-lifecycle-results.md); tenant admin: [org-admin-results.md](../status/org-admin-results.md);
MSP API: [msp-api-results.md](../status/msp-api-results.md); mail migration:
[migration-engine-results.md](../status/migration-engine-results.md).

## 4. Placement (keeps the design language, no new menu)

1. **One new page, `/platform/features`,** titled "Features and status". It reuses the `/platform` page frame and the status chips from
   `/why/microsoft-365-alternative`; the six category headings above become section headings with a small icon from the existing
   `ux-icons.svg` sprite (folder, mail, users, shield, settings, refresh). No new colours, fonts or components.
2. **No new top-level menu item.** Add one entry at the top of the existing Platform menu, under the "Applications" group heading:
   "All features and their status". Do not add the feature names themselves to the menu.
3. **Cross-links instead of nav entries:** a "See every feature and its status" link at the end of `/platform`, `/roadmap` and
   `/why/microsoft-365-alternative`; each application page (`/platform/files-sync`, `/platform/email-calendar`,
   `/platform/identity-administration`, `/platform/security-controls`) links to its own section anchor.
4. **Home page:** no list; one sentence near "Explore Office Unbound" linking to the page. The home page should stay concept-led.
5. **Filter, optional:** a single chip row (All · Planned · In development · Tested in lab · Available) using the same chip classes; works
   without JavaScript as plain anchors if the site avoids scripts.
6. **Generated, not hand-edited, if possible:** the site already reads the roadmap from GitHub for `/progress`. The feature list should
   read labels from the same source (a small `features` list keyed to matrix IDs) so labels cannot drift from evidence.

## 5. Owner decisions

1. Approve the four public labels and the mapping (in particular: `integrated_lab` shown as "Tested in lab" only with a linked passing test).
2. Approve the new page `/platform/features` and the single Platform-menu entry.
3. Apply the static text corrections above (pre-alpha / "only tagged build, 0.1.0").
4. (Withdrawn 2026-11-23: the M365 comparison does not claim delegation or resource booking for Office Unbound.)
