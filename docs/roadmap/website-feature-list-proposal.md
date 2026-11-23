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
- **Out of date.** The header status line reads "Phase 1 · Core Platform Proof · v0.9.4" and `/progress` says "Pre-alpha (lab)",
  "0.9.4 Ironwood" and "22 of 24 passing", while the repository is at **0.10.0 "Juniper", alpha**. If the page reads from GitHub
  `main`, it updates when the release lands there; otherwise this needs a site change (owner check).
- **Wording to revisit.** The M365 comparison says shared mailboxes, delegation and resource booking for Office Unbound as one
  "Integrated in lab" entry; delegation and resource booking are not tested ([matrix](../requirements/m365-feature-parity.md), EXO rows).

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
3. Fix the out-of-date status line (0.9.4 / pre-alpha) if it is not generated from `main`.
4. Split the "shared mailboxes, delegation, resource booking" entry on the M365 comparison page so untested parts read "Planned".
