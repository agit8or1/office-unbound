# Concept alignment audit (owner brief 2026-11-26, "Comprehensive UI/UX Concept Alignment and Modernization")

Status: **audit complete, implementation in progress** (2026-11-26). This file is the shared reference for every UI change in the
programme. It is kept current: each phase updates the scores and the evidence links.

## Sources and evidence types

| Source | What it is | Evidence type |
|---|---|---|
| `docs/design/concepts/*.webp`, `*-concept-page.png` | the 13 interface concepts on https://officeunbound.com (hero tabs and `/product-concepts/*`), downloaded 2026-11-26 | **design concept**, example data, "not a screenshot" |
| `docs/screenshots/live-0.13.6/` | authenticated captures of the real deployment officeunbound8 (doctest), 2026-11-25 | **live deployment** |
| console captures 2026-11-26 (scratchpad, ICS 0.13.12 data, 0.13.13 frontend preview) | the ICS console against live data | **live data, unreleased frontend** |
| `docs/screenshots/apps-v5`, `portal-v5`, `files-v5`, `org-admin`, `console-v3`, `e2e/` | earlier rounds; several are mocked APIs or browser-injected previews (see their READMEs) | historical / fixture; **not** used as the baseline |

The concepts share one frame: a navy top bar (mark, "Office Unbound | <app>", a centred global search with a `/` shortcut, launcher,
help, notifications with a count, avatar with presence), a **64 px icon rail with labels** (Home, Mail, Calendar, Contacts, Files, Docs,
Chat, Meet, Calls; Settings at the bottom; badges on Mail and Chat), a copper primary action at the top of each app's own column, dense
lists with initials avatars, and right-hand detail panes. Admin surfaces (Org admin, MSP, ICS) keep the bar but swap the rail for their own
navigation and show an "EXAMPLE DATA" marker in the concept.

The token system already matches the concepts' palette (navy bar, copper accent, teal action, warm paper canvas, IBM Plex):
`blueprints/catalog/templates/brand/ou-brand.css`, documented in `docs/design/design-system.md`. **The gap is structure, not colour.**

## Scores

Visual score weights: layout 25, navigation 20, colour/branding 15, typography/spacing 15, components/icons 10, responsive 10, polish 5.
Functional score: what a user can really do that the concept shows; placeholders, mocks and planned features score 0.

| Interface | Concept | Current (owner of the UI) | Visual | Functional | Priority |
|---|---|---|---|---|---|
| Home / dashboard | `home.webp` | portal `home.html` (ours) | 45 | 30 | P0/P1 |
| Mail | `mail-concept-page.png` | grommunio-web (ExtJS), brand CSS + our app bar | 40 | 70 | P0 |
| Calendar | `calendar.webp` | grommunio-web | 25 | 55 | **P0** |
| Contacts | (rail item) | grommunio-web | 40 | 65 | P1 |
| Files | `files.webp` | OpenCloud web, theme + CSS | 55 | 70 | P1 |
| Documents / spreadsheets | `document.webp`, `spreadsheet.webp` | Office Unbound Docs (Collabora build ou6) | 55 | 80 | P3 |
| Chat | `chat.webp` | Element web, config only | 30 | 70 | P1 |
| Meetings | `meeting.webp` | experimental (ICS_EXPERIMENTAL=meetings), not deployed | n/a | 5 | P3 |
| Mobile | `mobile.webp` | portal phone layout; apps' own mobile modes | 50 | 50 | P1 |
| Organization admin | `org-home-concept-page.png` | portal admin area (ours) | 50 | 50 | P2 |
| MSP Control Center | `msp-console.webp` | ICS Tenants pages (ours) | 35 | 30 | P2 |
| Infrastructure (ICS) | `ics-overview.webp` | ICS console (ours) | 65 | 70 | P2 |
| Migration | `migration-assessment.webp` | **not implemented** (planned) | 0 | 0 | P2 (honest "planned" page only) |

## Per-interface differences, gaps and acceptance

### Home / dashboard (portal)
- **Differences:** top tab bar instead of the rail; an app-tile row the concept does not have; "Inbox" and "This week" cards say
  previews are "not available yet"; no next-meeting card, no agenda with a now-line, no "Needs your attention", no notifications column.
- **Functional gaps:** the portal has no read path to the user's mail and calendar. Recent files, favourites and shares are real.
- **Recommended:** the shared shell (rail + bar) in the portal; widgets fed by the user's own token: calendar via CalDAV
  (grommunio-dav), mail via IMAP/EWS-free read of flagged/unread (grommunio supports OAuth bearer through Keycloak on its DAV/EAS
  endpoints: verify), files via the OpenCloud Graph API already used. Never a service account reading every mailbox.
- **Acceptance:** greeting + date + next-meeting line from real data; agenda and attention feed show real items for a populated
  account and an honest empty state otherwise; widgets reorder/hide with per-user persistence; 0 placeholder counters.

### Mail (grommunio-web)
- **Differences:** text tabs in a top bar instead of the rail; a 40 px icon toolbar (new, address book, refresh, print, view) the concept
  replaces with a copper "New message" at the top of the folder column and inline Reply/Reply all/Forward in the reading pane; list
  rows lack initials avatars and two-line previews; folder tree icons are large.
- **Acceptance:** rail + bar identical to the portal; toolbar icons 18-20 px with tooltips; list rows with initials, sender, subject,
  preview, time, attachment/flag icons; every existing action still reachable (overflow menu). No ExtJS geometry changes through CSS
  (see the 2026-11-25 rule in `design-system.md`); structural changes through grommunio-web settings/plugins.

### Calendar (grommunio-web) — P0
- **Differences:** the week view draws **no day columns, no date headers, no all-day row** (live-0.13.6); the concept has clear
  columns, a today highlight, a now-line, an all-day row, "My calendars / Shared with me / Rooms" in the side column.
- **Acceptance:** Day, Work week, Week, Month, Agenda each show dates and columns, light and dark, with a populated test calendar;
  the root cause (theme, hidden element or upstream rendering) documented; fix through a supported hook.

### Files (OpenCloud)
- **Differences:** OpenCloud's own top bar and app switcher instead of the shell; no owner/sharing columns in the default list; the
  concept's right pane shows access and version history; status legend at the bottom.
- **Acceptance:** bar/rail visually identical (OpenCloud theme + supported web extension or the shell bar); list view default with
  Owner, Modified, Size, Sharing; search field contrast AA.

### Chat (Element)
- **Differences:** stock Element: space bar, onboarding toast, large teal cards; the concept has Teams/Channels/Direct messages in one
  column, a channel header with Posts/Files/Notes tabs, a thread pane.
- **Acceptance:** Element custom theme (colours, fonts, radii) from the tokens, branded welcome page, room list grouped through
  Element's supported settings, shell bar link back; encryption/recovery flows untouched in behaviour, copy reviewed.

### Organization admin (portal admin)
- Concept: org home with health, users, licences-free plan summary, security posture, tasks. Current: overview, users, groups, shared,
  domains, storage, branding exist (real). Gaps: security/MFA posture, audit view for the org, onboarding checklist.

### MSP Control Center (ICS Tenants)
- Concept: one table of customer organizations (users, modules, status, storage bar, migration, alerts, updates), filters, your-access
  card, maintenance, platform capacity, alerts. Current: per-tenant pages (cleaned up 2026-11-26), no portfolio table, no storage or
  user counts per tenant. **Acceptance:** a Customers table with real per-tenant numbers (users from the directory API, storage from
  OpenCloud quotas, health from checks), filters, and the same shell bar.

### Infrastructure (ICS console)
- Concept: KPI row, utilization as bars with 30-day peaks, hypervisor host table, recent incidents, capacity forecast, upcoming
  maintenance, service health grouped by function. Current (0.13.13): KPI row, line charts, health matrix, activity. Gaps: hosts table,
  capacity forecast, service health by function, environment switcher.

### Migration
- Not implemented. Acceptance for now: the console shows Migration as **Planned** (as Catalog and Changes are), linking the roadmap;
  no wizard that pretends to work.

## Cross-cutting

1. **One shell** (P0): the bar + rail as a shared component: portal (ours, server-rendered), ICS console (ours, Vue), grommunio-web and
   OpenCloud through their supported theming/extension points, Element through its custom theme and `branding` config. No iframes, no
   CSP relaxations, deep links and SSO unchanged.
2. **Calendar rendering** (P0).
3. **Demo organization** (P0): "Northstar Advisory Group" seeded through real APIs into an **isolated demo deployment**. Creating that
   deployment (VMs, DNS names) is an infrastructure change that needs the owner's go-ahead; the seeding tool is built and tested first
   against the lab.
4. **Visual regression** (P3): the existing Playwright e2e (`ics/e2e`, 491+27 tests with overflow checks at 320-2560 px) is extended
   with a manifest (app, screen, version, commit, viewport, theme, evidence type).

## Upstream modification inventory

Maintained in `docs/design/upstream-modifications.md` (created with the first upstream change of this programme). Current state: brand
stylesheets for Keycloak, OpenCloud and grommunio-web rendered by `ics/ics/deploy/brand.py`; the Office Unbound Docs build (Collabora,
`blueprints/build/oci/collabora`, `?v=` cache key); Element `config.json`. No upstream source patches.
