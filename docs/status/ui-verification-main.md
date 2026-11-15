# UI verification of main (redesigned console), 2026-11-15

Status: harness **Implemented & tested**; findings below are **open defects** unless marked fixed.
Under test: main at `2da07bb` (vue-router shell, ADR-0009 IA, new dashboard, Integrations, operator user management, monitoring hardening) merged into the harness branch. Previous baseline: `ui-verification-baseline.md` (older UI).
Run: `ics/e2e/run.sh <checkout>`; full run = read-only pass at 1440x900 / 1024x768 / 400x860 (241 passed, 147 failed; every failure is one of the findings below, mostly per-route axe results) + a mutating `flows` pass (all pass). Screenshots: `docs/screenshots/e2e/` (48 files). Raw findings: `ics/e2e/results/findings.jsonl` (`npm run summary`).

## D1-D7 from the baseline
| # | Status | Evidence now |
|---|---|---|
| D1 Users page said "API has no user list", showed no accounts | **FIXED** | Directory lists the accounts of `GET /users` (spec 03 passes); copy gone |
| D2 5 of 6 IA groups missing, no Planned labels | **FIXED, 2 items still open** | All 6 groups exist; Catalog, Changes, Updates, Access policies, Configuration carry a "Planned" label. Still absent and not labelled Planned: **Deployments > History**, **Administration > System** (see N1) |
| D3 dashboard had audit log, 7/8 cards missing | **FIXED** | No audit on Overview; the 8 ADR cards (infrastructure health, clusters, nodes, VMs, containers, deployments, pending operations, incidents) present; Pending operations / Active incidents equal the API; clusters/nodes cards show none because `/infra/*` is not merged yet |
| D4 raw `SSLError: [SSL: WRONG_VERSION_NUMBER] ... (_ssl.c:1...)` shown | **OPEN** | Still verbatim on Health checks, check detail and incident detail (all viewports) |
| D5 `scrollable-region-focusable` on table wrapper at 400px | **OPEN (moved)** | Overview no longer flagged; same defect on `.ux-scroll` of Users > Roles at 400px |
| D6 Login/Enroll: no main landmark, content outside landmarks, dead skip link | **OPEN** | `landmark-one-main`, `region`, `skip-link` on login and enroll, 3 viewports x 2 themes |
| D7 approve/reject confirmation vanishes | **OPEN** | Still absent 1.5 s after the 2nd approval and after Reject (Plans page unchanged) |

## New defects on the redesigned console
| # | Area | Defect | Severity |
|---|---|---|---|
| N1 | IA / dead link | "New deployment" is shown in the nav but opens a not-found/empty page: `hasPath('/deployments/new')` matches the `/deployments/:id` route, so the wizard-presence check is always true. Also ADR items Deployments > History and Administration > System are neither built nor labelled Planned. | high |
| N2 | Layout 1024 / 400 | **Users** and **Users > Invitations** scroll the whole page horizontally at 1024 (scrollWidth 1150 and 1134 > 1024) and at 400 (520 and 626 > 400); all other 21 routes are clean. At 1440 the Directory actions column is clipped inside its scroll box ("Change ro...", "Revoke invi...") (manual observation from the screenshot). | medium |
| N3 | A11y serious | `color-contrast` on the three "Planned" tags in the sidebar (Catalog, Changes, Updates) in the light theme, every route at 1440 and 1024. Dark theme clean. | medium |
| N4 | A11y serious | `aria-prohibited-attr`: the page-title help icon (`.help`, a span with `aria-label` and no role) on 17 pages. | medium |
| N5 | A11y serious | `link-in-text-block`: links inside sentences distinguished by colour only on Users > Roles, Users > Invitations, Inventory. | low |
| N6 | A11y serious | `target-size` of the "Back to sign in" link on Enroll (smaller than 24px). | low |
| N7 | A11y moderate | `heading-order` (an h3 after h1) on 10 pages (overview, 6 infrastructure lists, deployments, maintenance, integrations). | low |
| N8 | Pending API (not counted as defect) | Dashboard and Infrastructure call `/api/v1/infra/{clusters,nodes,storage,networks,guests}` which return 404 until the integration agent merges them; UI degrades to empty states without console errors. The harness records these as "pending API" and will fail them once the API exists but the UI disagrees. | n/a |

## Checked and clean
- **Dead controls:** none on 23 routes (non-mutating controls clicked; Details/Disable/Revoke sessions/Add endpoint open dialogs or drawers). Flows verified end to end: two-approver approval -> approved + job; Reject -> rejected; incident Acknowledge -> acked; invitation (plan or user as reported by the UI); directory Disable -> `user.disable` plan; privileged-account workflow -> high-risk plan; Audit verify, Plan preview, Add endpoint dialog.
- **No fake data:** Overview cards, health-check list and summary cards, incident, approval, job, endpoint, user and audit lists equal the API (spec 03 passes except where listed).
- **Console/CSP/network:** no console errors, CSP violations or failed requests on any route other than the pending `/infra/*` 404s.
- **Raw API errors:** only D4. Wrong enrollment token and unknown-user role change give readable messages.
- **Overflow/overlap:** none except N2. Mobile menu ("Open navigation") works.
- **Themes:** toggle persists across reload; dark theme has no contrast violations; N3 is light only.
- **Planned labels:** present on 5 inert nav items (verified by the IA spec).

## Harness changes for the new console
Seed uses `interval_seconds: 15` (new floor); routes follow the new hash router (`ics/e2e/lib/routes.ts`, 23 routes + user sub-tabs); stat-card selectors; the 08 IA spec is case-insensitive and tolerant of items landing as Planned; wizard/infra routes are probed optionally (`/setup` is skipped until merged). Scan finds controls that open dialogs (reload between clicks). Per-spec notes: when `/infra/*`, `/setup`, `/deployments/new` land, rerun `ics/e2e/run.sh <checkout>`; the nav, dashboard-card and 404 checks pick them up automatically, but new wizard flows still need their own spec (add under `specs/09-flows.spec.ts`).
