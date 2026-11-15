# UI verification baseline (current main UI)

Status: **Implemented & tested (harness)**; the UI findings below are **open defects** (nothing here is fixed by the harness agent).
Date: 2026-11-15. UI under test: `ics/frontend` at commit `1a0a702` (Vue 3 console, 10 routes, no ADR-0009 IA yet).
Harness: `ics/e2e/run.sh <checkout_dir>` (Playwright 1.65.1 + @axe-core/playwright 4.14.0, Chromium headless, real ICS backend on 127.0.0.1:8108, DB `ics_test_h`).
Owner requirement (ADR-0009 section 6/8): all displayed data real, all advertised actions work, responsive layouts and both themes verified.

## What the harness does (all executed)
- Starts the backend from a **copy** of the given checkout (the checkout is never written), builds the frontend there, resets+migrates `ics_test_h` with alembic, seeds **only through the HTTP API and `ics.cli`**: admin/2 approvers via CLI `create-admin`+enrollment, operator/viewer/invitee via API invite + CLI `issue-enrollment` + real TOTP enrollment, two checks (`tcp_tls` against a local TLS listener = ok, against a local plain TCP listener = critical) created through `check.create` plans, an incident opened by the real monitor, 4 pending high-risk plans and 1 rejected plan.
- Specs (3 viewports 1440x900 / 1024x768 / 400x860 where viewport matters): login + TOTP enrollment through the UI (`01`), clean render of every route and detail route: no console errors, CSP violations, failed/4xx requests, internal-gap copy, raw errors (`02`), every number/list compared with the API response (`03`), dead-control scan + real flows ending in server state (`04`, `09`), axe in light and dark (`05`), horizontal overflow / overlap / clipped text by bounding box (`06`), theme toggle + screenshots (`07`, 30 PNGs in `docs/screenshots/e2e/<viewport>-<theme>-<page>.png`), ADR-0009 IA (`08`).
- Result of the final full run: read-only pass 187 passed / 13 failed / 42 skipped (skips = desktop-only specs at other viewports); flows pass 12 passed. Failures are the defects below (each is also written to `ics/e2e/results/findings.jsonl`; `npm run summary`).

## Defects found today
| # | Area | Defect | Evidence (spec) | Severity |
|---|---|---|---|---|
| D1 | Fake/missing data + internal-gap copy | **Users page** says "The API has no user list yet, so existing accounts cannot be shown here." `GET /api/v1/users` exists and returns the 6 seeded accounts; none is displayed. The sentence is internal-gap copy and false. | `03` users list = API, `02` route users (all 3 viewports) | high |
| D2 | IA | 5 of 6 ADR-0009 section 6 groups absent from navigation (Infrastructure, Deployments, Operations, Monitoring, Administration); flat 10-item list; no setup wizard, no "Planned" labels anywhere. | `08` | high (known; IA work not merged) |
| D3 | IA / dashboard | Dashboard shows "Latest audit entries" (ADR: audit never on the dashboard); 7 of 8 required status cards missing (infra health, clusters, nodes, VMs, containers, deployments, incidents); only endpoints, plans pending, jobs running, jobs failed, readiness exist. No utilization charts, health matrix, actionable incidents. | `08` dashboard | high |
| D4 | Raw error/exception text shown | Monitor failure text is rendered verbatim: `SSLError: [SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:1...)` on Checks list, check detail and incident detail (all viewports). Needs a human message plus optional "technical detail". | `02` route checks, detail routes | medium |
| D5 | Accessibility, serious | `scrollable-region-focusable` (axe serious) on the `.scroll` table wrapper of Overview at 400px, light and dark: keyboard users cannot scroll the audit table (no `tabindex`/focusable content). The same wrapper exists on every table page; it triggers whenever the table overflows. | `05` mobile overview light/dark | medium |
| D6 | Accessibility, moderate | Login and Enroll pages (all viewports/themes): no `main` landmark (`landmark-one-main`), content outside landmarks (`region`), skip link target `#main` does not exist there (`skip-link`). 12 axe findings (3 rules x 2 pages x 2 themes). | `05` unauthenticated | low |
| D7 | Feedback | After the second approval or a Reject on the Plans detail panel, the success message ("Approved; job queued." / "Plan rejected.") is rendered inside the `pending_approval`-only block, so it disappears as soon as the list reloads (visible for under ~1.5 s). The operator gets no lasting confirmation. | `09` approval flow, reject flow | low |

## Checked and clean today (no defect found)
- **Dead buttons:** none. The scan clicked every non-mutating control on all 10 routes and found no control without effect; the mutating controls were exercised end to end: two-approver approval ends `approved` with 2 approvals and a job in `/jobs`; reject ends `rejected`; incident Acknowledge ends `acked`; Users invite and privileged-account plan create the account/plan; Audit "Verify chain" and Plan preview issue real requests; Register endpoint opens its form. No disabled-without-reason controls.
- **Numbers vs API:** Overview cards (endpoints, plans pending, jobs running/queued, jobs failed), readiness rows, recent-audit row count, Checks/Incidents/Plans/Jobs/Endpoints row counts and the Checks state summary all equal the API.
- **Console/CSP/network:** no console errors, no CSP violations, no failed or 4xx/5xx requests on any route (intentional 401/429 on wrong login excluded).
- **Responsive 1440/1024/400:** no horizontal page scroll, no overlapping controls, no out-of-viewport controls on any route, detail panel or login; navigation reachable through the Menu button at 400. (Manual observation, not caught by the checker: the Checks "Last result" column is clipped inside its scroll panel at 1440, e.g. `wrong versio`; see `docs/screenshots/e2e/desktop-light-checks.png`.)
- **Themes:** light and dark render, toggle cycles auto/light/dark and persists; axe contrast (`color-contrast`) reports nothing in either theme on all routes.
- **Raw API errors:** a role change for an unknown user and a wrong enrollment token produce readable text, not raw JSON/status lines.

## Counts
Distinct findings recorded by the harness: 32 (IA 13 incl. dashboard, axe moderate 12, axe serious 2, data missing 6 as one root cause, copy 5 for 2 root causes, feedback lost 2) = **7 root-cause defects** (D1-D7); dead buttons 0; layout/overflow 0; CSP/console 0.

## Re-run
```
ics/e2e/run.sh <checkout_dir>                      # full run (about 5 minutes on a loaded host)
ics/e2e/run.sh <checkout_dir> --project=setup --project=desktop specs/03   # custom selection
```
Requires: env file `/etc/office-unbound/ics-test-h.env` (or `E2E_ENV_FILE`), a Python with the ICS requirements (`<checkout>/ics/.venv` or the main checkout venv, override `E2E_PY`), Node 22. Browsers, npm cache, shared-library shims and work files live under `E2E_ROOT` (default: the session scratchpad `ui-h/`); nothing is installed system-wide. Uses only port 8108 and DB `ics_test_h`; never touches the `ics` service or `deploy/install.sh`.
Limits: the backend seed has no Proxmox endpoint, so Inventory and Endpoints are verified only in their empty states; the harness cannot see data that needs a real Proxmox, node agent or identity stack.
