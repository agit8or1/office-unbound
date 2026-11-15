# Organization Admin (roadmap P4.2, Organization Admin slice): results

Date: 2026-11-15. Lab only. Status words follow ADR-0000: the Organization Admin slice is **Integrated in lab** (LDAP + Keycloak real, OpenCloud verified through the user's token; Gromox/OpenCloud agent steps NOT run, see section 7). The MSP Control Center half of P4.2 is not started.
Code: `ics/ics/tenant_admin/{service,api,jwtv,dnscheck}.py`, `ics/migrations/versions/0009a_tenant_admin.py`, `idm.user.reset_credentials` in `ics/ics/identity.py`, `portal/app/{admin,icsclient}.py` + `portal/app/templates/admin/`, harness `ics/scripts/lab_org_admin.py`, e2e `portal/e2e/org-admin-e2e.js`, Keycloak helper `portal/deploy/kc-org-admin-role.py`. Screenshots: `docs/screenshots/org-admin/` (15 pages, light/dark, desktop 1280 and mobile 390).

## 1. Design (and why)
**Separation (ADR-0002).** The customer's administrator never gets an ICS account or any infrastructure privilege. The portal's Admin area (visible only with the Keycloak realm role `org-admin`) talks to a *new* endpoint family `/api/v1/tenant/*` that is not the operator API: it can only list/ask for identity changes in the one identity stack that belongs to the caller's customer, read/write that customer's branding and app switches, and run a read-only DNS check. It has no route to nodes, endpoints, credentials, plans of other customers or the audit log.

**Two proofs per request.**
1. `X-OU-Tenant-Key: tsk_<key_id>.<secret>`: per-customer service credential held by that customer's portal (file, `PORTAL_ICS_KEY_FILE`). The ICS stores only `sha256(secret)`; it is issued once by an ICS admin with the all-customers scope (`POST /api/v1/customers/{id}/tenant-admin`), can be rotated, and binds the request to exactly one customer and one identity stack.
2. `X-OU-User-Token`: the signed-in administrator's own Keycloak access token. The ICS verifies RS256/ES256 against the JWKS of **that customer's realm** (fetched over TLS pinned to the stack's CA), takes issuer and client (`azp`) from its own database, requires the realm role `org-admin`, caps token lifetime at 15 min, and for every state-changing call re-checks live in Keycloak that the user still exists, is enabled and still holds the role.
**Why not token exchange:** an exchange needs per-customer Keycloak permission configuration and yields a token for another audience that the ICS would still have to validate. Validating the portal client's token directly needs no new Keycloak setup, keeps one realm-signed proof, and lets the ICS bind issuer + client + role to the customer it already knows from the service credential. A signed assertion minted by the portal would be weaker (the portal would vouch for itself). Cost: the portal must forward the access token (it already holds it server side, never in the browser).

**Execution = the existing machinery.** Mutations are normal `idm.*` plans (closed catalog, plan-hash-bound approvals, single-use jobs, hash-chained audit) requested by a per-customer *principal* (an ICS `users` row that is never enrolled, so it can never log in, scoped to exactly that customer). Idm stacks gained `customer_id` (migration 0009a), so scoping and policy evaluation now work for identity plans. The audit chain records `tenant.request / tenant.auto_approved / tenant.approved / tenant.enrollment_link_shown ...` with the end user's `sub`, name, realm and IP.

**Approval policy (per customer, `tenant_admin_bindings.policy`).** Defaults: everyday changes (create, enable/disable, app access, reset password/2-step) are auto-approved for the customer's own admins (`self_service_auto`); a high-risk action (delete user) needs a **second org-admin** (`destructive_approval = second_admin`; the requester's own approval is refused and audited) or, if configured, **one MSP approver** in the ICS console (`msp`). `self_service_auto=false` makes every change need a second org-admin. The plan tier approval is supplied by the customer's authority (`plans.tenant_required`); the customer's `extra_approvals` still add distinct ICS approvers. Privileged groups (e.g. OpenCloud admin) are never assignable by a tenant admin; only groups mapped to an app (`mail`, `files`) by the MSP are.

**No passwords, no invite e-mails.** Creating a person (or re-enabling, or "forgot password") produces the one-time enrollment token the ICS already had; an org-admin can reveal it once (`POST .../enrollment`) and the portal turns it into a link `/welcome?s=..&u=..&t=..` that the admin delivers. The *new person* sets their own password on that page; the portal relays it to `/api/v1/identity/enroll` and does not store or log it. 2-step reset removes the user's OTP credentials and sets the Keycloak required action `CONFIGURE_TOTP` (new action `idm.user.reset_credentials`, normal risk). The ICS never sends mail.

## 2. What the Admin area offers
| Item | State |
|---|---|
| Users directory, user detail (apps, status, history), invite flow (3 steps, progress page, one-time link), disable / enable / delete (confirmation pages), reset password / 2-step | **Integrated in lab** (e2e below) |
| Groups and apps: per-user app toggles = group membership (mapped groups only), org-wide app switches (hide an app from every home page) | Integrated in lab (toggle per user via plan: unit-tested + UI; org switch verified in e2e home page rendering and tests) |
| Domains: list (the stack's mail domain), live DNS check for MX, SPF, DKIM, DMARC, autodiscover with plain guidance | Integrated in lab (live check ran; lab zone has no public records so all five reported "Missing", which is the correct answer for the lab) |
| Branding: name, accent colour (contrast-checked, white text >= 4.5:1), logo PNG/JPEG/plain SVG, applied to header, buttons (CSS variables via same-origin `/branding.css`, strict CSP kept), home tiles | Integrated in lab |
| Activity (who asked, who confirmed, state), second-admin approvals | Integrated in lab |
| Mailbox aliases, shared-mailbox delegation | **Planned**: the Gromox runbooks (`sync_user`, `kick_user`, `user_state`) have no alias or delegation verb; labelled "Planned" in the UI |
| Per-user storage quota (OpenCloud) | **Planned**: needs an OpenCloud admin identity for the ICS that does not exist; labelled "Planned" (no invented numbers) |
| Creating/renaming groups, adding domains | Planned (domains are added by the MSP; the LDAP ICS identity may not create groups by design) |

## 3. Tests executed
* `ics/tests/test_tenant_admin.py`: **15 tests, all PASS**. Authz: missing/bad service key, no user token, other realm's valid token with this customer's key (both directions), forged payload (signature mismatch), attacker-signed token, `alg=none`, HS256 confusion, wrong `azp`/issuer, expired, absurd lifetime, missing role (403, audited), disabled admin blocked on writes, operator session cookie is not a tenant credential, principals cannot log in. Cross-customer: other customer's requests/users/approve/enrollment all 404, key shown only as hash. Policy: auto-approved create executes through the real worker and audit carries `tenant_user`/`sub` (and no token/key), delete needs a second admin (requester refused, other customer refused, decided once), `msp` mode needs one ICS approver, `self_service_auto=false`, privileged groups refused, self-disable/delete refused, reset password/2-step, branding validation (contrast, hostile SVG, wrong type), per-customer isolation of branding and apps, DNS statuses (ok/differs/unknown), JWT and DNS wire parsing.
* `portal/tests` (venv with fastapi 0.101.0 / starlette 0.27 / PyJWT 2.7 like the machine): **26 PASS** (16 existing + 10 in `test_admin.py`): role gating (no `/admin` for non-admins or without ICS config; nothing about people is requested for them), both proofs forwarded, CSRF on every state change, plain-language error mapping (ICS 403/502/409), progress + one-time-link handling, welcome flow (password relayed once, never echoed, used link refused), branding injection safe (non-hex accent dropped, names escaped, logo served with sandbox CSP), apps filter on home, pages have no script/inline style/handlers.
* Full ICS suite: **543 tests: 542 passed, 1 failed** on the first full run (`test_migration_chain::test_single_linear_chain`, which pins the migration head; updated for `0009a`), then that file plus `test_tenant_admin.py` re-run: 18 passed. The whole suite was not re-run after that one-line expectation change.
* **Real lab e2e, `portal/e2e/org-admin-e2e.js`: 48 PASS / 0 FAIL** (Playwright headless Chromium; throwaway Keycloak client `ou-portal-ax`; dev ICS on 127.0.0.1:8124 with DB `ics_test_axe` and the real lab LDAP + Keycloak; passwords read at run time, never printed). Highlights, all executed:
  * ordinary user `bob`: no Admin entry, `/admin` and `/admin/users` answer 404;
  * org-admin `axadmin1`: invite flow end to end: request ran against **real LDAP + Keycloak**, one-time link shown once (not shown again), the new person set their own password through `/welcome`, the same link is refused the second time;
  * **LDAP**: entry exists, not locked, member of `mail-users` and `opencloudUser`; **Keycloak**: the new person signs in with their own password; **OpenCloud**: Graph `/me` with that token = HTTP 200 (user resolved through LDAP);
  * **disable** through the portal: Keycloak refuses the user's password (400), OpenCloud refuses the token issued before (401, polled; the job's own VERIFY step reported `PASS` in `canary_probe` mode, 9-12 s total), LDAP `pwdAccountLockedTime` set; this is the existing lifecycle verify (user-lifecycle-results.md section 3) reused, not re-measured per path;
  * **delete** needs a second administrator: waits, requester has no approve button, nothing changed in LDAP; `axadmin2` signs in, sees "Waiting for you", confirms, job runs, LDAP entry gone, activity shows `axadmin2`;
  * domains: live DNS check ran (5 records); branding: name, logo, accent (`--accent: #1a5fb4`) applied, a too-light colour refused in plain language; no CSP violation on any page; no horizontal scroll at 390 px on user page and domains;
  * **axe-core 4.10.2 on 11 pages: 0 serious/critical violations** (and 0 minor/moderate).
  The run was repeated three times while fixing two real bugs the e2e found (see section 6).

## 4. Security notes
* Tenant API credentials: service key sha256 only, constant-time compare, failures audited (`tenant.auth_failed`, no key material). Rotation invalidates the old key at once. A disabled customer or binding refuses every call.
* A valid token for realm A is useless with customer B's key, because issuer and JWKS come from B's binding, not from the token (tested both directions). Cross-customer ids answer 404.
* Role claim forgery requires a forged signature; the flat `roles` claim is honoured only from a verified token. Disabled or de-roled admins keep read access only until the token (<= 5 min in the lab) expires; every change is re-checked live.
* The portal sees the new person's password in transit on `/welcome` (it relays it to the ICS and keeps nothing). This is the one place a password touches the portal; the alternative (a direct ICS page) would need an ICS-hosted UI for end users. The admin never sees it.
* The link token is in the URL query (needed for a clickable link). Mitigations: `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, no third-party resources, single use, expiry, and it is shown once. It may still land in browser history or proxy logs on the user's side.
* Logo uploads: size cap, magic-byte sniffing, SVG scanned for script/handlers/links, served with `nosniff` and `Content-Security-Policy: sandbox` and only used through `<img>`.

## 5. Operating it
1. ICS admin: `POST /api/v1/customers/{id}/tenant-admin {"stack": "...", "portal_client_id": "ou-portal", "app_groups": {"mail": "mail-users", "files": "opencloudUser"}}` returns the service key once.
2. Portal env: `PORTAL_ICS_URL`, `PORTAL_ICS_KEY_FILE` (and `PORTAL_ICS_CA_BUNDLE`); without `PORTAL_ICS_URL` the Admin area does not exist.
3. Keycloak: `portal/deploy/kc-org-admin-role.py` (inside the identity machine) creates the role `org-admin` and grants/revokes it by user name. The portal client must emit realm roles in the access token (the existing `roles-flat` mapper does).
Lab harness: `ics/scripts/lab_org_admin.py {ics-up,seed,portal-up,cleanup,down}`; e2e: `portal/e2e/org-admin-e2e.js` (needs `playwright-core`, optional `axe-core`).

## 6. Bugs found by the real run (fixed)
* `Referrer-Policy: no-referrer` makes browsers send `Origin: null`; the welcome POST was refused. Now `null` is accepted there (the one-time token is the CSRF secret) and `Sec-Fetch-Site: cross-site` is refused.
* The portal's security-header middleware overwrote a route's tighter CSP/Referrer-Policy; it now only sets defaults (a route may tighten, never loosen).
* Also tightened before the run: a Pydantic validation error from a plan (e.g. a too-short reason) is now a plain 422, not a 500.

## 7. Not done / honest limits
* **Gromox and OpenCloud *agent* steps were not exercised.** The dev ICS has no node enrolled: enrolling `ou-files1`/`ou-gw1` into a second ICS would reset the production ICS's agent trust (`arm-enroll` rewrites `trust.json`). So "appears in Gromox" is **not verified here**; OpenCloud visibility is verified through the user's own token (HTTP 200), not through the `opencloud.check_user` runbook. Mailbox creation/suspension for tenant-created users therefore remains covered only by the earlier lifecycle run (user-lifecycle-results.md) and the in-memory-fake tests.
* No real e-mail/DNS zone for the lab domain: the DNS check reported "Missing" everywhere (correct, but no "ok" case was seen live; "ok/differs" are unit-tested with a fake resolver). DKIM expects an operator-published key; the ICS does not generate DKIM keys yet.
* Two-step reset was unit-tested against the Keycloak fake and the role mapping logic, **not run against a real Keycloak user with TOTP**. Password reset reuses the enrollment path (the old password stays valid until the new one is saved).
* Quota display, aliases, shared-mailbox delegation, group creation: Planned (see section 2).
* The MSP approving a destructive request is done in the existing ICS console (plan approve); there is no MSP-facing view of tenant requests yet (MSP Control Center).
* Branding is cached 60 s in the portal; the org app switch hides tiles only (access is controlled by groups).
* Only users created through the ICS are listed (users created out of band in LDAP are not in `idm_users`; the reconcile loop reports them to the MSP, the tenant sees nothing).
* Browser matrix: Chromium only; no screen-reader run (axe only).

## 8. Test status line
`cd ics && pytest -q` (own DB `ics_test_ax`, 733 s): 542 passed + 1 failed (migration head pin, fixed, re-run green). Portal: 26 passed. e2e: 48 PASS.
