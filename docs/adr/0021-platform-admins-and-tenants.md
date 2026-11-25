# ADR-0021: Platform admins and tenants: one administration model in the console, with an audited "switch to tenant"

Status: **Proposed: PLANNED** (owner, 2026-11-25: "users and roles is confusing. We should have platform admins, then tenants/tenant
admins. platform admins should be able to 'switch' to a tenant admin. also need settings under tenant for domain, users, etc.").
The owner chose the switch to be **a tenant view inside the console** (no account is created in the tenant's directory). It is built
after the UI-audit release. It builds on ADR-0002 (ICS security model), ADR-0006 (deployment model), ADR-0009 (console IA),
ADR-0013 (MSP provisioning API), ADR-0017 (single-admin approval mode) and the tenancy modes (`ics/ics/tenancy_mode.py`).
Status words: ADR-0000.

## Context: what exists today (verified in code, 2026-11-25)

| Concept today | Where | What it really is |
|---|---|---|
| **Users & roles** (console, Administration) | `ics/frontend/src/views/admin/users/`, `users` table | ICS **operators**: who can sign in to the control plane. Roles are viewer, operator, approver and admin. An operator is either all-customers (`users.all_customers`) or scoped to customers (`operator_customers`, `ics/ics/tenancy/scope.py`; an out-of-scope object answers 404). |
| **Customers** (console, Administration) | `views/providers/CustomersPage.vue`, `customers` table | The **tenants**, with their provisioning mode (auto, customer approval, monitoring only) and change-approval categories. |
| Deployments | `deployments.customer_id` | A tenant's running stack (VMs, apps, domain). |
| People panel (deployment detail) | `components/PeoplePanel.vue`, typed actions `directory.account.*` | The tenant's **users**, managed by ICS operators from inside a deployment page. |
| Organization admin (deployed portal) | `portal/app/` admin area → `/api/v1/tenant/*` (`ics/ics/tenant_admin/`) | The tenant's own **tenant admins** (realm role `org-admin`). They see users, groups, apps, aliases, shared mailboxes, quotas, domains, branding and requests. Two authentications: `Ctx` (a customer bound to an identity stack, service key plus the admin's Keycloak token) and `DeploymentCtx` (a deployment the ICS created, `tdk_` key plus a token checked against the realm key the ICS generated). Changes are typed-action plans with `tenant_required` and `tenant_requests` rows. |

Why it is confusing:
- "Users" names two different populations: the control-plane operators and the tenants' people.
- A tenant's settings are spread across three places: Customers (policy), the deployment page (People, domain, apps) and the
  deployed portal (organisation admin).
- A platform admin cannot see what a tenant admin sees without signing in to the tenant's portal as one of its users.

## Decision

### 1. Two levels of administration with distinct names
- **Platform admins**: the current ICS users. The page "Users & roles" becomes **Platform admins**, with the same roles, scoping,
  invitations, privileged access and access policies. Tenants' people never appear here.
- **Tenants**: the current customers. The page "Customers" becomes **Tenants**. Each tenant has **tenant admins** (its directory accounts
  with the `org-admin` role) and **users** (its other directory accounts).
- Single-tenant installations (`system.tenancy = single`) show one tenant, the organisation. The console opens it directly ("Your
  organisation") and has no tenant list or picker.

### 2. A tenant page with the tenant's settings
`/tenants/<id>` has these sections. Each reads and writes through the code that already exists; no new data model is needed.

| Section | Backed by |
|---|---|
| Overview: deployments, apps, health, open requests | deployments, checks, `tenant_requests` |
| Domains: names, certificate, and a **DNS checker** (section 2a) | `tenant_admin` domains + `dnscheck` (extended), gateway certificate state |
| Users: list, create, disable or enable, reset, delete, groups, aliases, quotas | the `tenant_admin.service` functions behind `/api/v1/tenant/users*` |
| Tenant admins: who holds `org-admin`; grant or remove | `directory.account.*` with the org-admin group (always a HIGH-risk plan, as today) |
| Groups and shared mailboxes | `/api/v1/tenant/groups`, `/shared*` |
| Apps: which apps each user may use | tenant apps |
| Branding: display name, accent, logo | `set_branding`, `set_logo` |
| Policy: provisioning mode, approval categories, the portal binding and its key rotation | the current Customers editor, `/customers/{id}/tenant-admin*` |
| Requests: what tenant admins asked for and its state | `requests_view` |

### 2a. DNS checker (owner, 2026-11-25: "add for tenants; under their domains; dns checker. checks all dns records. autodiscover, etc")
Under each of the tenant's domains, one **Check DNS** button. It is read-only and can be run on demand by viewer and up. It checks every
record the deployment needs against what the ICS expects. The record list comes from the applied plan, never from a caller-supplied name,
as `dnscheck` does today.

| Group | Records checked | Expected value from |
|---|---|---|
| Web names | A/AAAA (or CNAME) of `app.`, `auth.`, `cloud.`, `office.`, `mail.`, `autodiscover.`, and `chat.`, `matrix.`, `mas.` when chat is deployed | `gateway.web_names(plan)` and the installation's public IP (Network & domains) |
| Incoming mail | MX on the domain → the mail host; the mail host's A record | applied plan |
| Sending | SPF (exactly one `v=spf1`, includes the mail host or `mx`), DKIM (the TXT at `<selector>._domainkey` **equals** the public key the deployment generated, not merely "a key"), DMARC present (and its policy shown) | plan, the deployment's DKIM key |
| Client setup | `autodiscover.` CNAME or A; SRV `_autodiscover._tcp`, `_imaps._tcp`, `_submission._tcp`, `_caldavs._tcp`, `_carddavs._tcp` (recommended, shown as optional) | applied plan |
| Certificates | CAA: if present, it must allow `letsencrypt.org` (otherwise issuance fails) | — |
| Reverse DNS | PTR of the public IP matches the mail host (warning only: set by the IP's provider) | installation public IP |

Each row shows its status (ok, missing, differs, optional missing, or unknown when the resolver failed), what was found, the exact record
to create (copy button), and why it matters. Results show their check time. They are kept for 24 h so the page opens without a new query.
Queries go to the ICS host's own resolver, and for the public view to the domain's authoritative servers, found from its NS records. No
third-party DNS API is used. It is a standalone, low-risk read; it ships with step 1, and the tenant's portal organisation admin gets
the same view.

The deployment page keeps deployment matters (VMs, components, checks, upgrades). Its People panel becomes a link to the tenant's
Users section.

### 3. "Switch to tenant": the console in a tenant context
- A platform admin whose scope includes the tenant picks it in the top bar (or presses "Switch to tenant" on the tenant page). The console
  then shows that tenant's sections only: the same capabilities, in the same order and with the same words as the tenant's portal
  organisation admin. A persistent banner reads "You are acting in <tenant> as a platform admin" and has an **Exit tenant** button.
- **Server side** (the security boundary; the client context is presentation only): a new `ConsoleTenantCtx` beside `Ctx` and
  `DeploymentCtx`, built from:
  - the signed-in ICS session (no tenant token);
  - the tenant id in the request path, checked with `scope.assert_customer` (404 when out of scope);
  - a minimum role: viewer to read; operator to request changes.

  It reuses the existing `tenant_admin.service` reads and `submit` path, with these differences:
  - the requesting principal is the **platform admin's own ICS user**, not the binding's service requester;
  - the plan follows **ICS approval** (approver role; single-admin mode per ADR-0017), never the tenant's `self_service_auto`.
    A platform admin cannot use the tenant's auto-approval to skip their own approval rules;
  - the `tenant_requests` row records `requester_name = platform:<username>` so tenant admins see who acted. Credential-takeover
    actions against privileged targets stay HIGH risk (review 6 H2: sign-in links of privileged targets are never shown).
- **Audit**: `tenant.switch_in` and `tenant.switch_out` events (actor, tenant, IP, time). Every request made in the context carries
  `acting_in_tenant` in its plan and audit details, so the hash-chained log answers "who did what in which tenant".
- **No impersonation of people.** The switch shows the tenant admin's view. It never signs in as a tenant user, never reads mail, files
  or chat content, and never creates accounts or tokens in the tenant's Keycloak or LDAP.
- A tenant whose provisioning mode is `customer_approval` still requires the customer's approval for the categories it lists. A tenant
  in `monitoring_only` gets a read-only switch: the change buttons are disabled with the reason given.

### 4. Navigation
- Administration contains: **Tenants**, then **Platform admins**, then Integrations, Images, Audit log, Network & domains and System.
- The top bar gains the tenant picker (multi-tenant installations only; it lists the tenants in the admin's scope).
- In tenant context, the navigation shows the tenant's sections plus a way back to platform pages.

## Consequences
- Fewer places to look: every tenant setting is on its tenant page, and "users" means only a tenant's people.
- No new trust anchor: the switch rides on the existing ICS session, scope and approval rules. The risk is a platform admin acting in a
  tenant without the tenant's knowledge. It is mitigated by the banner, the audit events and the `platform:` requester shown in the
  tenant's own Requests list.
- Routes `/users` and `/administration/customers` keep working as redirects for one release.
- Tests to add:
  - scope (an operator scoped to tenant A gets 404 for tenant B in every context route);
  - role (a viewer cannot request changes);
  - approval (a context request never auto-approves through `self_service_auto`);
  - audit (switch in and out, `acting_in_tenant` on plans);
  - `monitoring_only` read-only behaviour;
  - single-tenant mode (no picker);
  - e2e for the navigation and banner at 320–2560 px.

## Delivery
1. **Names and navigation** (low risk, usability): rename the pages; Tenants list; tenant page with Overview, Domains, Users (read),
   Policy; redirects.
   *Progress 2026-11-25 (branch `ui-redesign`, 074324c + c43ea64; not yet gated or deployed):* `GET /api/v1/tenants`, `/tenants/{id}`,
   `/tenants/{id}/dns` (`ics/ics/tenants_api.py`) and the console pages `/tenants`, `/tenants/<id>/<tab>` exist; "Users & roles" is
   "Platform admins". Executed: `ics/tests/test_tenants_api.py` 6 passed, vitest 218 passed, vue-tsc clean. The DNS checker was run read-only
   against officeunbound8's real zone. Differences from section 2a found while building it:
   - the deployments do not sign mail with DKIM yet, so the DKIM row reads "Not available" instead of comparing a key;
   - queries use the ICS host's resolver (as Network & domains does); querying the authoritative servers directly is still to do;
   - an A record to the public address is accepted in place of a CNAME;
   - `/administration/customers` stays as the policy editor (linked from the Policy tab) until step 2 moves its writes, so it is not a
     redirect yet.
2. **Tenant settings writes** through `ConsoleTenantCtx` (users, groups, aliases, shared, quotas, apps, branding), with the tests above.
3. **Switch** (top-bar picker, banner, switch audit events), plus the People panel → tenant Users link.

The 2026-11-25 public-alpha directive freezes new features that are not needed for the alpha. Step 1 is an administration usability fix,
and it is scheduled with the alpha's P2 usability work. Steps 2–3 are scheduled in the public-alpha tracker
(`docs/status/PUBLIC-ALPHA-READINESS.md`) by the owner's priority. Until a step ships with executed tests, this ADR stays PLANNED for it.
