# Providers UI (Infrastructure > Providers > Proxmox), agent W

Branch `providers-ui`. Code: `ics/frontend/src/views/providers/` (routes in `routes.ts`, registered in `src/routes.ts`; nav entries "Proxmox clusters" and "Customers" in `src/nav.ts`).
Status: Implemented, typechecked, unit-tested (model.test.ts, 39 tests) and rendered against a dev-only mock. **Not exercised against a real ICS backend**: the three backend branches were read, not run.

## Screens
`/infrastructure/providers` list, `/infrastructure/providers/proxmox/connect` wizard, `/infrastructure/providers/:id` dashboard, `.../permissions`, `.../credentials`, `/administration/customers`.
Customer approval page: restyle of M's inline page as a patch, `docs/patches/customer-approval-page.patch` (apply on `vault-m`; CSP hashes are computed from the constants, so no other change).

## Backend contract relied on
Reads: `GET /endpoints[/{id}]`, `/infra/{nodes,storage,networks,guests,templates,metrics}`, `/providers/{id}/permissions`, `POST /providers/{id}/permissions/check`,
`/providers/{id|unbound}/provisioning/packages/{pkg}?format=json|zip|<file>`, `/credentials`, `/credentials/{id}`, `/credentials/access-review`, `/customers`, `/customer-approvals[/{id}]`,
`POST /customer-approvals`, `.../submit`, `.../cancel`, `POST /setup/probe` (tls stage + full), `GET /plans`, `/jobs[/{id}]`, `/incidents`, `/audit`.
Mutations (all `POST /plans`): `endpoint.register`, `provider.provision.plan_preview|apply|package`, `provider.credential.import`, `provider.permissions.reconcile`, `provider.token.rotate|revoke`,
`credential.test|rotate|replace|revoke`, `customer.create|update`.

## Gaps found (backend work needed, UI degrades honestly)
1. No read-only discovery with temporary admin credentials or for the package path: discovery comes only from `/setup/probe` with an API token. For "set it up for me" and "package" the Access step takes names typed by the operator. Suggest a `provider.provision.discover` action or `facts` in the preview result.
2. `GET /providers/{id}/permissions` returns only `preset` + `scope` of the stored policy: capabilities are inferred from `roles` keys, and custom grants, allow_* flags and role/token name prefixes are not returned, so "Change access" cannot show them as current.
3. `GET /providers/{id}/permissions` has `actual` = expected paths only; the real per-path privileges are visible only through drift (`last_drift`).
4. Package token ids are read from `package.json` (`plan.facts.tokens`, `service_user`); the customer-approval `permissions` list is built client-side from ACL steps (`path`, `privilege=role`) because `plan_provider` is still the stub.
5. Node allowlist, VMID ranges, guest types and CPU/RAM/disk caps are labelled "Enforced by Office Unbound only" / "Not enforced yet" exactly as `provider-provisioning.md` states; they are not enforced by Proxmox.
6. `POST /plans` for a customer-owned cluster may return `customer_approval_id`; the wizard only shows a notice, the operator creates the link from the package step or Customers page.
7. Metric names assumed from `provider-proxmox.md`: `cpu_pct`, `mem_used_bytes`, `mem_total_bytes`, storage `used_bytes`/`total_bytes`.

## Secrets
Token secrets, temporary admin credentials and imported token secrets live in a non-reactive `SecretBag` (model.ts), are copied into exactly one request body and wiped right after it (`wipe`, `wipeAdmin`, unmount). The wizard model, URLs, localStorage and component state never hold them; inputs are `type=password`, `autocomplete=new-password`.

## Dev mock and screenshots
`ics/frontend/src/views/providers/dev/` (mock-plugin.ts, vite.config.ts) is a Vite dev-server plugin with invented data; it is not imported by the app and `vite build` output contains none of its strings (grep of dist for demo names, fingerprint, "design-review" returned 0 files).
Run: `npx vite --config src/views/providers/dev/vite.config.ts` (127.0.0.1:8107, console at `/ui/`). Screenshots: `docs/screenshots/providers/design-review-mock_*` (light/dark, 1440x900 and 400x860). All are mock-backed.
