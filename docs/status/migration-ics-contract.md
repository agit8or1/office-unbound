# Migration assessment: ICS integration contract (DESIGN ONLY, not wired)

Date: 2026-11-15. Status (ADR-0000): Planned. Nothing in `ics/` was changed. This describes how `migration/` would run as an ICS
typed action, following the existing patterns in `ics/README.md` (typed actions -> plan (hash-bound) -> approvals -> single-use durable job ->
hash-chained audit; AES-256-GCM vault with AAD binding; `idm.*` stack actions as the model for per-customer scoping).

## 1. Why not run it in-process in the ICS worker
The job runner has a 120 s wall-clock budget and a single worker thread (README "Runtime limits", "Not implemented yet": no separate privileged
executor). An assessment of a real tenant takes minutes to hours and holds tenant credentials. Therefore the ICS must NOT run `ou_migration`
inside the API/worker process. Contract: a **dedicated runner process** (systemd transient unit or the node-agent pattern: unprivileged user
`ou-migrate`, `NoNewPrivileges`, `ProtectSystem=strict`, empty capability set, network egress restricted to the provider endpoints
`graph.microsoft.com`, `login.microsoftonline.com`, `reports.office.com` (report download host named in the Learn pages; confirm on first run),
`*.googleapis.com`, `oauth2.googleapis.com`, and the DNS resolver). The ICS job only starts it, polls its status file, and ingests the result.
This needs the planned executor/agent work; until then the runner is started by an operator on the ICS host with the same env contract.

## 2. Typed actions (proposed catalog entries)
| action | risk | params (pydantic, `extra=forbid`) | effect |
|---|---|---|---|
| `migration.source.register` | **high** (2 approvers; customer-consent evidence field required) | `customer_id`, `provider` (`m365`\|`google`), `label`, M365: `tenant_id`, `client_id`, `client_secret` (secret); Google: `service_account_json` (secret), `admin_subject`; `consent_ref` (ticket/contract id, free text) | stores credentials in the vault; no network call at plan time |
| `migration.assessment.run` | **normal** (1 approver, never the requester; becomes **high** when `deep=true` because DWD impersonation / content-capable permissions are used) | `source_id`, `bandwidth_mbps`, `deep` (bool), `deep_max_users` (<= 500), `dns_resolvers[]` (allow-listed) | creates a job -> runner -> report artifact |
| `migration.assessment.cancel` | low | `job_id` | SIGTERM to runner; checkpoint kept |
| `migration.source.delete` | **high** | `source_id` | wipes vault ciphertext; keeps audit rows and reports |

Hash binding: `params_hash = sha256(canon(action, params, sha256(secret_enc), source binding))` exactly as for `endpoint.register`; the binding for a
source is `(provider, tenant_id|admin_subject domain, client_id|sa_email)`, so changing the tenant invalidates the stored secret (AAD
`migration-source:{id}:{binding}`).

## 3. Credential flow (secrets never in DB plaintext, argv, logs, audit, API responses, LLM prompts)
1. `migration.source.register` -> vault `encrypt(secret, "migration-source:{id}:{binding}")`; the plan row keeps only `sha256(secret_enc)`.
2. At job start the worker decrypts in memory and hands the runner credentials over an inherited pipe/memfd (preferred) or a 0600 file in a per-job
   tmpfs directory owned by `ou-migrate`, removed in a `finally` and on reaper cleanup. This matches `ou_migration.secrets` (`*_FILE` must be 0600 regular, no
   symlink) so the package needs no change; env vars are only used for non-secret ids (`OU_M365_TENANT_ID`, `OU_M365_CLIENT_ID`, `OU_GOOGLE_ADMIN_SUBJECT`).
3. Access tokens exist only in runner memory (already the case). The runner exits non-zero with a credential error message that contains no values.
4. Recommendation for production: certificate credentials (M365) / workload identity instead of client secrets; not implemented in `migration/` yet.

## 4. Job lifecycle and artifacts
- Job states reuse the ICS job table: `queued -> running -> succeeded|failed|cancelled`. Heartbeat from the runner status file (stage name, counters, `coverage`)
  every 15 s; the ICS reaper marks a job failed when the heartbeat stops (never re-runs; operator re-issues the action and `--checkpoint` resumes).
- Checkpoint directory per job: `/var/lib/office-unbound/migration/<source_id>/ckpt.json` (0600, owner `ou-migrate`). Contains metadata only (see assessment doc section 4).
- Result artifacts: `assessment.json` and `assessment.html` (0600) stored under `/var/lib/office-unbound/migration/<source_id>/<job_id>/`, plus a DB row
  `migration_reports(id, job_id, source_id, schema, sha256_json, sha256_html, risk_score, band, confidence, created_at)`. Only the hashes and the headline
  numbers go into the DB; the audit entry for job completion carries `{job_id, source_id, sha256s, score, band}` (sanitised, no identities).
- API (viewer role can list headline rows; approver/operator can download): `GET migration/sources` (no secrets, no ciphertext), `GET migration/reports`,
  `GET migration/reports/{id}/json|html`. The HTML is served with the existing strict CSP plus `Content-Disposition: attachment` (the report has no scripts and
  no external assets, so a `default-src 'none'; style-src 'unsafe-inline'` CSP renders it if inline view is desired). Download is an audited event.
- Retention: reports contain directory identities; default delete after 90 days (operator-adjustable), deletion audited.

## 5. Guard rails the ICS must enforce (in addition to the package's own)
1. Consent: `consent_ref` mandatory; shown in the plan and approvals.
2. One running assessment per source; global concurrency cap of 2 (source tenants throttle per app, and the ICS host is shared).
3. Destination guard: runner egress allow-list as in section 1; the existing "destination guard" idea (no loopback/link-local/metadata) applies to any
   user-supplied URL. The package only accepts fixed provider hosts via code, tests use loopback only with an explicit flag that the CLI does not expose.
4. TLS verification is never configurable (package has no verify-off option; optional `ca_file` only).
5. Output sanitation before anything enters the audit chain: counts/ids only (the audit canonicaliser already rejects floats/odd types).
6. No migration (write) action exists. A future `migration.cutover.*` family needs its own ADR and write-capable scoped credentials, separate from the read-only source credentials registered here.

## 6. Open questions
- Where the runner lives until the executor exists (ICS host vs a lab node; the ICS host has no tenant egress rules documented in `authorized-endpoints.md`: provider hosts must be added there by the owner before any real run).
- Scheduling re-assessments (delta of inventory before cutover) and diffing two reports.
- Whether the report should be pushed into the future "Migration Center" UI (ARCHITECTURE.md section 3.7, Planned) or stay downloadable.
