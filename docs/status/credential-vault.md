# Credential vault, MSP customers/policies, customer approval (agent M)

Status values per ADR-0000. "tested" means executed in `ics/tests/test_vault_m.py` against the test database and mock Proxmox; nothing here has touched a real provider.

## Separation of identities
ICS has its own operator accounts (argon2id + TOTP), vault, credentials, plans, jobs, audit and approvals. Nothing reads Keycloak/OIDC, tenant admins or
employee accounts. Customers have no ICS account: the only thing a customer holds is a single-use approval link. A tenant login can never become an
infrastructure credential because credentials are created only by typed actions executed by ICS operators.

## Credential subsystem (`ics/ics/credentials/`)
Table `credentials`: provider, customer, datacenter/cluster/host, credential_type (api_token|password|ssh_key|client_cert), purpose
(inventory|provision|temporary_provisioning), identity (non-secret), status (active|expiring|expired|revoked|invalid, plus `retired` for rotated-out records),
created_at/last_validated_at/last_used_at/expires_at, rotation links; `credential_events` = who/when/why history.
- Envelope encryption (`envelope.py`): random 256-bit data key per credential encrypts the secret (AES-256-GCM); the data key is wrapped by the master key
  (the existing vault key file, root:ics 0640). AAD of both layers = `credential:<id>:<provider>:<customer>`; moving/editing any of them fails (tested).
- Typed actions: `credential.create|replace|rotate|revoke|test`. create/replace/revoke high (2 approvers), rotate normal, test low.
  replace/rotate authenticate the new secret against the provider BEFORE persisting (endpoint-attached credentials). The old record is retired (kept, unusable)
  for 7 days, then its ciphertext is purged; history is kept forever. Revocation destroys the ciphertext immediately and is never undone by ICS.
- Read API (metadata only): `GET /credentials`, `GET /credentials/{id}` (+history), `GET /credentials/access-review` (approver; derived from the audit chain:
  `credential.use` rows carry who/what/purpose; inventory use is audited at most every 5 min per credential).
- Only `service.get_secret` returns plaintext; it refuses revoked/expired/invalid/retired credentials (tested: revocation stops use).
- Expiry (`expiry.py`, worker, every 60 s): `expiring` (14 days) and `expired` transitions, one alert per (credential, kind) written to the existing
  `notifications` outbox for every enabled alert channel (`credential.expiring|expired`, no secret in text). Tested.
- Endpoints now reference credentials (`endpoints.inventory_credential_id/provision_credential_id`); `endpoint.register/update/remove` create, supersede and
  revoke them. Legacy `token_secret_enc` / `provision_secret_enc` are NULL / empty after migration.
- Data migration: `service.adopt_all` (run at app start and by `python -m ics.cli migrate-credentials`; idempotent) decrypts the legacy blobs with their legacy AAD and
  re-seals them as credentials; `endpoint.update` also adopts first. Tested incl. inventory refresh through the migrated reference.
- Providers beyond proxmox register a connection test in `service.TESTERS[provider]`; ssh etc. need explicit authorisation first (not implemented).

## Master key rotation
`python -m ics.cli rewrap-master --new-key-file NEW` (one DB transaction, all-or-nothing): credentials re-wrap only their data keys; every other vault consumer
(TOTP seeds, check/alert-channel/IdM secrets, pending plan secrets, any un-migrated endpoint blobs) is re-encrypted with its original AAD. Procedure:
1. `umask 077; head -c 32 /dev/urandom > NEW; chown root:ics NEW; chmod 0640 NEW`
2. Stop jobs if possible; run the command as the ics user (it needs the CURRENT key from settings plus NEW). 3. Replace the key file referenced by
`ICS_VAULT_KEY_FILE` with NEW (keep the old file offline until verified), restart `ics`. 4. `GET /credentials` and one `credential.test`.
The audit event `vault.master_key_rewrapped` records old/new key ids (not keys). Tested (CLI + failure leaves data unchanged). Any new vault consumer must be added
to `rewrap._targets`.

## MSP customers and policies (`ics/ics/tenancy/`)
`customers` (msp_owned flag, provisioning_mode auto|customer_approval|monitoring_only, extra_approvals per category delete_guest|remove_storage|
network_change|expand_permissions|revoke_credential). Default customer "MSP (internal)" owns pre-existing endpoints. Every endpoint and credential has exactly one customer.
- Policy is evaluated at plan creation (`policy.evaluate`) and stored on the plan: monitoring-only refuses mutating actions (403), customer-owned infra gets a required
  customer approval, extra approvals add distinct ICS approvers (tested). Categories map action names (including L's future `deployment.*`, `guest.*`, `storage.*`,
  `network.*`) in `policy.CATEGORY_OF`/`MUTATING_PREFIXES`; update that table when L adds actions.
- Scoping: `users.all_customers` (default true = MSP all-customers scope) or rows in `operator_customers` (set with admin typed action `operator.set_scope`,
  customer actions `customer.create/update` need an all-customers admin). Enforced server-side in: endpoint list/get/inventory, `/infra/*`, health summary, setup state,
  metrics, credentials, customers, approvals, plans/jobs lists and `create_plan` (out-of-scope = 404; scoped operators cannot create plans without a customer binding; audit log
  needs the all-customers scope). Tested. Known gap: other global tables (checks, nodes, alert channels, IdM) are not customer-bound; scoped operators cannot create those plans.

## Customer approval workflow
Plan creation for a customer-owned customer creates a `draft` approval (`customer_approval_id`); the ICS approvals are recorded but the job is only released once the customer approved
(also re-verified before execution). Operator: `POST /customer-approvals` (stand-alone) or via plan, `POST .../submit` returns `/approve#t=<token>` ONCE
(fragment, so it never reaches server/proxy logs), `POST .../cancel`. Customer page `/approve` (CSP with script/style hashes, no cookies) uses POST-only JSON endpoints
`/api/v1/public/approvals/{view,instructions,decide,complete}`: token HMAC-signed (key derived from the audit key), only sha256 stored, single use, expiry (default 72 h, max 7 d),
uniform 404, per-IP rate limit (30/min) + failure backoff, JSON content type required. Approve requires name, email, statement and the proposal hash the customer saw.
Decision records name, email, IP, user agent, time, statement in the hash-chained audit (`customer_approval.approved|rejected|changes_requested|provisioned`). After approval a separate single-use
completion link confirms provisioning. Permission plan interface for agent L: `tenancy/plan_provider.py` (`register(provider, fn)`; stub until L registers).
Deliver links out of band only; ICS sends no email (no SMTP identity for customers).

## Not done / follow-ups
- Frontend screens (customers, credentials, approvals) are not built; API only.
- ssh/docker/backup providers: schema supports them, no testers yet. Customer-bound checks/nodes/alert channels not scoped.
- Approval link e-mail delivery intentionally absent. Real-Proxmox verification not performed.
