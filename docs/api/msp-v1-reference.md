# Office Unbound MSP Provisioning API 1.0.0 — reference

_Generated from `docs/api/msp-v1.yaml` by `ics/scripts/gen_msp_reference.py`; do not edit._

Base path `/api/msp/v1`. Separate from the operator console API (`/api/v1`, cookie sessions).

## Model
* Every **mutation creates a plan**, never a direct change. A plan is approved by humans (two approvers for high risk) and then
  executed by the ICS worker as a durable job. The response to a mutation is `202` with the plan id and its approval status;
  follow it with `GET /plans/{plan_id}`, a webhook (`plan.approved`, `job.completed`, ...) or `GET /events`.
* An API client can never approve its own plans. `approve` and `execute` are off by default and can only be granted by an
  approved plan (`msp.client.set_permissions`); even then they are limited to non-high-risk plans of MSP-owned customers.
* Out-of-scope customers answer `404`, not `403`.

## Authentication (HMAC-SHA256 request signing)
Credentials are created by an approved console plan (`msp.client.create`) and shown once: a `client_id` (`mspc_` + 16 hex) and a
secret (`mspk_...`). Every request carries:

| Header | Value |
|---|---|
| `X-MSP-Client` | the client id |
| `X-MSP-Timestamp` | unix seconds; must be within +-120 s of the server clock |
| `X-MSP-Nonce` | 16-64 chars `[A-Za-z0-9_-]`, unique per request (a reused nonce is `401 replayed_request`) |
| `X-MSP-Signature` | `v1=` + hex(HMAC-SHA256(secret, string_to_sign)) |

```
string_to_sign = "OU-MSP1" "\n" METHOD "\n" REQUEST_TARGET "\n" TIMESTAMP "\n" NONCE "\n" hex(sha256(body))
```
`REQUEST_TARGET` is the raw path plus `?query` exactly as sent; the body hash of an empty body is the SHA-256 of the empty string.
Clients may additionally be bound to a TLS client certificate (mTLS terminated by the reverse proxy, which forwards
`X-Client-Cert-SHA256`). After a key rotation the previous key keeps working for the grace period chosen in the rotation plan
(responses carry `X-MSP-Key-Status` while it is used).

## Idempotency
Every `POST`, `PATCH` and `DELETE` requires an `Idempotency-Key` header (8-128 chars of `A-Za-z0-9._:~-`). The first successful
response is stored (24 h) with a hash of method, target and body. A retry with the same key and request returns the original
response (`Idempotent-Replay: true`); the same key with a different request is `409 idempotency_key_reused`; a retry while the
first is still running is `409 idempotency_in_progress`. Failed requests (4xx/5xx) are not stored, so they can be corrected and retried.

## Permissions
`view` (reads, webhooks, events), `plan` (previews, submitting plans, reading one-time enrollment tokens of own plans),
`approve` (peer approval, default off), `execute` (low-risk plans on MSP-owned customers run without a human, default off).

## Errors
`{"error": {"code", "message", "request_id", "details"?}}`. Codes: `auth_headers_missing`, `auth_malformed`, `timestamp_out_of_window`,
`invalid_signature`, `replayed_request`, `client_certificate_required`, `forbidden`, `not_found`, `validation_error`, `conflict`,
`policy_denied`, `idempotency_key_required`, `idempotency_key_invalid`, `idempotency_key_reused`, `idempotency_in_progress`,
`rate_limited`, `too_many_failures`, `approval_not_permitted`, `approval_refused`, `no_identity_stack`, `internal_error`.

## Rate limits
Per client token bucket (`rate_limit_per_minute`, default 120). `X-RateLimit-Limit`, `X-RateLimit-Remaining`; `429` carries `Retry-After`.

## Versioning
No breaking change within `v1`: only new optional request fields, new response fields, new endpoints and new enum values in
*responses* are added; clients must ignore unknown response fields. A breaking change ships as `/api/msp/v2`. A deprecated v1
operation answers with `Deprecation: true`, `Sunset: <HTTP date>` and `Link: <successor>; rel="successor-version"` for at least
180 days before removal. Every response carries `X-MSP-API-Version: 1` and `X-Request-Id`.

## Webhooks
Event types: `plan.approved`, `plan.rejected`, `job.completed`, `job.failed`, `incident.opened`, `incident.recovered`. Delivery is
**at least once**: failed deliveries (non-2xx, timeout, TLS error) are retried after 5 s, 30 s, 2 min, 10 min, 1 h, 6 h, 12 h
(8 attempts, then marked dead; see `GET /webhooks/{id}/deliveries`). De-duplicate on the event `id`. Each POST has the JSON
envelope `Event` and headers `X-MSP-Event-Id`, `X-MSP-Event-Type`, `X-MSP-Delivery-Id`, `X-MSP-Delivery-Attempt` and
`X-MSP-Signature: t=<unix>,v1=<hex HMAC-SHA256(webhook secret, "<t>.<raw body>")>` - reject if `t` is older than 5 minutes.
Webhook urls must be https and every address the name resolves to must be a public one (no loopback, link-local, private, CGNAT, unique-local or metadata addresses, unless the operator allow-listed the destination); the ICS connects to the address it checked and never follows redirects. Creating, deleting and rotating webhooks needs the `plan` permission. Deliveries report only `delivered`, `pending` or `dead`, never the remote status or error.

## Operations

| Method | Path | Permission | operationId | Summary |
|---|---|---|---|---|
| GET | `/api/msp/v1/me` | view | getMe | The calling API client (permissions, scope, rate limit) |
| GET | `/api/msp/v1/customers` | view | listCustomers |  |
| POST | `/api/msp/v1/customers` | plan | createCustomer | Plan a new customer (high risk, two human approvers; all-customers clients only) |
| GET | `/api/msp/v1/customers/{customer_id}` | view | getCustomer |  |
| PATCH | `/api/msp/v1/customers/{customer_id}` | plan | updateCustomer | Plan a change of the customer's contact data |
| GET | `/api/msp/v1/customers/{customer_id}/usage` | view | getCustomerUsage | Metering snapshot (users, mailboxes, storage, VM resources) with the definition of every figure |
| POST | `/api/msp/v1/customers/{customer_id}/deployments/preview` | plan | previewDeployment | Dry-run deployment plan against the latest inventory (writes nothing). Returns the plan_hash the create call must echo. |
| POST | `/api/msp/v1/customers/{customer_id}/deployments` | plan | createDeployment | Plan a deployment (high risk, two approvers). `spec.customer_id` is set from the path. |
| GET | `/api/msp/v1/deployments` | view | listDeployments |  |
| GET | `/api/msp/v1/deployments/{slug}` | view | getDeployment | Status, revisions, resource summary and the steps of the latest job |
| GET | `/api/msp/v1/deployments/{slug}/health` | view | getDeploymentHealth | Service status / health summary (checks, open incidents, drift) |
| POST | `/api/msp/v1/deployments/{slug}/changes/preview` | plan | previewChange |  |
| POST | `/api/msp/v1/deployments/{slug}/changes` | plan | createChange | Plan a change (risk follows the diff; disruptive changes need a maintenance window or an override) |
| POST | `/api/msp/v1/deployments/{slug}/destroy/preview` | plan | previewDestroy |  |
| POST | `/api/msp/v1/deployments/{slug}/destroy` | plan | createDestroy | Plan a destroy (high risk). `confirm` must equal the slug. |
| GET | `/api/msp/v1/customers/{customer_id}/users` | view | listUsers |  |
| POST | `/api/msp/v1/customers/{customer_id}/users` | plan | createUser | Plan a user (idm.user.create). The initial credential is a one-time enrollment token, see POST /plans/{plan_id}/enrollment. |
| PATCH | `/api/msp/v1/customers/{customer_id}/users/{uid}` | plan | updateUserGroups | Plan a group membership change (privileged groups raise the risk to high) |
| DELETE | `/api/msp/v1/customers/{customer_id}/users/{uid}` | plan | deleteUser | Plan a user deletion (high risk; mailbox data is retained). `reason` (3-200 chars) is mandatory in the body. |
| POST | `/api/msp/v1/customers/{customer_id}/users/{uid}/disable` | plan | disableUser |  |
| POST | `/api/msp/v1/customers/{customer_id}/users/{uid}/enable` | plan | enableUser |  |
| POST | `/api/msp/v1/customers/{customer_id}/identity/reconcile` | plan | reconcileIdentity | Plan a read-only reconcile of the customer's identity stack (low risk) |
| GET | `/api/msp/v1/plans` | view | listPlans |  |
| GET | `/api/msp/v1/plans/{plan_id}` | view | getPlan | Approval status and execution state of a plan |
| POST | `/api/msp/v1/plans/{plan_id}/approve` | approve | approvePlan | Peer approval by an API client (needs `approve`, off by default; never own plans; MSP-owned customers; not high risk) |
| POST | `/api/msp/v1/plans/{plan_id}/enrollment` | plan | revealEnrollment | One-time enrollment token of an executed idm.user.create/enable plan this client requested (shown once) |
| GET | `/api/msp/v1/jobs/{job_id}` | view | getJob |  |
| GET | `/api/msp/v1/webhooks` | view | listWebhooks |  |
| POST | `/api/msp/v1/webhooks` | plan | createWebhook | Subscribe an https endpoint; the signing secret is returned once |
| GET | `/api/msp/v1/webhooks/{webhook_id}` | view | getWebhook |  |
| DELETE | `/api/msp/v1/webhooks/{webhook_id}` | plan | deleteWebhook |  |
| POST | `/api/msp/v1/webhooks/{webhook_id}/rotate-secret` | plan | rotateWebhookSecret |  |
| GET | `/api/msp/v1/webhooks/{webhook_id}/deliveries` | view | listWebhookDeliveries |  |
| GET | `/api/msp/v1/events` | view | listEvents | Polling alternative / catch-up feed of the same events, oldest first |

## Operation details

### GET `/api/msp/v1/me`

**getMe** — permission `view`

The calling API client (permissions, scope, rate limit)

| Status | Response |
|---|---|
| 200 | ok — [Me](#me) |
| 4XX | Error — [Error](#error) |

### GET `/api/msp/v1/customers`

**listCustomers** — permission `view`

| Parameter | In | Type | Required |
|---|---|---|---|
| `limit` | query | integer | no |
| `cursor` | query | string | no |
| `external_ref` | query | string | no |

| Status | Response |
|---|---|
| 200 | ok — [CustomerList](#customerlist) |
| 4XX | Error — [Error](#error) |

### POST `/api/msp/v1/customers`

**createCustomer** — permission `plan` — requires `Idempotency-Key`

Plan a new customer (high risk, two human approvers; all-customers clients only)

| Parameter | In | Type | Required |
|---|---|---|---|
| `Idempotency-Key` | header | string | yes |

Request body: [CustomerCreate](#customercreate)

| Status | Response |
|---|---|
| 202 | A plan was created (or the original response of an idempotent replay). Nothing has changed yet. — [PlanSubmitted](#plansubmitted) |
| 4XX | Error — [Error](#error) |

### GET `/api/msp/v1/customers/{customer_id}`

**getCustomer** — permission `view`

| Parameter | In | Type | Required |
|---|---|---|---|
| `customer_id` | path | string | yes |

| Status | Response |
|---|---|
| 200 | ok — [Customer](#customer) |
| 4XX | Error — [Error](#error) |

### PATCH `/api/msp/v1/customers/{customer_id}`

**updateCustomer** — permission `plan` — requires `Idempotency-Key`

Plan a change of the customer's contact data

| Parameter | In | Type | Required |
|---|---|---|---|
| `customer_id` | path | string | yes |
| `Idempotency-Key` | header | string | yes |

Request body: [CustomerPatch](#customerpatch)

| Status | Response |
|---|---|
| 202 | A plan was created (or the original response of an idempotent replay). Nothing has changed yet. — [PlanSubmitted](#plansubmitted) |
| 4XX | Error — [Error](#error) |

### GET `/api/msp/v1/customers/{customer_id}/usage`

**getCustomerUsage** — permission `view`

Metering snapshot (users, mailboxes, storage, VM resources) with the definition of every figure

| Parameter | In | Type | Required |
|---|---|---|---|
| `customer_id` | path | string | yes |

| Status | Response |
|---|---|
| 200 | ok — [Usage](#usage) |
| 4XX | Error — [Error](#error) |

### POST `/api/msp/v1/customers/{customer_id}/deployments/preview`

**previewDeployment** — permission `plan` — requires `Idempotency-Key`

Dry-run deployment plan against the latest inventory (writes nothing). Returns the plan_hash the create call must echo.

| Parameter | In | Type | Required |
|---|---|---|---|
| `customer_id` | path | string | yes |
| `Idempotency-Key` | header | string | yes |

Request body: [DeploymentSpec](#deploymentspec)

| Status | Response |
|---|---|
| 200 | ok — [DeploymentPreview](#deploymentpreview) |
| 4XX | Error — [Error](#error) |

### POST `/api/msp/v1/customers/{customer_id}/deployments`

**createDeployment** — permission `plan` — requires `Idempotency-Key`

Plan a deployment (high risk, two approvers). `spec.customer_id` is set from the path.

| Parameter | In | Type | Required |
|---|---|---|---|
| `customer_id` | path | string | yes |
| `Idempotency-Key` | header | string | yes |

Request body: object

| Status | Response |
|---|---|
| 202 | A plan was created (or the original response of an idempotent replay). Nothing has changed yet. — [PlanSubmitted](#plansubmitted) |
| 4XX | Error — [Error](#error) |

### GET `/api/msp/v1/deployments`

**listDeployments** — permission `view`

| Parameter | In | Type | Required |
|---|---|---|---|
| `limit` | query | integer | no |
| `cursor` | query | string | no |
| `customer_id` | query | string | no |

| Status | Response |
|---|---|
| 200 | ok — [DeploymentList](#deploymentlist) |
| 4XX | Error — [Error](#error) |

### GET `/api/msp/v1/deployments/{slug}`

**getDeployment** — permission `view`

Status, revisions, resource summary and the steps of the latest job

| Parameter | In | Type | Required |
|---|---|---|---|
| `slug` | path | string | yes |

| Status | Response |
|---|---|
| 200 | ok — [Deployment](#deployment) |
| 4XX | Error — [Error](#error) |

### GET `/api/msp/v1/deployments/{slug}/health`

**getDeploymentHealth** — permission `view`

Service status / health summary (checks, open incidents, drift)

| Parameter | In | Type | Required |
|---|---|---|---|
| `slug` | path | string | yes |

| Status | Response |
|---|---|
| 200 | ok — [Health](#health) |
| 4XX | Error — [Error](#error) |

### POST `/api/msp/v1/deployments/{slug}/changes/preview`

**previewChange** — permission `plan` — requires `Idempotency-Key`

| Parameter | In | Type | Required |
|---|---|---|---|
| `slug` | path | string | yes |
| `Idempotency-Key` | header | string | yes |

Request body: object

| Status | Response |
|---|---|
| 200 | ok — object |
| 4XX | Error — [Error](#error) |

### POST `/api/msp/v1/deployments/{slug}/changes`

**createChange** — permission `plan` — requires `Idempotency-Key`

Plan a change (risk follows the diff; disruptive changes need a maintenance window or an override)

| Parameter | In | Type | Required |
|---|---|---|---|
| `slug` | path | string | yes |
| `Idempotency-Key` | header | string | yes |

Request body: object

| Status | Response |
|---|---|
| 202 | A plan was created (or the original response of an idempotent replay). Nothing has changed yet. — [PlanSubmitted](#plansubmitted) |
| 4XX | Error — [Error](#error) |

### POST `/api/msp/v1/deployments/{slug}/destroy/preview`

**previewDestroy** — permission `plan` — requires `Idempotency-Key`

| Parameter | In | Type | Required |
|---|---|---|---|
| `slug` | path | string | yes |
| `Idempotency-Key` | header | string | yes |

| Status | Response |
|---|---|
| 200 | ok — object |
| 4XX | Error — [Error](#error) |

### POST `/api/msp/v1/deployments/{slug}/destroy`

**createDestroy** — permission `plan` — requires `Idempotency-Key`

Plan a destroy (high risk). `confirm` must equal the slug.

| Parameter | In | Type | Required |
|---|---|---|---|
| `slug` | path | string | yes |
| `Idempotency-Key` | header | string | yes |

Request body: object

| Status | Response |
|---|---|
| 202 | A plan was created (or the original response of an idempotent replay). Nothing has changed yet. — [PlanSubmitted](#plansubmitted) |
| 4XX | Error — [Error](#error) |

### GET `/api/msp/v1/customers/{customer_id}/users`

**listUsers** — permission `view`

| Parameter | In | Type | Required |
|---|---|---|---|
| `customer_id` | path | string | yes |
| `limit` | query | integer | no |
| `cursor` | query | string | no |
| `state` | query | string (active, disabled, deleted) | no |

| Status | Response |
|---|---|
| 200 | ok — [UserList](#userlist) |
| 4XX | Error — [Error](#error) |

### POST `/api/msp/v1/customers/{customer_id}/users`

**createUser** — permission `plan` — requires `Idempotency-Key`

Plan a user (idm.user.create). The initial credential is a one-time enrollment token, see POST /plans/{plan_id}/enrollment.

| Parameter | In | Type | Required |
|---|---|---|---|
| `customer_id` | path | string | yes |
| `Idempotency-Key` | header | string | yes |

Request body: object

| Status | Response |
|---|---|
| 202 | A plan was created (or the original response of an idempotent replay). Nothing has changed yet. — [PlanSubmitted](#plansubmitted) |
| 4XX | Error — [Error](#error) |

### PATCH `/api/msp/v1/customers/{customer_id}/users/{uid}`

**updateUserGroups** — permission `plan` — requires `Idempotency-Key`

Plan a group membership change (privileged groups raise the risk to high)

| Parameter | In | Type | Required |
|---|---|---|---|
| `customer_id` | path | string | yes |
| `uid` | path | string | yes |
| `Idempotency-Key` | header | string | yes |

Request body: object

| Status | Response |
|---|---|
| 202 | A plan was created (or the original response of an idempotent replay). Nothing has changed yet. — [PlanSubmitted](#plansubmitted) |
| 4XX | Error — [Error](#error) |

### DELETE `/api/msp/v1/customers/{customer_id}/users/{uid}`

**deleteUser** — permission `plan` — requires `Idempotency-Key`

Plan a user deletion (high risk; mailbox data is retained). `reason` (3-200 chars) is mandatory in the body.

| Parameter | In | Type | Required |
|---|---|---|---|
| `customer_id` | path | string | yes |
| `uid` | path | string | yes |
| `Idempotency-Key` | header | string | yes |

Request body: object

| Status | Response |
|---|---|
| 202 | A plan was created (or the original response of an idempotent replay). Nothing has changed yet. — [PlanSubmitted](#plansubmitted) |
| 4XX | Error — [Error](#error) |

### POST `/api/msp/v1/customers/{customer_id}/users/{uid}/disable`

**disableUser** — permission `plan` — requires `Idempotency-Key`

| Parameter | In | Type | Required |
|---|---|---|---|
| `customer_id` | path | string | yes |
| `uid` | path | string | yes |
| `Idempotency-Key` | header | string | yes |

Request body: [UserOp](#userop)

| Status | Response |
|---|---|
| 202 | A plan was created (or the original response of an idempotent replay). Nothing has changed yet. — [PlanSubmitted](#plansubmitted) |
| 4XX | Error — [Error](#error) |

### POST `/api/msp/v1/customers/{customer_id}/users/{uid}/enable`

**enableUser** — permission `plan` — requires `Idempotency-Key`

| Parameter | In | Type | Required |
|---|---|---|---|
| `customer_id` | path | string | yes |
| `uid` | path | string | yes |
| `Idempotency-Key` | header | string | yes |

Request body: [UserOp](#userop)

| Status | Response |
|---|---|
| 202 | A plan was created (or the original response of an idempotent replay). Nothing has changed yet. — [PlanSubmitted](#plansubmitted) |
| 4XX | Error — [Error](#error) |

### POST `/api/msp/v1/customers/{customer_id}/identity/reconcile`

**reconcileIdentity** — permission `plan` — requires `Idempotency-Key`

Plan a read-only reconcile of the customer's identity stack (low risk)

| Parameter | In | Type | Required |
|---|---|---|---|
| `customer_id` | path | string | yes |
| `Idempotency-Key` | header | string | yes |

Request body: [UserOp](#userop)

| Status | Response |
|---|---|
| 202 | A plan was created (or the original response of an idempotent replay). Nothing has changed yet. — [PlanSubmitted](#plansubmitted) |
| 4XX | Error — [Error](#error) |

### GET `/api/msp/v1/plans`

**listPlans** — permission `view`

| Parameter | In | Type | Required |
|---|---|---|---|
| `limit` | query | integer | no |
| `cursor` | query | string | no |
| `status` | query | string (pending_approval, approved, rejected) | no |
| `customer_id` | query | string | no |

| Status | Response |
|---|---|
| 200 | ok — [PlanList](#planlist) |
| 4XX | Error — [Error](#error) |

### GET `/api/msp/v1/plans/{plan_id}`

**getPlan** — permission `view`

Approval status and execution state of a plan

| Parameter | In | Type | Required |
|---|---|---|---|
| `plan_id` | path | string | yes |

| Status | Response |
|---|---|
| 200 | ok — [PlanView](#planview) |
| 4XX | Error — [Error](#error) |

### POST `/api/msp/v1/plans/{plan_id}/approve`

**approvePlan** — permission `approve` — requires `Idempotency-Key`

Peer approval by an API client (needs `approve`, off by default; never own plans; MSP-owned customers; not high risk)

| Parameter | In | Type | Required |
|---|---|---|---|
| `plan_id` | path | string | yes |
| `Idempotency-Key` | header | string | yes |

| Status | Response |
|---|---|
| 200 | ok — object |
| 4XX | Error — [Error](#error) |

### POST `/api/msp/v1/plans/{plan_id}/enrollment`

**revealEnrollment** — permission `plan` — requires `Idempotency-Key`

One-time enrollment token of an executed idm.user.create/enable plan this client requested (shown once)

| Parameter | In | Type | Required |
|---|---|---|---|
| `plan_id` | path | string | yes |
| `Idempotency-Key` | header | string | yes |

| Status | Response |
|---|---|
| 200 | ok — object |
| 4XX | Error — [Error](#error) |

### GET `/api/msp/v1/jobs/{job_id}`

**getJob** — permission `view`

| Parameter | In | Type | Required |
|---|---|---|---|
| `job_id` | path | string | yes |

| Status | Response |
|---|---|
| 200 | ok — [Job](#job) |
| 4XX | Error — [Error](#error) |

### GET `/api/msp/v1/webhooks`

**listWebhooks** — permission `view`

| Status | Response |
|---|---|
| 200 | ok — object |
| 4XX | Error — [Error](#error) |

### POST `/api/msp/v1/webhooks`

**createWebhook** — permission `plan` — requires `Idempotency-Key`

Subscribe an https endpoint; the signing secret is returned once

| Parameter | In | Type | Required |
|---|---|---|---|
| `Idempotency-Key` | header | string | yes |

Request body: object

| Status | Response |
|---|---|
| 201 | created — [WebhookCreated](#webhookcreated) |
| 4XX | Error — [Error](#error) |

### GET `/api/msp/v1/webhooks/{webhook_id}`

**getWebhook** — permission `view`

| Parameter | In | Type | Required |
|---|---|---|---|
| `webhook_id` | path | string | yes |

| Status | Response |
|---|---|
| 200 | ok — [Webhook](#webhook) |
| 4XX | Error — [Error](#error) |

### DELETE `/api/msp/v1/webhooks/{webhook_id}`

**deleteWebhook** — permission `plan` — requires `Idempotency-Key`

| Parameter | In | Type | Required |
|---|---|---|---|
| `webhook_id` | path | string | yes |
| `Idempotency-Key` | header | string | yes |

| Status | Response |
|---|---|
| 200 | ok — object |
| 4XX | Error — [Error](#error) |

### POST `/api/msp/v1/webhooks/{webhook_id}/rotate-secret`

**rotateWebhookSecret** — permission `plan` — requires `Idempotency-Key`

| Parameter | In | Type | Required |
|---|---|---|---|
| `webhook_id` | path | string | yes |
| `Idempotency-Key` | header | string | yes |

| Status | Response |
|---|---|
| 200 | ok — [WebhookCreated](#webhookcreated) |
| 4XX | Error — [Error](#error) |

### GET `/api/msp/v1/webhooks/{webhook_id}/deliveries`

**listWebhookDeliveries** — permission `view`

| Parameter | In | Type | Required |
|---|---|---|---|
| `webhook_id` | path | string | yes |

| Status | Response |
|---|---|
| 200 | ok — object |
| 4XX | Error — [Error](#error) |

### GET `/api/msp/v1/events`

**listEvents** — permission `view`

Polling alternative / catch-up feed of the same events, oldest first

| Parameter | In | Type | Required |
|---|---|---|---|
| `after_seq` | query | integer | no |
| `limit` | query | integer | no |

| Status | Response |
|---|---|
| 200 | ok — object |
| 4XX | Error — [Error](#error) |

## Schemas

### Error

| Field | Type | Required | Description |
|---|---|---|---|
| `error` | object | yes |  |

### Me

| Field | Type | Required | Description |
|---|---|---|---|
| `client_id` | string | yes |  |
| `name` | string | yes |  |
| `permissions` | array of string (view, plan, approve, execute) | yes |  |
| `all_customers` | boolean | yes |  |
| `customer_ids` | array or null | no |  |
| `rate_limit_per_minute` | integer | yes |  |
| `api_version` | string | yes |  |

### Customer

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes |  |
| `name` | string | yes |  |
| `slug` | string | yes | The `customer_id` of this customer's deployments |
| `external_ref` | string or null | yes |  |
| `msp_owned` | boolean | yes |  |
| `provisioning_mode` | string (auto, customer_approval, monitoring_only) | yes |  |
| `contact_name` | string or null | yes |  |
| `contact_email` | string or null | yes |  |
| `disabled` | boolean | yes |  |
| `created_at` | string | yes |  |

### CustomerList

| Field | Type | Required | Description |
|---|---|---|---|
| `items` | array of [Customer](#customer) | yes |  |
| `next_cursor` | string or null | yes |  |

### CustomerCreate

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes |  |
| `slug` | string | no |  |
| `external_ref` | string | no | The MSP system's own id (unique); use it to find the customer again |
| `contact_name` | string | no |  |
| `contact_email` | string | no |  |
| `msp_owned` | boolean | no |  |

### CustomerPatch

| Field | Type | Required | Description |
|---|---|---|---|
| `contact_name` | string | no |  |
| `contact_email` | string | no |  |

### PlanSubmitted

| Field | Type | Required | Description |
|---|---|---|---|
| `plan_id` | string | yes |  |
| `status` | string (pending_approval, approved, rejected) | yes |  |
| `risk` | string (low, normal, high) | yes |  |
| `approvals_required` | integer | yes |  |
| `job_id` | string or null | no |  |
| `params_hash` | string | yes |  |
| `customer_id` | string or null | no |  |
| `waiting_for` | string or null (customer_approval) | no |  |
| `customer_approval_id` | string or null | no |  |
| `links` | object | yes |  |

### PlanView

| Field | Type | Required | Description |
|---|---|---|---|
| `plan_id` | string | yes |  |
| `action` | string | yes |  |
| `risk` | string (low, normal, high) | yes |  |
| `status` | string (pending_approval, approved, rejected) | yes |  |
| `customer_id` | string or null | yes |  |
| `requested_by` | string | yes | `console` or `msp_client:<client_id>` |
| `own` | boolean | yes |  |
| `created_at` | string | yes |  |
| `decided_at` | string or null | no |  |
| `approvals` | integer | yes |  |
| `approvals_required` | integer | yes |  |
| `waiting_for` | string or null | no |  |
| `customer_approval` | object or null | no |  |
| `params` | object or null | no | Only for plans this client submitted |
| `execution` | object or null | yes |  |

### PlanList

| Field | Type | Required | Description |
|---|---|---|---|
| `items` | array of [PlanView](#planview) | yes |  |
| `next_cursor` | string or null | yes |  |

### Job

| Field | Type | Required | Description |
|---|---|---|---|
| `job_id` | string | yes |  |
| `status` | string | yes |  |
| `plan_id` | string | yes |  |
| `action` | string | yes |  |
| `result` | object or null | no |  |
| `error` | object or null | no |  |
| `steps` | array of object | yes |  |

### DeploymentSpec

| Field | Type | Required | Description |
|---|---|---|---|
| `deployment_id` | string | yes |  |
| `profile` | string | yes |  |
| `users` | integer | yes |  |
| `tenants` | integer | no |  |
| `domain` | string | yes |  |
| `endpoint` | string | yes |  |
| `pool` | string | yes |  |
| `storage` | string or null | no |  |
| `bridge` | string | no |  |
| `vlan` | integer or null | no |  |
| `os_image` | string or null | no |  |
| `allowed_nodes` | array or null | no |  |
| `optional` | object | no |  |
| `backup_retention_days` | integer or null | no |  |

### DeploymentPreview

| Field | Type | Required | Description |
|---|---|---|---|
| `plan_hash` | string | yes |  |
| `executable` | boolean | yes |  |
| `vms` | array of object | yes |  |
| `steps` | array of object | yes |  |
| `consumption` | object | yes |  |
| `warnings` | array | yes |  |
| `errors` | array | yes |  |

### ChangeSet

| Field | Type | Required | Description |
|---|---|---|---|
| `users` | integer | no |  |
| `profile` | string | no |  |
| `optional` | object | no |  |
| `backup_retention_days` | integer | no |  |
| `allowed_nodes` | array of string | no |  |
| `tenants` | integer | no |  |

### DeploymentList

| Field | Type | Required | Description |
|---|---|---|---|
| `items` | array of [DeploymentSummary](#deploymentsummary) | yes |  |
| `next_cursor` | string or null | yes |  |

### DeploymentSummary

| Field | Type | Required | Description |
|---|---|---|---|
| `slug` | string | yes |  |
| `customer_id` | string or null | yes |  |
| `profile` | string | yes |  |
| `profile_version` | string | no |  |
| `status` | string (planned, provisioning, active, failed, changing, destroying, destroyed) | yes |  |
| `current_revision` | integer | yes |  |
| `created_at` | string | no |  |
| `updated_at` | string | no |  |

### Deployment

| Field | Type | Required | Description |
|---|---|---|---|
| `slug` | string | yes |  |
| `customer_id` | string or null | no |  |
| `profile` | string | no |  |
| `status` | string | yes |  |
| `current_revision` | integer | yes |  |
| `revisions` | array of object | yes |  |
| `resource_summary` | array of object | yes |  |
| `latest_job_id` | string or null | no |  |
| `latest_job_steps` | array of object | yes |  |

### Health

| Field | Type | Required | Description |
|---|---|---|---|
| `slug` | string | yes |  |
| `deployment_status` | string | yes |  |
| `health` | string (healthy, degraded, unhealthy, unknown) | yes |  |
| `inventory_at` | string or null | no |  |
| `checks` | object | yes |  |
| `active_incidents` | array of object | yes |  |
| `drift` | object | yes |  |

### UserOp

| Field | Type | Required | Description |
|---|---|---|---|
| `stack` | string | no |  |
| `reason` | string | no |  |

### UserList

| Field | Type | Required | Description |
|---|---|---|---|
| `items` | array of object | yes |  |
| `next_cursor` | string or null | yes |  |

### Usage

| Field | Type | Required | Description |
|---|---|---|---|
| `customer_id` | string | yes |  |
| `as_of` | string | yes |  |
| `users` | object | yes |  |
| `mailboxes` | object | yes |  |
| `vm` | object | yes |  |
| `storage` | object | yes |  |
| `stacks` | array of object | yes |  |
| `deployments` | array of object | yes |  |
| `definitions` | object | yes |  |

### EventType

`string (plan.approved, plan.rejected, job.completed, job.failed, incident.opened, incident.recovered)`

### Event

| Field | Type | Required | Description |
|---|---|---|---|
| `seq` | integer | no | Only in GET /events |
| `id` | string | yes |  |
| `type` | [EventType](#eventtype) | yes |  |
| `api_version` | string (v1) | yes |  |
| `created_at` | string | yes |  |
| `customer_id` | string or null | yes |  |
| `data` | object | yes |  |

### Webhook

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes |  |
| `url` | string | yes |  |
| `events` | array of [EventType](#eventtype) | yes |  |
| `description` | string or null | no |  |
| `enabled` | boolean | yes |  |
| `created_at` | string | yes |  |

### WebhookCreated

| Field | Type | Required | Description |
|---|---|---|---|
| `secret` | string | yes |  |
| `secret_note` | string | no |  |

### Delivery

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes |  |
| `event_id` | string | yes |  |
| `type` | string | yes |  |
| `status` | string (pending, delivered, dead) | yes |  |
| `attempts` | integer | yes |  |
| `last_status` | integer or null | no |  |
| `last_error` | string or null | no |  |
| `next_attempt_at` | string or null | no |  |
| `delivered_at` | string or null | no |  |

