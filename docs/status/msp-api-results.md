# MSP provisioning API (roadmap P4.3) — results
Date: 2026-11-15. Design: `docs/adr/0013-msp-provisioning-api.md`. Contract: `docs/api/msp-v1.yaml` (OpenAPI 3.1), generated reference `docs/api/msp-v1-reference.md`. Reference client: `clients/msp-python/`.
Status (ADR-0000): **Integrated in lab** (dev ICS on 127.0.0.1:8125, throw-away DB `ics_test_f`) and **Tested** at API level. Not run against real customer stacks or a real MSP system (clientst0r); no console UI yet.

## What was built
* `ics/ics/msp/`: `gateway.py` (HMAC verification, nonce store, mTLS binding, permission check, scoping, idempotency, rate limit, audit, error envelope, deprecation headers), `api.py` (34 operations), `actions.py` (plan actions `msp.client.create|set_permissions|rotate|revoke`, `msp.stack.link`; one-time key reveal), `events.py` (outbox, signing, retry, SSRF guard), `metering.py`, `console.py` (list clients, reveal).
* Migration `0012b`: `msp_clients`, `msp_client_customers`, `msp_client_reveals`, `msp_nonces`, `msp_idempotency`, `msp_webhooks`, `msp_events`, `msp_deliveries`; `customers.slug/external_ref` (trigger-defaulted), `idm_stacks.customer_id`.
* Core changes (small, reviewed for regressions by the full suite): `create_plan(commit=, msp_auto=)`; `tscope.customer_of_params` resolves deployment slug/spec and identity stack to a customer; `audit.append` feeds the webhook outbox (guarded by a savepoint, cannot fail an audit write); `customer.create` accepts `slug`/`external_ref`; worker has a webhook delivery thread.

## Evidence
| Check | Result |
|---|---|
| Full ICS suite (`pytest`, DB `ics_test_f`), before the last two doc tests | 550 passed in 761 s |
| `tests/test_msp_api.py` (24 tests) | 24 passed |
| `scripts/msp_e2e.py` against the dev ICS | PASSED (transcript below) |

Test coverage (`ics/tests/test_msp_api.py`): key creation only via approved plan, shown once, encrypted at rest, absent from audit/plans, backing user disabled; elevated permissions need acknowledgement; signature skew (±120 s), nonce replay, body/path/query/method tamper, unknown client indistinguishable from bad key, revoked/rotated keys with grace period, mTLS binding only trusted from the proxy; idempotency (key required, replay returns the original response and header, one plan only, same key + different body = 409, failed requests not stored, responses encrypted); permission sets (`view`, `plan`, `approve`, `execute`); an API client never approves its own plan, approves only non-high-risk plans of MSP-owned customers; auto-approval only with `execute` on MSP-owned customers; cross-customer denial for 13 route/method combinations plus lists, events and endpoint ownership; rate limit per client; deprecation headers; customer create/update flow with plan tracking; deployment flow (preview, create with customer-approval gate, execution with the fake provider, health, usage, change/destroy previews and plans); users flow (stack linking, risk by privileged group, usage counts); webhook signing, retry with the same event id (at least once), dead letter after 8 attempts, rotate/delete, SSRF/scheme guards, scope and subscription filtering; incident events; reference-client roundtrip including a lost response retried with the same key (exactly one plan). **Every response in these tests is validated against `docs/api/msp-v1.yaml`** (`tests/msp_spec.py`), and the spec's operations are asserted identical to the registered routes and to require `Idempotency-Key` on every mutation.

## End-to-end transcript (real HTTP, reference client, `python scripts/msp_e2e.py`)
```
[   1.0s] schema rebuilt in ics_test_f (alembic head)
[   4.1s] dev ICS up on http://127.0.0.1:8125 (db ics_test_f, worker on)
[   5.1s] msp.client.create plan 1010ea28: status=pending_approval risk=high approvals_required=2
[   6.2s] key revealed once: client_id=mspc_cb09a39f751c2647 secret=mspk_*** (second reveal -> HTTP 404)
[   6.2s] GET /me -> {"client_id": "mspc_cb09a39f751c2647", "permissions": ["view", "plan"], "all_customers": true, ...}
[   6.3s] POST /customers -> plan f81fac82 pending_approval risk=high approvals_required=2
[   6.3s] idempotent replay: same plan id = True
[   6.3s] same key, different body -> HTTP 409 idempotency_key_reused
[   7.4s] customer plan executed: succeeded -> customer 87713c46 slug=e2e-example-gmbh external_ref=crm-e2e-1
[   7.6s] deployment preview: executable=False vms=3 cores=12 memory_mb=11402 disk_gb=372 plan_hash=01f152b9beb4 errors=['artifact_unpinned', 'artifact_unpinned'] ...
[   7.6s] POST /customers/{id}/users -> plan 12f42b37 pending_approval risk=normal approvals_required=1
[   7.7s] user plan rejected by an approver -> API view: rejected
[   7.7s] wrong key -> HTTP 401 invalid_signature
[   7.7s] identical signed request sent twice -> [200, (401, 'replayed_request')]
[   7.7s] request signed 600 s in the past -> HTTP 401 timestamp_out_of_window
[   8.7s] webhook deliveries received: plan.approved(sig_ok=True,attempt=1), job.completed(sig_ok=True,attempt=1), plan.rejected(sig_ok=True,attempt=1), plan.rejected(sig_ok=True,attempt=1)
[   8.8s] audit: 17 msp.request rows for mspc_cb09a39f751c2647, 3 msp.auth_failed rows, chain ok=True (55 entries)
[   8.8s] E2E PASSED
```
`ics_test_f` was checked for other connections (`pg_stat_activity`) before the schema was rebuilt; production `ics` DB, the ics service and Proxmox were not touched.

## Limits and honest gaps
* The deployment preview in the e2e is `executable=false` because this build's catalog OCI digests are unpinned (the engine's own refusal); the deployment *create* path is covered by the pytest suite with the fake provider, not by the e2e. The e2e Proxmox endpoint and identity stack are database rows, not real infrastructure; user creation was planned and rejected, never executed against a directory (that path is covered by `user-lifecycle-results.md`).
* Rate-limit buckets are per process (fine for the single ICS process; move to the DB for multi-instance).
* `approve` does not include rejecting; no console UI for API clients (list + reveal endpoints and the plan actions exist); mailbox storage is not metered (`null`); webhook SSRF check resolves DNS at registration and again at delivery (a rebinding race between check and connect is theoretically possible).
* The webhook receiver must be reachable over https in production; plain http is accepted only when `ICS_ALLOW_LOOPBACK_ENDPOINTS` is on (lab).
* Deploy note: the migration must be applied by the owner role before the new code starts; the TLS proxy must set `X-Client-Cert-SHA256` only from verified client certificates (and strip it from client requests) if mTLS-bound clients are used, with `ICS_TRUSTED_PROXY` set.
* Reproduce: `bash` runner with `ICS_TEST_DATABASE_URL`/`ICS_TEST_OWNER_DATABASE_URL` pointing at `…/ics_test_f`, then `.venv/bin/pytest tests/test_msp_api.py` and `.venv/bin/python scripts/msp_e2e.py`.
