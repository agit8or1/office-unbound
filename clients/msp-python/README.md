# ou_msp — Office Unbound MSP API reference client

Python 3.10+, standard library only. Contract: `docs/api/msp-v1.yaml` (reference: `docs/api/msp-v1-reference.md`, design: ADR-0013).

```python
from ou_msp import MspClient
api = MspClient("https://ics.example", "mspc_…", "mspk_…")   # credentials from an approved msp.client.create plan, shown once
plan = api.create_customer(name="Example GmbH", external_ref="crm-4711")   # -> 202, a PLAN; humans approve it
api.wait_for_plan(plan["plan_id"])                                         # or react to the plan.approved / job.completed webhooks
```

* Signing: `sign()` / `string_to_sign()` implement `OU-MSP1` (method, request target incl. query, timestamp, nonce, SHA-256 of the body).
  Fresh timestamp and nonce on every attempt.
* Idempotency: every `POST/PATCH/DELETE` gets an `Idempotency-Key` (a UUID unless you pass `idempotency_key=`); retries on connection errors,
  5xx, 429 and `idempotency_in_progress` reuse it, so a lost response can never create a second plan. Pass your own key when *your* job is
  retried (e.g. derive it from your ticket id).
* mTLS-bound clients: `MspClient(..., ssl_context=ctx)` with `ctx.load_cert_chain(cert, key)`; TLS verification is always on.
* Webhooks: `ou_msp.verify_signature(secret, raw_body, header)` and `EventDeduper`; see `examples/webhook_receiver.py`.
* `examples/quickstart.py`: customer → deployment preview/plan → user plan.

Errors raise `MspApiError(status, code, message, details, request_id)`; `code` values are listed in the API description.
