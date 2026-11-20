# ADR-0017: Single-admin approval mode

- Status: Accepted (owner decision, 2026-11-16)
- Context: ADR-0003/review rules require two distinct approvers for high-risk plans and never the requester. An MSP run by one person has no
  second approver and cannot make any high-risk change (connecting a cluster, rotating tokens, deployments). The owner, who is the only
  administrator, decided not to have a second-approver requirement.

## Decision

`ICS_APPROVAL_MODE` = `two_person` (default, unchanged) | `single_admin`.

In `single_admin` mode:

- An **admin** may approve or reject their own plan. Approver and operator accounts can never decide their own plans.
- Every ICS plan needs exactly **one** approval, whatever the risk tier or the customer's extra-approval policy. Tenant-admin plans keep their
  own customer authority rule. A release promotion to `stable` also needs only one approval.
- Unchanged: plan → explicit approval → durable job, the hash-bound digest re-checked at execution, scope and tenancy checks, customer
  approval gates, plan expiry, and the hash-chained audit. A self-approval is audited with `self_approval: true, approval_mode: single_admin`.
- The console says so: the policy endpoint reports `mode` / `self_approval`, a submitted plan has `self_approval`, and wizards offer
  **Approve and run** after showing the exact change.

## Consequences

- One compromised admin session can make high-risk changes. Login TOTP, session limits and the full audit are the remaining controls.
  Switch back to `two_person` when a second approver exists.
- Invalid values refuse to start (`RuntimeError`).

## Amendment 2026-11-20: enrollment tokens in the console

Owner decision ("yes, show tokens in the console"): an administrator can issue an invited account's one-time enrollment token in
Users & roles → Invitations (`POST /api/v1/invitations/{username}/token`). Conditions: admin role, a fresh authenticator code (`step_up`,
single use, throttled), only an account that was invited and never enrolled (not revoked, not yourself), shown once with
`Cache-Control: no-store`, never listed again, audited as `user.enrollment_issued` with `via: console`. Enrolled accounts are not
reset from the console (that would let one admin take over another's sign-in); the host CLI remains the recovery path. The person
still chooses their own password and authenticator. Trade-off accepted: the token now passes through the admin's browser.

