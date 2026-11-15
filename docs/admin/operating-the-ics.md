# Operating the ICS

Evidence: [ics/README.md](../../ics/README.md), [ics-monitoring-results.md](../status/ics-monitoring-results.md),
[security-review-ics-monitoring-2026-11-15.md](../status/security-review-ics-monitoring-2026-11-15.md) (remediation tables).

## The console
Login lands on the **Overview** dashboard (status cards for health, clusters, nodes, VMs, containers, deployments, pending operations, incidents). The sidebar groups: Infrastructure (clusters, nodes, VMs, containers, storage, networks), Deployments, Operations (jobs, approvals, maintenance), Monitoring (health checks, utilization, incidents), Administration (users & roles, integrations, audit log). Items not built are labelled **Planned** (Catalog, Changes, Updates, Access policies, Configuration).
Owner decision: wizards are an option, never auto-opened. With no cluster connected the dashboard offers **Start guided setup**; once connected and with no deployments it offers **Start deployment wizard**. Both only build plans that still need approval. Evidence: [ui-verification-main.md](../status/ui-verification-main.md) (UI check of the redesign, with open accessibility and layout defects listed there; the Infrastructure pages needed the Proxmox API that was merged afterwards and have not been re-verified in a browser), screenshots in `docs/screenshots/`.
The monitoring pages were not exercised in a browser in the monitoring session; those procedures were run through the API.

## Plans, approvals, jobs
- Discover actions with `GET actions`. Create a plan with `POST plans {action, params}`; approvers `approve|reject` it; the job runs once and re-verifies the plan hash. Pending plans expire after 7 days.
- Dry run a blueprint with `POST plans/preview {blueprint_yaml}`: returns `{valid, errors}` or the plan, no side effects.
- A job has a wall-clock budget. Hung or crashed jobs are marked failed and are **never re-run**; the plan secret is wiped. Inspect with `GET jobs/{id}`.
- Health: `/healthz`, `/readyz` (database, worker heartbeat, audit tail; 503 when not ready).

## Monitoring checks
`check.create` kinds: `http`, `tcp_tls`, `imap_login`, `smtp_banner`, `ews_getfolder`. Interval 15 s to 24 h (30 s minimum for credentialed kinds), at most 200 checks;
`fail_threshold` / `recover_threshold` damp flapping. TLS checks require exactly one trust anchor (CA bundle or SHA-256 pin). Check passwords are vault-encrypted and
never returned. All five kinds ran against the lab groupware node. States: `unknown -> ok | warning | critical`; results are kept 14 days.

## Incidents
One active incident per check: opens on the first non-ok state, updates on severity change, closes on recovery. `incident.ack` stops reminders (the first 5 acks per user per hour
are low risk; more need one approver). Notifications use a durable outbox: 5 attempts with exponential backoff, then `failed` (audited).

## Remediation policies and their safety limits
Bind with `check.bind_remediation`: `{node_id, runbook, unit|path, mode auto|approval, max_attempts, window_seconds, backoff_seconds, verify_timeout_seconds}`.
Runbooks are `service.restart`, `service.status`, `disk.usage` only, on units/paths in the node's root-owned allowlist. Limits (review remediation, tests in `ics/tests/test_review_fixes.py`):
- At most `max_attempts` per sliding window, then **terminal escalation** until a human acknowledges the incident or the check recovers.
- Global budget of 3 `service.restart` per (node, unit) per hour across all checks; `backoff_seconds >= 30`, `window_seconds >= 300`; verify timeout <= 45 s.
- A pending approval of any age blocks a new attempt; stale remediation plans are superseded on recovery or after 4 h.
- Failures tagged `cause: auth|config` (IMAP login rejected, EWS 401/403) do not trigger restarts.
- `service.restart mariadb` is high risk and cannot be `auto`. `mode: approval` needs one approver other than the requester (fix for review H2 was "pending integration" at the time of the review doc; confirm it is merged in your build).
- Maintenance windows block remediation.

Lab proof: failure to verified recovery in 25.2 s; escalation after 3 attempts with no fourth (ics-monitoring-results.md). Real stop/restart of `mariadb`/`nginx` through polkit was **not** exercised.

## Maintenance windows
`maintenance.create`: one check and <= 60 min is low risk; global or 60 min to 8 h is **high** (two approvers). Start and end are announced on every channel and cannot be suppressed;
at the end one summary of suppressed alerts is sent and still-open incidents are re-notified. Disabling a check (`check.set_enabled`) needs one approver and notifies all channels if an incident is open.

## Alert channels
`alert_channel.create` is high risk. **Email**: SMTP relay with verified STARTTLS/implicit TLS (CA or pin); `tls=none` only with explicit `allow_plaintext` and never with credentials. Verified in the lab through a real relay and mailbox read-back.
**Webhook**: https with HMAC-SHA256 (`X-OU-Timestamp`, `X-OU-Signature: v1=...`, 5 min replay window); tested only against a local receiver. **Pushover and SMS: interface only, always disabled** (paid third-party services, ADR-0007). Test a channel with `alert_channel.test`.

## Node agents
Enrollment: on the node `ou-agent init` prints a one-time token (1 h) and two fingerprints; a `node.enroll` plan (high, two approvers) carries them; the ICS checks both before sending the token.
Install on a node as root: `sh ics/agent/deploy/install-agent.sh <bind-ip> <hostname>`. Keep node clocks synced: requests outside their validity window are rejected (fail closed).
Rotating the ICS signing key means re-enrolling agents. No node revoke/disable action exists yet (**Planned**).

## Deployments (In development)
`deployment.create|change|destroy` plans, the deployment wizard and change wizard exist. Evidence ([deployment-engine.md](../status/deployment-engine.md)): plan generation, capacity, drift report and the executor are tested with a fake provider and fake agent; the Proxmox provider steps (clone, tag, configure, resize, start, snapshot, stop, destroy) passed once on a real VM ([provider-proxmox-real.md](../status/provider-proxmox-real.md)).
**End-to-end deployment is In development**: there is no `docs/status/first-real-deployment.md` yet, the guest-side steps after `agent.enroll` fail by design (no agent enrollment flow on real VMs), component artifacts are unpinned so real-catalog plans are non-executable (`artifact_unpinned`), and backup scheduling and DNS records are plan output only. Do not rely on it to build a customer environment.
Flow you can use for reviewing a plan: wizard or `POST deployments/plan` (no side effects) -> `deployment.create` plan (high risk, two approvers) -> job steps visible under **Deployments**. Disruptive changes need a maintenance window or an explicit override (two approvers). Drift is reported, never auto-repaired. Customer user actions: [users-and-access.md](users-and-access.md).

## Removing things
Only `endpoint.remove` (see [Connecting Proxmox](connecting-proxmox.md)), `idm.user.delete`, `user.revoke_invite` and `check.set_enabled` (disable) exist. Actions that remove checks, alert channels, node agents or old plans are **Planned**; they are not on main. Disable instead of remove for now.

## Roadmap feed
Project progress is one file, `docs/progress.json` (schema in [progress-schema.md](../progress-schema.md)); `ROADMAP.md` is generated from it. After editing the feed run:
```
python3 scripts/render_roadmap.py          # rewrite ROADMAP.md
python3 scripts/render_roadmap.py --check  # exit 1 if stale or invalid (evidence paths must exist)
```
A status may only advance with evidence in the repo (ADR-0000).
