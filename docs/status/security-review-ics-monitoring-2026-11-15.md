# ICS monitoring / alerting / node agent / remediation: security review, 2026-11-15

Independent review of the monitoring slice: `ics/agent/` (node agent and deploy files), `ics/ics/{agentclient,checks,monitor,alerts}.py`, the new actions in `ics/ics/actions.py`, migration `0003`, `frontend/src/views/{Checks,Incidents}.vue`, and `scripts/lab_*.py`. Context documents: ADR-0002, the previous review `security-review-ics-2026-11-15.md`, `ics-monitoring-results.md`, and `ics/README.md`. No project files were modified.

Evidence:
- Probes are in `/tmp/claude-1000/-home-administrator/a1d917f8-7438-424e-a57a-793b46deb95e/scratchpad/secreview2/` (`test_probes.py`, `live_p5.py`). Run them with `cd ics && PYTHONPATH=.:agent .venv/bin/pytest -q -s <path>/test_probes.py`, against `ics_test` and a real `ou_agent` on 127.0.0.1 with a stub systemctl. All 8 probes passed, which means every issue they test was reproduced.
- Full suite: `152 passed`.
- On ou-gw1 I sent only rejection-path and stall traffic, plus a `pkcheck` evaluation of the polkit rule. No unit was restarted or stopped.
- The production `ics` DB was only read (users and checks), never written.

## Summary

| # | Severity | Finding | Status |
|---|---|---|---|
| H1 | High | One idle TCP connection freezes the node agent: the TLS handshake runs in the accept loop with no timeout | CONFIRMED (local and live on ou-gw1) |
| H2 | High | The remediation policy `mode: "approval"` is ignored for low-risk runbooks: the restart is auto-executed | CONFIRMED |
| M1 | Medium | Remediation is a rate, not a cap. Escalation fires once, the budget refills every window, there is no per node/unit budget, and any cause of failure (such as a mailbox password) triggers restarts | CONFIRMED |
| M2 | Medium | Regression of the old M8 in a new code path: check runners have per-read timeouts only. One slow-dripping target stalls the single worker loop (checks, jobs, remediation, notifications), while the heartbeat stays green | CONFIRMED |
| M3 | Medium | Stale high-risk remediation plans pile up, one per window. An approval days later restarts `mariadb` even though the check is now ok | CONFIRMED |
| M4 | Medium | One operator can silence alerting with no second person: global 8 h maintenance windows (repeatable), `check.set_enabled`, `incident.ack`. Suppressed notifications are never re-sent | CONFIRMED |
| M5 | Medium | The lab demo left live production credentials (password and TOTP secret) for one operator and **two approvers** in `/tmp/ou-demo-creds.json`. One holder can satisfy every two-person rule | CONFIRMED (deployed) |
| L1 | Low | Anyone on the network can burn the enrollment token (5 bad guesses) | CONFIRMED |
| L2 | Low | The agent signs responses to unauthenticated requests and echoes the attacker-chosen `job_id`/`nonce` | CONFIRMED (no exploit found) |
| L3 | Low | The remediation policy accepts `verify_timeout_seconds` 46..90, but `runbook.execute` caps it at 45, so the policy silently fails every time. The job budget of 120 s is below 90 s (agent) + 45 s (verify) | CONFIRMED (by code) |
| L4 | Low | The SSRF guard has a DNS-rebinding TOCTOU (deferred L3 from the last review) and is a blind internal port scanner for operators. `smtp_banner` has no TLS and no anchor | PLAUSIBLE |
| L5 | Low | No quotas: checks are auto-approved at 5 s minimum interval with 14-day retention, giving unbounded `check_results` growth and scheduler load | CONFIRMED (by code) |
| L6 | Low | Small items: no directory fsync in the replay journal, unbounded agent threads, remediation runs as the check creator (not the binder, and the role is not re-checked), no node revoke or disable, `type` not checked in responses | mixed |

Regressions from the previous review: the old M8 regressed in the new check path (M2 above), and M5 above weakens the two-person rule that the previous H2 and L5 fixes established. Everything else I re-checked holds (see the last section).

---

## High

### H1. One TCP connection freezes the node agent. CONFIRMED (live)
- **Where:** `ics/agent/ou_agent/server.py:200` wraps the *listening* socket with `do_handshake_on_connect=True` (the default). `socketserver.serve_forever()` calls `SSLSocket.accept()`, which runs the TLS handshake on the accept thread before a handler thread exists. The accepted socket has no timeout, because `H.timeout = 15` is only applied later in `StreamRequestHandler.setup`.
- **Evidence:**
  - Local probe `test_p5`: with one raw TCP connection open that sends nothing, `agentclient.identity()` fails with `ConnectTimeout` after 5.1 s. It works again once that connection is closed.
  - Live on ou-gw1 (`live_p5.py`, 3 s stall): `baseline: ok 0.01s`, then `with 1 idle TCP conn: FAIL TimeoutError after 3.0s`, then `after close: ok`.
- **Failure scenario:** any host that can reach `192.168.186.218:8443` (another lab VM, or a compromised service on the node itself) keeps one socket open. Every remediation then fails with `transport_or_signature_error` and escalates. The DoS lasts indefinitely and needs no authentication, at the moment when auto-remediation is needed. This defeats the purpose of the agent, and an attacker can pair it with taking down a service.
- **Minimal fix:** do not wrap the listening socket. In `_Server.get_request()`, accept the plain socket, call `settimeout(10)`, and `wrap_socket(..., server_side=True, do_handshake_on_connect=False)`. Run `do_handshake()` in the handler thread, under a bounded `threading.BoundedSemaphore(32)`, and reject when it is full. Add a test that holds an idle connection open and asserts that `/v1/identity` still answers.

### H2. `mode: "approval"` is ignored, so a "manual approval" policy restarts automatically. CONFIRMED
- **Where:**
  - `ics/ics/monitor.py:42` defines `mode`.
  - `monitor.py:273` calls `actions.create_plan(... runbook_execute ...)`.
  - `actions.py:412` uses `auto = risk == "low"`.
  - `mode` is read nowhere except the high-risk validator (`monitor.py:54`).
  - The README (§Remediation policy) presents `mode auto|approval` as a control.
- **Evidence:** probe `test_p1`. A policy of `service.restart gromox-imap` with `mode: "approval"` produces attempt `queued`, plan `low`/`approved`, and the agent log shows `restart gromox-imap.service`. Nothing waits for a human.
- **Failure scenario:** an operator, or a reviewer reading the policy, believes restarts of `postfix`/`nginx`/`gromox-*` need approval, and they happen unattended. Audit shows `auto_approved: true` on a plan whose policy said approval. The only real gate is the hard-coded `HIGH_RISK_UNITS = {"mariadb"}`.
- **Minimal fix:** pass the mode into planning. For example, `create_plan(..., force_approval=pol.mode == "approval")`, which then sets `auto = risk == "low" and not force_approval` and requires one approver who is not the check owner. Add a test that a low-risk `approval` policy yields `pending_approval` and makes zero agent calls.

## Medium

### M1. Remediation bounds: a rate, not a cap. No per-unit budget, and it is cause-blind. CONFIRMED
- **Where:**
  - `monitor.py:247-261`: the attempt count only covers the sliding window.
  - `monitor.py:229`: `_escalate` returns early once `escalated_at` is set.
  - Policy limits are `window_seconds >= 60`, `max_attempts <= 10` and `backoff_seconds >= 0` (`monitor.py:43-45`).
  - Budgets are per check only.
- **Evidence:**
  - `test_p2`: three checks bound to the same `nginx` restart produce 3 restarts in one pass.
  - The existing `test_backoff_and_single_flight` shows that the budget resets after the window.
  - Escalation notifies once, and the attempts then silently resume when the window slides.
  - The docstring "Never loops" (`monitor.py:239`) is inaccurate.
  - Worst case for one check (window 60, max 10, backoff 0): about 10 restarts per minute, indefinitely. With N checks on one unit, multiply by N.
- **Deployed instance:** `gw1-imap-login` is an `imap_login` check (login as `frank`, a vault password) with policy `service.restart gromox-imap`, 3 per 900 s. Any non-service failure keeps the check critical and gives 3 restarts of IMAP every 15 minutes, for as long as the condition lasts. Examples: frank's password is changed, the account is locked or disabled, or the mailbox is renamed. Each restart drops every user's IMAP session, and there is only one escalation email.
- **Minimal fix:**
  1. Make escalation terminal: after `max_attempts`, stop until the incident is recovered or acked and a human re-arms it. Equivalently, count attempts per incident, not per window.
  2. Enforce a global per-(node, unit) restart budget, for example at most 3 per hour across all checks.
  3. Require `backoff_seconds >= 30` and `window_seconds >= 300`.
  4. Do not auto-restart on outcomes that indicate auth or config errors. Have the IMAP/EWS runners tag `details.cause = "auth"` and skip remediation when it is set.

### M2. Old M8 regressed: a slow target stalls the whole worker. CONFIRMED
- **Where:**
  - `ics/ics/checks.py:172,269`: `httpx.Timeout(timeout_seconds)` is a per-read timeout.
  - `checks.py:220` (imaplib) and `checks.py:238` (smtplib): per-socket-operation timeouts.
  - `monitor.py:364-366`: `ThreadPoolExecutor` with `f.result()` and no deadline.
  - `worker.py:51-52`: `monitor.tick` runs on the same thread as `run_once` jobs.
  - The heartbeat thread (`worker.py:36-43`) keeps `/readyz` green while this happens.
- **Evidence:** probe `test_p4`. A pinned HTTPS server that sends 1 byte every 1.5 s: `timeout_seconds=2 but run_check took 18.0s`. The duration is bounded only by the 1 MiB cap, so at 1 byte per 1.9 s that is about 23 days. The same applies to an IMAP or SMTP server that trickles lines.
- **Failure scenario:** a compromised monitored host trickles its responses. Monitored hosts are less trusted than ICS (the gromox VM, any HTTPS URL an operator adds). The ICS worker then blocks: no jobs (approved plans, remediation), no further checks, no notifications, no retention. `readyz` still reports the worker as healthy, so monitoring goes blind without any alarm.
- **Minimal fix:** give every runner a wall-clock deadline. Check `time.monotonic()` against `t0 + timeout_seconds` inside the `iter_raw` loop, and set `socket.settimeout(remaining)` before each imaplib/smtplib operation. Alternatively, run checks in a pool with `fut.result(timeout=timeout_seconds + 5)` and record `critical: deadline exceeded`, never joining stuck threads in `with` (use `shutdown(wait=False)`). Run `monitor.tick` on its own thread, separate from job execution. Add `last_tick_at` to `readyz`. `agentclient._post` has the same per-read pattern (`agentclient.py:87`); there the 120 s job budget catches it, but it should use the same deadline loop.

### M3. Stale high-risk remediation plans pile up and execute after recovery. CONFIRMED
- **Where:** `monitor.py:247-250`. The in-flight guard only sees attempts newer than `window_seconds`, so a `pending_approval` attempt older than the window no longer blocks a new one. The pending plan lives for 7 days (`plan_expiry_seconds`). No step re-checks the check state before execution (`actions._exec_runbook`).
- **Evidence:** probe `test_p3`. A `mariadb` approval policy with window 60 s, once aged, gives **2** pending high-risk plans. The check then recovers to `ok`. Two approvers approve the first, old plan, and the agent log shows `restart mariadb.service`.
- **Failure scenario:** approvers clear a queue of identical-looking "restart mariadb" plans hours or days later. The datastore restarts during business hours, for an incident that is long over. With a short window, the queue grows by one plan per window while the check stays critical.
- **Minimal fix:**
  - Treat `pending_approval` as in flight regardless of age (drop the `at >` filter for that status).
  - Give remediation plans a short expiry, for example `window_seconds`.
  - In `_exec_runbook`, refuse (`PlanIntegrityError: check no longer critical`) when `attempt_id` is set and the check is not `critical`, or its incident is closed.

### M4. One operator can silence all alerting, with no second person. CONFIRMED
- **Where:** `actions.py:247,249,252`: `check.set_enabled`, `maintenance.create` and `incident.ack` are all `low` and auto-approved. In `MaintenanceCreate`, `check_id` is optional, which makes the window global, up to 480 min, with no limit on how many. `monitor.py:85-89` marks notifications `suppressed`, and they are never re-sent when the window ends.
- **Evidence:** probe `test_p8`. An operator alone creates a global 480 min window. A check goes critical, the notifications are `['suppressed']`, and 0 emails are sent. The same window also blocks all remediation (`monitor.py:244`).
- **Failure scenario:** an insider, or a stolen operator session, opens a global window, re-opens it every 8 h, and disables or acks the relevant checks. Alerting is silent while they act. This sits poorly with ADR-0002 item 5's risk tiering, given that the previous review made `alert_channel.create` high risk precisely because alert routing matters.
- **Minimal fix:**
  - Make a global window, or any window over 60 min, high risk (two approvers).
  - Always send a non-suppressible "maintenance started/ended" notification to all channels.
  - At window end, send one summary of what was suppressed, or re-enqueue for incidents that are still open.
  - Make disabling a check with an open incident notify the channels.

### M5. Live approver credentials left on disk by the lab demo. CONFIRMED (deployed)
- **Where:** `ics/scripts/lab_monitoring_demo.py:26,79-82`. The script writes `{password, TOTP secret}` for `lab-op`, `lab-ap1` and `lab-ap2` to `/tmp/ou-demo-creds.json`. It does so with the default umask and only *then* calls `chmod 600` (a small window where the file is world-readable). The file persists after the demo.
- **Evidence:**
  - The file exists (`-rw------- administrator`) with keys `lab-ap1, lab-ap2, lab-op`, each holding `password` and `secret`. The values were not printed.
  - A read-only query of the production `ics` DB shows `lab-ap1 approver`, `lab-ap2 approver` and `lab-op operator`, all enabled and enrolled.
- **Failure scenario:** whoever can read that file (the interactive `administrator` user, any process running as it, or a backup of `/tmp`) can, alone, create and doubly approve any high-risk plan through the normal UI. That covers `node.enroll`, `alert_channel.create` (redirect alerts), `endpoint.register` and the `mariadb` restart. The audit log shows a clean two-person approval. This undoes in practice what the previous review's H2 and L5 fixes enforce. Host root can already do a lot, but it could not forge *approver identities* in the audit trail this cleanly.
- **Minimal fix:**
  - Disable `lab-op`, `lab-ap1` and `lab-ap2` now, or delete them through the user plans, and delete the file.
  - Change the script to create the file with `os.open(..., O_CREAT|O_EXCL, 0o600)` in a private directory, and to disable the accounts at the end of the run.
  - Never hold two approvers' secrets in one place. The demo should prompt for the second approval or run against `ics_test`.

## Low

### L1. Enrollment-token burn. CONFIRMED
`server.py:90-95`. Five unauthenticated wrong guesses permanently burn the token (probe `test_p7`: the real token is then refused with `token_expired`). The token itself is strong: `secrets.token_urlsafe(32)`, 256 bits, stored as SHA-256, valid 1 h, single use, and `compare_digest`. The only consequence is an enrollment DoS that needs console re-arming.
**Fix:** count failures per source IP, and add a small sleep per failure. Alternatively, accept enrollment only from an IP pinned when the token was armed (`ou-agent arm-enroll --from <ics-ip>`).

### L2. The agent signs responses to unauthenticated input. CONFIRMED, no exploit found
`server.py:111-116` copies any `job_id`/`nonce` string (64 characters or fewer) from the unverified body into a response that the agent then signs (probe `test_p6`: `job_id: "attacker-chosen"`, `status: "rejected"`). The status is always `rejected` for such requests, ICS generates the nonces randomly, and the TLS pin blocks MITM, so this cannot forge success. It is still a signing oracle over attacker-chosen fields.
**Fix:** echo `job_id`/`nonce` only after the signature verifies, and use `null` otherwise. Have ICS also require `resp.type == "exec"` (`agentclient.py:140`) and `resp.type == "enroll"` (`agentclient.py:123`).

### L3. Mismatched limits make remediation silently fail. CONFIRMED (by code)
`monitor.py:46` allows `verify_timeout_seconds <= 90`, but `actions.py:225` caps it at 45. A policy with 46..90 passes `check.create`/`bind`, but every attempt is then recorded as `failed: plan rejected: ValidationError` and escalates. There is also a budget gap: `job_timeout_seconds` is 120 (`config.py:51`), but the agent deadline is 90 s and verification up to 45 s, each `run_and_record` taking up to 30 s. A job can time out after the restart has already happened, and that counts as a failed attempt, which triggers another restart.
**Fix:** use one shared constant for the limit (45). Size the job budget so that it is at least the agent deadline plus verify plus one check timeout, or shorten the agent deadline to about 30 s.

### L4. Check destinations (SSRF). PLAUSIBLE
- `check_destination` (`proxmox.py:33-47`) resolves once, and httpx, imaplib and smtplib resolve again. This is the deferred L3 rebinding gap.
- For TLS kinds the trust anchor makes rebinding useless. `smtp_banner` has no TLS and no anchor, so an operator-controlled rebinding name can reach `127.0.0.1:5432/8088` and the bridge IPs as a plaintext banner and port probe. The connect errors, such as `ConnectionRefusedError` versus timeout, are stored in `last_message`, so any check kind works as a blind internal port scanner across RFC1918 for operators.
- `body_contains`/`json_equals` are boolean oracles on internal HTTPS content.
- Today the ICS host only listens on 22 and 443 externally (verified with `ss`), so the impact is small.
- **Fix:** connect to the resolved, checked IP, passing `server_hostname`/SNI separately, as the planned DNS-pinning fix would. Optionally restrict check destinations to declared management CIDRs.

### L5. No quotas. CONFIRMED (by code)
`check.create` is auto-approved, with a minimum interval of 5 s and no count limit. At 5 s, one check writes 17,280 rows a day, kept for 14 days. The scheduler takes `LIMIT 100` per tick with 8 threads and timeouts up to 30 s, so many slow checks also starve jobs (see M2).
**Fix:** cap the number of checks (for example 200), or make more than N checks high risk. Use a 30 s minimum interval for credentialed kinds, and downsample old results.

### L6. Smaller items
- **Replay journal** (`state.py:17-25`): fsyncs the file but not the directory. After a power loss the entry can vanish. Replay is still impractical, because requests travel inside pinned TLS and expire within 120 s plus skew. Add `os.fsync(dirfd)`.
- **Agent concurrency:** `ThreadingMixIn` has no thread cap, and the header phase can be slow-dripped (`timeout = 15` per read). Use the semaphore from the H1 fix.
- **Remediation identity:** plans are created as `checks.created_by` (`monitor.py:262-271`). A different operator who binds the policy is not the requester of the restarts. The owner's role is not re-checked, so a user later demoted to viewer still "requests" restarts. Use the binder as the requester, and require operator rank or higher at attempt time.
- **No node lifecycle:** there is no node revoke or disable action (`nodes.status` is unused), and a lost ICS signing key means re-enrolling every node by hand. Document the rotation, and add a `node.disable`.
- **`trust.json` and `agent_key.pem` are owned by `ou-agent`:** an agent-level compromise can re-point trust. This is acceptable, because that user can already restart the allowlisted units through polkit.
- **`render_polkit.py`** (`agent/deploy/render_polkit.py:9-10`) reads the config without the root-owner check that `load_config` applies. It is run by root during install, so this is fine as deployed.
- **Agent clock:** if the agent clock runs more than 60 s ahead of ICS, every request is `expired` (there is no grace on that side). Remediation then fails closed. Make sure NTP runs on the nodes.

---

## Verified as sound
- **Signing and canonicalisation:**
  - Ed25519 over a domain-separated prefix (`ou-agent-req-v1\n` / `-resp-v1\n`) plus canonical JSON: sorted keys, ASCII, no whitespace, NaN refused, floats refused after verification.
  - Verification runs over the re-canonicalised *parsed* object, so the object that is checked is exactly the object that runs. Duplicate keys or whitespace games cannot split them.
  - Exact field set, `v == 1` with no alternative algorithm (no downgrade), integer-only times, lowercase-UUID `node_id`/`job_id`, nonce charset.
  - Coverage is action, params, node id, job id, issued/expires and nonce. The HTTP method and path need not be covered: there is a single exec endpoint, and the action lives inside the signed body.
  - Responses must verify against the enrolled agent key and echo nonce, job id and node id (`agentclient.py:134-141`).
- **Replay protection:** nonce and job id are recorded `O_EXCL` plus fsync *before* the allowlist check and execution. Job ids are never garbage-collected, so a job never runs twice even after a nonce GC or a clock change. The nonce TTL of 1 day is far longer than window plus skew (240 s). The journal sits in `/var/lib/ou-agent/journal` (0700) and survives restarts: 19 entries on ou-gw1. The live proofs (`ics-monitoring-results.md`) and my code review agree.
- **Clock skew:** window 120 s or less, future skew 120 s or less. The worst-case real-time acceptance is about 180 s.
- **Enrollment binding:**
  - The operator supplies both the TLS pin and the agent-key fingerprint out of band.
  - ICS checks the TLS pin and the pubkey fingerprint *before* sending the token. The existing test proves the token is not sent on a mismatch.
  - The response must be signed by that key and echo `node_id` and `agent_pubkey`.
  - The agent refuses re-enrollment while `trust.json` exists, and the plan is high risk (two approvers).
  - A rogue host cannot enroll without matching fingerprints, and cannot hijack an enrolled node id: requests carry the node id, and the agent compares it with its own trust.
- **Allowlist exactness:**
  - `params` must be exactly `{unit}` or `{path}`, with an exact string match. `gromox-imap.service`, `sshd`, `nginx; id` and `shell.exec` are all rejected (live proofs).
  - `.service` is appended by the agent, so a template `foo@.service` can only be targeted if it is literally in the root-owned allowlist.
  - argv is a list with no shell, and `PATH` and env are fixed.
- **Polkit rule** (deployed rule identical to `render_polkit.py`; evaluated with `pkcheck` on ou-gw1 for the agent's PID, systemd 252, polkitd 122):
  - `restart` on an allowlisted unit: yes.
  - Each of these is NO: `stop`, `start`, `reload-or-restart`, `try-restart` and `kill` on the same unit; `restart` on `sshd.service`/`ssh.service`; `manage-unit-files`; `reload-daemon`; `set-environment`.
  - Aliases resolve to the canonical id (`mysql.service` resolves to `mariadb.service`), so an alias cannot escape the rule.
  - None of the allowlisted units has `ConsistsOf`/`BoundBy` dependents except `postfix@-.service`, which is expected.
- **Agent host hardening:**
  - The agent runs as `ou-agent` (uid 994, no extra groups).
  - Hardened unit: `NoNewPrivileges`, `ProtectSystem=strict`, empty `CapabilityBoundingSet`.
  - Code, config and rule are root-owned 0644, and the agent refuses a config that is not owned by root or is group- or world-writable.
  - The state files are 0600 apart from the public certificate.
  - Bound to a single lab IP.
- **Agent TLS:** TLS 1.2 is the minimum (1.1 refused live), and the live session negotiated TLS 1.3, AES-256-GCM with X25519. The 16 KiB body cap is enforced before reading, and responses are capped at 64 KiB on the ICS side.
- **Check TLS:** every TLS kind needs exactly one anchor (CA or pin) and verification is never disabled. The pin is checked on the same socket inside `wrap_socket`, and `imaplib`, `smtplib` and httpcore all call `ctx.wrap_socket`. `trust_env=False`, `follow_redirects=False`, credential-free `https` URLs only. A DTD in EWS responses is refused.
- **Check password vault binding:**
  - AAD is `check-secret:{id}:{sha256(canon(config))}`, so changing the host or config in the DB makes the secret undecryptable, and a secret cannot be redirected to another host.
  - The secret goes in `secret_enc` only. The API returns `has_secret` only, and `ca_pem` is masked. Errors are scrubbed and control characters removed.
  - Channel secrets use the same scheme.
- **Email:**
  - No header injection: names match `NAME_RE`, messages are scrubbed to printable ASCII, and `EmailMessage` (policy default) rejects CR/LF.
  - STARTTLS failure is an error, not a downgrade.
  - Plaintext requires `allow_plaintext` and forbids credentials.
- **Webhook:** HMAC-SHA256 over `ts.body` with a key of at least 16 characters, verified in constant time with a 300 s window. No secrets in payloads. Errors carry the class name only.
- **Audit:** no secrets appear in plan params or audit details for the new actions (tests plus code review).
- **Frontend:** `Checks.vue` and `Incidents.vue` use text interpolation only, with no `v-html`. Links are built from UUIDs.
- **Migration 0003:** grants are DML on the new tables only, and the app role gets no DDL.
- **No regressions found in:**
  - `X-Forwarded-For` handling: nginx overwrites the header with `$remote_addr`, and uvicorn trusts only 127.0.0.1.
  - The 256 KiB body cap.
  - Security headers.
  - Plan digest re-verification, which now also covers the new actions.
  - Job lease and timeout.
  - Two-approver plus provenance checks for high-risk actions, by code; see M5 for how this is bypassed operationally.

## Remediation (lead, 2026-11-15)
| Finding | Status | Evidence |
|---|---|---|
| H1 agent stalls on idle TCP connection | **Fixed** | `agent/ou_agent/server.py`: plain accept, per-connection TLS handshake in worker thread with 10 s deadline, max 32 concurrent connections. Tests `test_idle_tcp_connection_does_not_block_agent`, `test_agent_handshake_deadline_closes_silent_connection`. Deployed to ou-gw1: with 5 idle connections held, `/v1/identity` answered in 0.01 s; all 5 idle connections closed after the deadline |
| H2 `mode: approval` ineffective for low-risk units | **Fixed — merged to main in commit 83c6d8b** (uses the `normal` risk tier) | `require_approval` param (hash-bound, visible to approvers) set from policy mode → risk `normal` (1 approver ≠ requester, never auto). Tests `test_approval_mode_waits_for_a_human_even_for_low_risk_units`, `test_auto_mode_low_risk_still_auto_executes` |
| M1–M4, Lows | Open | scheduled after user-lifecycle integration |
| M5 demo approver credentials on disk | **Accepted risk (owner decision)**: lab accounts kept for approval testing; file to move to a root-only location | — |

## Remediation update (agent D, branch `worktree-agent-affa1323bcfd38a47`, migration `0006d`)
All tests are in `ics/tests/test_review_fixes.py` unless noted. Status "Fixed" means implemented and covered by an executed test in `ics/` (suite run: see the commit message). CI workflows (`.github/workflows/`) were written and linted with actionlint 1.7.12 and gitleaks 8.30.1 locally, but could not be run on GitHub from this host.

| Finding | Status | Fix | Test |
|---|---|---|---|
| M1 restart storms | **Fixed** | Global budget of 3 `service.restart` per (node, unit) per hour across all checks (`remediation_attempts.node_id/target`, `Settings.remediation_unit_budget*`); escalation is terminal until `incident.ack` (which clears `escalated_at`; attempts then count from the ack); floors `backoff_seconds >= 30`, `window_seconds >= 300` (`Settings.remediation_min_*`, enforced in `check.create`/`bind`); runners tag `details.cause = auth` (IMAP login rejected, EWS 401/403) or `config` (SELECT failed, bad config, missing/undecryptable secret, destination refused) and `maybe_remediate` never restarts for those (one notice per incident, `incidents.remediation_skipped_at`, audit `remediation.skipped`) | `test_m1_restart_budget_is_global_per_node_and_unit_across_checks`, `test_m1_escalation_is_terminal_until_a_human_acknowledges`, `test_m1_auth_failure_is_not_a_service_outage_but_a_real_outage_is`, `test_m1_runner_tags_auth_and_config_causes`, `test_m1_policy_floors_apply_with_production_settings` |
| M2 stalled worker | **Fixed** | `timeout_seconds` is now the wall-clock budget of the whole check: the runner runs in its own thread, in-loop deadline checks plus socket close on expiry, abandoned threads capped at 32; per-pass batch bounded (`monitor_parallelism * 4`), pool never joined on stuck threads. The worker has separate job and monitor threads; the heartbeat timer only writes while both make progress (`monitor_stall_seconds`, job timeout + 30 s), and `run_once` no longer beats on its own inside the Worker | `test_m2_trickling_target_is_cut_at_the_overall_deadline[http,imap_login]`, `test_m2_stuck_check_threads_are_capped`, `test_m2_a_stalled_monitor_does_not_block_jobs_and_turns_the_heartbeat_stale`, `test_m2_heartbeat_stays_fresh_while_both_loops_progress` |
| M3 stale high-risk plans | **Fixed** | A pending/queued attempt of any age blocks new ones; recovery, disabling, a non-critical check or a 4 h TTL supersedes the attempt (plan `rejected`, secret wiped, queued job failed, audit `plan.superseded`); `decide_plan` refuses to approve a stale remediation and `_exec_runbook` re-checks immediately before the agent call | `test_m3_pending_approval_blocks_new_attempts_even_after_the_window`, `test_m3_recovery_supersedes_the_plan_and_approving_it_executes_nothing`, `test_m3_approval_of_a_plan_whose_check_recovered_is_refused_even_if_it_was_not_superseded`, `test_m3_executor_refuses_a_queued_remediation_whose_check_is_no_longer_critical`, `test_m3_pending_plans_expire_after_their_ttl` |
| M4 one-person silencing | **Fixed** | Global or > 60 min maintenance = high (2 approvers); disabling a check, and `incident.ack` beyond 5 per user per hour = normal (1 approver other than the requester); non-suppressible `maintenance_started`/`maintenance_ended` notices; at window end a summary of suppressed alerts plus a reminder for still-open incidents (`maintenance_windows.summary_sent_at`); disabling a check with an open incident notifies all channels | `test_m4_global_or_long_maintenance_and_disabling_need_approval`, `test_m4_ack_bursts_need_a_second_person`, `test_m4_window_start_and_end_are_announced_and_suppressed_alerts_summarised`, `test_m4_disabling_a_check_with_an_open_incident_notifies_the_channels`; changed `test_maintenance_suppresses_notifications_and_remediation` (tests/test_monitor.py) |
| M5 demo credentials | **Accepted (owner)**, hardened | Scripts read `OU_DEMO_CREDS` (default `/etc/office-unbound/lab/demo-creds.json`), file created `0600` atomically (no world-readable window); README documents it. The file itself is moved by the host owner, not by this change | none (operational) |
| L1 token burn | **Fixed** | Agent: wrong guesses throttle the source (5 per 10 min, 60 total) and cost 0.5 s each; the token is never burned, it only expires | `test_wrong_guesses_throttle_the_source_but_never_burn_the_token` (tests/test_agent.py; replaces `..._burns_after_repeated_failures`) |
| L2 signing oracle | **Fixed** | Pre-authentication refusals (`not_enrolled`, `bad_format`, `bad_signature`) are unsigned `{"error": code}` and echo nothing; job id/nonce are echoed only after the signature verified; ICS requires `resp.type` = `exec`/`enroll` | `test_unauthenticated_requests_get_unsigned_answers_and_nothing_is_echoed`, `test_enrolled_agent_unauth_requests_are_unsigned_too`, `test_unenrolled_agent_executes_nothing`, `test_tampered_or_foreign_signature_rejected` (tests/test_agent.py) |
| L3 limits mismatch | **Fixed** | One `MAX_VERIFY_TIMEOUT = 45` for policy and `runbook.execute`; `job_timeout_seconds` 120 -> 180 (agent 90 + verify 45 + check 30 + slack) | `test_l3_one_verify_limit_and_a_job_budget_that_covers_the_agent_deadline` |
| L4 DNS rebinding | **Fixed** | `check_destination` result is pinned: http/ews connect to the validated IP with `Host` header and `sni_hostname` (name kept for certificate validation), tcp_tls/imap/smtp connect to the IP. The `smtp_banner` plaintext and blind-port-probe aspects remain (operator-only, ICS listens on 22/443 only); optional management-CIDR restriction not done | `test_l4_checks_connect_to_the_validated_address_not_a_second_lookup` |
| L5 quotas | **Fixed** | Max 200 checks, min interval 15 s (30 s for credentialed kinds), 20 000 results per check (pruned with the age retention) | `test_l5_check_count_and_interval_quotas`, `test_l5_check_results_are_capped_per_check` |
| L6 small items | **Partly fixed** | Done: replay journal fsyncs the directory (`test_replay_journal_fsyncs_the_directory`), agent connection cap (H1), response `type` check (L2), remediation requires the check owner to still be operator or higher (`test_l6_a_demoted_check_owner_no_longer_requests_restarts`). Not done: binder as requester, `node.disable` action, key-rotation documentation | |

Production notes: run `ics-migrate` (0006d) before restarting `ics`; the new defaults tighten existing checks (interval floor and the remediation floors apply to newly created/bound checks only; existing rows are not rewritten). The agent on ou-gw1 must be redeployed for L1/L2/L6 (an old agent keeps the old token-burn and signed pre-auth refusals).
