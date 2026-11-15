# ICS monitoring, alerting, node agent: results (2026-11-15)

Status vocabulary (ADR-0000): **VERIFIED-IN-LAB** = executed in this session against `ou-gw1`, output quoted below. Unit/integration tests: `cd ics && .venv/bin/pytest` -> **151 passed** (79 before this slice + 72 new: `test_ops_api` 6, `test_agent` 28, `test_checks` 14, `test_monitor` 24; frontend `npm test` 7 passed, `vue-tsc` clean, build ok). Security-review remediation tests (`test_security_review.py`) are untouched and pass.

## What was built
| Part | Where | Status |
|---|---|---|
| A. `GET /users`, richer `GET /plans` (`params_hash`, requester, approvers, count), `auth/me`+login `id`, `audit?before_seq`, `jobs?status&limit`, `endpoints/{id}/inventory/refresh-state` | `ics/ics/main.py`, `tests/test_ops_api.py` | tested |
| B. checks (http, tcp_tls, imap_login, smtp_banner, ews_getfolder), scheduler, time series + retention, ok/warning/critical/unknown with flap damping | `checks.py`, `monitor.py`, migration `0003` | tested; all five kinds VERIFIED-IN-LAB on ou-gw1 |
| C. incidents (dedupe, ack, recovery, escalation), maintenance suppression, outbox; email + webhook (HMAC); pushover/sms interface only, disabled (ADR-0007) | `monitor.py`, `alerts.py` | tested; email VERIFIED-IN-LAB (relay ou-gw1:25, STARTTLS verified vs lab CA, receipt read back over IMAP); webhook tested against a local TLS receiver only |
| D. node agent, enrollment, Ed25519 both ways, replay journal, allowlist, polkit | `ics/agent/`, `ics/ics/agentclient.py` | tested; VERIFIED-IN-LAB |
| E. remediation policy | `monitor.py`, `actions._exec_runbook` | tested; auto-restart and escalation VERIFIED-IN-LAB |
| G. UI | `frontend/src/views/{Checks,Incidents}.vue` (real API data only) | built into `ics/ics/static`, typecheck + vitest pass; **not exercised in a browser** |

## Lab setup on ou-gw1 (only the agent was installed; no groupware config touched)
- Agent unit `ou-agent.service`, user `ou-agent`, listening `192.168.186.218:8443` (the lab IP), allowlist in root-owned `/etc/ou-agent/agent.json`: restart/status for `gromox-http gromox-imap gromox-delivery nginx php8.2-fpm postfix mariadb`, `disk.usage` for `/ /var/lib/mysql /var/lib/gromox`. The exact unit stopped in the demo is `gromox-imap.service`.
- Privilege: polkit rule only (`restart` of those 7 units for `ou-agent`). Checked on the node: `setpriv --reuid=ou-agent ... systemctl stop console-getty.service` -> `Access denied`.
- Enrollment (via API plan `node.enroll`, 2 approvers): agent public key + TLS cert fingerprints supplied from the node console; ICS verified both before sending the token. Reported capabilities were stored.
- Checks (interval 10 s, recover after 2 ok): `gw1-imap-login` (frank@, vault password, SELECT INBOX, fail_threshold 3, **bound policy**: `service.restart gromox-imap`, auto, 3 attempts / 900 s, backoff 10 s, verify 45 s), `gw1-ews-getfolder` (EWS GetFolder inbox, ok = Success/NoError), `gw1-web-http` (`/web/` 200), `gw1-imaps-cert` (tcp_tls 993, warn 21 d / crit 7 d, threshold 2), `gw1-smtp-banner` (25, "ESMTP"). All TLS checks verified against the lab CA, no pins disabled.
- Alert channel `mail-grace`: SMTP `gw1.ou-lab.internal:25` STARTTLS (CA verified) -> `grace@gw1.ou-lab.internal`; receipt read via IMAPS as grace.

## Acceptance 15/16: auto-recovery demo (`ics/scripts/lab_monitoring_demo.py failure`, real output, UTC)
```
17:10:01.082Z  BASELINE all ok; stopping gromox-imap inside ou-gw1 (simulated failure)
17:10:02.104Z  T0 gromox-imap stopped (rc=0)
17:10:23.145Z  +  21.0s check_critical / incident_open / attempt_created
17:10:27.342Z  +  25.2s recovered_state_ok / incident_recovered
incident opened_at=17:10:22.808  recovered_at=17:10:27.115
remediation attempt #1 service.restart status=verified verified=True  at=17:10:22.820  finished=17:10:27.201
  job started=17:10:23.876 finished=17:10:27.145 result.verified=True :: check recovered: state ok after 3 s
  agent result: {"unit":"gromox-imap","sub_state":"running","returncode":0,"active_state":"active"}
EMAIL via IMAP (grace@): [OU-ICS] CRITICAL: gw1-imap-login opened     internaldate 17:10:22
EMAIL via IMAP (grace@): [OU-ICS] OK: gw1-imap-login RECOVERED        internaldate 17:10:27
```
| Interval | Value |
|---|---|
| failure -> `critical` (3 consecutive failures x 10 s, flap damping) | **21.0 s** |
| `critical` -> agent restart job started | 1.1 s |
| restart + verification (check back to ok after 2 ok results) | 3.3 s (job 17:10:23.9 -> 17:10:27.1) |
| incident duration (opened -> recovered) | 4.3 s |
| failure -> recovered (end to end) | **25.2 s** |
| recovery email visible in the lab mailbox | same second as `recovered_at` (INTERNALDATE 17:10:27) |

Notes: `gw1-imaps-cert` (tcp_tls on 993, threshold 2) correctly detected the closed port first (incident opened 17:10:15, recovered 17:10:37, email pair received) and has no policy, so it did not trigger anything. EWS, HTTP and SMTP checks stayed ok (only IMAP was stopped). Audit chain after the run: `verify-chain` ok, 145 entries, no problems. Agent journal on the node lists the request in `agent_requests` (`service.restart`, `done`, `ok`).

## Agent-level negative proofs (`ics/scripts/lab_agent_proofs.py`, real agent on ou-gw1, requests signed with the real ICS key)
```
1 valid signed service.status gromox-imap                  -> status=ok code=ok
2 REPLAY of the identical signed request                   -> status=rejected code=replay_nonce
3 same job id, fresh nonce (job ids are single use)        -> status=rejected code=replay_job
4 non-allowlisted unit sshd (service.restart)              -> status=rejected code=not_allowed
5 unit not matching exactly (gromox-imap.service)          -> status=rejected code=not_allowed
6 shell metacharacters in unit                             -> status=rejected code=not_allowed
7 unknown runbook shell.exec                               -> status=rejected code=not_allowed
8 EXPIRED request (issued 300 s ago, ttl 60 s)             -> status=rejected code=expired
9 validity window too long (600 s)                         -> status=rejected code=window_too_long
10 params tampered after signing                           -> status=rejected code=bad_signature
11 request addressed to another node id                    -> status=rejected code=wrong_node
```
ICS-side, a plan for a unit that is not on the node's reported allowlist is refused with 422 (`test_runbook_plans_validate_against_node_capabilities_and_risk`); if ICS were tampered with, the agent is still the authority (`test_agent_rejection_is_a_failed_job_with_evidence`).

## Policy stops after max attempts (`... demo.py escalate`; wrong port, services untouched)
Check `gw1-wrong-port` = `https://gw1.ou-lab.internal:8444/` (closed port), policy `service.status nginx` (read-only runbook, so nothing is restarted), 3 attempts / 900 s, backoff 5 s:
```
17:11:12.6  +10.5s critical + incident + attempt1
17:11:18.9  +16.9s attempt2          (backoff 5 s)
17:11:30.0  +27.9s attempt3          (backoff 10 s)
17:11:31.0  +29.0s escalated         (audit remediation.escalated, email "[OU-ICS] CRITICAL: gw1-wrong-port ESCALATED")
17:12:31    attempts after 60 more seconds: 3 -> [(3 failed), (2 failed), (1 failed)]   (no 4th attempt, no loop)
```
All three agent requests were `service.status` (`agent_requests`); no service on ou-gw1 was restarted by this part. The demo check was acknowledged (plan `incident.ack`) and disabled afterwards.

## Design decisions and limits
- **Push, not poll**: ICS keeps its API on 127.0.0.1 and lab machines cannot reach host services, so ICS connects to the agent's lab IP.
- TLS to the agent is pin-only (self-signed cert, fingerprint from the console), no client cert; the Ed25519 signatures provide mutual authentication and replay protection. Compromise of the ICS signing key allows any allowlisted runbook on every enrolled node (not arbitrary commands). Key rotation = re-enroll.
- Check passwords: vault AAD binds check id + config hash; they are never returned, logged or audited (test asserts none in audit/plans/jobs/API/notification mail).
- `check.create`/`check.bind_remediation` are low risk (auto-approved): an operator can therefore enable unattended restarts of allowlisted low-risk units. `service.restart mariadb` is high risk and cannot be bound as `auto`.
- Pushover/SMS are not implemented beyond interface + validation and can never be enabled (ADR-0007, no paid services). The webhook channel is only tested against a local receiver, not a real endpoint.
- The worker runs jobs and checks on one thread; a remediation verification (<= 45 s) delays other checks. Notification outbox retries 5x with backoff; no escalation channel beyond the configured ones; no on-call schedule.
- The agent has no Windows/other-distro support; `postfix` unit is the `postfix.service` meta unit on Debian; the real stop/restart of `mariadb`/`nginx` etc. through polkit was **not** exercised (only `gromox-imap` restart, plus denial of a non-allowlisted unit).
- UI pages were built and type-checked but not opened in a browser in this session. Browser-level approval of `node.enroll`/`alert_channel.create` plans is available through the existing Plans page.
