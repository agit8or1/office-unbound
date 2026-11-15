# ICS backend security review, 2026-11-15

Scope: `/home/administrator/office-unbound/ics/` (FastAPI, SQLAlchemy, Postgres), checked against ADR-0002 (`docs/adr/0002-ics-security-model.md`) and `ics/README.md`. This was an independent review and no project files were changed. The existing suite passes (31 tests). The probes ran against `ics_test` only. They live in `/tmp/claude-1000/-home-administrator/a1d917f8-7438-424e-a57a-793b46deb95e/scratchpad/secreview/probe/` (`test_probes.py`, `slowdrip.py`). No secret values were printed.

Labels: **CONFIRMED** means a probe demonstrated it. **PLAUSIBLE** means it was established by reading the code and not exercised.

## Summary

| # | Severity | Finding | Status |
|---|---|---|---|
| H1 | High | The Proxmox token secret leaks into `jobs.error` (visible to every viewer) and into the append-only audit log | CONFIRMED |
| H2 | High | An admin can defeat "requester can never approve": they create a sockpuppet approver, and receive its password and TOTP secret | CONFIRMED |
| H3 | High | The runtime process loads the DB owner credentials, which defeats the audit-table grant separation | CONFIRMED |
| M1 | Medium | TOTP replay protection races: one code gives N sessions when the logins are concurrent | CONFIRMED |
| M2 | Medium | A non-ASCII TOTP or CSRF value raises 500. This gives a password oracle that bypasses TOTP, and the attempt is neither recorded nor audited | CONFIRMED |
| M3 | Medium | Any unauthenticated client can lock out any account, admin included (per-username lockout, extended indefinitely) | CONFIRMED |
| M4 | Medium | A remote endpoint can permanently break audit-chain verification (jsonb numeric round-trip), so `/readyz` returns 503 | CONFIRMED |
| M5 | Medium | The approval is not bound to the parameters it approved, and endpoint trust anchors are not integrity-bound | CONFIRMED (plans) / PLAUSIBLE (endpoints) |
| M6 | Medium | `/docs` loads unpinned Swagger UI from a CDN without SRI, on the same origin as the authenticated API | CONFIRMED (HTML) / PLAUSIBLE (impact) |
| M7 | Medium | The vault key and the env file are readable by the interactive sudo user that runs the app | CONFIRMED (dev host) |
| M8 | Medium | The worker has no job deadline or response-size cap, so one slow endpoint stalls all jobs | CONFIRMED |
| L1 | Low | `X-Forwarded-For` is trusted from 127.0.0.1 by default in uvicorn, so the audit IP and per-IP limits can be spoofed | CONFIRMED |
| L2 | Low | Crashed jobs stay `running` forever and the plan secret is never wiped | CONFIRMED |
| L3 | Low | No destination restriction on `base_url` (SSRF surface: metadata/loopback/RFC1918) | CONFIRMED (accepted) |
| L4 | Low | The audit chain can be extended with forged but valid entries by `ics_app` (no authenticity) | CONFIRMED |
| L5 | Low | The two-approver rule for high risk is not implemented (ADR-0002 item 5) | CONFIRMED (known gap) |
| L6 | Low | Deeply nested YAML in preview returns 500, and there is no request body size limit | CONFIRMED |
| L7 | Low | Vulnerable dependency versions (starlette 0.41.3, cryptography 44.0.0, pytest 8.3.4). None are reachable as used today | CONFIRMED (pip-audit) |
| L8 | Low | Small items: cookie hardening, unauthenticated `/openapi.json` and `/readyz` detail, no session revoke-all, no plan expiry, unbounded snapshots, token secret charset | mixed |

No Critical findings.

---

## High

### H1. The token secret leaks into `jobs.error` and the immutable audit log. CONFIRMED
- **Where:** `ics/ics/proxmox.py:84-88` interpolates the transport exception (`{e}`) into `ProxmoxError`. `ics/ics/actions.py:161-162` stores `str(e)[:500]` in `jobs.error`. `actions.py:169-170` writes the same string into the `job.failed` audit details. `actions.py:31` accepts any characters in `token_secret`. `audit.scrub` (`audit.py:27-36`) only redacts by key name, never by value.
- **Evidence:** probe `test_p15` registers with `token_secret = "<marker>\n"`, which is a realistic trailing newline from copy-paste. h11 rejects the header with `Illegal header value b'PVEAPIToken=…=<secret>\n'`, and that text ends up in `GET /api/v1/jobs/{id}` (viewer role) and in `audit_events`. Result: `secret marker in GET /jobs: True, in audit: True`.
- **Failure scenario:** an operator pastes a token with a trailing newline. The approver approves. The full Proxmox token is now readable by every viewer and is permanently stored in an audit table that `ics_app` cannot delete from. This violates ADR-0002 item 4.
- **Minimal fix:**
  - Constrain `token_secret` to the PVE format (UUID, `^[0-9a-fA-F-]{36}$`, or at least printable ASCII with no whitespace) and strip it.
  - In `_get`, never interpolate the exception text. Use only `type(e).__name__`, or a fixed message per exception class.
  - In `run_job`, redact any known secret values (from `secrets_`) out of the error string before storing it.
  - Add a regression test.

### H2. One admin can approve their own plan through a sockpuppet. CONFIRMED
- **Where:**
  - `ics/ics/auth.py:39-53`: the admin chooses the new user's password, and the server generates the TOTP secret and returns it to the admin.
  - `ics/ics/main.py:110-119`: `POST /users` returns `totp_provisioning_uri`.
  - `ics/ics/actions.py:116`: self-approval is checked only by `requested_by == user.id`.
- **Evidence:** probe `test_p1`. The admin creates an `endpoint.register` plan, and the admin's own approval is refused with 403. The admin then calls `POST /users` with role approver, uses the returned URI to log in as the new user, and approves. The job succeeded.
- **Failure scenario:** a single compromised or rogue admin account executes high-risk actions with no second human. The four-eyes control in ADR-0002 items 1 and 5 does not hold against admins. In practice the admin also permanently holds both factors of every account they create, because there is no forced password change and no TOTP re-enrollment.
- **Minimal fix:**
  - Do not return the TOTP secret to the creating admin. Issue a one-time enrollment token instead: the user sets their own password and enrolls TOTP, and the account is not usable until the user verifies a code.
  - Make `decide_plan` refuse approvers created or role-changed by the requester, or require a user to be at least N hours old and not created by the requester.
  - Audit-alert when a newly created user approves a plan of their creator.
  - Longer term, user creation itself should be a two-person action.

### H3. The runtime app holds the DB owner credentials. CONFIRMED
- **Where:** `ics/ics/config.py:28,49` (`migrate_database_url` is loaded into the runtime `Settings`). The single `/etc/office-unbound/ics.env` contains `ICS_MIGRATE_DATABASE_URL` (key present, value not read). `migrations/env.py:6` and the README both use this one file.
- **Evidence:** probe `test_p5`: `rt.settings.migrate_database_url is not None` and it names `ics_owner`.
- **Failure scenario:** any code execution or file read in the app process gives `ics_owner`. That role can `UPDATE`, `DELETE` and `TRUNCATE` `audit_events` and rewrite the whole chain. This voids the least-privilege grant in migration 0001 (`0001_init.py:103`) and ADR-0002 item 6, because the app can trivially become the owner.
- **Minimal fix:**
  - Put the owner URL in a separate file (for example `/etc/office-unbound/ics-migrate.env`, mode 0600, owned by the deploy or admin user) that the service user cannot read.
  - Have `load_settings()` for the server not read `ICS_MIGRATE_DATABASE_URL` at all. Only Alembic and the tests should.

## Medium

### M1. TOTP replay through concurrent logins. CONFIRMED
- **Where:** `ics/ics/auth.py:75` reads the user row without `FOR UPDATE`. `auth.py:90-94` checks `s > row.last_totp_step` against that stale value, and then runs an unconditional `UPDATE users SET last_totp_step = :s`.
- **Evidence:** probe `test_p2`. Four concurrent logins with the same code returned `[200, 200, 200, 200]` and created 4 sessions. The argon2 verify between the read and the write (about 50 ms or more) makes the race window wide.
- **Failure scenario:** an attacker who has the password and observes one TOTP code (shoulder-surfing, a phishing relay) races the victim's own login and gets their own session.
- **Minimal fix:** make the step update atomic and conditional, and treat zero affected rows as a TOTP failure:
  ```sql
  UPDATE users SET last_totp_step = :s WHERE id = :id AND last_totp_step < :s
  ```
  `SELECT … FOR UPDATE` on the user row also works.

### M2. Non-ASCII input gives a 500 and an unaudited password oracle. CONFIRMED
- **Where:** `ics/ics/auth.py:91` calls `hmac.compare_digest(totp.at(...), totp_code)`. `auth.py:144` calls `hmac.compare_digest(sent, row.csrf_token)`. Both raise `TypeError` when the input is not ASCII.
- **Evidence:** probe `test_p4`. `totp_code="é"` with the correct password returns 500, and `login_attempts` for the user is 0 (nothing recorded and nothing audited). A wrong password with the same input returns 401 instead, because the password check comes first. A CSRF header of `b"\xe9\xe9\xe9"` returns 500 instead of 403, and no `auth.csrf_rejected` event is written.
- **Failure scenario:** the 500 versus 401 difference reveals whether a password is correct without the TOTP. Such a guess leaves no `auth.login_failed` row, and a correct guess consumes no lockout budget. This undermines the uniform "invalid credentials" design and lets an attacker validate credential-stuffing hits silently.
- **Minimal fix:** before comparing, require `totp_code` to match `^\d{6}$` and treat anything else as `bad_totp`. Compare the CSRF value as bytes (`sent.encode("latin-1", "replace")`, `row.csrf_token.encode()`), or reject non-ASCII input with 403 through the normal audited path.

### M3. Unauthenticated lockout of any account, including the break-glass admin. CONFIRMED
- **Where:** `ics/ics/auth.py:56-62,73-74`. Five failures per username in 15 minutes produce 429 even for correct credentials. Every 429 is itself inserted as a failure (`fail("rate_limited")`), so the lockout persists for as long as the attacker keeps sending about one request every 15 minutes.
- **Evidence:** probe `test_p3`, plus the existing `test_rate_limit`. After 5 bad attempts from anyone, the legitimate admin with a valid password and TOTP gets 429.
- **Failure scenario:** ADR-0002 item 1 says ICS doubles as break-glass. An attacker who knows or guesses usernames can keep every admin and approver locked out during an incident.
- **Minimal fix:**
  - Do not count `rate_limited` responses as new failures.
  - Key the throttle on (username, IP) plus a global per-IP limit, rather than on username alone.
  - Use exponential backoff instead of a hard lock, or exempt a client that presents a valid TOTP after a valid password. Since TOTP is mandatory, online password guessing is already bounded by the second factor.

### M4. A remote endpoint can break audit-chain verification permanently. CONFIRMED
- **Where:**
  - `ics/ics/audit.py:23-24`: `canon` hashes Python `json.dumps` output.
  - `audit.py:68`: details are stored as `jsonb`.
  - `audit.py:88`: verify re-canonicalizes the value read back from `jsonb`.
  - `ics/ics/actions.py:210-211`: `pve_version` comes straight from the remote `/version` response.
- **Evidence:** probe `test_p10`. The mock PVE returns `"version": 1e16`. Python hashes `1e+16`, jsonb stores `10000000000000000`, and the value reads back as an int. `audit/verify` then reports `ok: False`, with `altered` on 2 rows, and `/readyz` returns 503. The rows can never be fixed, because `ics_app` cannot UPDATE.
- **Failure scenario:** a compromised or malicious registered endpoint, or simply an odd value, makes the audit log look tampered with forever. This creates false alarms and hides real tampering in the noise, and readiness stays red.
- **Minimal fix:** compute the hash over exactly the stored bytes. Store the canonical text in a `text` column (for example `details_canon`) and verify against it. Alternatively, restrict details to strings, ints and bools by coercing remote values with `str()`.

### M5. Approvals and endpoint trust are not integrity-bound. CONFIRMED (plans) / PLAUSIBLE (endpoints)
- **Where:**
  - `ics/ics/actions.py:123-127`: approval records only `{"action"}`, with no parameter digest.
  - `actions.py:154-158`: the job re-reads `plans.params` and executes whatever is there.
  - `actions.py:174-176`: `base_url`, `fingerprint_sha256` and `ca_pem` are used from the endpoint row. The vault AAD binds the token only to `endpoint-token:{id}` (`actions.py:175,206`), not to the trust anchor.
  - Migration `0001_init.py:101-102` gives `ics_app` UPDATE on `plans` and `endpoints`.
- **Evidence:** probe `test_p7`. After approval, an `ics_app` `UPDATE plans SET params = …` changed the endpoint name, and the job registered `swapped-name`. By inspection, the same works for `base_url` and `fingerprint_sha256`, and for an existing endpoint's `base_url` and `fingerprint` before an auto-approved `inventory.refresh`.
- **Failure scenario:** any SQL write primitive (a future injection, or H3) silently redirects an approved action, or sends the decrypted inventory token to an attacker's host whose cert matches the new pin. The audit log shows a clean approval.
- **Minimal fix:**
  - At approval, store and audit `sha256(canon(params) || secret_enc)`. The job must recompute it and refuse on mismatch.
  - Include `base_url`, `token_id` and the fingerprint (or a hash of `ca_pem`) in the endpoint token's AAD, for example `endpoint-token:{id}:{base_url}:{fp}`, so that changing the trust anchor makes decryption fail.

### M6. Swagger UI is loaded from a CDN on the API origin. CONFIRMED (HTML) / PLAUSIBLE (impact)
- **Where:** `ics/ics/main.py:64` uses FastAPI's default `docs_url`. The page loads `https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js`, which floats on the major version and has no SRI.
- **Failure scenario:** a compromised CDN or package release runs script on the ICS origin. That script can call `GET /auth/me` to read the CSRF token, and then make any API call as the logged-in operator or approver (SameSite does not help, because the call is same-origin). The README advertises `/docs`.
- **Minimal fix:** `FastAPI(docs_url=None, redoc_url=None, openapi_url=None)` in production, or self-host pinned Swagger assets with a strict CSP.

### M7. Key and config permissions on the host. CONFIRMED (dev)
- **Where:** `/etc/office-unbound/vault.key` and `ics.env` are `root:administrator 0640`. `administrator` (uid 1000) is the interactive login and a member of `sudo`/`admin`, and the app runs as this user. `ics/ics/vault.py:22-26` loads the key without checking owner or mode.
- **Failure scenario:** anything running as the desktop/admin user (an editor plugin, an agent, a browser exploit) reads the vault key and both DB URLs. This does not match ADR-0002 item 4 ("readable only by the ICS service user").
- **Minimal fix:**
  - Run the service as a dedicated system user, with the key at `root:ics-svc 0640` (or 0400 owned by `ics-svc`), or load it through systemd `LoadCredential=`.
  - In `Vault.from_file`, refuse a key file that is group- or world-readable beyond the service group, or that is not a regular file.

### M8. No job deadline or size cap: one endpoint can stall the worker. CONFIRMED
- **Where:** `ics/ics/proxmox.py:78` sets `timeout=10`, but in httpx that is a per-read timeout, not a total. Responses are buffered with no size limit (`r.json()`). `ics/ics/worker.py:34-41` runs a single serial thread.
- **Evidence:** `slowdrip.py`. A pinned server that dribbles 1 byte every 6 seconds completed `version()` after 30 seconds despite `timeout=10`. The same server can stream an unbounded body.
- **Failure scenario:** a misbehaving or compromised endpoint holds the only worker indefinitely, or exhausts its memory. All other jobs, including other customers' inventory, stop. Heartbeats also stop, because heartbeat runs only between jobs.
- **Minimal fix:**
  - Wrap each request in an overall deadline: stream with `client.stream()`, check elapsed time, and enforce a maximum byte count (for example 16 MiB).
  - Give each job a wall-clock budget.
  - Move the heartbeat to its own timer thread.

## Low

### L1. `X-Forwarded-For` spoofing through uvicorn defaults. CONFIRMED
`ics/ics/auth.py:124-125` uses `request.client.host`. uvicorn 0.34 defaults to `proxy_headers=True` with `forwarded_allow_ips=127.0.0.1`, and the README binds to 127.0.0.1. Probe `test_p14` sent `X-Forwarded-For: 203.0.113.77` from localhost, and that IP was recorded in `login_attempts` and in audit. Any local process, or a proxy that does not overwrite the header, can forge audit IPs and get a fresh per-IP budget on each attempt.

**Fix:** run uvicorn with `--no-proxy-headers` until a proxy exists. When one does, set `--forwarded-allow-ips` to exactly that proxy and have the proxy overwrite the header, not append to it.

### L2. Crashed or failed-finalize jobs are stuck, and the secret is retained. CONFIRMED
`ics/ics/actions.py:136-147` provides no lease or expiry. If `run_job`'s final transaction (`actions.py:163-171`) fails, or the process dies, the job stays `running` forever and `plans.secret_enc` is never nulled. Probe `test_p8` shows `job running`, `secret still stored: True`, and the job cannot be reclaimed. The README notes the missing recovery, but not the secret retention.

**Fix:**
- Add `lease_expires_at` to jobs.
- Add a reaper that marks expired `running` jobs `failed` (never re-runs them, to keep at-most-once execution) and nulls `secret_enc`.
- Wrap the finalize step in a retry.

### L3. No restriction on `base_url` destinations. CONFIRMED (accepted at plan creation)
`ics/ics/actions.py:35-41` checks only the scheme and the shape of the URL. Probe `test_p9` shows plans for `https://169.254.169.254`, `https://127.0.0.1:5432`, `https://localhost:8088`, `https://[::1]:22` and `https://10.0.0.1:8006` were all accepted (201). Actual reach is limited, because a connection only happens after approval, TLS must pass the pin or CA check, and the request is a fixed GET to `/api2/json/...` that requires a JSON `data` key. It is still a probe primitive, and the approver has no help judging it.

**Fix:**
- Resolve the host at plan creation and at execution, and reject loopback, link-local, metadata and the ICS host's own addresses.
- Optionally keep an allowlist of management CIDRs.
- Show the resolved IP to the approver.

### L4. `ics_app` can append forged but valid audit entries. CONFIRMED
Probe `test_p6` shows that `ics_app` UPDATE, DELETE and CREATE are correctly denied, but an `audit.append()` of a fake `plan.approve` passes `verify_chain`. This is inherent to an unkeyed chain, and the code comments are honest that the chain gives integrity, not authenticity.

**Fix:** periodically export a signed head (seq, hash) to an off-host sink, using a key not available to the app. This is already on the README list. Also restrict explicit `seq` inserts, for example with a trigger owned by `ics_owner` that rejects `seq` not equal to `max+1` and `prev_hash` not equal to the tail hash. The trigger also makes forking impossible even without the advisory lock.

### L5. The two-approver rule is missing. CONFIRMED (documented gap)
`ics/ics/actions.py:68,111-131` approves a high-risk plan with one decision. Combined with H2, high-risk actions effectively need only one admin. Track this together with H2.

### L6. Input-size and parser robustness. CONFIRMED
`ics/ics/blueprint.py:58` (`yaml.safe_load`) raises `RecursionError` on 50k nested brackets, which is not caught at `blueprint.py:62-67` and returns 500 (probe `test_p13`). `main.py:192` checks the 200k limit only after the whole JSON body is parsed, and there is no request body cap anywhere. That includes `login.password`, which is fed to argon2, and `users.password`, which has no maximum.

**Fix:**
- Cap the request body (at the proxy, or with an ASGI middleware, for example 256 KiB).
- Give passwords a maximum length (for example 1024).
- Catch `RecursionError` in the preview and return `{valid: false}`.

### L7. Dependencies (pip-audit 2026-11-15, installed set). CONFIRMED
- **starlette 0.41.3** (pulled in by fastapi 0.115.6):
  - CVE-2025-54121 (multipart, fixed in 0.47.2).
  - CVE-2025-62727 (FileResponse Range, fixed in 0.49.1).
  - CVE-2026-48710 and CVE-2026-54282 (Host header and path injection into `request.url`, fixed in 1.0.1 and 1.3.0). These are marginally reachable: `request.url.path` goes into audit details at `auth.py:146,156`. Use `request.scope["path"]` instead.
  - CVE-2026-48817/48818 (HTTPEndpoint, StaticFiles on Windows) and CVE-2026-54283 (urlencoded form limits): not used.
- **cryptography 44.0.0:**
  - CVE-2024-12797 and GHSA-537c (bundled OpenSSL).
  - CVE-2026-26007 (EC public key validation).
  - CVE-2026-34073, 69248 and 69249 (x509 verifier).
  - CVE-2026-69247 (PKCS7).
  - ICS uses only AESGCM, and TLS goes through the stdlib `ssl` module and system OpenSSL, so none of these are reachable today. Upgrade anyway, to 50.x or later.
- **pytest 8.3.4:** CVE-2025-71176 (`/tmp/pytest-of-user` dir; affects dev hosts only).
- **Fix:** move to fastapi/starlette with starlette 1.3.1 or later, and cryptography 50 or later. Pin transitive dependencies with hashes (`pip-compile --generate-hashes`). Today only top-level packages are pinned, so starlette, h11, httpcore and pydantic-core float.

### L8. Smaller items
- The cookie lacks the `__Host-` prefix (`main.py:96`). Rename it to `__Host-ics_session`, which forces Secure, `path=/` and no Domain.
- `/openapi.json` and `/docs` are unauthenticated (probe `test_p12`). `/readyz` publishes the audit head hash and the worker heartbeat age without authentication (`main.py:72-90`). These are low value, but consider binding them to localhost or a monitoring token.
- No "log out all sessions", no revocation on future role or disable changes (the disabled flag is checked per request, which is good), and no limit on concurrent sessions.
- TOTP accepts `step+1`. A code from the next window advances `last_totp_step`, so a legitimate current code is then refused for up to 30 seconds. This is a usability issue only.
- Pending plans never expire and keep `secret_enc` indefinitely. `inventory.refresh` is auto-approved and unthrottled, and snapshots are unbounded (a storage DoS by any operator).
- `token_id` regex `[^\s!@]+` allows `=`, which confuses the `PVEAPIToken=id=secret` format. Tighten it to `[A-Za-z0-9._-]+`.
- `ca_pem` is checked only by substring. Parse it with `x509.load_pem_x509_certificates` at plan time, and reject non-CA certificates and expired roots, so that the approver sees subject and fingerprint.

---

## Checked and found sound
- **TOTP before access:** a session row is created only after password and TOTP succeed (`auth.py:97-103`). There is no partially authenticated state, and every route except login, healthz, readyz and docs depends on `current_user`. No route is reachable before TOTP.
- **Argon2:** argon2id with t=3, m=64 MiB, p=4, a 32-byte hash and a 16-byte salt (argon2-cffi defaults, RFC 9106 second recommendation). A dummy hash for unknown or disabled users equalizes timing. Wrong password, wrong TOTP and unknown user all return the same 401 body, apart from M2.
- **Sessions:** 256-bit random tokens, stored as SHA-256 only. A new token is issued at each login, so there is no fixation. There is a 12-hour absolute expiry and a 1-hour idle expiry, both enforced server-side. Logout deletes the row. Disabled users are rejected on every request. The cookie is HttpOnly, Secure by default (not overridden in `ics.env`), `SameSite=Strict` and `path=/`.
- **CSRF:** a per-session synchronizer token is required in a header on every non-GET/HEAD/OPTIONS route, and comparison is constant-time. No CORS is configured, so other origins cannot read `/auth/me`. All GET routes are read-only. Apart from M2 and M6, the design is sound.
- **Role checks:** every route was inspected. Viewer covers catalog, plans, jobs, endpoints and inventory. Operator covers creating plans and preview. Approver covers approve, reject and audit. Admin covers users. `test_roles` and the probes agree. Self-approval and self-rejection are both blocked. Concurrent double approval is serialized by `FOR UPDATE`, and the second request gets 409. `jobs.plan_id UNIQUE` guarantees at most one job per plan. A rejected plan has its secret wiped. IDOR is not applicable: there is a single tenant and every viewer sees everything by design, and no secret columns are selected (`main.py:171`).
- **Catalog:** a closed enum with `extra="forbid"`. The job re-validates parameters with the same model (`actions.py:158`). The secret is split into `secret_enc` and never stored in `params`, the API or audit (except H1). `base_url` is rebuilt from the netloc, which drops path, `;params`, query and userinfo. There is no file path parameter: `ca_pem` is passed as `cadata` (in-memory PEM), so a parameter cannot read local files. Node names are regex-checked before use in a path.
- **TLS pinning (`proxmox.py`):**
  - The pin is checked inside `wrap_socket` immediately after the handshake (`do_handshake_on_connect` is the default) on the same socket that httpcore then uses. httpcore 1.0.9 `SyncStream.start_tls` calls `ssl_context.wrap_socket`.
  - There is no second connection and no proxy (`trust_env=False`). `follow_redirects=False`, and anything other than 200 is rejected.
  - HTTP/2 is off. TLS 1.2 is the minimum.
  - The existing test proves that a wrong pin sends no HTTP request and no token.
  - CA mode uses only the supplied bundle (`create_default_context(cadata=…)` does not load system roots when `cadata` is given), with hostname checking on.
  - Skipping hostname and expiry checks in pin mode is acceptable for a leaf pin.
- **Vault:** AES-256-GCM with a random 96-bit nonce per encryption and a version byte. AAD binds each blob to its row, so a probe swap between rows fails, as covered by the existing `test_vault_audit`. The key must be exactly 32 bytes. Decryption failure is a hard `VaultError` with no fallback, and the error message contains no key material. Gaps are noted in M5 (AAD scope) and M7 (permissions).
- **Audit chain concurrency:** `pg_advisory_xact_lock` is held until commit, and `seq` is assigned under the lock. Under READ COMMITTED the next writer sees the committed tail, so the chain cannot fork between app writers or the CLI. Gaps from rollbacks do not matter, because links use `prev_hash`, not `seq`. Lock ordering (plan or job row, then advisory lock) is consistent, so no deadlock was found. The hash input `prev||"\n"||canonical-json` is unambiguous, because `prev` has a fixed length. The migration grants were verified live: `ics_app` gets InsufficientPrivilege on UPDATE and DELETE of `audit_events` and on CREATE TABLE.
- **Job claim:** `FOR UPDATE SKIP LOCKED` with an immediate commit of `running` gives at-most-once execution (the existing race tests use 8 threads).
- **Logs:** no request bodies are logged. The worker logs `log.exception` tracebacks without local variables. uvicorn access logs contain paths only.
- **Blueprint preview:** `yaml.safe_load` (no object construction), a strict schema and dry-run only.

## Not verified
- `pg_hba.conf` and the Postgres server configuration (the README says scram over 127.0.0.1).
- Production deployment: the service user and TLS termination do not exist yet.
- Behaviour behind a real reverse proxy (see L1).

---

## Remediation (2026-11-15)

All tests are in `ics/tests/test_security_review.py` unless noted. Suite: `cd ics && .venv/bin/pytest` (79 passed). Service: `ics.service` runs as system user `ics` on 127.0.0.1:8088 (`ics/deploy/`).

| Finding | Status | What changed | Test(s) |
|---|---|---|---|
| H1 | fixed | `token_secret` is stripped and restricted to `[A-Za-z0-9_-]{8,200}`; the client re-validates and never echoes transport text (class name only, except TLS/connect errors); job errors, results and audit details go through `audit.redact` (known secret values in raw/stripped/escaped form plus any `PVEAPIToken=` pattern); non-whitelisted exception types return a generic message; `audit.scrub` also masks `PVEAPIToken=` | `test_h1_trailing_newline_secret_is_normalised_and_never_leaks`, `test_h1_bad_secret_rejected_without_echo`, `test_h1_job_error_and_audit_are_redacted`, `test_h1_unknown_exception_text_is_not_passed_through`, `test_h1_redact_unit`, `test_h1_proxmox_errors_do_not_echo_transport_text` |
| H2 | fixed | Accounts are created as invites with no credentials; the one-time enrollment token is issued on the host by `ics.cli`; users set their own password and TOTP (`auth/enroll`, `auth/enroll/confirm`). approver/admin creation and any role change are high-risk plan actions (`user.create`, `user.set_role`, admin-only). Provenance (`created_by`, `role_set_by`) blocks an approver created/elevated by X (directly or via a chain) from deciding X's plans. Residual host-root risk documented in the README | `test_h2_no_credentials_returned_and_only_viewer_operator_via_api`, `test_h2_invited_user_cannot_login_until_enrolled_and_sets_own_credentials`, `test_h2_approver_creation_needs_second_approver_and_is_recorded`, `test_h2_sockpuppet_approver_cannot_approve_creators_plans`, `test_h2_elevation_is_a_high_risk_plan_with_provenance` |
| H3 | fixed | `Settings` has no owner URL; owner URL is only in `/etc/office-unbound/ics-migrate.env` (root 0600), read by `load_migrate_url()` for Alembic / `ics.migrate` / `ics-migrate.service` | `test_h3_app_settings_have_no_owner_credentials`, `test_h3_runtime_role_is_not_owner`, `test_h3_deployed_config_split` |
| M1 | fixed | TOTP step consumed with `UPDATE ... WHERE last_totp_step < :s` and `rowcount == 1` | `test_m1_concurrent_logins_with_one_code_yield_one_session` |
| M2 | fixed | TOTP must match `^[0-9]{6}$` (else audited `bad_totp`); CSRF compared as bytes | `test_m2_non_ascii_totp_and_csrf_are_clean_failures` |
| M3 | fixed | Per-(username, IP) exponential backoff (15 s base, 15 min cap), 429 responses neither recorded nor audited, coarse per-IP limit, success resets; CLI `issue-enrollment`/`unlock` never throttled | `test_m3_lockout_is_per_user_and_ip_and_does_not_extend_itself`, `test_m3_backoff_is_exponential_and_capped`, `test_m3_cli_break_glass_is_never_locked`; updated `test_auth.py::test_rate_limit` |
| M4 | fixed | Audit v2 hashes the exact stored `details_canon` text; remote data sanitised (floats, huge ints, unknown types become strings); `canon` rejects NaN/Infinity; inventory numbers sanitised | `test_m4_remote_numeric_value_cannot_break_verification`, `test_m4_canon_rejects_nonfinite_and_sanitize_handles_everything` |
| M5 | fixed | `params_hash` over action, params, secret ciphertext digest and endpoint binding; stored in an insert-only `plan_approvals` table at approval; job recomputes and refuses on mismatch; endpoint token AAD includes the trust-anchor binding | `test_m5_params_tamper_after_approval_is_refused`, `test_m5_endpoint_trust_anchor_tamper_is_refused`, `test_m5_tamper_after_plan_creation_before_approval_on_refresh_binding` |
| M6 | fixed | `/docs`, `/redoc`, `/openapi.json` off unless `ICS_ENABLE_DOCS`; CSP, `frame-ancestors 'none'`, nosniff, no-referrer, X-Frame-Options, CORP, no-store on every response | `test_m6_docs_disabled_and_security_headers` |
| M7 | fixed | system user `ics`; keys/env `root:ics 0640`, `/etc/office-unbound` 0711, `administrator` not in group; `deploy/ics.service` (hardened), `ics-migrate.service`, `install.sh` (root-owned copy in `/opt/office-unbound/ics`); `Vault.from_file` rejects symlink/non-regular/world-accessible/group-writable files | `test_m7_vault_rejects_unsafe_key_files`, `test_m7_systemd_units_are_hardened`, `test_m7_deployed_permissions` |
| M8 | fixed | 30 s wall-clock deadline per Proxmox request, 16 MiB cap, 120 s job budget (`JobTimeout`, late commit suppressed), heartbeat in its own thread | `test_m8_overall_deadline_and_size_cap`, `test_m8_job_wall_clock_timeout_and_secret_wipe`, `test_m8_worker_has_independent_heartbeat_thread` |
| L1 | fixed | `ics.serve` runs uvicorn with `proxy_headers=False`; audit path from `request.scope["path"]` | `test_l1_uvicorn_ignores_forwarded_headers` |
| L2 | fixed | job lease + reaper (fail, never re-run, wipe secret), finalize with retry, expired pending plans wiped | `test_l2_expired_lease_job_is_failed_and_secret_wiped`, `test_l2_claim_sets_a_lease` |
| L3 | fixed | loopback/link-local/metadata/unspecified/multicast refused at plan time and at execution, resolved IPs recorded for the approver; RFC1918 stays allowed (management networks). DNS-rebinding pinning between check and connect deferred (TLS pin / CA+hostname check covers it) | `test_l3_destination_restrictions` |
| L4 | fixed | per-row HMAC with `audit.key` (not in the DB) plus DB trigger forcing `prev_hash` = tail, sequence-assigned `seq`, non-null MAC; documented that app-process compromise can still sign. Off-host signed head export is deferred (needs an external sink) | `test_l4_forged_entries_are_rejected`, `test_l4_legacy_rows_still_verify_but_are_counted` |
| L5 | fixed | high-risk plans need 2 distinct approvers (setting `required_approvals_high`, default 2); job re-verifies | `test_l5_two_distinct_approvers_required_and_job_reverifies`, `test_flow.py::test_self_approval_rejected_and_full_flow` |
| L6 | fixed | 256 KiB body cap (413), password max 1024, `RecursionError` caught in preview | `test_l6_nesting_body_cap_and_password_cap` |
| L7 | fixed | fastapi 0.163.1 (starlette 1.10.0), cryptography 50.0.2, pytest 9.2.0; `requirements.txt` top-level pins plus `requirements.lock` (all transitive deps, hashes); `pip-audit` on the lock: no known vulnerabilities | `test_l7_dependencies_are_patched_and_pinned` |
| L8 | partly fixed | fixed: `__Host-` cookie, `token_id` charset, `ca_pem` parsed, `/readyz` booleans only, `logout-all`, 10-session cap, plan expiry (7 d), snapshot retention (50). Deferred: TOTP `step+1` acceptance (usability only; the test helper relies on it), no per-user session listing UI | `test_l8_cookie_host_prefix_and_logout_all`, `test_l8_input_validation_and_readyz_is_minimal`, `test_l8_snapshot_retention_and_plan_expiry` |

Deferred: off-host signed audit-head export (L4 tail truncation), DNS answer pinning (L3), TOTP forward-window (L8). Test infrastructure changed: the suite no longer reads `ics.env`; it uses `/etc/office-unbound/ics-test.env` (roles `ics_test_owner`/`ics_test_app`, database `ics_test` only) and throwaway keys in a temp dir.
