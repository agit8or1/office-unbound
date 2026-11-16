# Security review 6 (2026-11-15)

Independent review of four unmerged branches:

| # | Target | Source |
|---|--------|--------|
| 1 | Organization Admin / tenant API | `worktree-agent-a74f300af8c04d808` (commits 97b1a54..c1c5fa1) |
| 2 | MSP provisioning API | worktree `agent-a64333fb637749229`. **Not committed**: the branch has no commits beyond main, so the uncommitted working tree as of this review was read. |
| 3 | Warm standby / controller epoch | `worktree-agent-aeff4a9f67df2219b` (0c27655) |
| 4 | Golden image | `golden-at` (8f9496b) |

The reviewer did not write any of this code, and nothing except this file was modified. Line numbers refer to the file on the named branch or worktree.

**How each finding was checked:**
- **CONFIRMED (by code):** the failing path is unambiguous in the source.
- **CONFIRMED (by test):** the branch's own test exercises the path that is the problem.
- **PLAUSIBLE:** depends on deployment or an outside precondition.

Items fixed in reviews 3-5 are not repeated here.

## Summary

| ID | Sev | Area | Finding | Status |
|----|-----|------|---------|--------|
| H1 | High | golden image | The image signer's boot-test gate is self-attested: the build user writes the "first-boot pass" record itself | CONFIRMED (by code) |
| H2 | High | tenant API | An org-admin takes over any user in the organisation, including other org-admins, with no second person: auto-approved password reset + MFA reset + revealed link. This also defeats `second_admin` | CONFIRMED (by test) |
| M1 | Medium | MSP API | A holder of an MSP key approves the plans they submit through it. Provenance is checked in one direction only | CONFIRMED (by code) |
| M2 | Medium | MSP API | Webhook SSRF into the management network with only the `view` permission (RFC1918 allowed; status/error oracle) | CONFIRMED (by code) |
| M3 | Medium | MSP API | Migration `0009p` binds existing deployments to customers through slugs derived from names, with no review | PLAUSIBLE |
| M4 | Medium | tenant API | Unauthenticated requests write an audit row each, under the global audit advisory lock (no throttle) | CONFIRMED (by code) |
| M5 | Medium | integration | Revision `0009a` is used twice (tenant + standby), and `idm_stacks.customer_id` is defined twice with conflicting semantics (tenant + MSP) | CONFIRMED (by code) |
| L1-L10 | Low | various | see below | |

**Interaction with fixes-r5:**
- fixes-r5 (`ou-test-attest`, ICS-signed promotion manifests) fixes the release signer only.
- The new `ou-image-sign` repeats exactly the review-5 H2 pattern (H1 below), so fixes-r5's runner-attestation approach must be extended to it.
- fixes-r5 also touches `actions.py`/`config.py`, as do all three ICS branches here. Expect merge conflicts in `CATALOG`/`needed_approvals`/`create_plan`. After merging, re-check that M1 and the tenant `tenant_required` override still hold together.

---

## High

### H1. The golden-image signer gate is self-attested
**Where:**
- `golden-at:blueprints/build/guest-image/signer/ou-image-sign:97-106` (`cmd_record`): any caller writes `records/<sha>.json` with `first-boot pass` and an arbitrary `log_sha256`. Nothing is verified.
- `:70-75`: `sign` only reads that record.
- `install-image-signer.sh:22`: the sudoers rule is `administrator ALL=(ou-imgsign) NOPASSWD: /usr/local/sbin/ou-image-sign *`. The same principal that supplies the image therefore also calls `record-test`.

**Failure scenario:** code running as the build user can be:
- a compromised mmdebstrap hook or package;
- syft;
- any untrusted build output (review 4 threat model).

That code runs:
1. `sudo -u ou-imgsign ou-image-sign record-test <sha256 of a trojaned qcow2> first-boot pass <64 hex>`;
2. `recipe.sh … sign`.

The result is a validly signed `SHA256SUMS` that `ics/guest/golden.py` accepts. The "boot-test record gating" provides no assurance: it is the same flaw as review-5 H2 (`ou-release-sign record-test`). Today `NOPASSWD: ALL` makes it moot anyway, as the installer itself states.

**Minimal fix:**
- Remove `record-test` from the build user's sudo rule.
- Have the boot proof run under a separate principal (the fixes-r5 `ou-test-attest` runner). It signs `{image_sha256, test, result, log_sha256, ics_side evidence JSON}` with a runner key, and `ou-image-sign sign` verifies that signature against a pinned runner public key.
- At minimum, bind the record to the evidence: require the `ics_side.py` JSON (`final_state=enrolled`, `secrets_wiped=true`) and its hash.

## High (tenant)

### H2. Account takeover inside the organisation by a single org-admin; `second_admin` bypassed
**Where:**
- `worktree-agent-a74f300af8c04d808:ics/ics/actions.py` CATALOG: `idm.user.reset_credentials` has `risk: "normal"`.
- `ics/ics/identity.py` `risk_for` gives `normal` regardless of the target's groups. `precheck` only requires `active`.
- `tenant_admin/service.py:308-311`: a non-high plan is auto-approved when `self_service_auto` is true (the default, `DEFAULT_POLICY`).
- `api.py:194-198`: there is no target guard on reset (`_self_guard` is applied only to disable/delete).
- `service.py:353-363` and `portal/app/admin.py:236-249` reveal the new enrollment link to the requesting admin.
- The same holds for `idm.user.enable` (`normal`, issues an enrollment).

**Failure scenario:** organisation with two org-admins A and B, policy `destructive_approval=second_admin`:
1. A submits `reset password` for B, which is auto-approved, executes, and A clicks "Create link" to get B's one-time token.
2. A submits `reset mfa` for B, which is auto-approved: TOTP is removed and `CONFIGURE_TOTP` is set.
3. A uses `/welcome` to set B's password, signs in as B and enrols a new authenticator.
4. A now holds two distinct `sub`s and approves their own deletes and other destructive requests as B (`decide` only compares `requester_sub != ctx.sub`). It is also a silent takeover of any user's mailbox and files.

Users in `privileged_groups` are equally exposed. `disable` of another admin is also single-person (normal + auto).

Evidence: `tests/test_tenant_admin.py:222-235` shows both resets reach `done` without any decision.

**Minimal fix:**
- Make `reset_credentials` (both kinds) and `enable` for a target that holds the admin role or any privileged group `high` → `destructive_approval`. The tenant side can check this live through `live_user_check(target)`, or the ICS can resolve the Keycloak role of the target.
- Better: never auto-approve a reset of another admin, and add `_self_guard`-style refusal of resetting an account that holds `admin_role` unless a second admin approves.
- Consider delivering reset links only to the target (out of band) instead of to the admin.

---

## Medium

### M1. MSP key holder is requester and approver of the same plan (separation of duties)
**Where:** `agent-a64333fb637749229:ics/ics/actions.py:767-782` (`_provenance_conflict`) only walks the approver's chain to look for the requester.
- The MSP service user is created with `created_by = plan.requested_by` (`msp/actions.py:151`).
- The secret is revealed to that requester (`msp/actions.py:226-233`).

**Failure scenario:**
1. Human H requests `msp.client.create`; two others approve; H reveals the key.
2. H now submits any normal-risk plan through the API as `msp-xxxx` and approves it in the console as H. `decide_plan` sees requester ≠ approver and no conflict in H's own chain.

Four-eyes is reduced to one person for every normal-risk action the client's scope allows: deployments changes, idm.* and customer contacts. For high risk, H counts as one of the two approvers.

**Minimal fix:**
- In `decide_plan`, also refuse when the requester's chain (`created_by`/`role_set_by`, up to N levels) contains the approver.
- For MSP principals, also refuse the user who revealed the client secret (store `revealed_by` in `msp_client_reveals`).

### M2. Webhook SSRF with read-only keys
**Where:**
- `msp/api.py:538-553`: `POST /webhooks` needs only `view`.
- `msp/events.py:41-51` uses `proxmox.check_destination`, which allows RFC1918 by design ("management networks").
- `events.py:155-168`: the URL is resolved again at send time (TOCTOU / rebinding).
- `last_error` (exception class or `http <status>`) is returned by `GET /webhooks/{id}/deliveries` (`api.py:573-581`).

**Failure scenario:**
1. A read-only integration key registers `https://10.x.y.z:<port>/…` or the name of an internal service whose certificate the ICS trusts, such as the lab CA in the system store (`auth.ou-lab.internal`, Proxmox).
2. The ICS POSTs JSON to it on every event and reports the status or connect-error class.

This gives blind POST SSRF plus host/port reachability mapping of the management network, from the least-privileged credential. TLS verification limits rebinding to hosts with a valid certificate for the attacker's name, so this is PLAUSIBLE only for the loopback/link-local bypass.

**Minimal fix:**
- Refuse private, CGNAT and ULA ranges for webhooks; webhooks are MSP-side endpoints, not management networks. Add an explicit operator allowlist for exceptions.
- Pin the connection to the address that was checked (custom transport that connects to the validated IP with SNI = host).
- Require `plan` (or a dedicated `webhooks` permission) to create webhooks.
- Report only `delivered`/`failed` to the client.

### M3. Implicit ownership binding by migration-derived slug
**Where:**
- `0009p_msp_api.py` DDL: it backfills `customers.slug` from `name` (`lower`, non-alnum → `-`).
- `tenancy/scope.py` (`customer_of_params`) now maps `deployments.customer_id` (a free-text slug chosen at deployment creation) to the customer with that slug.
- `msp/api.py:_deployment`: deployments join `customers.slug = d.customer_id`.

**Failure scenario:**
- A pre-existing deployment whose `customer_id` string equals a slug derived from some customer's name ("lab", "acme") silently becomes that customer's. Its scoped operators/API clients then see it and plan against it.
- The same happens later: `customer.create` with a slug equal to an orphan deployment's `customer_id` captures it. Precheck only checks `customers.slug` uniqueness.

**Minimal fix:**
- In the migration, report (do not auto-bind) deployments whose `customer_id` matches a generated slug.
- Make the binding explicit: a `deployments.customer_uuid` set by an approved plan.
- In `customer.create`, refuse a slug that equals any existing `deployments.customer_id`.

### M4. Unauthenticated audit amplification on `/api/v1/tenant/*`
**Where:** `tenant_admin/service.py:164-167,178-179`. Every request with a missing or bad `X-OU-Tenant-Key` runs `audit.append`, which takes the global `pg_advisory_xact_lock`, plus a commit. There is no throttle; compare `auth.throttle_remaining` for login and the MSP gateway's `FAIL_LIMIT`.

**Failure scenario:** anyone who can reach the ICS listener floods the hash-chained log. Every audit writer (jobs, approvals) serialises behind the lock, and the audit table grows without bound.

**Minimal fix:**
- Throttle per address (reuse `login_attempts` or the MSP `_fail_count`).
- Audit bad-key failures sampled or aggregated. Keep full audit for a bad *user token* with a valid key.

### M5. Merge hazards that change security semantics
**Where:**
- `0009a_tenant_admin.py` and `0009a_controller_epoch.py` both declare `revision = "0009a"`, `down_revision = "0008i"`. `0009p` also has `down_revision = "0008i"`.
- The tenant branch adds `idm_stacks.customer_id NOT NULL DEFAULT <default customer>`. The MSP branch adds a nullable column with the same name.

**Failure scenario:**
- Alembic refuses a duplicate revision or produces multiple heads. A hurried manual merge can drop `controller_state`: then `epoch.get_state` raises and agents are never stamped.
- Or the merge keeps one column definition. MSP `customer_of_params` treats NULL as unscoped, while the tenant branch treats the default customer as the owner. Stacks then resolve to the default customer for scoped principals, or stop being scoped.

**Minimal fix:** rename the revisions (`0009b`/`0009c`), chain them linearly, and define `idm_stacks.customer_id` once with one meaning. Re-run the scoping tests of both branches together.

---

## Low

- **L1 (tenant, SVG filter bypass, defence in depth):** `service.py:397` `SVG_BAD` does not match namespaced elements (`<x:script>` with `xmlns:x="http://www.w3.org/2000/svg"`) or `<set attributeName="href" to="java&#x73;cript:…">`. Exploitation is blocked because both the ICS (`api.py:106`) and the portal (`main.py` `/branding/logo`) serve with `CSP: default-src 'none'; sandbox` and the portal uses `<img>`. Fix: parse with an XML parser and allowlist elements/attributes, or rasterise; keep the CSP.
- **L2 (tenant, top-level `roles` claim):** `jwtv.realm_roles` also accepts a top-level `roles` claim, and the portal's `is_admin` does too. Any realm mapper that emits `roles` from user-editable attributes would grant read access to the tenant API (mutations are re-checked live). Fix: use only `realm_access.roles`. Also no `typ == "Bearer"` check, so ID tokens with `azp` are accepted; add it.
- **L3 (tenant, `/welcome` token in the query string):** `main.py` `/welcome?s=&u=&t=`. The one-time token lands in reverse-proxy/access logs and browser history (Referrer is suppressed). It is single-use with 256 bits, 5 failures burn it, it is superseded on reissue, and it has a TTL. Fix: put the token in the URL fragment, or exchange it on first GET for a short-lived server-side handle; do not log the query string for `/welcome`.
- **L4 (tenant):** `put_logo` reads the full request body before `sniff_logo` checks its size (authenticated admins only). An unknown `kid` forces a JWKS refetch per request (needs the service key). The `ctx.username == uid` self-guard compares Keycloak `preferred_username` with the LDAP uid. Fix: stream with a 200 kB cap; rate-limit refetches to 1/min; compare by Keycloak id.
- **L5 (MSP, mTLS binding unusable behind the proxy):**
  - `gateway.py:187-190` requires `ip == trusted_proxy`. With `proxy_headers` enabled (`serve.py:11`), `request.client.host` is the forwarded client address, so a bound client always fails. This is fail-closed.
  - The only way to satisfy the check is a direct connection from the proxy host without XFF. Any local process on a loopback proxy host can then forge `X-Client-Cert-SHA256` (it still needs the HMAC secret).
  - Fix: take the fingerprint from a header the proxy always overwrites, and check `scope["client"]` before proxy-header rewriting (or a dedicated proxy-auth header).
- **L6 (MSP, robustness):**
  - `gateway.py:166-168`: `ts.isdigit()` accepts Unicode digits such as latin-1 `\xb2`, so `int(ts)` raises outside the `MspError` handler and the request returns an unaudited 500.
  - `_note_fail` clears *all* counters once 10,000 addresses are tracked, which resets the per-address limit for IPv6 attackers.
  - The `Idempotency-Key` and `Host` headers are not covered by the signature (low value; nonce prevents replay).
  - Fix: `re.fullmatch(r"[0-9]{1,12}", ts)`; evict the oldest entries instead of clearing; optionally sign `Host`.
- **L7 (standby, epoch mark durability):**
  - `proto.py` `EpochGate`: a corrupt or unreadable `epoch.json` silently becomes 0 (`ValueError` → fail-open: epoch-less and any epoch accepted again).
  - The rename is not followed by an fsync of the directory, so a crash can roll the mark back.
  - Reinstall resets the mark (documented).
  - Fix: refuse to start on an unreadable file (fail closed); `fsync` the directory fd after `os.replace`; record the mark in the agent's trust file, so re-enrollment carries it.
- **L8 (standby, fencing path and key material at rest):**
  - `promote.py:107-112` fences the old primary over its app-role DSN, but `ics-standby-prepare-primary.sh:72-76` only admits `replicator` from the standby in `pg_hba`, so the documented `--fence-old-dsn-file` path cannot connect. The operator then stops the primary by hand or promotes unfenced during a partition (the residual risk is stated in the ADR).
  - The bundle and the passphrase are written to the same directory (`--out-dir`, default `/root/ics-standby`), and bootstrap never deletes the imported bundle/passphrase files on the standby.
  - `controller_state` lets `ics_app` set `role` back from `fenced` to `primary`; the trigger only guards the epoch. Agents still refuse the old primary by epoch.
  - Fix: add a dedicated fencing role and `pg_hba` line, or document SSH stop as the only path; write the passphrase to stdout or a separate path and shred both after import; make the trigger refuse `fenced → primary`.
- **L9 (standby, replication credential scope):** acceptable. The scope is `REPLICATION LOGIN` only, `hostssl` from the standby /32, scram, `verify-full`. By nature it can read the whole cluster, vault ciphertexts included. The PostgreSQL TLS key is a copy of the console's nginx key (`prepare-primary.sh:38`), so one key compromise covers both. Fix: issue a separate PostgreSQL server certificate from the ICS CA.
- **L10 (golden image):**
  - `recipe.sh:143` uses a fixed `systemd-repart --seed`, so every VM shares partition and filesystem UUIDs (and possibly the ext4 hash seed). Not exploitable as such; prefer per-build randomness or regenerate the UUIDs at first boot.
  - Not verified on the artefact (no image inspected): that no `/var/lib/systemd/random-seed` or `credential.secret` is baked in. Add a build-time assertion.

---

## Verified sound

**Tenant API**
- The service key fixes the customer: the key id is looked up and the sha256 compared with `compare_digest`.
- Issuer, `azp` and role name come from the database row for that customer, never from the token. A token from customer B with customer A's key fails on `iss` (test `test_cross_customer_denial`).
- alg is limited to RS256/ES256; `none`/HS* are refused. The kid must match exactly one JWKS key, and the key type must match the alg.
- The token lifetime is capped at 900 s.
- Mutations re-check the user live in Keycloak (enabled + composite realm role).
- Every read and decision is filtered by `customer_id` or `stack_id`: requests, users, `decide`, `reveal_enrollment` (also bound to the tenant requester principal).
- Mass assignment is blocked:
  - pydantic `extra=forbid` on every body;
  - `stack` is forced from the binding;
  - groups are limited to `assignable_groups` (privileged groups excluded);
  - the app→group map is validated at `bind`;
  - `BindIn` cannot set `extra_groups`.
- Privilege escalation to MSP/ICS is blocked: tenant principals are unloginable, scoped to one customer, and only idm.* plans are reachable.
- The `bind`/`rotate` endpoints need ICS admin with all-customers scope.
- The DNS check only queries names derived from the configured mail domain, never input from the caller.
- Portal admin forms check CSRF (`gate(request, csrf)`); `/welcome` POST checks Origin/Sec-Fetch-Site and relies on the one-time token.
- The portal's CSP may only be tightened per route (`setdefault`). Logos are served sandboxed.
- `/welcome` token: 256-bit, single use, superseded on reissue, burned after 5 failures, TTL, one generic error.

**MSP API**
- The HMAC covers method, the raw path with the query exactly as sent, ts, nonce, and the body hash. There is no canonicalisation ambiguity.
- ±120 s skew.
- Nonces are consumed in Postgres only after the signature verifies, and committed before anything else (survives restarts, multiple workers). Their growth is bounded by authenticated rate × 270 s TTL, with housekeeping.
- Idempotency is keyed on `(client row, key)`, so it cannot collide across clients. The request hash covers method, target and body. Responses are vault-encrypted with an AAD bound to client and key. The marker commits atomically with the plan.
- Permission sets are enforced per route.
- `approve` refuses own plans (requester check), high-risk plans and non-MSP-owned customers. `execute` auto-runs only low-risk plans of MSP-owned customers.
- API clients cannot manage API clients: those actions are admin-only, high risk, and the MSP exception covers only `customer.create`/`customer.update`.
- Out-of-scope objects return 404.
- Webhooks: redirects off, HTTPS required, the secret is vault-held and shown once, and each delivery is signed with a timestamp.

**Standby**
- The epoch is stamped on every signed agent request path (`_exec_runbook`, `guest/agentcall`, `identity.agent_user`, announce). `agentclient.call` without `req_override` has no remaining caller.
- `check_active` refuses a configured standby or a fenced role before signing. The epoch is covered by the agent signature, and the agent checks it after signature and envelope checks and before the journal or execution.
- The agent refuses a lower epoch and refuses epoch-less requests once it has seen an epoch.
- A trigger keeps the epoch monotonic; DELETE is refused.
- On a standby:
  - worker and adoption are off;
  - the guard returns 503 for every non-GET method;
  - PostgreSQL is a hot standby, so writes are impossible anyway;
  - migrations are skipped in recovery;
  - bootstrap forces `ICS_ROLE=standby` after importing the primary's `ics.env`.
- Promotion requires root on the standby and a typed confirmation, refuses while the old primary is still streaming, bumps the epoch and writes the audit row in one transaction, then verifies the whole audit chain.
- Key bundle:
  - AES-256-GCM with the header as AAD;
  - scrypt (N=2^15) over a generated 160-bit passphrase;
  - an allowlist of file names (no paths);
  - modes set on the fd before `os.replace`;
  - the export is audited.

**Golden image**
- The signer re-hashes the image and the SBOM itself, accepts only regular top-level tar members with a size cap, and builds `SHA256SUMS` itself. The key is passphrase-protected and owned by a separate user.
- Upstream Debian keys are pinned by full fingerprint and the pin set must be exact. The agent is installed only from the OU repo through `signed-by` after a fingerprint pin. Mirrors are HTTPS plus signed-by.
- No SSH: openssh is not installed and the units are masked. Root is locked, cloud-init is disabled, `machine-id` is emptied, host keys are removed, the payload is removed.
- The agent package ships no keys or tokens and is not enabled.
- Default-deny nftables. The first-boot ruleset is generated only from validated ints and `ipaddress`-normalised CIDRs, so there is no injection.
- SMBIOS input:
  - strict regexes;
  - the host is used only for the connection;
  - nothing reaches a shell or a path;
  - the pin is checked before any byte is sent;
  - the ack and config are MAC'd;
  - the config schema is closed.

## Tests
- Standby branch: `tests/test_agent_epoch.py` and `tests/test_standby.py` were run against DB e. Result: **17 passed**.
- Tenant branch: `tests/test_tenant_admin.py` was run against DB e. It was **killed by the 500 s timeout without producing a result**, so its status is not established. It may be hanging on a lock or an external call; this was not investigated. H2 is supported by the test's assertions at `:222-235`, not by a run.
- No new exploit code was written. Findings are by code, plus the branch's own test for H2.

---

## Remediation (branch `tenant-msp`, 2026-11-16)

The tenant/MSP findings are fixed on `tenant-msp` (merge of `mbx-be` = AX + BE, the MSP API branch `worktree-agent-a64333fb637749229` = AY, `collab-images` = BB + BF). H1, L7-L10 (golden image, warm standby) belong to other branches and are not touched here. Every fix has a regression test that fails against the pre-fix code.

| ID | Fix | Test |
|----|-----|------|
| H2 | `idm.user.reset_credentials` / `idm.user.enable` / `idm.user.disable` are **high** risk when the target is a member of a privileged group (directory) or holds the organisation-admin role (checked live in Keycloak by the tenant API, **fail-closed**: an error means "privileged"; the plan carries `privileged_target`). High means `destructive_approval` (second admin or MSP), never auto-approved, and the requester cannot decide (existing `requester_sub` check). The enrollment link of a privileged target is refused to the requester (`tenant.enrollment_link_refused`) and is taken once by an in-scope ICS operator (`POST /api/v1/identity/enrollments/{plan}/deliver`, never the plan's requester) to hand to the account owner out of band, redeemed on `/welcome`. Ordinary users stay self-service. | `test_h2_admin_takeover_chain_is_refused`, `test_h2_privileged_group_member_is_protected_without_the_role_flag`, `test_h2_target_check_fails_closed_and_ordinary_users_stay_self_service` |
| M1 | `decide_plan` also refuses (`plan.provenance_rejected`) any human who created the API client, requested or revealed any of its secrets (`msp_client_reveals.revealed_by` added), or is in the client principal's creation chain, when the plan was submitted through that client. | `test_m1_key_holder_cannot_approve_plans_submitted_through_the_client` |
| M2 | Webhook targets: https only; resolved at creation and again at every delivery; every address must be global unicast (loopback, RFC1918, link-local/metadata, CGNAT, ULA, multicast, reserved, v4-mapped refused) unless the operator allow-listed it (`ICS_MSP_WEBHOOK_ALLOW`); the connection is pinned to the checked address (SNI and `Host` = original name); no redirects; one refusal message; the API reports no remote status or error; create/delete/rotate need `plan`. | `test_m2_*` (14 range cases, uniform error, allow-list, view-only key, DNS rebinding between create and send, pinning + 302 not followed) |
| M3 | Migration (now `0011b`) no longer derives slugs from names: existing customers get `c-<12 hex of id>`; it logs every deployment as unbound. Binding is explicit: `customer.create`/`customer.update` with a `slug` equal to existing deployments' `customer_id` needs `adopt_existing_deployments` (high risk, audited list); derived slugs skip colliding names; re-checked at execution. | `test_m3_msp_migration_does_not_bind_deployments_by_name_derived_slug`, `test_m3_customer_create_cannot_capture_an_existing_deployment_by_slug`, `test_m3_customer_update_slug_is_the_explicit_mapping_for_existing_deployments` |
| M4 | Per-address throttle (20 failures/60 s then 429 without any DB access) for requests without a valid service credential; no audit row per failure, one `tenant.auth_failed_summary` row per 300 s window. A bad user token with a valid key is still audited in full. | `test_m4_*` |
| M5 | Chain is linear: `0009b -> 0011a (tenant) -> 0011b (msp) -> 0011c (collab check kinds) -> 0011d (mailbox)`. `idm_stacks.customer_id` is defined once, in `0011a`: `NOT NULL DEFAULT` the MSP-internal customer (the fixes-r5 model for nodes/checks), backfilled from the stack config; MSP's nullable column removed; `scope.customer_of_params`, the console stack/user/reconcile lists, `idm.stack.register` and `msp.stack.link` all use the column. The standby `0009a` and fixes-r5 `0010` are renamed by the integration step. | `test_migration_chain.py` (head `0011d`, production-head upgrade), tenant/MSP scope suites |
| L1 | SVG logos are parsed (no DTD/entities) and allow-listed: SVG namespace only, allow-listed elements and attributes, only `#id` references; namespaced scripts, `set`/`animate`, `foreignObject`, external `url()` refused. CSP + `<img>` unchanged. | `test_l1_*` |
| L2 | Roles come only from `realm_access.roles`; `typ` must be `Bearer`. (The portal's `is_admin` UI hint is unchanged because its mock and realm emit a flat claim for display; the ICS re-checks every call.) | `test_role_claim_forgery_and_token_checks`, `test_jwt_and_dns_wire_helpers` |
| L3 | Not changed: `/welcome` keeps the token in the query string (single use, 5 failures burn it, TTL). A fragment-based exchange needs a portal JS flow; tracked as follow-up. | - |
| L4 | Logo upload streams with a 200 kB cap (413); an unknown `kid` refetches the JWKS at most once a minute. The username-vs-uid self-guard is unchanged (follow-up: compare Keycloak ids). | `test_l4_*` |
| L5 | mTLS binding no longer relies on the peer address: it needs `X-Client-Cert-SHA256` plus the proxy's shared secret in `X-OU-Proxy-Auth` (`ICS_MSP_PROXY_AUTH_FILE`); fail-closed when unset. Documented in ADR-0013. | `test_mtls_binding` |
| L6 | Timestamp must match `[0-9]{1,12}` (clean 401, no 500); the failure table evicts the stalest address instead of clearing all. `Idempotency-Key`/`Host` signing: not changed. | `test_l6_*` |

**The `tests/test_tenant_admin.py` hang.** It did not reproduce: on the tenant branch alone and on the merged tree the file passes (15/20+ tests in 20-60 s). The cause of a 500 s stall is the shared test database: the `rt` fixture and `owner_engine` run `TRUNCATE ... CASCADE` / `DROP SCHEMA` which need ACCESS EXCLUSIVE locks and waited **forever** behind any other connection holding a lock on the same DB (a second pytest run on DB e, or an idle-in-transaction connection of a killed run). Reproduced by holding a transaction open on the test DB: the suite blocked silently. `tests/conftest.py` now sets `lock_timeout=60s` on the owner connection, so the same situation fails within a minute with `LockNotAvailable` instead of hanging. Do not run two suites against one test database.
