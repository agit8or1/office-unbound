# Security review 7 (2026-11-16)

Independent review. The reviewer did not write this code, and the only file written is this report.

**Purpose:**
1. verify the fixes claimed for review 5 (remediation table on `fixes-r5`) and review 6;
2. review warm standby (ADR-0012) and the golden-image code merged in `integration-6`.

**Code read:** `integration-7` at `ab30b85`, which is `9882464` (merge integration-6) + `6d63f91` (merge fixes-r5) + `ab30b85` (merge agent AU). The branch moved during the review. To get a stable copy, the tree was exported with `git archive ab30b85` into a scratch directory, and all line numbers refer to that commit.

**How each finding was checked:**
- **CONFIRMED (executed):** reproduced in a scratch copy or sandbox.
  - Release signer work used a throw-away GnuPG key, a throw-away `OU_RELEASE_STATE` and an unprivileged `apt` with `signed-by` the sandbox key. The real lab key, `/var/lib/ou-release` and sudo were never touched.
  - Tenant probes ran as a temporary test inside the scratch copy against DB e, and were deleted afterwards.
- **CONFIRMED (by code):** the failing path is unambiguous in the source.
- **PLAUSIBLE:** depends on a precondition outside the repo.

**Live host fact (read-only `sudo -n -l` as `administrator`):**
- still present: `(ALL : ALL) NOPASSWD: ALL`;
- also present: `(ou-release) NOPASSWD: /usr/local/sbin/ou-release-sign`, `(ou-testrunner) NOPASSWD: /usr/local/sbin/ou-test-attest`, `(ou-imgsign) NOPASSWD: /usr/local/sbin/ou-image-sign *`.

## 1. Review-5 verdicts

| # | Verdict | Evidence |
|---|---------|----------|
| H1 signer binds Release to ledger | **PARTIAL** | Refused (executed): unlisted extra file; listed-but-unsupplied index; by-hash; non-allowlisted path; `..` in Filename; plain trojan stanza; caller Suite/Codename/Valid-Until (Release rebuilt, `ou-release-sign:279-288`). Compressed index must equal the plain one (`:272`), and all hash sections are checked (`:255-262`). **Bypass, executed incl. real apt:** two stanzas may share a basename (new H-1). **Also open:** stanza metadata is unchecked (new M-3); one key signs every channel (new H-2). |
| H2 separation of duties | **PARTIAL** | Holds: Ed25519 manifest from root-owned `trust/ics-promotion.pub` (`:312-324`); sudo `env_reset` strips the state override; `from`/`to` signed and compared (`:376`), so staging→stable confusion is refused; lifetime ≤ 24 h (`:378`); exact file set + sha256 + name/version bound (`:401-409`); 2 approvers + requester excluded (`:387-391`); nonces single use in an `ou-release`-owned file (`:441-447`; replay refused). ICS side: `release.promote` is admin-only, stable is high risk, `exec_promote` re-reads `plan_approvals` (`release.py:90-95`). **Fails:** `ou-test-attest` runs no test and signs whatever the caller says (new H-3), and `NOPASSWD: ALL` is still live, which makes every gate moot today. |
| H3 PBX helper symlink | **FIXED** | `ou-pbx-user:31-78`: `/run/ou-rb-secret` is root-owned and opened once with `O_DIRECTORY\|O_NOFOLLOW`; all operations use `dir_fd`; `O_CREAT\|O_EXCL\|O_NOFOLLOW`; `fchown` on the fd. Parent swap: `/run` is root 0755, so the agent cannot replace the directory. A dangling or re-planted entry gives EEXIST and the helper fails closed. Hard links are blocked by `protected_hardlinks` and by `O_EXCL` after the unlink. The non-issue verbs write only to `/run/ou-rb`, which is root 0755 through `RuntimeDirectory`. `tests/test_pbx_helper_symlink.py`: 6 passed. Nits: the unit uses `ProtectSystem=full`, not `strict`; the comment at `agent/ou_agent/runbooks.py:42` still says the directory is "owned by ou-agent". |
| M1 bootstrap DoS | **FIXED** (residual Low) | There is no global bucket. The buckets are per IP, per known bid and one shared bucket for unknown ids (`callback.py:37-41,133-149`). The guest retries 429/503 with backoff (`firstboot.py:102-104,295`). Residual: see new L-1. |
| M2 VM binding | **PARTIAL** | `agentport.py:207-224` checks the ARP entry against the `net0` MAC. A replay on a `reported` record fails it and wipes its material (`callback.py:182-188`). But the check reads `/proc/net/arp` once, and the enrollment connection is made later, up to 10×5 s afterwards (new M-2). |
| M3 scope direction | **FIXED** | Templates count in `_reach`/`direction` (`scope_change.py:48-60`). Any uncovered ACL entry or added role privilege raises to `widen` (`:164-165`). Plan risk = max(risk_fn, preview risk) (`provisioning/actions.py:407`, `actions.py:697-699`). Latent nit: `_covers` (`:63-68`) treats a same-path entry as covered even if the new entry propagates and the old one did not. Today `design()` fixes propagate per path type, so this cannot be reached. Fix: require `prop0 or not prop1`. `test_review5.py -k m3`: passed. |
| M4 decide_plan scope | **FIXED** | `actions.py:841`. There are no other plan-by-id mutations. `/jobs/{id}` and `/jobs/{id}/steps` join `plans.customer_id`. |
| M5 unscoped reads | **FIXED for GET** | All 90 routes were enumerated (script in scratch). Every GET list and by-id route is scoped. The regression test (`test_review5.py:83`) enumerates GET routes only and fills ids with random UUIDs, so by-id handlers are never run against another customer's real object. **But plan creation is not scoped per referenced object** (new H-4). |
| M6 cross-tenant node | **FIXED** (residual Low) | Checked at plan time and at execution (`identity.py:840-848,961`). `agent_user(customer=)` is used for SIP issue (`:1110`). Gromox, OpenCloud and `pbx.user_state` (`:942-956,1204-1269,1335`) rely on the register-time check only. A stack registered before 0010 that already points at a foreign node keeps those paths. |
| M7 image import | **PARTIAL** | `import_image` now calls `verify_release` and derives path and sha256 from it (`provider.py:1005-1013`). But the **public key and its pin both come from the caller's `ImageImportSpec`** (`base.py:155-156`), so the pin anchors nothing unless the caller takes both from settings. The verb still has no non-test caller. The rollback floor is read from Proxmox tags of the templates visible to the token (`provider.py:1023`, `golden.py:41-48`): deleting or re-tagging the newest template lowers it. There is no version or expiry in the signed manifest. See new M-4. |
| L1 secret sweepers | **FIXED** | `bootsecrets.sweep` (`:136-150`) and `identity.sweep_sip_credentials` (`:1656-1675`) run from `reap_expired` (`actions.py:935-940`). The PBX "kick" does not revoke the digest of the unrevealed password, but no one holds that password any more. |
| L2 body cap / limiter | **FIXED** (cap) | 4 KiB is enforced on Content-Length and on the streamed body (`callback.py:231-240`). The limiter is still per process. By default (`ICS_GUEST_CALLBACK_DEDICATED=false`) the console app and `ics-callback.service` both serve the route, which gives two independent limiters. |
| L3 timing | **FIXED** (info) | `_dummy_work` (`callback.py:112-118`). The split between known-bid and unknown-bid buckets is itself an existence oracle (see L-1); at 64 bits this is informational. |
| L4 dedicated listener | **PARTIAL** | `serve_callback.py` and `ics-callback.service` exist, but the default is still off and the reverse-proxy and bind setup has not been done. |
| L5 version disclosure | **PARTIAL** | `/api/v1/version` is correct (`main.py:234-245`). `/api/v1/system` (`sysinfo.py:35`) is `require("admin")` without an all-customers check, so a customer-scoped admin gets the exact version, commit, dirty flag and schema. `/readyz` now also tells anonymous callers the role, epoch, fenced state and replication lag (integration-6). |
| L6 Mode B confirm | **FIXED** | `provisioning/actions.py:729-742` collects live facts, guests and storages, re-checks orphans and verifies the live state. |
| L7 upstream freshness | **FIXED** (residual) | `recipe.sh:56-67,98` requires a dated serial, a maximum age and no going backwards. Debian uses the signed archive (apt Valid-Until). Residual: for Ubuntu the serial is only the URL path; the signed `SHA256SUMS` content is not bound to it, so freshness relies on HTTPS to the upstream host. |

## 2. Review-6 status on integration-7

| # | Status |
|---|--------|
| H1 `ou-image-sign` self-attested gate | **OPEN** on integration-7: `record-test` exists (`signer/ou-image-sign:97-106,121`) and sudo is `ou-image-sign *`. A fix is in progress on branch `oci-signing`, uncommitted in its worktree (`ou-image-sign`, `install-image-signer.sh`, `bootproof.sh`, `ou-test-attest` modified). Note that `ou-test-attest` itself has the same flaw (new H-3), so routing the image proof through it as it stands would not fix H1. |
| H2, M1-M5, L1-L6 (tenant admin / MSP branches) | Not merged into integration-7, so not re-verified. `_provenance_conflict` (`actions.py:806`) is still one-directional and must be fixed before the MSP API merges. |
| L7 epoch mark durability | **OPEN, CONFIRMED (executed)**: a corrupt or empty `epoch.json` → mark 0 (`agent/ou_agent/proto.py:110-114`). After that, both epoch-less and epoch-1 (old primary) requests are accepted. There is no directory fsync after `os.replace` (`:128`). |
| L8 fencing path / bundle at rest / `fenced→primary` | **OPEN**: `pg_hba` still admits only `replicator` (`ics-standby-prepare-primary.sh:75`), so `--fence-old-dsn-file` cannot connect. The bundle and passphrase still go to the same `$OUT` directory (`:118`), and bootstrap does not delete them. The trigger still guards only the epoch (`0009a_controller_epoch.py:17-24`). |
| L9, L10 | Unchanged (accepted / informational). |

## 3. Key question: can a resurrected old primary downgrade a NEW agent via the `bad_format` fallback?

**No (CONFIRMED by code and executed).**
- The fallback in `agentclient.call` (`agentclient.py:143-149`) fires only when the agent sends a **signed** `rejected/bad_format` response with the message "unexpected or missing fields".
- A new agent accepts `REQ_FIELDS_EPOCH` (`proto.py:73-75`), so it never produces that message for an ICS-built request. Executed: `check_envelope` accepts an epoch request.
- A stale epoch yields `stale_epoch` (no fallback), and the old primary self-fences.
- Even if the old primary sent the request without an epoch, an agent with mark > 0 answers `epoch_required` (executed).
- The response is Ed25519-signed by the agent key, behind a pinned TLS session, and echoes a fresh nonce, so a man-in-the-middle can neither forge nor replay the trigger.

Residual paths to the same effect:
1. **The agent mark is reset.** A corrupt or empty file (review-6 L7, executed), a reinstall, or an image restore resets the mark to 0. From then on the agent accepts epoch-less requests and any epoch.
2. **Agents not yet announced.** Until the new primary's `announce` reaches an agent, that agent accepts the old epoch (documented in ADR-0012).
3. **Truly legacy agents** are never fenced (documented).
4. **No upper bound on the epoch.** Anyone holding the shared ICS signing key can set any agent's mark to 2^62-1 (executed), which permanently fences every legitimate controller (see L-3).

## 4. New findings

### Critical
None.

### High

**H-1. Release signer: duplicate-basename stanzas bypass the ledger.** CONFIRMED (executed, real apt).
- **Where:** `blueprints/build/repo/ou-release-sign:218-235`, `index_requirements`: `need[basename] = SHA256`. The last stanza with a given basename wins; Sources `Checksums-Sha256` behaves the same.
- **Repro (sandbox key):**
  - stanza 1: `Package: ou-a`, `Version: 2`, `Filename: pool/stable/x/ou-a_1_amd64.deb`, `SHA256: <trojan>`;
  - stanza 2: the same basename under `pool/stable/c/`, with the admitted hash;
  - `sign stable` → SIGNED. An unprivileged `apt-get update` with `signed-by` the sandbox key shows Candidate 2, and `apt-get download` fetched the trojan bytes.
- **Failure scenario:** code running as the build user signs an arbitrary package into `stable` with no promotion, attestation or approver. This defeats H1 and the whole manifest gate.
- **Minimal fix:** refuse a repeated basename or Filename; check every stanza's SHA256 against the ledger, keyed by the full Filename; better, have the signer generate `Packages`/`Sources` itself from ledger-recorded control data.

**H-2. One signing key for dev, staging and stable (channel confusion).** CONFIRMED (executed, first-contact guests).
- **Where:** `admit dev` is ungated (`ou-release-sign:292-298`), and `sign dev` uses the same key that stable guests trust.
- **Repro:** admit a trojan to dev, `sign dev`, serve the output under `dists/stable`. apt only warned "Conflicting distribution (expected stable but got dev)", then installed the trojan.
- **Not tested:** guests that already hold stable lists. They likely refuse the Label/Codename change.
- **Minimal fix:** a separate key (or subkey) per channel, with stable guests' `signed-by` pinned to the stable key only.

**H-3. `ou-test-attest` attests what the caller says, so the test gate is still self-attested.** CONFIRMED (by code; executed in sandbox).
- **Where:**
  - `ou-test-attest:55-67` runs no test and signs caller-supplied `(sha, name, result, log_sha256)`. Its only check is that the sha appears in *some* ledger, and `admit dev` is ungated.
  - `install-signer.sh:77` and the live sudoers give `administrator` NOPASSWD on it as `ou-testrunner`.
  - The ICS evidence hashes are free-text plan input (`ics/ics/release.py:38-41`), so approvers cannot check them.
- **Sandbox result:** a self-made `install-smoke pass` for a trojan was accepted.
- **Failure scenario:** after `NOPASSWD: ALL` is removed, the only real gate left is the human ICS approval, and approvers see "tests passed" evidence that the build user forged.
- **Minimal fix:**
  - the runner fetches the `.deb` by sha from the ledger copy, runs the smoke test in its own sandbox and hashes its own log;
  - remove the build user's sudo right to `attest`;
  - the ICS fetches and displays the attestation instead of taking a typed hash.
- The same applies to review-6 H1 (image boot proof).

**H-4. Cross-tenant plans: the customer is resolved from the first matching parameter, and caller-supplied `customer_id` wins.** CONFIRMED (executed in scratch copy, DB e).
- **Where:**
  - `ics/ics/actions.py:701`: `cust = full.get("customer_id") or customer_of_params(...)`;
  - `ics/ics/tenancy/scope.py:62-90` returns on the first key found (`check_id` before `node_id`), and never looks at nested `remediation.node_id`;
  - `monitor.py:80` applies a maintenance window without `check_id` to every customer's checks.
- **Results as a customer-A-scoped operator (all returned 201):**

  | Request | Effect |
  |---------|--------|
  | `maintenance.create {customer_id: A, check_id: <B's check>}` | auto-approved (low risk): silences B's alerting |
  | `check.bind_remediation {check_id: <A's check>, remediation.node_id: <B's node>, service.restart}` | auto-approved: the monitor later restarts services on B's node whenever A's check fails, and A controls when that is |
  | `runbook.execute {node_id: <B's node>, check_id: <A's check>}` | auto-approved; the same request without `check_id` → 404 |
  | `maintenance.create {customer_id: A}` without `check_id` | high-risk plan that A's own approvers can pass; it then mutes all customers |

- **Minimal fix:**
  - resolve the customer of **every** referenced object (`check_id`, `node_id`, `remediation.node_id`, `runner_node_id`, `channel_id`, `incident_id`, `maintenance_id`, `policy`, `endpoint_id`, `stack`, `credential_id`);
  - require them all to be equal and in the caller's scope;
  - require an explicit `customer_id` to equal them;
  - scope a window without `check_id` to its own customer in `in_maintenance`;
  - extend the M5 regression test to POST `/plans` per action, using a real object of another customer.

**H-5. Fencing covers only signed agent requests: a resurrected or fenced primary keeps running everything else.** CONFIRMED (by code).
- **Where:**
  - `ics/ics/epoch.py:24-30`: `check_active` is called only by the agent-request builders (`runtime.agent_epoch`).
  - `ics/ics/main.py:166`: the Worker starts whenever the *configured* role is primary.
  - `ics/ics/worker.py`: `_job_loop`, `_backup_loop`, `_monitor_loop` and `_inventory_loop` never consult `controller_state`.
  - `main.py:188`: `StandbyGuard` is installed only for a configured standby, so a self-fenced controller still accepts logins, approvals and plan creation.
  - Enrollment (`agentclient.identity/enroll`, `agentport.py:442-449`, `actions.py:1180-1186`) is not epoch-gated, and a newly enrolled agent starts with mark 0.
- **Failure scenario:**
  1. A partition separates the primary from the standby. The WAL receiver is no longer `streaming`, so `promote` proceeds without fencing.
  2. The old primary, which never died, keeps executing approved and queued plans against Proxmox (VM create/destroy, scope changes, token rotation), Keycloak, DNS, backups and notifications. In parallel the new primary executes the same plans from its replica, so plans run twice.
  3. Self-fencing happens only after an agent refuses a request, and even then the worker keeps running non-agent jobs.
  4. Operators who still reach the old console can approve plans that only the old controller runs.
  5. The old primary can also enroll new agents, which then accept it.
- **Minimal fix:**
  - claim each job only after `check_active` passes (configured primary AND `controller_state.role='primary'`), and re-check it before every provider call;
  - on `self_fence`, stop the worker loops and install the standby guard (503 on mutations);
  - gate `enroll` on `check_active`;
  - as part of promotion, rotate (or re-scope) provider and Keycloak credentials so the old primary is also fenced at those services, or document SSH stop of the old primary as mandatory before promotion.

### Medium

**M-1. A scoped admin can create an all-customers operator.** CONFIRMED (by code).
- **Where:** `POST /api/v1/users` (`main.py:283`) calls `create_invite` (`auth.py:72`), which never sets `all_customers`, and the column defaults to true (`0007m_vault.py:24`).
- **Failure scenario:** a customer-A admin invites a viewer or operator who, once enrolled, sees every customer. Enrollment still needs the host CLI, which mitigates this.
- **Minimal fix:** for a scoped creator, insert `all_customers=false` and copy the creator's `operator_customers`, or refuse.

**M-2. NIC binding is checked once, before a later connection (ARP TOCTOU).** PLAUSIBLE.
- **Where:** `agentport.py:207-224` reads `/proc/net/arp` once (`neigh.py:11-32`). `_enroll_retry` (`:226-236`) connects up to 10×5 s later, and the TLS session is not tied to the MAC.
- **Failure scenario:** an attacker who holds the bootstrap secret (VM.Audit, vzdump) and has an L2-adjacent host or guest:
  1. reports from its own IP X;
  2. sends a gratuitous ARP "X is-at <VM MAC>" so the check passes;
  3. re-ARPs X to its own MAC;
  4. the ICS enrolls the attacker's agent.

  Proxmox does not stop MAC cloning unless the firewall `macfilter`/`ipfilter` is on.
- **Minimal fix:**
  - re-read the neighbour entry immediately after enrollment (and before `_finish`), and require it to be unchanged;
  - prefer a `REACHABLE` entry the kernel learned itself;
  - document `macfilter`/`ipfilter` (Proxmox firewall) on guest bridges as required;
  - optionally compare with the address the qemu guest agent or IPAM reports.

**M-3. Release stanza metadata is unchecked.** CONFIRMED (executed).
- **Where:** `ou-release-sign` checks only Filename and SHA256. Package, Version, Depends, Conflicts, Pre-Depends, Size and MD5sum are free; `Package: ou-b`, `Version: 99`, `Conflicts: nftables` pointing at admitted bytes was SIGNED.
- **Failure scenario:** rollback to any older ledger package advertised as newer, or forced removal of security packages on guests.
- **Minimal fix:** the same as H-1 (ledger-recorded control fields, or signer-generated indexes).

**M-4. Image import pin is caller-supplied, and the rollback floor is mutable.** CONFIRMED (by code), latent: the verb has no non-test caller.
- **Where:**
  - `providers/base.py:155-156` and `provider.py:1005-1008`: key and pin both come from the spec;
  - `provider.py:1023-1026`: the floor comes from template tags visible to the token.
- **Failure scenario:** a future plan or UI path that forwards operator input imports an image signed by any key. Deleting or re-tagging the newest template re-enables a downgrade.
- **Minimal fix:**
  - read the release key and pin from Settings only (drop them from the spec);
  - persist the per-OS floor in the ICS database (written by the verb, monotonic);
  - add version and expiry to the signed manifest.

### Low

- **L-1. Callback limiter edge cases** (CONFIRMED by code, `callback.py:81-98,133-149`):
  - The per-IP key is the full address, so an IPv6 source can rotate inside its /64. Every new address gets 12 requests that each run `by_bid`, a DB SELECT, before the per-bid or unknown bucket applies.
  - Under a spray of more than 10,000 fresh keys, eviction removes only stale entries, so memory grows with the request rate.
  - Exhausting the `unknown` bucket turns 429 vs 401 into a bid-existence oracle.
  - Whoever knows a bid (VM.Audit) can drain its 30/min bucket from 3 addresses and outlast the guest's 600 s retry budget.
  - **Fix:** key IPv6 by /64; evict the oldest entries; do the `by_bid` lookup after the per-IP bucket and in constant work; make the guest's retry budget cover the whole `guest_bootstrap_timeout`.
- **L-2. Review-6 L7 is still open, and reinstall/restore remains fail-open** (CONFIRMED executed, `proto.py:110-114,123-129`).
  - **Fix:** refuse to start on an unreadable `epoch.json`; fsync the directory; carry the mark in `trust.json`, and have the ICS refuse to drive an agent whose reported `agent_epoch` is lower than the epoch the controller last saw from it. Store that per node in `nodes`; this also detects a reset mark.
- **L-3. Unbounded epoch jump** (CONFIRMED executed, `proto.py:79-80,121-130`): one signed request with `epoch=2^62-1` fences every legitimate controller for good. This needs the ICS key, which the standby bundle also carries.
  - **Fix:** refuse epochs greater than mark + small N unless an operator re-arms the agent; log mark raises.
- **L-4. `release.promote` signs with the online agent-signing key** (`release.py:97`): it is separated only by the signature prefix and travels in the standby bundle. Compromising the ICS process lets an attacker mint stable manifests.
  - **Fix:** a dedicated promotion key, ideally with an approver co-signature.
- **L-5. Attestations have no freshness check** (`ou-release-sign:359-362`): `at` is not compared, so an old `pass` can overwrite a later `fail`.
  - **Fix:** a monotonic `at` per (sha, name).
- **L-6. `backup.policy.create` does not compare the runner node's customer** (`backups/ops.py:150-158`). PLAUSIBLE.
  - **Fix:** require `node.customer_id == p.customer_id`.
- **L-7. `/plans/preview` existence oracle** for other customers' endpoint names (`blueprint.py:70`, `main.py:402`).
- **L-8. Standby nits:**
  - The `ics_standby` replication slot retains WAL indefinitely if the standby dies, which can fill the primary's disk. Monitor it or set `max_slot_wal_keep_size`.
  - On a standby, `ics-callback.service` (if enabled) has no `StandbyGuard`; the hot-standby database makes its writes fail anyway.

## 5. Standby write refusal and key bundle (integration-6)

**Standby write refusal:** complete for a *configured* standby.
- `StandbyGuard` returns 503 on every non-GET/HEAD/OPTIONS method (`standby.py:51-53`).
- The worker and credential adoption are off (`main.py:166-176`).
- The database is a hot standby (any write fails), and bootstrap forces `ICS_ROLE=standby` (`bootstrap.sh:229`).
- The gap is the *fenced* primary (H-5), not the standby.

**Key bundle (`keybundle.py`):**
- AES-256-GCM, header as AAD, scrypt N=2^15 over a 160-bit passphrase;
- file names allowlisted on seal and on unseal;
- `fchown`/`fchmod` on the fd before `os.replace`;
- the import target is root's `/etc/office-unbound`, which is not attacker-writable.

The bundle and passphrase are still written to the same directory and never shredded (review-6 L8).

## 6. Tests executed (scratch copy of ab30b85, DB e)

| Tests | Result |
|-------|--------|
| `tests/test_pbx_helper_symlink.py` | 6 passed |
| `tests/test_agent_epoch.py`, `test_standby.py`, `test_review5_bootstrap.py`, `test_image_import.py` | 40 passed |
| `tests/test_review5.py -k "m3 or l1 or l6 or l7"` | 4 passed |
| `tests/test_review5.py -k "m4 or m5 or m6 or l5"` | 7 passed |
| `tests/test_release_signer.py`, `tests/test_release_promote.py` | 25 passed |

No test was skipped. The existing suites pass, yet H-1 through H-5 are reproducible, so a green suite does not mean these areas are safe.

**Ad-hoc reproductions (scratch only, deleted or left in the session scratchpad):**
- `EpochGate` probes;
- signer PoCs with sandbox keys and an unprivileged apt;
- tenant probe test.


## Remediation (branch `fixes-r7`, agent BU)

Every row has a regression test that fails on the pre-fix code (the PoCs of this review were re-run: the signer now refuses all of them, see `ics/tests/test_release_signer7.py`). Operator procedure: [docs/admin/security.md](../admin/security.md) "Security review 7 hardening".

| # | Fix | Test |
|---|-----|------|
| H-1 duplicate-basename stanzas | `ou-release-sign` parses indexes with a strict deb822 parser; refuses duplicate fields, stanzas, `Filename`s/basenames and `Package`+`Version`+`Architecture`; checks EVERY stanza (name -> sha256 in the suite ledger), not the last one | `test_release_signer7.py::test_h1_*` |
| H-2 one key for all channels | one signing key per channel (`FINGERPRINT-<suite>`; stable keeps the lab key, first-contact guests pin only it); signer sets Suite/Codename; guest agent apt runs `AllowReleaseInfoChange=false` and checks Suite/Codename of the fetched `InRelease`; lab scripts pin the channel key and check the Release | `test_h2_*` (gpgv with each channel key: a dev Release does not verify with the stable key), `test_review7_client.py` |
| H-3 `ou-test-attest` self-attests | the runner takes only `run <kind> <ref>`, fetches the admitted bytes by hash from the signer's blob store, runs the fixed program in a throw-away nspawn container itself, signs what it observed (attestation v2, kind-bound); the sudoers rule is `ou-test-attest run *`; `record-test` accepts only kind `deb-install-smoke` and rejects older attestations (L-5). Stable interface and the `image-first-boot` kind for agent BI: header of `blueprints/build/repo/ou-test-attest` | `test_h3_*`, `test_h3_record_*`; real nspawn run in the lab (pass attested for `ou-grommunio-web`) |
| H-4 cross-tenant plans | `ics/tenancy/resolve.py`: customer derived from EVERY referenced resource; conflicts -> 409, a scoped caller naming another customer's object -> 404; explicit `customer_id` may only confirm; windows without a check and alert notifications stay inside their customer; catalog test: every action has a resolver or an explicit MSP-global reason, and reference-looking model fields must be covered | `test_review7_tenancy.py` |
| H-5 fencing beyond agents (lease added after consolidation review: R7-H5 PARTIAL) | `epoch.assert_active` (configured role + `controller_state` role + DB epoch equals the process epoch, sticky) at job claim (`FOR SHARE` in the claim transaction), before each job, in every worker loop, in `egress.require()` (agent, Proxmox, identity/Keycloak HTTP, notifications, promotion, SSH bootstrap, enrollment), and as a 503 middleware on console/API/guest callback; WITNESS LEASE (`ics/lease.py`, `ics/witness.py`): with a witness configured the controller acts only while it holds a signed, time-bounded grant (T=30 s, renewed every 5 s), promotion revokes the witness and waits T + margin before the epoch bump, so an isolated old primary fences itself; lease off without a witness; `fenced -> primary` only via a higher epoch (migration `0012r7`) | `test_review7_fencing.py` (resurrected-primary simulation), `test_review7_lease.py` (fake clock, partition, promotion proof, forged/replayed grants) |
| M-1 scoped admin invites | invitee inherits the creator's customers (never all-customers) and at most the creator's role | `test_review7_mediums.py::test_m1_*` |
| M-2 NIC binding TOCTOU | neighbour entry re-verified before the connection, before the token is sent and after the agent answered; node not recorded on a change; `macfilter`/`ipfilter` documented | `test_m2_*` |
| M-3 stanza metadata | see H-1: Package/Version/Architecture/Depends/Conflicts/Size/hashes bound to the ledger-recorded control data | `test_m3_*`, real `apt-ftparchive` output signs unchanged |
| M-4 / review-5 M7 image import | release key + pin only from `ICS_GUEST_RELEASE_PUBKEY_FILE`/`_PIN_SHA256` (the spec has no such fields); downgrade floor in the ICS DB (`image_floor`, monotonic trigger, migration `0013r7`) | `test_image_import.py::test_m4_*` |
| Review-6 L7 / L-2 epoch file | corrupt/empty -> fail closed (`epoch_state_corrupt`), `epoch.json` + `.bak` written atomically with fsync of file and directory, operator re-seed from a signed doc (`ics-cli epoch-attest`, `ou-agent reseed-epoch`) | `test_review7_agent.py` |
| Review-6 L8 | bundle passphrase shown on the terminal only, never beside the bundle; bundle and passphrase file wiped after import; `pg_hba` admits the standby app role for `--fence-old-dsn-file`; trigger refuses `fenced -> primary` without a promotion | `test_review7_fencing.py::test_h5_a_fenced_row_*` |
| Review-5 H1, H2 | H1 closed by H-1/M-3; H2 closed by H-3 + L-4 (below); the live `NOPASSWD: ALL` remains an OWNER ACTION | see above |
| Review-5 L4 | `ics/deploy/ics-callback.nginx.conf` + documented steps; default stays off until the owner places the proxy | n/a (deployment artifact) |
| Review-5 L5 | `/api/v1/system` only for all-customers admins | `test_l5_system_*` |
| L-4 promotion key | optional dedicated `ICS_RELEASE_PROMOTION_KEY_FILE` | `test_release_promote.py::test_review7_l4_*` |
| L-5 attestation freshness | `record-test` refuses an attestation not newer than the stored one | `test_h3_record_refuses_v1_wrong_kind_and_old_attestation` |
| L-6 backup runner node | covered by the resolver (`runner_node_id`) | `test_h4_every_*` |

**Not changed (accepted / owner action / open).** L-1 (callback limiter edge cases: IPv6 /64 keys, eviction, guest retry budget), L-3 (unbounded epoch jump), L-7 (`/plans/preview` existence oracle), L-8 (standby WAL slot / callback guard), `/readyz` still tells anonymous callers the role/epoch/fenced state (needed by the standby tooling), ICS-side detection of a reset agent mark (a reinstalled agent with no state directory counts as a node that never saw an epoch). Owner actions: remove `NOPASSWD: ALL` from `administrator`; run `install-signer.sh` + `repo.sh resign-all` (done in the lab, see host-changes); give guests that follow `dev`/`staging` the matching channel key; configure `ICS_GUEST_RELEASE_PUBKEY_FILE`/`_PIN_SHA256` before the first `image.import`; place the callback proxy; enable the Proxmox firewall `macfilter`/`ipfilter` on guest NICs.

**Note for agent BI (branch `oci-signing`, image signer).** Do not add an `attest-image <sha256> < evidence.json` interface: the runner no longer accepts caller evidence. Use `sudo -u ou-testrunner /usr/local/sbin/ou-test-attest run image-first-boot <absolute image path below /var/lib/ou-imgbuild/out>`; provide the fixed root-owned program `/usr/local/lib/ou-testrunner/image-first-boot <copy of the image>` (exit 0 = booted and called back, 1 = failed, other = infrastructure error, no attestation) from your installer. The attestation is `{"attestation": {"v": 2, "kind": "image-first-boot", "name": "first-boot", "sha256": <image sha256 computed by the runner>, "result", "log_sha256", "at", "run_id"}, "sig": <Ed25519 over b"ou-test-attestation-v1\n" + canonical JSON>}` with the runner key `trust/test-runner.pub`; `ou-image-sign record-test` must require `v == 2`, `kind == "image-first-boot"`, `sha256` equal to the image it signs, a valid signature, and an `at` newer than any stored record. `ou-release-sign record-test` rejects that kind, so the two signers cannot be confused.
