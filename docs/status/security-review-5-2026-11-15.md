# Security review 5 (2026-11-15)

Independent, read-only review. The only file written is this report. Code was read on `integration-5`
(`.claude/worktrees/agent-a6ad5f75af66eecd4`, HEAD `f34ed33`, clean). That branch merges bootstrap-v2, scope-ak, telephony
(a8e2), versioning (a060), tenant scoping (a7c4) and release-ag. Findings already reported and fixed in reviews 3/4 are not
repeated here.

**How each finding was checked:**
- **CONFIRMED (executed):** reproduced in a scratch sandbox. Two of these are against the release signer, using a throw-away
  GnuPG key and `OU_RELEASE_STATE`. The sandbox was deleted afterwards.
- **CONFIRMED (by code):** the failing path is unambiguous in the source.
- **PLAUSIBLE:** depends on something outside the repo, for example PVE logging behaviour or an attacker's precondition.

Line numbers are for `integration-5`.

## Summary

| # | Sev | Area | Finding | Status |
|---|-----|------|---------|--------|
| H1 | High | release | `ou-release-sign sign` does not bind the signed `Release` to the ledger. It only parses the uncompressed `Packages`/`Sources`. It never checks index paths that are listed but not supplied, or `Packages.gz`/`.xz` contents. It keeps the caller's `Suite:`/`Codename:`. Result: any code running as `administrator` gets an arbitrary package signed into `stable` | CONFIRMED (executed) |
| H2 | High | release | Review-4 H2 is still not effective. `administrator` still has `NOPASSWD: ALL` (live `sudo -l`). Even after that rule is removed, every promotion gate in the signer is attested by the same caller: `record-test ... pass` and a free-text `approved_by` | CONFIRMED |
| H3 | High | telephony | `ou-pbx-user issue` (root) opens a predictable file in a directory owned by `ou-agent`, without `O_NOFOLLOW`/`O_EXCL`, then `chown`s it. A planted symlink gives a root-created, agent-owned file at any path, so a compromised agent becomes root on the PBX node | CONFIRMED (by code) |
| M1 | Medium | bootstrap | Unauthenticated DoS. The global callback limit (120/min) can be saturated from about 10 LAN addresses. The guest treats HTTP 429 as final, so every first boot in flight fails closed for good | CONFIRMED (by code) |
| M2 | Medium | bootstrap | The callback is bound to the VM only by possession of the secret. The ICS never checks that the reporting IP is the VM it created (MAC/neighbour/lease). A replay alarm does not stop the deployment. The secret sits in the Proxmox VM config (readable with VM.Audit, included in vzdump) until enrollment | CONFIRMED (by code) / exposure paths PLAUSIBLE |
| M3 | Medium | scope | A scope change that adds `template_vmids` (new `VM.Clone` ACLs) is classified `same`. Combined with dropping a storage it is classified `narrow`. Both get `normal` risk (1 approver). `_scope_risk` also ignores the preview's own `risk` | CONFIRMED (executed) |
| M4 | Medium | tenancy | `decide_plan` has no customer-scope check. A customer-scoped approver can approve or reject another customer's plan, given its id | CONFIRMED (by code) |
| M5 | Medium | tenancy | Still unscoped for scoped operators: `/nodes`, `/checks` (+ `results`, `remediation`), `/incidents` (+ `{id}`), `/alert-channels`, `/maintenance`, `/backups/policies|runs|verifications` | CONFIRMED (by code) |
| M6 | Medium | tenancy/telephony | `idm.stack.register` accepts any existing `pbx_node_id`/`gromox_node_id`/`files_node_id`, and nodes have no customer. Customer A's stack can therefore point at customer B's PBX and obtain SIP credentials for B's users | PLAUSIBLE |
| M7 | Medium | image supply chain | `image.import` is not wired to `verify_release`. `import_image` trusts a caller-supplied sha256. There is no anti-rollback for golden images | CONFIRMED (by code), latent |
| L1 | Low | secrets at rest | No sweeper for `guest_bootstrap` (pending/reported rows of abandoned deployments keep `secret_enc`/`token_enc`) or for expired, never-revealed `idm_sip_credentials` (the ciphertext of a still-valid SIP password) | CONFIRMED (by code) |
| L2 | Low | bootstrap | The documented "4 KiB cap" is not enforced (256 KiB global). The limiter is per process, so N workers get N times the limits | CONFIRMED (by code) |
| L3 | Low | bootstrap | Timing difference between known and unknown `bid` (vault decrypt plus an `UPDATE`/audit only for known ids). The 64-bit random bid makes this informational | CONFIRMED (by code) |
| L4 | Low | bootstrap | The callback is served by the full console app. Every guest network that must reach the callback also reaches login and the whole API | PLAUSIBLE |
| L5 | Low | versioning | `/api/v1/version` and `/readyz` disclose the exact version to anyone. Any session, including a customer-scoped viewer, gets commit, dirty flag, schema and component versions | CONFIRMED (by code) |
| L6 | Low | scope | The Mode B `confirm_package` path recomputes with `facts=None` and does not re-check `blocked`/orphans before committing | CONFIRMED (by code) |
| L7 | Low | image recipe | Upstream images come from `.../latest` with no freshness check. An older, validly signed SHA512SUMS plus image can be replayed | PLAUSIBLE |

---

## High

### H1. The release signer signs indexes it never checked, and under any suite name
**Where:** `blueprints/build/repo/ou-release-sign:189-232` (`cmd_sign`). The deployed `/usr/local/sbin/ou-release-sign` is byte-identical to this file (`cmp`).
- `:198-200`: only paths that are both listed in `Release` and supplied in the tar are hash-checked. A path listed but not supplied (`main/binary-amd64/Packages.xz`) is signed without any check.
- `:201-217`: the ledger check parses only files ending in `/Packages` and `/Sources`. The contents of `Packages.gz`/`Packages.xz` are hashed (when supplied) but never parsed. `repo.sh index` itself ships `Packages.gz`, and apt prefers compressed indexes.
- `:223-227`: the caller's header is kept except `Date`/`Valid-Until`. `Suite:`/`Codename:`/`Origin:` are not forced to the `<suite>` argument.
- The MD5Sum/SHA1/SHA512 sections after the marker are kept unverified.

**Reproduction (sandbox key, same program):**
1. Ledger `stable` contains only `good-deb`.
2. Supply a `Packages` that lists the ledger hash, and a `Packages.gz` that lists `ou-x_2_amd64.deb` with an unadmitted hash.
3. The `Release` lists both, plus an unsupplied `Packages.xz`.
4. Result: `SIGNED`, with all three entries in the signed `Release`.

Second run: with `sign dev` and a header of `Suite: stable` / `Codename: stable`, the output is signed with `Suite: stable`.

**Failure scenario:** the build user runs untrusted build output and scanners (review 4). Code running as that user:
1. `admit dev` (no gate) or skip the ledger altogether;
2. sign a `Release` whose `Packages.gz` (or a listed `.xz`) points at a trojan `.deb`, or sign `dev` content labelled `stable`;
3. place it in `dists/stable`. `repo.sh serve`, or the hourly `ou-repo-resign` timer, publishes it.

Every guest trusts the key through `signed-by`, so they install it. This defeats the M7 promotion ledger completely.

**Minimal fix:** in `cmd_sign`:
- require that every path in every hash section is supplied and verified;
- refuse any listed path other than the exact allowlist (`main/binary-amd64/Packages{,.gz}`, `main/source/Sources{,.gz}`);
- decompress and parse each compressed index and require it to equal the uncompressed one;
- drop the MD5Sum/SHA1/SHA512 sections or verify them too;
- rebuild the header from fixed values with `Suite: <suite>` and `Codename: <suite>`, and drop the caller's header.

Also check, on each `Packages` stanza, `Filename` (`pool/<suite>/...`), `Size`, and every `SHA512`/`MD5sum` field against the ledger entry.

### H2. Review-4 H2 is not fixed: separation of duties exists only inside a program the separated party controls
**Where:**
- live `sudo -n -l` for `administrator`: `(ALL : ALL) NOPASSWD: ALL` and `(ALL) NOPASSWD: ALL` are still present next to `(ou-release) NOPASSWD: /usr/local/sbin/ou-release-sign`;
- `install-signer.sh:10-11` states this itself;
- `ou-release-sign:244-253` (`record-test`: any caller can write `install-smoke pass` for any sha256; `recorded_by_uid` is just `SUDO_UID`);
- `:259` (`approved_by` is free text checked only by a regex);
- `:270-276` (the only promotion gate is that self-written record).

**Failure scenario:**
- Today: root via `NOPASSWD: ALL` reads `/var/lib/ou-release/passphrase` and the key.
- After `NOPASSWD: ALL` is removed: the same user can run `admit dev`, then `record-test <sha> install-smoke pass <any>`, then `promote dev staging`, then `promote staging stable "Owner"`, then `sign stable`. No second human is involved. H1 makes even this unnecessary.

**Minimal fix:**
- remove `NOPASSWD: ALL` from the build user;
- have the test runner (not the build user) produce records signed with a separate key, and verify that signature in `promote`;
- for `stable`, require an approver signature (detached signature by an approver key listed in the signer state), not a name string.

Production signing stays offline/HSM as already documented.

### H3. Agent-to-root on the PBX node through the SIP issue helper (symlink)
**Where:** `ics/agent/deploy/runbooks/ou-pbx-user:35-50`.
1. The root helper makes `/run/ou-rb-secret`, owned by `ou-agent` with mode 0700 (`:37-39`).
2. It runs the cleanup loop (`:40-45`). That loop uses `os.stat`, which follows links; a dangling symlink makes it raise, and the link is skipped and kept.
3. It runs `os.open(path, O_WRONLY|O_CREAT|O_TRUNC, 0600)` without `O_NOFOLLOW`/`O_EXCL` (`:47`).
4. It runs `os.chown(path, ou-agent)`, which follows the link (`:50`).

`fs.protected_symlinks` does not apply, because the directory is not sticky and not world-writable. The unit `ou-rb-pbx-issue@.service` has no `ProtectSystem=`, so `/etc` is writable for the helper. Polkit lets `ou-agent` start `ou-rb-pbx-issue@<uid>.<device>.service` itself.

**Failure scenario:** a bug in the network-facing agent, which runs as `ou-agent`, lets an attacker run code as that user. The attacker:
1. creates `/run/ou-rb-secret/pbx-issue-alice.web.json` as a symlink to `/etc/ld.so.preload`, which does not exist;
2. starts the issue unit;
3. root creates `/etc/ld.so.preload` and chowns it to `ou-agent`;
4. the attacker writes the path of their own shared library into it, and every later root process loads it.

This defeats the "agent is unprivileged; polkit only starts fixed units" boundary.

**Minimal fix:**
- keep the directory root-owned with mode 0750, group `ou-agent`;
- create the file with `O_CREAT|O_EXCL|O_NOFOLLOW` after `unlink`, then `fchown`/`fchmod` the fd, and let the agent unlink it through group write on a root-owned directory with mode 1770; or return the secret over a pipe or socket instead of a file;
- add `ProtectSystem=strict` and `ReadWritePaths=/run/ou-rb-secret` to the unit.

---

## Medium

### M1. Unauthenticated bootstrap DoS (global rate limit plus no retry on 429)
**Where:**
- `ics/ics/guest/callback.py:37-38,117-118`: the per-IP limit is 12/min and the global limit is 120/min. The limiter is consulted before any proof work, and FastAPI accepts any schema-valid body.
- `ics/agent/ou_agent/firstboot.py:94-95`: a 429 becomes `Refused("the ICS refused the report (HTTP 429)")`.
- `firstboot.py:284`: "refused the report" means no retry; the failed marker is written.
- `ou-bootstrap.service`: `Restart=no`, `ConditionPathExists=!.../failed`.

**Failure scenario:** a host on the VM/LAN network with about 10 addresses (or 10 compromised guests) sends 2 dummy reports per second. Every VM booting in that window gets 429 once and fails closed permanently. The deployment step then times out and has to be destroyed and re-created. The attacker can repeat this indefinitely. No secret is needed.

**Minimal fix:**
- guest: retry 429/503 with backoff until the deadline, and treat only 401 as final;
- ICS: drop the global bucket, or apply it only to requests whose `bid` does not exist (known bids are bounded by live records); per-bid limiting is enough for brute-force resistance at 256-bit HMAC.

### M2. The callback trusts whoever holds the secret, wherever they are
**Where:**
- `ics/ics/deploy/agentport.py:143-166`: `await_callback` accepts any `reported` state.
- `agentport.py:188-201`: `_enroll_from_callback` connects to the reported address.
- `callback.py:147`: the only check is source IP equals the self-reported address.
- `callback.py:156-161`: the replay alarm is audit only.
- The secret sits in `smbios1` (base64) in the VM config from `vm.configure` until `_finish` after enrollment.

Compare the lab path: it ties the guest to the Proxmox MAC (`sshboot.link_local(guest_mac)`). The production path has no equivalent.

**Failure scenario:** someone who can read the VM config during the up to 30-minute window reports first, from their own LAN host. This covers a Proxmox user or token with VM.Audit on the pool, a vzdump job, a config backup, and (PLAUSIBLE) the PVE `update VM <id>: -smbios1 ...` cluster log and journal line. The ICS then enrolls the attacker's agent as the customer VM and pushes component configuration and runbooks to it. The genuine guest's report then raises `guest.bootstrap_replay_alarm`, but the deployment carries on.

**Minimal fix:**
- before accepting, check that `src` is a neighbour whose MAC equals the VM's `net0` MAC (ARP/ND lookup, as in the lab path), or that it is the address the guest agent or IPAM reports for that vmid;
- make a replay alarm on a record that is not yet `enrolled` fatal: mark it `failed`, `fail_closed`, stop the VM;
- set the SMBIOS material as late as possible, just before `vm.start`, and document that VM.Audit on the deployment pool is equivalent to bootstrap authority.

### M3. Scope widening through templates is classified as `same`/`narrow` (fewer approvals)
**Where:**
- `ics/ics/providers/proxmox/scope_change.py:48-60`: `_reach`/`direction` consider nodes, storages, migrate, overrides and whole-cluster, but not `template_vmids` or role-privilege changes.
- `ics/ics/provisioning/actions.py:243-244`: `_scope_risk` uses only `direction`/`detach` and ignores `sc.risk`/`plan.risk`.
- `provisioning.py:235,240-241`: each template adds `/vms/<t>` monitor plus `template_clone` (`VM.Clone`) ACLs.

**Reproduction:** `direction(old, target_policy(old, ScopeTarget(mode='single_node', nodes=['pve06'], template_vmids=[9612,131,555])))` returns `same`. With `storages=['PVE06-Storage']` (one storage dropped) it returns `narrow`.

**Failure scenario:** an operator gains VM.Clone and VM.Audit on extra templates (another tenant's or an owner template) with `normal` risk. That means one approver instead of `required_approvals_high`. The approver UI labels the change "narrow".

**Minimal fix:** compute direction from the permission diff instead (`acl_add` non-empty, or any role `added` privileges, means `widen`). Have `_scope_risk` use the preview's stored `risk` (take the maximum).

### M4. Approving another customer's plan
**Where:** `ics/ics/actions.py:811-866` (`decide_plan`). It checks requester, provenance, self-target, status and expiry, but never `tscope.allowed(user, plan.customer_id)`. `GET /plans` is scoped, but approve/reject by id is not.

**Failure scenario:**
- A customer-A-scoped approver who learns a plan id of customer B supplies one of B's two high-risk approvals, or rejects B's plans (DoS).
- Plan ids can be seen in shared links, screenshots or job references. Approval quorum is meant to be per tenant.

**Minimal fix:** in `decide_plan`, `if plan.customer_id and not tscope.allowed(user, plan.customer_id) or plan.customer_id is None and user.customer_ids is not None: raise PlanError(404, "plan not found")`.

### M5. Remaining unscoped read surfaces (tenant isolation)
**Where:** `ics/ics/main.py`. None of these handlers filter by customer:
- `:410` `/nodes`: every enrolled guest's address, port, TLS and key fingerprints.
- `:416` `/checks`: targets and configs.
- `:431` `/checks/{id}/results`.
- `:439` `/checks/{id}/remediation`.
- `:444` `/incidents`.
- `:456` `/incidents/{id}`: notification details.
- `:468` `/alert-channels`.
- `:480` `/maintenance`.
- `:549/554/559` `/backups/*` (`backups/ops.py:413-433`).

`docs/status/tenant-isolation-results.md:54` lists checks, nodes and alert channels as "not covered". This was verified as still open, and the backup and maintenance views are also affected. `/users`, `/users/{id}` and `/invitations` (`userdir.py:96-146`) show the ICS operator directory to every scoped viewer. That is acceptable only if operators are MSP staff.

Every other list/get endpoint was enumerated and is scoped:
- plans, jobs, job steps;
- endpoints, inventory, infra;
- credentials, customers, customer approvals;
- deployments, identity;
- provider permissions and packages;
- audit (all-customers only).

**Failure scenario:** a customer-A operator maps customer B's VMs, monitored services, incident texts and backup state. The node ids learned this way feed M6.

**Minimal fix:** add `customer_id` to `nodes` (from the deployment's endpoint at enrollment) and to `checks` and `alert_channels`, then apply `tscope.clause` to these handlers. Until then, return 403 for `user.customer_ids is not None`, as `/audit` does.

### M6. Cross-tenant node reference in identity stacks (SIP credential of another tenant)
**Where:** `ics/ics/identity.py:847-849`: the precheck only tests `SELECT 1 FROM nodes WHERE id = :i`. Nodes carry no customer (M5). `exec_issue_sip` then calls `pbx.issue_credential` on that node for a uid of the requesting stack, and only checks that the returned extension equals the local record.

**Failure scenario:**
1. A customer-A operator registers stack `a2` with `customer_id=A` and `pbx_node_id=<B's PBX, from /nodes>`. This is high risk, so approvers must pass it, but the parameters look ordinary.
2. They create user `alice` with B-alice's extension, which they can guess or enumerate through PBX sync errors.
3. They issue a SIP credential and reveal it. The result: they can register as B's alice, place calls and receive her calls.

The same holds for `gromox_node_id` (kick sessions) and `files_node_id`.

**Minimal fix:** bind nodes to a customer and require `node.customer_id == stack customer_id` in the precheck and again at execution.

### M7. Golden-image import: verification not enforced at the verb, no anti-rollback
**Where:**
- `ics/ics/guest/golden.py:47-80` (`verify_release`) has no caller in the code base; only tests use it.
- `ics/ics/providers/proxmox/provider.py:980-985` (`import_image`) documents "the caller has ALREADY verified the release signature", takes a bare `spec.sha256` and re-hashes only against that.
- No release monotonicity: `IMAGE_RE` carries a date, but nothing compares it with already imported templates or with a minimum.

**Failure scenario:**
- When the verb is wired to a plan or UI, a path that passes an operator-supplied checksum imports an unsigned image.
- An attacker controlling the release directory can swap in an older, correctly signed release with known-vulnerable packages, and it imports cleanly.

**Minimal fix:**
- make `ImageImportSpec` take a `golden.Release` (or have `import_image` call `verify_release` with the settings-pinned key itself);
- record imported release dates per OS and refuse anything older than the newest imported, unless an explicit high-risk override is given;
- put a version and expiry into the signed manifest.

---

## Low

### L1. One-time secrets that outlive their purpose
**Where:**
- `bootsecrets.py`: there is no sweeper. Records of a deployment destroyed or cancelled while `pending`/`reported` keep `secret_enc`/`token_enc`. Expiry is only enforced when a report arrives.
- `identity.py:684-708`: unrevealed SIP credentials stay encrypted after `expires_at`, and the password stays valid on the PBX.
- Neither table is cleaned by `worker`.

**Fix:** a periodic `UPDATE ... SET secret_enc = NULL ... WHERE expires_at < now()` for both tables, with state `expired`. On SIP expiry, also rotate or purge the PBX credential (`pbx.kick_user`).

### L2. Size and limiter claims
**Where:**
- `callback.py:7` claims a 4 KiB cap; the enforced cap is `max_body_bytes` = 256 KiB (`config.py:50`).
- `LIMITER` lives in process memory (`callback.py:101`), so the effective limits multiply with workers.

**Fix:** check `content-length <= 4096` in the route. Document a single worker, or move the limiter into the DB.

### L3. Bid-existence timing difference
**Where:** `callback.py:129-145`: vault decrypt and `UPDATE attempts` (plus audit at 1/10/100) happen only for existing bids.

**Note:** the bid is 64-bit random and confidential, so this is informational. If wanted, do a dummy decrypt and update for unknown bids.

### L4. The callback shares the console listener
**Where:** `main.py:400` registers the callback on the main app, and `ICS_GUEST_CALLBACK_URL` has no path. Customer guest networks must reach the whole ICS (login, API).

**Fix:** a separate listener or bind address that serves only `POST /api/v1/guest-bootstrap/report`, or a reverse-proxy allowlist.

### L5. Version disclosure
**Where:**
- `main.py:209`: `/readyz` (unauthenticated) returns `version`.
- `main.py:224-231`: any valid session, including customer-scoped viewers, gets commit, dirty flag, build time, DB revision and component versions.

**Fix:** keep the public version (as intended), but return the full build detail only to `admin` or all-customers users. Consider removing `version` from `/readyz`.

### L6. Mode B confirm skips the orphan and blocked re-check
**Where:** `provisioning/actions.py:728-743` builds with `facts=None` and never consults `sc.blocked`. Guests deployed onto a node that leaves the scope between preview and confirm are committed as out of scope and not detached.

**Fix:** collect facts (they are already read through `_Reader(c0)`), pass them to `build_from` and refuse when `blocked`.

### L7. Upstream image freshness
**Where:** `blueprints/build/guest-image/os/*.env` uses `.../latest`. `recipe.sh:35-46` verifies the signature and checksum but not freshness. A MITM or mirror can serve an older validly signed `SHA512SUMS` plus image.

**Fix:** pin the expected upstream image date or serial in the profile, or record the previous build's upstream hash and refuse to go backwards.

**Note (outside the stated targets):** live `sudo -l` also shows `(ou-imgsign) NOPASSWD: /usr/local/sbin/ou-image-sign *`. The trailing `*` allows arbitrary arguments, so that program must validate all of them itself.

---

## Fix verification (review 4)

| Item | Claim | Verdict |
|------|-------|---------|
| H1 (symlink in builder artifacts) | `artifact-check.py extract`; `strict_dir`; `cp --no-dereference` | **Effective.** `lib/artifact-check.py:101-124` accepts only `m.isreg()` members, names without `/`, and opens with `O_CREAT\|O_EXCL\|O_NOFOLLOW` into a fresh 0700 directory. `repo.sh:24-36,61-70` refuses non-regular or hardlinked files and copies with `--no-dereference` plus a hash compare. Both `build.sh:102,125` paths use the checker. |
| H2 (signing key reachable by `administrator`) | dedicated `ou-release` user, passphrase, sudoers wrapper, ledger, Valid-Until | **Not effective** (see H1/H2 above). The key is now passphrase-protected (`install-signer.sh:42`), and the sudoers rule is exact: one absolute path, run as `ou-release`. The environment is stripped: `OU_RELEASE_STATE=/nonexistent sudo ... status` still reports the real ledger. But `NOPASSWD: ALL` is live, the gates are self-attested, and the wrapper signs unverified indexes. |

## Verified sound
- **Callback proof:** HMAC-SHA256 over a domain-separated canonical string. It binds bid, nonce, ts, address, port, TLS and key fingerprints, and the token hash. Comparison is `compare_digest`, with a dummy key for unknown bids. Every failure returns one generic 401. Strict regexes apply to every field, and loopback, link-local and reserved addresses are refused.
- **Single use:** an atomic `UPDATE ... WHERE state='pending' AND expires_at > now AND mode='callback'`. A valid proof on a used or expired record raises `bootstrap_replay_alarm` and accepts nothing. Skew is ±5 min. The source must equal the reported address. XFF is honoured only from a single loopback `trusted_proxy`.
- **Guest side:** the pin is checked before any byte of the request is sent. The ICS must prove the secret (ack) and MAC the config. The config schema is closed and validated again on the guest. The guest fails closed (default-deny nftables, SSH masked, cloud-init disabled, `Restart=no`), and an authentication failure is never retried.
- **SMBIOS secret confidentiality:** in the guest, the kernel makes `product_serial` and `/sys/firmware/dmi/tables` mode 0400 root, and the image has no user accounts before first boot. In the ICS, step results return only `{"configured": true}`. No log line or audit entry contains the secret.
- **Secret clearing:** after enrollment, `_finish`/`_clear_material` removes `serial/sku/family` (keeping the uuid), and `fail_closed` does the same on any failure. The vault columns are NULLed. A re-created instance revokes and wipes earlier records.
- **Lab SSH path:** refused unless `ICS_ENVIRONMENT=lab` (`Settings.__post_init__` → `_check_lab_only`), whichever way the Settings object is built.
- **Golden-image manifest check:**
  - ECDSA P-256 only, with the SPKI pin compared;
  - exactly one image and its SBOM, no `/`, no duplicates, no symlinks;
  - the Proxmox upload carries `checksum-algorithm=sha256`, so a swap after the re-hash is caught by PVE.
- **Upstream key:** the recipe refuses an empty `UPSTREAM_KEY_FPR` and requires `VALIDSIG <pinned fpr>`.
- **Scope change, Mode A:**
  - the client's `direction`/`detach` must equal the stored preview;
  - mixed widen-plus-narrow changes count as `widen`;
  - the hash is recomputed from live facts and must equal the approved `plan_hash`;
  - failed verification reverts to the old policy.
- **Scope change, Mode B:** confirmation verifies the live Proxmox state against the approved new design (missing, unexpected, forbidden, scope_reach). Extra privileges inserted into the package make it fail.
- **SIP one-time reveal:**
  - single use (`FOR UPDATE`, then `revealed_at`/`secret_enc=NULL` in the same transaction), requester-only, `Cache-Control: no-store`;
  - per-row AAD, and the reveal is audited;
  - the password is added to `known[]` for redaction, and the raw agent result is not audited;
  - the job result carries only the username;
  - the agent unlinks the result file;
  - risk `normal` means one approver who is not the requester; self-approval is refused globally (`actions.py:818`).
- **Tenant fixes (a7c4):** deployments, deployment sub-resources, previews, `/jobs/{id}/steps` and identity stacks/users/reconcile are scoped. Plan creation refuses customer-less or out-of-scope targets for scoped operators (`actions.py:688-691`).
- **Versioning:** `BUILD_INFO.json` is written at install time. The service never runs git or any subprocess. `update_status` is local only.
- **Release pipeline:**
  - `Valid-Until` is set by the signer (14 days), and the re-sign timer keeps it alive;
  - the builder is ephemeral: a fresh clone of the golden image per build, dropped afterwards;
  - the repo is served from a dedicated read-only machine (`DynamicUser`, `ProtectSystem=strict`).

## Tests
No project test suites were run; the review was by code reading plus two sandbox reproductions (signer) and one pure-function
execution (`scope_change.direction`).


---

## Remediation (agent BA, branch `fixes-r5`, 2026-11-15)

Every finding has a regression test that fails on the pre-fix code. Gate: `ICS_TEST_ENV_FILE=/etc/office-unbound/ics-test-d.env ics/.venv/bin/pytest -q -p no:cacheprovider` (result in the commit message of the last commit), `blueprints/build/tests/test-pipeline-security.sh` 33/0, telephony P05 14/0 on `ou-pbx2`.

| # | Fix | Test |
|---|-----|------|
| H1 | `ou-release-sign sign` parses every index named in `Release` (`Packages`, `.gz`, `.xz`, `Sources*`), requires each listed file to be supplied and to match size and every hash section, refuses unlisted extra files and non-allowlisted paths, refuses compressed variants that differ from the plain index, requires every stanza to name `pool/<suite>/<component>/` and a ledger sha256 of that suite, and **rebuilds** the signed `Release` (Suite/Codename from its own argument, Date, Valid-Until, hashes computed from the verified files). Re-installed in the lab (`install-signer.sh`, host-changes.md). | `ics/tests/test_release_signer.py` (`test_h1_*`), `blueprints/build/tests/test-pipeline-security.sh` |
| H2 | Typed action `release.promote` (`ics/ics/release.py`): the plan carries the exact package set + test evidence hashes; dev>staging = 1 approver, staging>stable = high risk (2 approvers); requester excluded by the global rules. The executor signs a promotion manifest with the ICS signing key and calls `repo.sh promote-manifest`; the signer verifies signature, expiry, approver count, requester exclusion, single-use nonce, exact file set and the evidence. Test records come only from `ou-test-attest` (own user and key) as signed attestations; `record-test <sha> pass ...` and `repo.sh promote --approved-by` are gone. **Not fixable in code:** `administrator` still has `NOPASSWD: ALL` (`/etc/sudoers.d/90-cloud-init-users`, `/etc/sudoers.d/90-claude-administrator`): owner action with the exact change in `docs/admin/security.md` ("Release signing, promotion and the build user"). Sudoers was not changed. The ICS public key still has to be installed into `trust/ics-promotion.pub` (`OU_ICS_PROMOTION_PUB`) and `ICS_RELEASE_PROMOTE_CMD` set. | `test_release_signer.py` (`test_h2_*`), `ics/tests/test_release_promote.py` |
| H3 | `ou-pbx-user issue`: `/run/ou-rb-secret` is root-owned mode 1770 (group `ou-agent`), rebuilt if it is anything else; the directory is opened once (`O_DIRECTORY\|O_NOFOLLOW`) and every operation goes through that fd (`unlink`/`open`/`stat` with `dir_fd`); the file is created `O_CREAT\|O_EXCL\|O_NOFOLLOW` and `fchown`ed on the fd; the unit has `ProtectSystem=full` + `ReadWritePaths=/etc/asterisk`. Redeployed on `ou-pbx2`: planted symlink to `/etc/ld.so.preload` did not create it, the agent still reads and unlinks its file; real unit run OK; P05 14/0. | `ics/tests/test_pbx_helper_symlink.py`, lab run |
| M1 | Callback limits: per source IP, per bootstrap id (reserved budget of every known VM) and a separate bounded budget for unknown ids (no global bucket). The guest treats 429/503 as transient (`Busy`, backoff 10..120 s, honours Retry-After, bounded by its 600 s retry budget); only authentication failures are final. | `test_review5_bootstrap.py::test_m1_*` |
| M2 | Before enrolling, the reporting address must resolve in the ICS host's ARP table (`ics/guest/neigh.py`, no scan; at most one connect to the reported agent port) to the MAC of the VM's `net0` (`guest_mac`); a mismatch or missing entry fails closed (VM stopped, material cleared); switch off only with `ICS_GUEST_REQUIRE_NIC_BINDING=false` for routed guest networks. A valid replay on a `pending`/`reported` record fails the record, wipes its secrets and so stops the deployment. The SMBIOS material is cleared after enrollment (`_finish`) and in `fail_closed`; the PVE task log of the configure step is checked (`task_log_mentions`) and a hit is logged in the step output. PVE task logs cannot be edited from the API: purge a flagged task in Proxmox. | `test_review5_bootstrap.py::test_m2_*` |
| M3 | `direction()` counts added template VMIDs as widening; any new ACL entry or role privilege in the permission diff raises the direction to `widen` regardless of what else is dropped; the plan risk is `max(risk_fn, preview risk)`; summaries list templates. | `test_review5.py::test_m3_*` |
| M4 | `decide_plan` answers 404 when the approver is outside the plan's customer (or the plan is customer-less and the approver is scoped). | `test_review5.py::test_m4_*` |
| M5 | Migration `0010`: `customer_id` (default MSP-internal) on `nodes`, `checks`, `alert_channels`, `maintenance_windows`, `backup_policies`; every listed endpoint and `/checks/{id}/results|remediation`, `/incidents/{id}` is scoped; creating actions take an optional `customer_id`, executors store the plan's customer, deployments stamp their endpoint's customer; plan targets (`check_id`, `node_id`, ...) resolve their customer. A test enumerates every GET route and requires scoping or an allowlist entry with a reason. | `test_review5.py::test_m5_*` |
| M6 | `idm.stack.register` refuses nodes of another customer (and unknown nodes, same message) at plan time and again at execution; `agent_user(..., customer=)` refuses a foreign node for SIP issue. | `test_review5.py::test_m6_*` |
| M7 | `import_image` takes the release directory + key + pin, calls `verify_release` itself, derives path and sha256 from the verified release (claims must match), and refuses a release older than the newest imported one for that OS (read from `ou-rel-<os>-<date>` template tags set by the verb) unless `allow_downgrade` (to be carried by a separately approved high-risk plan). | `test_image_import.py::test_m7_*` |
| L1 | `bootsecrets.sweep` (expired + 15 min grace, never-enrolled material) and `identity.sweep_sip_credentials` (expired, unrevealed: ciphertext wiped, best-effort `pbx.kick_user`) run from `reap_expired` and are audited. | `test_review5.py::test_l1_*` |
| L2 | 4 KiB body cap enforced in the route (Content-Length and streamed). The limiter stays per process: run the callback listener as one worker (documented in the listener module). | `test_review5_bootstrap.py::test_l2_*` |
| L3 | Unknown ids run the same vault decrypt and DB round trip (`_dummy_work`). | `test_l3_*` |
| L4 | `python -m ics.serve_callback` (+ `deploy/ics-callback.service`) serves only the callback route and `/healthz`; `ICS_GUEST_CALLBACK_DEDICATED=true` removes it from the console app. Reverse-proxy/bind configuration is deployment work (not done in the lab). | route registration only (no listener test) |
| L5 | `/api/v1/version` and `/readyz`: product + major only for anonymous, non-admin and scoped users; full detail for all-customers admins. | `test_review5.py::test_l5_*`, `test_version.py` |
| L6 | Mode B confirm collects the same live inputs as Mode A (facts, node rows, guest storages) and refuses when the change is blocked (orphans). | existing Mode B tests, run through the new path |
| L7 | Image profiles pin a dated upstream build (`UPSTREAM_SERIAL`, no `latest`); `fetch`/`verify` refuse an empty serial, a build older than `UPSTREAM_MAX_AGE_DAYS` (60) and one older than the last accepted (`$WORK/upstream-serial.last`). The profiles ship with the serial unset: the operator pins it together with the key fingerprint. | `test_review5.py::test_l7_*` |

Open after this round: the `NOPASSWD: ALL` rule (owner), installing the ICS public key into the signer and configuring `ICS_RELEASE_PROMOTE_CMD` (owner/operator), the dedicated callback listener/reverse proxy (deployment), in-process limiter with several workers, no frontend for `release.promote` yet (API/plan only).
