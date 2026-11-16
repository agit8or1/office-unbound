# Security review 8 (2026-11-16)

Independent review. The reviewer did not write this code, and the only file written is this report. Earlier reviews were read for format only; every verdict below was re-derived from the source.

**Purpose:** review what changed since review 7, highest risk first:
1. SSH onboarding (ADR-0014): `ics/ics/sshonboard/*`, its API routes, migration `0014s`, the console view `SshOnboard.vue`;
2. golden images and the downgrade floor: `ics/ics/guest/golden.py`, migration `0015g`, `providers/proxmox/provider.py` `import_image`, `providers/base.py` `ImageImportSpec`;
3. artifact distribution (`ics/ics/artifacts.py`, `ics/deploy/artifacts/*`), the OCI signing client and `ou-test-attest`, privilege separation (`ics/deploy/privsep/*`);
4. spot checks: plan customer resolution for SSH actions, `_error_dict`, `/api/v1/system`, `/api/v1/version`.

**Code read:** `main` at `781f35f` (an isolated worktree). Deployed production is `f861d5c`. All line numbers refer to `781f35f`.

**How each finding was checked:**
- **CONFIRMED (executed):** reproduced in a scratch directory (stdlib-only code; no network, no hosts touched).
- **CONFIRMED (by code):** the failing path is unambiguous in the source.
- **PLAUSIBLE:** depends on a precondition outside the repo, or on behaviour that was not executed.

**Limits:** the ICS virtualenv in this worktree is a broken self-referencing symlink and no Python on the host has `paramiko`, so the SSH-onboarding unit tests could not be run. No database test environment was used. No Proxmox host, VM 126 or production service was contacted.

## 1. What holds (SSH onboarding)

| Question | Verdict | Evidence |
|---|---|---|
| Can the requester widen PVE rights beyond the approved plan? | **No** | `exec_onboard` recomputes the whole plan from live facts and the stored preview, and refuses unless the new `bind_hash` (plan hash + SSH binding + exact command lines + identity) equals the approved one (`sshonboard/actions.py:514-520`). The preview artifact is written only by the preview job; no API edits it. Plan risk = max(catalog, preview risk) (`actions.py:744-748`). |
| Injection through host / user / node / pool / storage / ACL path | **None found** | Every value placed in a remote argv passes a strict regex (`templates.py:14-22,66-69`) and the line is rendered with `shlex.join` (`:56-57`). The helper takes only `SSH_ORIGINAL_COMMAND`, splits on spaces, regex-checks every token and execs fixed argv lists without a shell (`ou_pve_helper.py:322-379`). |
| Host-key handling | **Holds** | Strict pin: no known_hosts, no auto-add, one algorithm per transport, compared with `hmac.compare_digest` before authentication (`client.py:169-186,222-231`). The confirmation is TOFU by design: the console shows the candidate and asks the admin to compare it with `ssh-keygen -lf` on the node console (`SshOnboard.vue:172-180`). |
| Credential wipe | **Holds** | Success: `S.wipe` in the same transaction as the result (`actions.py:558`). Failure: rollback, then a wipe in an independent transaction (`:571-576`, `:583-587`). Expiry: `sweep` from the reaper (`session.py:163-173`, `actions.py:1029`). The secret is never in params, results or audit. |
| Tenant scoping | **Holds** | `tresolve` maps `ssh_session_id`, `endpoint_id` and `preview_id` (`tenancy/resolve.py:32,97-102`). `customer_for` refuses a session/endpoint/customer mismatch (`sshonboard/actions.py:138-157`). Executors re-check that the session belongs to the plan's requester and customer (`:358,424,495,603`). |
| Approver ≠ requester | **Holds** | `decide_plan` refuses the requester (`actions.py:927`), and the job re-verifies approvals (`:1054-1070`). |
| authorized_keys / sudoers | **Holds (but see M-1, L-2)** | `restrict,command="sudo -n /usr/local/sbin/ou-pve-helper"` (`admin.py:213-220`). The sudoers rule allows exactly the helper with an empty argument list (`:206-210`) and is staged, checked with `visudo -cf`, then moved into place (`templates.py:223-236`). `_helper_verify` probes 8 forbidden commands after installation (`actions.py:482-486`). |
| `_error_dict` | **Holds** | Only `_SAFE_ERRORS` text is passed through, redacted against `known` (which `_connect` fills with the admin secret). Other exceptions log frames only (`actions.py:1043-1051`). `prov.safe` withholds pydantic text (`provisioning/actions.py:278-290`). |
| `/api/v1/system`, `/api/v1/version` | **Hold** | `/system` returns 404 for customer-scoped admins (`sysinfo.py:60-61`). `/version` gives the major version only, unless the caller is an all-customers admin (`main.py:270-279`). `/readyz` still tells anonymous callers the role, epoch and fenced state (already reported in review 7 L5; unchanged). |

## 2. Golden images: status of review-7 M-4

| Item | Verdict | Evidence |
|---|---|---|
| Floor in the ICS database, monotonic | **FIXED** | `image_floor` gains `version` / `image_sha256`. The trigger refuses lowering the date or the version and refuses DELETE (`0015g:9-20`). The app role has no DELETE or TRUNCATE (`0013r7:29-30`). `advance_floor` only ever raises the floor (`golden.py:301-312`). |
| Signed manifest carries a version and an attestation | **FIXED** | Closed schema, canonical bytes, every bound file hashed. Ed25519 test-runner attestation of the image hash, `pass`, not stale (`golden.py:190-277`). |
| Trust and floor come only from Settings and the database | **PARTIAL**: the helper functions do this, but the provider verb still trusts its caller (new M-4). |

## 3. New findings

### Critical
None.

### High

**H-1. The deb smoke test runs untrusted maintainer scripts as real root in `systemd-nspawn` without user namespacing.** PLAUSIBLE (the escape itself was not executed).
- **Where:**
  - `blueprints/build/repo/testrunner/nspawn-smoke:28-29`: `systemd-nspawn --volatile=overlay -D "$BASE" --private-network ...` has no `--private-users` / `-U`, and no capability drop. `dpkg -i` (`:21`) runs the package's `preinst`/`postinst` as uid 0 of the host.
  - `ics/deploy/privsep/sudoers/ou-priv-testrunner:3-5` gives `ou-testrunner` root for this helper. `ou-priv-signers:9,20-21` lets the operator `admit dev` (ungated) and `run deb-install-smoke <sha>`.
- **Failure scenario:** after `NOPASSWD: ALL` is removed (the purpose of `apply-privsep.sh`), the build account admits a crafted `.deb` to `dev` and asks the test runner to smoke-test it. Its `postinst` runs as root inside a container that keeps nspawn's default capability set (which includes `CAP_SYS_ADMIN` and `CAP_MKNOD`). systemd documents that nspawn without user namespacing is not a security boundary. An escape gives host root, and with it the release, image and OCI signing keys and the test-runner key. That collapses the separation of duties privsep is meant to create.
- **Contrast:** the lab containers the operator may run are forced to `PrivateUsers=pick` (`privsep/lib/ou-lab-policy:20-23`); the root-run smoke test is the one place untrusted code runs without it.
- **Minimal fix:**
  - add `--private-users=pick --private-users-ownership=auto` (or run the smoke test in a throw-away VM);
  - add `--drop-capability=CAP_SYS_ADMIN,CAP_MKNOD,CAP_SYS_PTRACE,CAP_SYS_MODULE` and `--no-new-privileges=yes`;
  - better: run the test runner on a different host from the signers.

### Medium

**M-1. Node identity: an existing Linux account is silently adopted, and rollback/offboard then `userdel --remove` it. Fixed paths are shared by every integration on the node.** CONFIRMED (by code).
- **Where:**
  - `SshPreview.account` is free input (`sshonboard/actions.py:53`, `^[a-z_][a-z0-9_-]{0,31}$`).
  - `install_identity` reuses an account that `getent` finds. It skips `useradd` and the password lock, and **overwrites** `~/.ssh/authorized_keys` under `/var/lib/<account>` (`admin.py:242,259-265`; `templates.py:205-208`).
  - `installed = True` is set before `install_identity` runs (`actions.py:525`). Any later failure runs `remove_identity` (`:567-568`): `rm -f /etc/sudoers.d/ou-ics`, the helper, the config, then `userdel --remove <account>` (`admin.py:235-236,283-291`). Offboarding does the same (`actions.py:637-638`).
  - `HELPER_PATH`, `CONF_PATH` and `SUDOERS_PATH` are fixed per node (`templates.py:34-38`).
- **Failure scenarios:**
  1. A requester (or a typo) sets `account` to an existing user, for example an admin's personal account or `backup`. The key lands in `/var/lib/<account>`, not the real home, so `_helper_verify` cannot log in. The job fails, and the rollback deletes the pre-existing account **and its home directory** (`userdel` refuses only if the user has running processes). The approver saw only `getent passwd <account>`. The console also states "locked password, no login except the one forced command" (`SshOnboard.vue:273`), which is false for an adopted account.
  2. Two integrations on one node (a second endpoint, or two customers on a shared cluster): the second onboarding replaces the first one's `authorized_keys`, helper config and sudoers file, so the first identity stops working. Offboarding either integration, or any failed onboarding or re-onboarding after `apply_plan`, removes the shared account and files of both. The DB rollback keeps the first integration's `ssh_identities` row pointing at an identity that no longer exists.
- **Minimal fix:**
  - refuse (block the preview) when the account exists and is not recorded in `ssh_identities` for this endpoint with a matching `authorized_line`;
  - remove the account only if this run created it (track `account_created` like `installed_sudo`);
  - make the helper, config and sudoers paths per account (for example `/etc/sudoers.d/ou-ics-<account>`), or refuse a second integration per node.

**M-2. Offboarding does not bind the SSH session to the endpoint's cluster.** CONFIRMED (by code).
- **Where:** `exec_offboard` (`sshonboard/actions.py:601-653`) and its precheck (`:198-206`) check only that the session and the endpoint belong to the same customer (`customer_for`). They never compare the session's host, host key or cluster with the endpoint (`endpoints.base_url`, `ssh_identities.host` / `hostkey_fp`). No live-facts check that the cluster is the onboarded one is made either.
- **Failure scenario:** an operator of customer C opens an SSH session to cluster X and offboards C's endpoint Y (2 approvals; the plan params show only UUIDs). The job runs `pveum acl delete`, `token remove`, `user delete officeunbound@pve`, `role delete` and `userdel ou-ics` for Y's recorded names **on X**. These names are identical across integrations, so it destroys X's integration. Then Y is marked revoked and its stored secrets are wiped, while Y's real token, ACLs and node identity stay valid on Y.
- **Minimal fix:** in precheck and in the executor, require that the session host and pinned host key equal `ssh_identities.host` / `hostkey_fp` (or that the API URL equals the endpoint's), and that `/cluster/status` matches the stored cluster name. Show the target host in the plan.

**M-3. `provider.ssh.helper` reads the whole cluster as root, low risk and auto-approved, beyond the endpoint's approved scope.** CONFIRMED (by code); the cross-tenant impact is PLAUSIBLE (it needs a cluster shared by customers).
- **Where:** the helper runs `pvesh get` as root via sudo for `resources`, `users`, `acl`, `roles`, `storage`, node `network` / firewall rules for any node name, plus `lvs` / `zfs list` (`ou_pve_helper.py:280-284,335-346`). The action is `risk: low` (`sshonboard/actions.py:106`), so any operator in the endpoint's customer scope gets the result at once (`create_plan` auto-approval, `actions.py:793`).
- **Failure scenario:** the endpoint's API token is limited to one pool or node, but through this action a customer-scoped operator reads every VM, pool, PVE user, ACL and firewall rule of the cluster, including other customers' VMs when the MSP hosts several customers on one cluster. This bypasses the least-privilege design that the token scope enforces.
- **Minimal fix:**
  - filter helper output to the endpoint's `scope` (pools / nodes / storages);
  - or run `pvesh` as the ICS's own PVE user (`pvesh` has no `--userid`, so use the API with the inventory token instead);
  - and make `users` / `acl` / `fw-*` discovery at least `normal` risk.

**M-4. `import_image` still accepts the trust root, the floor and `allow_downgrade` from its caller.** CONFIRMED (by code); latent: there is no non-test caller yet.
- **Where:** `ImageImportSpec.trust`, `.floor` and `.allow_downgrade` are caller fields (`providers/base.py:156-159`). The verb checks only `isinstance(spec.trust, golden.Trust)` and passes all three to `verify_release` (`providers/proxmox/provider.py:1034-1038`).
- **Failure scenario:** a caller (a future plan executor, or a bug in one) builds `golden.Trust(own_pem, key_pin(own_pem), own_attestor)` or passes `floor=None` / `allow_downgrade=True`. A self-signed or downgraded image is then imported as a template. The docstring promise "trust comes from Settings, never from a request" is not enforced where it matters.
- **Also:**
  - there are two parallel configurations: `golden.configure` / `trust_root()` read `ICS_GUEST_RELEASE_PUBKEY_FILE` + `..._PIN_SHA256` (`runtime.py:24`, `golden.py:78-89`, unused), while `trust_from_settings` reads `ICS_GUEST_GOLDEN_RELEASE_PUBKEY_FILE` / `..._PIN_SHA256` / `..._ATTESTOR_PUBKEY` (`config.py:102,110-112`). An operator can configure one and believe the other is in force.
  - the release-date floor is raised but never checked (only `version` is compared, `golden.py:272-276`).
- **Minimal fix:**
  - inside the verb, call `golden.verify_for_import(rt, release_dir)`, and drop `trust` / `floor` from the spec;
  - let `allow_downgrade` come only from a dedicated high-risk action type, re-read from the approved plan in the executor;
  - delete the unused `_TRUST` path and one of the two setting names.

### Low

**L-1. Channel key pin covers only the first key in the armored file.** CONFIRMED (executed).
- **Where:** `pgp_fingerprint` parses only the first packet (`artifacts.py:75-105`). `load_map` compares that against `OU_ARTIFACT_CHANNEL_FPRS` but ships the **whole** armored file to guests as the `signed-by` keyring (`artifacts.py:181-184`; `guest/cloudinit.py:360,445`). `ou-artifacts-setup.sh:66-67` derives the pin from the same file it installs.
- **Executed:** an armored block of key A followed by key B gives the same fingerprint as A alone.
- **Failure scenario:** an operator exports `gpg --export --armor` without naming one key. The stable keyring then also contains the dev key (review 7 H-2: the dev channel is ungated), and stable guests accept a dev-signed `InRelease`.
- **Fix:** walk every packet and refuse a second primary-key packet (tag 6). Ideally re-export the single pinned key and ship that.

**L-2. The node key has no `from=` restriction in practice.** CONFIRMED (by code).
- **Where:** `from=` is written only when `ics_address` is given (`admin.py:213-218`), and the console never sends it (`SshOnboard.vue` has no `ics_address`).
- **Failure scenario:** a leaked ICS identity key (from a vault export or a backup) gives root-level cluster reads and ACL deletion from any address that can reach the node's SSH port.
- **Fix:** default `ics_address` to the ICS's management address, and show it in the preview.

**L-3. SSH host-key fetch is an internal TCP port probe for any operator.** CONFIRMED (by code).
- **Where:** `POST /ssh-sessions` accepts any host and port (`api.py:193-194`). `/hostkey` then connects (`session.py:86-99`) and returns different errors for "could not connect" and "did not offer a host key" (`client.py:171-185`). `check_destination` allows RFC1918 and resolves separately from the connect (DNS-rebinding window).
- **Failure scenario:** a customer-scoped operator maps open ports of the MSP management network (one audited session per probe).
- **Fix:** restrict SSH onboarding to admins or to ports 22 / 2222, rate-limit sessions per user, return one generic error, and connect to the address `check_destination` returned.

### Info
- **`ou-test-attest` environment:** `OU_RELEASE_STATE` and `OU_TESTRUNNER_STATE` are read from the environment without the `SANDBOX` gate (`ou-test-attest:43-44`). Today this is safe only because sudoers `env_reset` strips them (`ou-priv-signers:24`). Gate them like `LIB` / `IMGDIR`.
- **Test runner logs** are kept in a directory of mode 0755 (`ou-test-attest:186`), so build output is world-readable.
- **`install-oci-runner.sh:32-33`** grants `run oci-scan *` and `run image-first-boot *` with wildcards, while `ou-priv-signers` pins arguments with regexes and has no `oci-scan` entry. Applying privsep after the OCI installer leaves the wildcard file in place. The program validates `ref` itself, so this is consistency only.
- **Onboarding risk:** `provider.ssh_onboard` is `normal` (one approver) by owner decision, although it installs a root-run helper, sudoers and (if missing) the `sudo` package on the hypervisor. Consider `high` for a first onboarding of a node.

## 4. Summary

| ID | Severity | Status | Where | Summary |
|---|---|---|---|---|
| H-1 | High | PLAUSIBLE | `repo/testrunner/nspawn-smoke:28` | Untrusted deb maintainer scripts run as root in nspawn without user namespacing: build user → host root once privsep is applied |
| M-1 | Medium | CONFIRMED (code) | `sshonboard/admin.py:242-291`, `actions.py:525,567` | Existing account adopted; rollback/offboard `userdel --remove` it; fixed node paths clobber other integrations |
| M-2 | Medium | CONFIRMED (code) | `sshonboard/actions.py:601-653` | Offboard runs the endpoint's deletions on whatever cluster the SSH session reaches |
| M-3 | Medium | CONFIRMED (code) | `ou_pve_helper.py:335-346`, `actions.py:106` | Low-risk, auto-approved root `pvesh` reads of the whole cluster, beyond the token scope |
| M-4 | Medium (latent) | CONFIRMED (code) | `providers/base.py:156-159`, `provider.py:1034-1038` | Import verb still takes trust, floor and `allow_downgrade` from its caller; duplicate trust settings |
| L-1 | Low | CONFIRMED (executed) | `artifacts.py:75-105,181` | Channel pin checks only the first key of the keyring shipped to guests |
| L-2 | Low | CONFIRMED (code) | `admin.py:213-218` | No `from=` on the ICS node key (the console never sends `ics_address`) |
| L-3 | Low | CONFIRMED (code) | `sshonboard/session.py:86-99` | Host-key fetch is an internal port-probe oracle for operators |
