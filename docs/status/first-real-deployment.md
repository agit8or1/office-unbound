# First real deployment (agent Z, 2026-11-15) — `deployment.create` end to end on pve06

Status vocabulary: ADR-0000 / ADR-0009 section 8. **VERIFIED-ON-REAL-INFRA** below means: executed against the real node pve06 during this session, evidence quoted.
Scope (owner-authorized): pool `officeunbound-pve06`, storage `PVE06-Storage`, bridge `vmbr0`, node `pve06`, clone source VM 131 only; VM 126 (the ICS) protected and never touched.
Everything created was destroyed (see "Cleanup"). No production ICS service, database or key was used or modified.

## Result
| Item | Status |
|---|---|
| `deployment.create` (profile `lab`, 1 VM, 1 containerized component) through the real HTTP API of a real ICS started from this worktree (`127.0.0.1:8112`, DB `ics_test_c`, throwaway keys), endpoint registered through the real `endpoint.register` plan (pinned TLS, allowed_* = scope above, protected 126), 1 requester + 2 approvers | **VERIFIED-ON-REAL-INFRA** (8 deployments were run while fixing defects; the last two ran start to finish without intervention) |
| Create-time root disk resize (new step `vm.resize`) | VERIFIED-ON-REAL-INFRA (template 3 GB -> 12 GB; guest sees 12.4 GB) |
| Agent port wired to the real node agent (bootstrap, one-time-token enrollment, signed runbooks) | VERIFIED-ON-REAL-INFRA |
| Signed, digest-pinned container via `podman.pull_verified` + `podman.deploy_unit`, health check registered and verified from the ICS | VERIFIED-ON-REAL-INFRA (rootless Podman 4.3.1 on Debian 12, see limits) |
| `deployment.destroy` (2 approvals) + cleanup verification | VERIFIED-ON-REAL-INFRA |
| Regression tests for every defect found | `tests/test_first_real_deployment.py` (19), plus changes in `test_guest_bootstrap.py`, `test_deploy_plan.py`, `test_deploy_exec.py`, simulator extended (`pve_sim.py`) |

### Timing of the last full run (deployment `e2e8`, job started 21:34:02, `ICS_GUEST_KEEP_BOOTSTRAP_SSH` off = SSH sealed after enrollment)
| Step | Seconds | What it did |
|---|---|---|
| `vm.clone` | 9.4 | full clone of template 131 into the pool (earlier runs 6-19 s) |
| `vm.tag` | 1.1 | `finalize_clone` applies `ou-managed;ou-deployment-<id>` |
| `vm.configure` | 0.1 | cores/memory/NIC, `ciuser`, `sshkeys`, `ciupgrade=0`, `ipconfig0=dhcp`, SMBIOS proof secret |
| `vm.resize` | 3.1 | scsi0 3 GB -> 12 GB |
| `vm.start` | 3.9 | |
| `agent.enroll` | **98.2** | boot, SSH proof, user-data applied, packages installed, agent installed, TLS-pinned enrollment, seal |
| `comp.install:echo` | 1.8 | `podman.pull_verified` + `podman.deploy_unit` |
| `checks.register` | 0.0 | |
| `health.verify` | 3.0 | smtp_banner check (greeting + EHLO) from the ICS |
| **job total** | **120.8** | (plan estimate 595 s) |
Destroy (`deployment.destroy`): `vm.stop` 5 s + `vm.destroy` 5 s, job 10 s.
Evidence after the run: `podman.status` = `active/running`, `digest_matches: true`, 0 restarts; `guest.facts` = Debian 12, podman 4.3.1 rootless, 12.4 GB root; the ICS check `…-echo-banner` = `ok` ("SMTP 220 banner + EHLO ok"); SSH to the guest refused after sealing (link-local `Connection refused`, IPv4 22 filtered); audit chain `verify-chain` = ok (266 events); 26 `guest.runbook` + 8 `node.enrolled` audit entries.

## How the guest gets its first code (evaluation, as requested)
Facts established on the real cluster: storage `PVE06-Storage` is lvmthin with `images,rootdir` only (no `snippets`); the Proxmox **API cannot upload snippets at all** (upload accepts `iso|vztmpl|import`), so even a directory storage with snippets needs file-level access to the node; template 131 has cloud-init 22.4.2 but **no qemu-guest-agent**; the token has only `VM.GuestAgent.Audit`.
| Option | Verdict |
|---|---|
| `cicustom` snippets | Needs an owner-built directory storage **plus** a file channel into the node (NFS export from the ICS or SSH): new attack surface, owner action, and the API cannot write snippets. Not needed -> not requested. |
| NoCloud-net via SMBIOS (`ds=nocloud;s=http://ICS/...`) | cloud-init would fetch **unauthenticated** user-data (root code execution for anyone who can spoof the LAN); an HTTPS seed fails because cloud-init does not trust the ICS's private CA. Rejected. |
| Only `ciuser` / `sshkeys` | Cannot carry code, but is an *authenticated* ICS -> guest channel written through the Proxmox API. Used as the trust anchor (below). |
| New template built by the ICS | Needs an exec channel to build it, and the task fixes VM 131 as clone source. Possible later as hardening (owner action: a template with the agent baked in would remove the SSH step below). |
| qemu-guest-agent exec | Not installed in 131; ADR-0002 s7 forbids guest-agent exec. Rejected. |
**Chosen** (`ics/ics/guest/sshboot.py`, `ics/ics/deploy/agentport.py`), all material derived from the ICS signing key by HMAC (nothing stored, resume-safe):
1. `configure_vm` writes the per-VM SSH **public** key into `sshkeys` (`ciuser=ou-boot`, `ciupgrade=0`) and a per-VM secret into the **SMBIOS serial** (root-only in the guest). The plaintext enrollment token never leaves the ICS; only its SHA-256 is in the user-data (as before).
2. After start the ICS reaches the guest on its **IPv6 link-local address computed from the MAC** Proxmox reports (EUI-64; no scan, no DHCP guessing; needs L2 adjacency to the bridge, which the ICS has). It logs in with the key (only the ICS can) and **authenticates the guest** with an HMAC over a fresh nonce and every output, keyed with the SMBIOS secret (no SSH host-key TOFU; an impostor fails with `ProofFailed` and receives nothing).
3. The unchanged `guest/cloudinit.py` user-data (agent bundle, nftables default-deny, rootless Podman, signed-image policy pinned to the operator's key) is applied as a NoCloud **seed** and cloud-init is re-run from it (the first-boot drive is disabled with `fs_label: null`). Every remote command is a fixed script from `sshboot.py`; only charset-validated values are interpolated; there is no API to choose a command.
4. The ICS reads the agent's TLS/key fingerprints (MAC-authenticated), enrolls over the pinned TLS channel with the one-time token, records the node, then **seals** the guest (`ou-bootstrap-seal`: SSH disabled+masked, bootstrap account locked, key and sudo rule removed). A guest-side timer seals it after 1 h even if the ICS dies.
Honest caveat for review: this puts a fixed-script SSH client in the ICS worker. ADR-0002 s7 bans SSH-with-sudo *exposed through ICS APIs*, which this is not, but it is a new privileged channel; its trust root is the Proxmox API (the same trust the whole system already places in it). If the owner prefers, the alternative is a pre-built "ou-agent template" (owner action) and this step collapses to a callback.

## What changed
- `deploy/agentport.py` (new): real `AgentPort` (`bootstrap_config`, `wait_enrollment`, `run_runbook`, `address`; `tls_trust` explicitly unsupported). `deploy/envs.py` wires it; `ops._run` passes `created_by` and the plan.
- `deploy/plan.py`: `vm.resize:<vm>` step (idempotent: skipped when the disk is already big enough); runbook params in exactly the shapes the agent's closed schemas accept; the node agent (`every_vm`) is no longer "installed" by a `pkg.install_pinned` step (the bootstrap installs it).
- `providers`: `VmConfigSpec.ciupgrade`/`smbios_serial`; `guest_mac`, `disk_size_gb` (read-only helpers); cloud-init drive only added when the guest has none; `finalize_clone` authoritative-config check.
- `guest/cloudinit.py`: `bootstrap_user` (SSH kept until sealed, link-local-only nft rule, seal script + timer), `insecure_registries` (lab transport; the signature policy still applies).
- Agent: plain-systemd-unit renderer for podman < 4.4, Python sigstore verification fallback, pull-only policy, `insecure` registry list, unit sandboxing fix.
- Config knobs (`ICS_JOB_TIMEOUT_SECONDS`, `ICS_GUEST_*`), `scripts/lab_registry.py` (lab tool: builds, cosign-format-signs and serves the test image over HTTP), `blueprints/e2e-catalog/` (the single-component `lab` catalog; `OU_CATALOG_DIR`).

## Real-cluster defects found, fixed, and pinned by regression tests
| # | Symptom on pve06 | Cause / fix | Test |
|---|---|---|---|
| 1 | `inventory.refresh` failed `GET /cluster/status 403 (Sys.Audit on /)`; no snapshot -> plans had `no_inventory` | token has `Sys.Audit` only on `/nodes/<n>`; `inventory()` now tolerates 403 for cluster status (other errors still fail) | `test_inventory_tolerates_a_token_without_sys_audit_on_root` |
| 2 | `vm.tag` refused: "guest 137 is named None" | `/cluster/resources` lags right after a clone; `finalize_clone` waits for pool membership and takes name/tags from the **live config** (still refuses a foreign name) | `test_finalize_clone_survives_the_cluster_resources_cache_lag` (sim models the lag) |
| 3 | `vm.configure` failed `lvcreate vm-N-cloudinit already exists` | the template already carries `ide2 … cloudinit`; only add a drive when none exists | `test_configure_does_not_create_a_second_cloud_init_drive` (sim models it) |
| 4 | `agent.enroll` could never work: nothing reached the guest (`ciuser/sshkeys/ipconfig` never set) and plan params did not match the agent schemas | see "first code" above; params fixed | `test_configure_step_hands_the_guest_its_first_contact_material`, `test_wait_enrollment_*`, `test_steps_form_a_valid_dependency_order` |
| 5 | root disk stays 3 GB | `vm.resize` step | `test_steps_form_a_valid_dependency_order`, provider tests |
| 6 | node enrollment record collided across re-created deployments; destroy left the node `enrolled` | node name includes the vmid; destroy marks nodes `decommissioned` (live-verified; fake-agent test updated) | live evidence + `test_destroy_removes_only_owned_guests` |
| 7 | Debian 12 has podman 4.3.1: **no Quadlet** | plain systemd user unit rendered from the same validated spec | `test_plain_unit_rendering_*`, `test_deploy_without_quadlet_*` |
| 8 | `podman run --network=<user-defined>` -> "network not found" (4.3.1) | no per-component network on the plain-unit path (documented limit) | `test_plain_unit_rendering_is_confined_and_has_no_user_defined_network` |
| 9 | container crashed: `crun: create directory …/user@1001.service/user.slice/libpod-….scope: No such file or directory` | `--cgroup-manager=cgroupfs` (keeps the memory limit; `--cgroups=disabled` would not) | same rendering test |
| 10 | `podman pull` -> **"Debian-local change: sigstore disabled"**: `sigstoreSigned` is patched out of Debian's podman | agent verifies the cosign-format signature itself (manifest re-hashed by digest, payload must name this digest+repo, ECDSA vs the ONE pinned key), then pulls by digest under a pull-only policy | `test_python_sigstore_verification_matches_the_policy_rules`, `test_pull_falls_back_to_python_verification_*` (unsigned/other-key/other-repo/tampered all refused; also executed against the real registry) |
| 11 | every podman runbook failed `newuidmap: write to uid_map failed: Operation not permitted` | bisected on the VM: on systemd 252/kernel 6.1 **seccomp-based unit options (LockPersonality, RestrictRealtime, ProtectKernel*) stacked with mount-namespace options** break `newuidmap`; each group alone works. Unit now has only `ProtectControlGroups` | `test_podman_runbook_unit_does_not_stack_seccomp_and_mount_sandboxing` |
| 12 | after #11 the pull "worked" but the image was unusable (`open /var/tmp/<n>: no such file`) | `PrivateTmp` poisoned the long-lived rootless `pause` process's mount namespace; removed (a stale VM needs `podman system migrate`) | same unit test |
| 13 | `ICS_JOB_TIMEOUT_SECONDS` was not read from the environment | `load_settings` reads it (a real deployment needs more than the 180 s default once retries happen) | `test_settings_read_the_guest_and_job_timeout_knobs` |

## Limits and things NOT claimed
- **Job robustness (agent Q / review H1, not touched):** restarting the ICS while a `deployment.create` job was running left the deployment in `provisioning` (destroy answers 409 "deployment is provisioning"); the job is lost. I cleaned that one throwaway deployment by destroying its VM through the provider and fixing the row in the throwaway DB. Resubmitting the same create works (steps are carried over, verified live: `vm.clone`..`agent.enroll` carried over).
- The agent listens on, and the guest firewall is bound to, the **DHCP address at bootstrap time**; a changed lease breaks the agent until re-bootstrapped (ask the owner for a DHCP reservation, or add static addressing).
- Link-local bootstrap requires the ICS to share the L2 segment (bridge/VLAN) with the guest.
- `tls_trust` is not implemented, so catalog checks of kind `http`/`tcp_tls` fail at `checks.register`; the test component uses `smtp_banner` (no TLS).
- Inter-VM firewall rules (`internal`/`edge` exposure) are not rendered (only `public` and `ics` ports); single-VM only so far. `pkg.install_pinned`/OU apt repo path: unchanged, not exercised here.
- Plain-HTTP lab registry on the ICS host (`192.168.22.167:5000`, temporary process): integrity rests on digest + signature, not on the transport. The product still needs a real registry and the ADR-0008 pipeline; the catalog digest in `blueprints/e2e-catalog` is the lab image.
- Debian 12 + podman 4.3.1 is a *degraded* guest platform (no Quadlet, no component networks, Python signature check). Ubuntu 24.04 (the catalog default, template `ou-tpl-ubuntu-2404` does not exist on pve06) remains the validated target.
- `ICS_GUEST_KEEP_BOOTSTRAP_SSH` (debug) leaves the bootstrap SSH open (the guest's timer still seals after 1 h); it is off by default and was off for the final run.
- Process note: one quick test run used the wrong test database (`ics-test-b`, owned by another agent) and recreated its schema; no data of mine or the lead's was involved, but that agent's run may have seen one failure.

## Reproduce
```
python ics/scripts/lab_registry.py keygen <dir>; python ics/scripts/lab_registry.py build <dir> <host:5000/ou/echo>   # prints image digest + pin
python ics/scripts/lab_registry.py serve <dir> <ics-lan-ip> 5000
ICS_ENV_FILE=<env> OU_CATALOG_DIR=blueprints/e2e-catalog ICS_JOB_TIMEOUT_SECONDS=3000 ICS_GUEST_IMAGE_REGISTRIES=<ip>:5000 \
  ICS_GUEST_INSECURE_REGISTRIES=<ip>:5000 ICS_GUEST_IMAGE_SIGNING_PUBKEY_FILE=<dir>/sign.pub ICS_GUEST_IMAGE_SIGNING_KEY_SHA256=<pin> \
  python -m uvicorn ics.main:create_app --factory --host 127.0.0.1 --port 8112
# then (as the wizard does): endpoint.register -> inventory.refresh -> POST /deployments/plan -> POST /plans {deployment.create} -> 2 approvals -> job -> deployment.destroy
```

## Cleanup (verified)
After the last destroy: `GET /cluster/resources?type=vm` = guests `[126, 131]`, no guest tagged `ou-managed`, no volume of vmid > 131 on `PVE06-Storage`. Temporary processes (live ICS on 8112, lab registry on 5000) stopped. Test VMs created over the session: vmids 136 and 137, re-used as each was destroyed (all destroyed through the ICS provider/API with its tag and scope guards; the dev VM through the provider).
