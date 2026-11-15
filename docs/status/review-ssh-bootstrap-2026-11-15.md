# Review: ICS-driven SSH guest bootstrap (agent Z, first real deployment) — 2026-11-15

Independent security and architecture review. The reviewer did not write this code. No project file other than this report was changed. Nothing was run against Proxmox or any guest. Every finding comes from reading the code, and each one is marked CONFIRMED (the mechanism is visible in the code) or PLAUSIBLE (it depends on platform behaviour that was not reproduced).

Subject: branch `worktree-agent-a87f99356d33a7322`, commit `832c907` (worktree `.claude/worktrees/agent-a87f99356d33a7322/`). Paths below are relative to that worktree.
Read: `docs/status/first-real-deployment.md`, `ics/ics/guest/sshboot.py`, `ics/ics/deploy/agentport.py`, and the diff of `guest/cloudinit.py`, `deploy/executor.py`, `deploy/ops.py`, `deploy/envs.py`, `providers/{base,proxmox/provider}.py`, `config.py` and `proxmox.py`. Against: ADR-0002 (§3 no TOFU, §4 secrets, §5 closed actions, §7), ADR-0009 (header, §5 Guests), `guest-bootstrap-results.md`, and earlier `security-review-*.md`.
Not reviewed in depth: the 13 defect fixes on the agent side (Podman unit rendering, sigstore fallback, `lab_registry.py`).

## Verdict
**Do not merge this as the production guest-bootstrap path in its current form.** The cryptography is sound. The proof construction is good, and no user-controlled value reaches the shell layer. The problem is the failure modes. On every failure path before the seal, the design leaves a NOPASSWD-sudo SSH account open, keyed to the ICS (H1). The seal itself is neither durable nor verified (H2).

- **Merge with fixes, as a lab-only feature flag that is off by default**: acceptable once H1, H2, M1, M2 and M4 are fixed and ADR-0002 gets an addendum that names this exception.
- **Production: replace it** with the golden image plus authenticated callback design in the last section. That design reuses most of Z's work and removes inbound SSH completely.
- Split the commit. `vm.resize`, the provider fixes for defects 1–3, the node-name/decommission fix and the agent-side fixes do not depend on the SSH channel and can be reviewed and merged separately.

## Summary of findings
| ID | Severity | Status | Title |
|---|---|---|---|
| H1 | High | CONFIRMED | Fail-open: an `agent.enroll` failure before `install` leaves the VM with root SSH open on every interface, with no firewall and no dead-man timer, indefinitely |
| H2 | High | CONFIRMED | The seal is not durable, not verified and not audited, and a resume after enrollment skips it |
| M1 | Medium | CONFIRMED | The bootstrap identity (SSH key, PSK, "one-time" enrollment token) is deterministic per (slug, vm), not per VM instance, and cannot be revoked |
| M2 | Medium | CONFIRMED | The PSK is exposed in guest argv and stays in the Proxmox config (and backups) forever. The ICS key and `ciuser` stay in the cloud-init config |
| M3 | Medium | CONFIRMED | Blast radius: the worker gains a general "run as root" primitive on unsealed guests, which goes beyond the closed-runbook model ADR-0002 §5/§7 is built on |
| M4 | Medium | CONFIRMED | The payload goes to an unverified host before the proof is checked (no host-key pin). LAN neighbours can DoS deployments. The operator message "nothing was sent to it" is false |
| M5 | Medium | CONFIRMED / PLAUSIBLE | Architecture: assumes L2 adjacency and EUI-64 link-local addresses. VLAN or segmented guests never become reachable and fall into H1 |
| L1 | Low | CONFIRMED | The per-VM private key is written to `/tmp` and survives a SIGKILL of the worker |
| L2 | Low | CONFIRMED | `ICS_GUEST_KEEP_BOOTSTRAP_SSH` silently disables sealing in any environment, with no audit |
| L3 | Low | CONFIRMED | Agent bundle provenance: built at run time from a directory set in config. The hash protects transit only |
| L4 | Low | CONFIRMED | A crash between the agent's enroll and the DB insert dead-ends with "already enrolled" while SSH stays open |
| L5 | Low | PLAUSIBLE | The bootstrap account is only locked, and the Proxmox cloud-init drive still carries its key. A later cloud-init re-run could restore access |

## Answers to the questions asked

### (1) ADR-0002 compatibility and injection
- **Injection: none found.** I traced every value that reaches the remote side:
  - The nonce is `secrets.token_hex`.
  - The SSH argv is `user` (constant) plus `link_local(mac, iface)`. The MAC passes `MAC_RE` and the interface passes `IFACE_RE` (`sshboot.py:74-81`), and the remote command is the constant `sudo -n /bin/sh -s`.
  - `env` is fixed (`sshboot.py:180`).
  - `install_body` interpolates `instance_id` (regex; derived from a hex hash), `hostname` (the plan's VM name, checked by an RFC 1123 regex here and again in `GuestSpec`) and the user-data as base64 inside a quoted heredoc. The delimiter cannot occur in base64 output.
  - The user-data comes from `cloudinit.render(GuestSpec)`, where every field is validated (ports are ints with a `Literal` proto, CIDRs are parsed, registries and package names go through regexes, the signing key is pinned) and `shlex.quote` is used in `bootstrap_script`.
  - No API parameter selects a body. `Guest.call` is reachable only from `GuestAgentPort`, which runs inside a job.
- **"Truly fixed":** yes in the sense that every body is a constant in `sshboot.py`, or rendered from validated data by ICS code. The script's integrity on the way to the real VM comes from SSH client authentication. The VM accepts only the ICS-derived key, there is no agent forwarding, and a publickey signature is bound to the session ID, so a MITM cannot relay a modified script to the genuine guest. The script is not signed. Its trust root is the ICS code on disk, the same as all other ICS code.
- **ADR intent:** the letter of §7 holds, because nothing is exposed through an ICS API. The intent ("no SSH-with-sudo") is only partly kept. The ICS now holds and uses an SSH-with-NOPASSWD-sudo credential for every new guest, and §5/§7 leave no room for that. Accepting it requires (i) an explicit ADR-0002 addendum, (ii) a channel that is guaranteed to close (H1, H2) and (iii) narrowing the primitive (M3). Without those it is not compatible.

### (2) Impostor / MITM on the LAN
- **Can another host answer as the VM?** Yes. IPv6 neighbour discovery is unauthenticated, so any L2 neighbour on the bridge or LAN segment can claim `fe80::<eui64>`. With `StrictHostKeyChecking=no` (`sshboot.py:175`), the ICS completes SSH with any server, and an impostor's sshd simply "accepts" the client key. **What the impostor gets:** the stdin script. For `probe` that is only the nonce. For `install`, if the attacker lets the probe through and then spoofs, it is the whole user-data: agent bundle, firewall, registry and ICS addresses, signing public key, token *hash*. No secrets today (M4). **What it cannot do:** produce the HMAC, so it gets `ProofFailed`. It also cannot get commands onto the real VM.
- **HMAC soundness:** sound. The nonce is 128-bit and fresh per call. HMAC-SHA256 covers `nonce\nOUT`, and the comparison is `hmac.compare_digest` (`sshboot.py:96-109, 189`). Replay is impossible because the nonce differs per call. Parsing takes the last `OU-MAC` line, and the body lines that the guest could influence (`log=`) are flattened to one line. Weaknesses:
  - The binding is to (slug, vm), not to the VM instance: no vmid or MAC in the key or the message (M1).
  - The proof is checked only after the payload has been sent (M4).
  - The guest exposes the key in argv (M2).
- **Host key:** not verified, and not TOFU either. It is ignored on purpose, with the HMAC used instead. That is acceptable for authenticity, but it gives up the confidentiality of the payload against impostors (M4). Minimal fix: pin the host key that the HMAC-authenticated probe reports.

### (3) Secret exposure and lifetime
- **SMBIOS serial, in the guest:** `/sys/class/dmi/id/product_serial` and the DMI tables are 0400 root on Linux, so unprivileged users cannot read them directly. **However**, `_wrap` passes the secret as `openssl dgst -hmac "$S"` (`sshboot.py:108`), which puts it in `/proc/<pid>/cmdline`. Any local user can read that during every call, including `ou-agent` and `ou-svc`, which exist once `install` has run (M2).
- **SMBIOS serial, on Proxmox:** anyone with `VM.Audit` on the VM or the pool can read it through `GET …/config` (`smbios1: base64=1,serial=…`). It is also in `/etc/pve/qemu-server/<id>.conf`, in vzdump backups, and in the `qemu … -smbios type=1,serial=…` command line that any local user on the node can see. pvedaemon may also log it in its "update VM" lines (PLAUSIBLE). It is **never removed** (M2).
- **Lifetime and rotation:** none. The PSK, SSH key and enrollment token are pure functions of `(ICS signing key, slug, vm)` (`sshboot.py:51-71`). Nothing is stored, so nothing can be deleted or rotated. Rotating the signing key breaks resume of every in-flight bootstrap. Anyone who has the signing key can recompute every past and future value (M1).
- **Private key in the ICS:** not in the vault. It is derived on demand and written to a 0600 file in a `tempfile.TemporaryDirectory` (normally under `/tmp`) for each call (L1). The design's "nothing stored" claim is true, but it buys determinism and costs revocability.

### (4) Sealing
- **The happy path works.** The live evidence shows SSH refused afterwards. `seal_script` (`cloudinit.py:351-364`) disables and masks ssh, runs `passwd -l`, sets an expiry date (which blocks key logins through PAM), removes `authorized_keys` and deletes the sudoers line. Those steps are adequate.
- **Not reliable in general:**
  - The ICS triggers the seal as a 4-second transient `systemd-run` and swallows every error (`sshboot.py:155, 207-211`).
  - The dead-man switch is also a transient `systemd-run --on-active=3600` (`cloudinit.py:305`), and transient units do not survive a reboot.
  - The dead-man switch exists only once the user-data has run.
  - A resume after enrollment returns before the seal (`agentport.py:79-81`).
  - Nothing verifies or audits that the seal happened (H2).
- **Failure midway:** there is no compensation in `run_steps` (`executor.py:330-390`), and `agent.enroll` is marked failed. Before `install` the VM keeps the template's sshd on all interfaces, with no nftables and with `ou-boot ALL=NOPASSWD` (H1). After `install` it is sealed after 1 h unless the VM reboots first (H2).
- **Idempotency:** the probe → install → status → fingerprints sequence is re-entrant (`done` and `running` markers, `cloud-init clean`). Two gaps: an enrollment that succeeded is never sealed on resume (H2), and a crash between enroll and the DB insert dead-ends (L4).

### (5) Blast radius of a compromised ICS worker
- **Before this change:** the worker holds the signing key. Against enrolled guests it can call only the agents' **closed, schema-validated runbooks**: signed images from allowlisted registries, fixed unit templates, pinned packages. There is no arbitrary execution in guests.
- **With this change:** the same worker can additionally (a) derive the root SSH key for any (slug, vm) and get a **root shell** on every guest that is unsealed. That means every guest in its first minutes, every guest that failed before the seal (H1), and every guest rebooted before its timer fired (H2). It can also (b) derive the PSK of any VM and impersonate it at a re-bootstrap (M1). The `Guest.call(body)` primitive is general-purpose (M3). Steady state, once guests are sealed, is unchanged. The transient and failure states are now "root everywhere", not "bounded runbooks".

### (6) Alternatives
| Option | What it needs from the owner | Security | Verdict |
|---|---|---|---|
| **(a) Golden "ou-agent" image** built in the ADR-0008 pipeline (Debian 12 / Ubuntu 24.04 cloud image + pinned agent + first-boot enrollment unit, SSH masked, nft default-deny), imported through the API (`upload content=import` → VM with `import-from`) and converted to a template | A **file-based storage with `import` content** on pve06, because PVE06-Storage is lvmthin with `images,rootdir` only and cannot hold an import (for example a small `dir` storage on local disk). The provision token needs `Datastore.AllocateTemplate` + `Datastore.Audit` on it, and `VM.Allocate` + `VM.Config.*` in the pool for the template VM. `Datastore.AllocateSpace` on PVE06-Storage is already granted. One-time owner step: approve the image. | No inbound SSH and no exec channel. Code provenance is the signed pipeline (better than today). The per-VM secret still goes through SMBIOS (same exposure to VM.Audit holders as today, but one-time and cleared afterwards) | **Recommended (with d)** |
| (b) qemu-guest-agent in the template + `VM.GuestAgent.*` | Template change (so (a) is needed anyway) plus `VM.GuestAgent.FileWrite`/`FileRead` on the pool | File-write into a guest as root is equivalent to exec (cron.d, systemd units), so "file-write only" does not change the ADR §7 analysis and it is pool-wide. **FileRead only** (to fetch `fingerprints.json` over the hypervisor-authenticated virtio channel) is attractive for impostor resistance, but it can read any guest file (shadow, keys) | Reject write. FileRead: optional, needs an ADR decision; not needed if (d) is used |
| (c) `cicustom` snippets on a dir storage | A dir storage with `snippets`, **plus** a file channel into the node, because the API cannot upload snippets (Z verified this): an NFS export from the ICS mounted by pve06, or SSH to the node. Possibly extra privileges to set `cicustom` (PLAUSIBLE) | Adds a hypervisor-side trust path (the node mounts ICS-written files). Snippets are readable by Datastore.Audit holders. Still needs a separate way to authenticate the agent | Reject |
| (d) ICS-hosted bootstrap endpoint, pulled by the VM with a one-time token from SMBIOS | **On the stock template 131 it does not work safely.** cloud-init's NoCloud-net seed cannot pin a private CA, so the first stub is unauthenticated (root on the new VM for a LAN attacker). It works with a publicly trusted ICS certificate (needs DNS + ACME), or with code baked in by (a) | With (a): an outbound-only call, integrity by HMAC/pinned CA, no inbound port before enrollment | **Recommended as the enrollment half of (a)** |

## Recommended design: golden image + SMBIOS-keyed callback ("no SSH at all")
1. **Image.** The ADR-0008 pipeline builds and signs `ou-tpl-<os>-agent` from the checksum-pinned cloud image. It contains the node agent (pinned version), the renderer output of Z's `bootstrap_script` minus the SSH parts (nft default-deny, `ou-svc`, Podman, policy), SSH masked, and `ou-firstboot.service`. The ICS imports it through the `import` storage, verifies its hash, and makes it the template. This needs the owner action from (a).
2. **Per-VM material.** It is still delivered through Proxmox at `vm.configure`, but it is **random and per instance**: a 256-bit `boot_secret` generated by the ICS, stored encrypted in the vault (`credential-vault.md`) and keyed by deployment, VM and vmid. SMBIOS serial = `v1;<ics-ip:port>;<ics-tls-pin>;<boot_secret>`, size-checked against the PVE serial limit, or split across `serial`/`sku`/`family`. The ICS pin rides in SMBIOS, so no CA is baked into the image.
3. **First boot.** `ou-firstboot` reads SMBIOS as root (no argv: Python reads sysfs directly), generates the agent's keys, and opens the agent port to the ICS IP only. It then **POSTs** `{deployment, vm, vmid, nonce, agent TLS fp, agent key fp, ipv4}` with `HMAC(boot_secret, …)` to the ICS over TLS pinned to `<ics-tls-pin>`. This is Z's proof, reused as is, with the vmid and MAC added to the message.
4. **ICS.** It verifies the HMAC and freshness, and accepts **once**. A second report with the same secret raises an alarm (impostor or clone). Optionally it cross-checks that the source IP's neighbour-table MAC equals the Proxmox `net0` MAC. It then enrolls over pinned TLS exactly as `_enroll` does today. It deletes `boot_secret` from the vault and **clears `smbios1` serial/`sshkeys`/`ciuser`** in the VM config.
5. **Per-VM configuration** that is not in the image (declared ports, registries, signing key pin) is delivered by signed, typed agent runbooks after enrollment, or carried in the callback response under the same HMAC.
6. **Failure.** No inbound access exists at any point, so a failed bootstrap leaves only a VM with an agent port open to the ICS IP. Policy: stop the VM on terminal failure anyway.
7. **Residual risk.** A Proxmox user with `VM.Audit` on the pool can read the one-time secret before the VM uses it and race the enrollment with a fake agent. That attempt is detected by the duplicate-report alarm, the MAC cross-check and the ADR-0002 §2 ACL rule (keep `VM.Audit` on `officeunbound-*` pools to the ICS tokens). The secret is cleared after use.

**Migration path from Z's implementation**
- **Phase 0, now (lab only).** Put the SSH bootstrap behind `ICS_GUEST_BOOTSTRAP=ssh-lab`, off by default and refused unless a lab marker is set. Add the ADR-0002 addendum. Apply the minimal fixes for H1, H2, M1, M2 and M4 below. Merge the independent fixes separately.
- **Phase 1.** Pipeline-built image plus the owner's `import` storage. Add `vm.import_template` (a high-risk plan action, two approvers). Add the `/api/v1/guest-bootstrap/report` endpoint (HMAC-only, no session, rate-limited, one shot per secret). `agentport.wait_enrollment` waits for the report instead of probing over SSH. `_enroll`, `_render` (now an image and runbook input), the SMBIOS provider plumbing and `vm.resize` all carry over.
- **Phase 2.** Delete `guest/sshboot.py`, `GuestSpec.bootstrap_user`, the `fe80::/10` port-22 rule and `seal_script`. Add a test asserting that the ICS package contains no SSH client invocation.

## Findings

### H1. Fail-open: an early failure leaves root SSH open indefinitely
**Status:** CONFIRMED. **Where:** `ics/ics/deploy/agentport.py:94-106` (probe, IPv4 check, `_render`, install), `:123-130` (ProofFailed and timeouts become non-retryable StepFailed); `ics/ics/deploy/executor.py:330-390` (no compensation); `ics/ics/guest/cloudinit.py:303-306` (the only dead-man timer is created by the user-data itself).
**Failure scenario:**
1. `vm.configure` gives the template's default cloud-init user `ou-boot` NOPASSWD sudo and the ICS key, and the template's sshd listens on every interface.
2. Then any of these happens before `guest.install()` has run: an operator misconfiguration that `_render` rejects (`ICS_GUEST_IMAGE_SIGNING_KEY_SHA256` mismatch, an unknown `os_image`, `agentport.py:145, 171-172`), DHCP without IPv4 (`:96-100`), a ProofFailed, a probe timeout (wrong `default_iface`, M5), a job timeout, or an ICS restart (review 3 H1).
3. `agent.enroll` fails and the deployment becomes `failed`.
4. The VM keeps running with SSH reachable on its LAN IPv4, with no nftables and no seal timer, until someone destroys it.
**Minimal fix:**
- (a) Render and validate the user-data **at plan time or before `vm.start`**, so configuration errors never produce a booted VM.
- (b) Wrap `wait_enrollment`: on any terminal failure, call `guest.seal()` if the user-data was applied and the proof succeeded, otherwise **stop the VM** through the provider. Also clear `sshkeys`/`ciuser` in the config. Audit `guest.bootstrap_failed_closed`.
- (c) Long term, the recommended design removes this class of failure.

### H2. The seal is not durable, not verified and not audited, and resume skips it
**Status:** CONFIRMED. **Where:** `sshboot.py:155-156, 207-211` (detached 4 s transient seal, errors swallowed); `cloudinit.py:305` (transient `--on-active` dead-man timer, lost on reboot); `agentport.py:79-81` (an existing node row returns before any seal); `agentport.py:114-115` (the seal result is unused and has no audit event).
**Failure scenario:**
- The worker is killed after `_enroll` commits but before `guest.seal()`. The resubmitted job returns the node ID at line 81 and never seals. A reboot within the hour (unattended upgrades never reboot, but operators do) removes the transient timer, and SSH (link-local, NOPASSWD-sudo, ICS key) stays open for good.
- An L2 neighbour answering during the seal call also makes the seal silently not happen. The ProofFailed is swallowed.
**Minimal fix:**
- Run the seal **synchronously** inside the authenticated session: `systemctl stop` does not end the current session, because `KillMode=process`. Return an HMAC'd `sealed=1` after re-checking `systemctl is-enabled ssh` (masked), `passwd -S` (locked) and the absence of `authorized_keys`.
- Then verify from the ICS that TCP 22 on the link-local address is refused.
- Record `sealed_at` in the VM's `provider_ref`, and audit `guest.bootstrap_sealed`.
- On resume, seal whenever the node exists and `sealed_at` is missing.
- Make the dead-man switch a **persistent** unit pair written by the user-data (`OnBootSec=` plus a deadline file checked at every boot), not `systemd-run`.

### M1. Bootstrap identity is per (slug, vm), deterministic and unrevocable
**Status:** CONFIRMED. **Where:** `sshboot.py:51-71`; `agentport.py:74, 84`.
**Failure scenario:**
1. A failed `deployment.create` is resubmitted after its VM was replaced (the doc's "steps are carried over" path can redo `vm.clone`, and a future `deployment.change` may replace VMs). The new instance gets the **same** SSH key, PSK and "one-time" enrollment token as the old one.
2. Whoever had root on the old instance knows the PSK (sysfs) and the token in plaintext (the agent receives it at enrollment). Anyone with VM.Audit on the old VM's config knows the PSK too.
3. From the LAN, that attacker can pass the proof for the new VM and report their own agent fingerprints, and the ICS then enrolls a rogue node and pushes workloads to it.
4. Separately: the values cannot be deleted after use, cannot be rotated, and are all recomputable from the signing key.
**Minimal fix:** generate random per-instance values (PSK, token, SSH key) at `vm.configure`, store them encrypted in the vault keyed by vmid, and delete them after the seal. Add the vmid and MAC to the HMAC message. Re-generate on every new VM instance.

### M2. PSK exposure and leftover first-contact material
**Status:** CONFIRMED (argv; Proxmox config through the PVE permission model). PLAUSIBLE (pvedaemon syslog lines). **Where:** `sshboot.py:108`; `providers/proxmox/provider.py:824-828`; nothing ever clears `smbios1`, `sshkeys` or `ciuser`.
**Failure scenario:**
- Any local guest user, including the network-facing `ou-agent` service and the `ou-svc` workload user, can read the PSK from `/proc/*/cmdline` while the ICS polls `status` during the bootstrap.
- On Proxmox it stays readable for the VM's lifetime by every principal with `VM.Audit` on the pool or the VM, in backups, and in the node's process list.
- Combined with M1, a leaked PSK is a reusable impersonation credential.
**Minimal fix:**
- Compute the HMAC with `python3 -c` reading sysfs inside the interpreter, so the key never appears in argv. python3 is already required by the agent.
- After the seal, run a config update that deletes `serial` from `smbios1` (keeping `uuid`) and removes `sshkeys`/`ciuser`.
- Document that `VM.Audit` on `officeunbound-*` pools is restricted to the ICS tokens.

### M3. Blast radius: a general root-exec primitive in the worker
**Status:** CONFIRMED. **Where:** `sshboot.py:162-191` (`Guest.call(body)` runs any string as root); `sshboot.py:177` (`sudo -n /bin/sh -s`); `providers/proxmox/provider.py:36, 796-800` (`_SSHKEY` forbids authorized_keys options, so the key cannot be restricted).
**Failure scenario:** after a worker compromise the attacker has a root shell, not a closed runbook, on every unsealed guest (see answer 5). This breaks the property that ADR-0002 §5 and the agent design depend on.
**Minimal fix:**
- Make `call` private and the bodies an enum, with a test that only those constants reach `_wrap`.
- Allow a fixed `restrict,from="fe80::/10"` prefix on the bootstrap key (validated as an exact constant).
- Add the ADR-0002 addendum, with an expiry: Phase 2 of the migration.

### M4. Payload sent before proof; impostor DoS; misleading message
**Status:** CONFIRMED. **Where:** `sshboot.py:174-191` (`StrictHostKeyChecking=no`, `UserKnownHostsFile=/dev/null`, a new connection per call, the proof checked only on the response); `agentport.py:124-125` ("nothing was sent to it").
**Failure scenario:**
- An L2 neighbour lets the probe through, then answers NDP during `install`, and receives the full user-data. That exposes the deployment topology, registries, mgmt sources and agent code.
- The same neighbour can make every deployment fail with a non-retryable `ProofFailed`.
- Today the user-data holds no secret. The day a secret is added (registry credentials, a break-glass key), it leaks to impostors.
**Minimal fix:**
- Have the probe report `/etc/ssh/ssh_host_ed25519_key.pub` under the HMAC, and pin it with `StrictHostKeyChecking=yes` and a per-call known_hosts for every later call.
- Set `ssh_deletekeys: false` in the seed, because the `cloud-init clean` re-run otherwise regenerates the host keys.
- Add a test that fails if any secret-typed field enters `GuestSpec`.
- Correct the message to "only non-secret bootstrap data was sent".

### M5. L2/EUI-64 assumption
**Status:** CONFIRMED (code), PLAUSIBLE (Ubuntu behaviour). **Where:** `sshboot.py:74-93` (the interface of the IPv4 default route; the address computed by EUI-64).
**Failure scenario:**
- A VM on a VLAN (`NicSpec.vlan`) or another bridge than the ICS, or an ICS with more than one NIC, never answers. That runs into the timeout and then into H1.
- Images that use stable-privacy link-local addresses (`addr_gen_mode` 2/3, which some netplan or networkd configurations use) are unreachable. The design also forces the ICS onto every customer L2 segment.
**Minimal fix:** a plan-time check that each guest's bridge and VLAN equals the ICS's own segment, with the plan refused otherwise. Document the requirement, and pin `addr_gen_mode` in the image or accept it as a reason for the recommended design.

### L1. Private key on disk in /tmp
**Status:** CONFIRMED. **Where:** `sshboot.py:169-173`.
**Failure scenario:** a SIGKILL or OOM-kill of the worker leaves `/tmp/ou-boot-*/k`, a root-equivalent key while that guest is unsealed.
**Minimal fix:** use `dir=` under the ICS's 0700 state or runtime directory, and sweep stale `ou-boot-*` directories at worker start. An in-process SSH client (paramiko) is the other option.

### L2. Debug knob disables sealing everywhere
**Status:** CONFIRMED. **Where:** `config.py` (`guest_keep_bootstrap_ssh`); `agentport.py:114`.
**Failure scenario:** a leftover `ICS_GUEST_KEEP_BOOTSTRAP_SSH=1` in a production env file leaves every guest open for up to 1 h, and indefinitely after a reboot (H2), with no trace.
**Minimal fix:** refuse the knob unless lab mode is set, log a warning at startup, and add `keep_ssh: true` to the `node.enrolled` audit details.

### L3. Agent bundle provenance
**Status:** CONFIRMED. **Where:** `agentport.py:33-34, 160`.
**Failure scenario:** `ICS_GUEST_AGENT_DIR`, or the repository working tree, is tarred at run time and pushed to the guest as root code. The sha256 protects transit only, not provenance.
**Minimal fix:** ship the bundle as an ADR-0008-signed artifact, verified before it is embedded. The golden image design solves this.

### L4. Enrolled-but-unrecorded dead end
**Status:** CONFIRMED. **Where:** `agentport.py:191-193` (the agent enrolls, then the ICS crashes before the insert at `:199-209`).
**Failure scenario:** a crash between the agent's enroll and the DB insert means the next run fails non-retryably with "already enrolled", and SSH stays open until the timer fires (or indefinitely after a reboot).
**Minimal fix:** choose `node_id` deterministically per instance and write the node row as `pending` *before* calling `enroll`, so a resume can recognise its own enrollment. Seal on that error path (H1 b).

### L5. Account locked, not removed; Proxmox drive still provisions it
**Status:** PLAUSIBLE. **Where:** `cloudinit.py:351-364`; `sshboot.py:141` (the Proxmox NoCloud drive is disabled only by `fs_label: null`).
**Failure scenario:** if that override file is removed, or a cloud-init upgrade changes the semantics, cloud-init can re-apply `ciuser`/`sshkeys` from the still-attached Proxmox drive. That restores the key and the sudo rule. It can also unmask SSH if a package re-enables it. The `fe80::/10 tcp dport 22 accept` nft rule (`cloudinit.py:263`) stays in the ruleset permanently.
**Minimal fix:** `userdel -r ou-boot` in the seal. Clear the Proxmox cloud-init fields (M2). Remove the nft rule after the seal by re-rendering the ruleset without `bootstrap_user`.

## What is good and should be kept
- The HMAC proof: a fresh nonce, the response covered by the MAC, constant-time comparison, and a non-retryable `ProofFailed`.
- The enrollment token's plaintext never enters the user-data.
- Enrollment uses fingerprints that arrived over the authenticated channel, plus pinned TLS, plus `expect_agent_pubkey`.
- No user input reaches the shell layer.
- Output size cap, and stderr is not echoed.
- Provider-side validation of `ciuser`, `sshkeys` and `smbios_serial`.
- The `smbios1` uuid is preserved, which ICS self-identity matching relies on.
- The honest caveat in the status doc.
