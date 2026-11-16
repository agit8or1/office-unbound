# Alpha readiness — current state and execution queue

Owner directive 2026-11-16: "Alpha readiness & execution". Feature expansion is frozen. Order: security → production no-SSH Proxmox deployment → full stack → two-customer isolation → operations → internal alpha → MSP pilot report. A stage with an open blocking security issue does not progress into customer-facing deployment.

Evidence levels used everywhere: **Unit tested · Integration tested · Lab tested · Real infrastructure · Production verified**.

## Stage 1 — state established (2026-11-16)

**Production ICS:** v0.1.0, commit 416aafe, schema 0009b, one owner account, no Proxmox endpoint registered, audit chain verifies.

**main** = 518e326. Acceptance A1–A24: 22 lab-demonstrated (`integrated_lab`), A14 (real Outlook/mobile) and A24 (admin docs) implementing. **No acceptance item is production verified.**

**Unmerged work (27 branches):**
- `integration-7`: standby/epoch fencing, review-5 fixes, per-customer backups, editor drill, client-compat results, admin docs. Being gated.
- `tenant-msp`: Org Admin, mailbox admin, MSP API, collaboration catalog. Merged on the branch; review-6 fixes in progress.
- `fixes-r7`: review-7 fixes, in progress.
- Others: `oci-signing`, `golden-prod`, `privsep`, `fullstack-plan`, `ssh-onboard`, `hardening`, `ics-pkg`, `console-new`, `gw-fixes`, `docs-reliability`. Each has its own agent.
- An earlier capacity worktree (`agent-a3ae…`) holds uncommitted `blueprints/lab/perf/`. Its agent stopped; it is kept and not deleted, and is to be salvaged by the capacity follow-up.
- Frozen: PIM migration (`worktree-agent-a1c66e0c…`, committed as WIP).

### Security findings: open Critical/High, verified against the current code by review 7

| ID | Finding | Status | Owner (branch) |
|---|---|---|---|
| R7-H1 | Signer: duplicate stanzas get a trojan signed into stable (reproduced) | Open | fixes-r7 |
| R7-H2 | One signing key for all channels | Open | fixes-r7 |
| R7-H3 | ou-test-attest signs caller-supplied results | Open | fixes-r7, consumed by oci-signing and golden-prod |
| R7-H4 | Cross-tenant plans: customer taken from caller parameters (reproduced) | Open | fixes-r7 |
| R7-H5 | Fencing covers agent calls only | Open | fixes-r7, then a two-controller partition test |
| R6-H1 | Image signer boot-test record forgeable | Open | oci-signing |
| R6-H2 | Org-admin account takeover via reset | Open | tenant-msp |
| R5 partials H1, H2, M2, M7, L4, L5 | See review 7 | Partial | fixes-r7 |
| Host | `administrator` has NOPASSWD: ALL | Open, **owner action** | privsep prepares the script |

Consolidated evidence: `docs/status/SECURITY-REMEDIATION.md`. It is produced once the fixes land, followed by an independent re-verification (review 8).

## Execution queue

| # | Stage | Work | State |
|---|---|---|---|
| 1 | 2 | Review-7 fixes: signer, channel keys, real attestation, tenant resolver, full fencing | fixes-r7 running |
| 2 | 2 | Review-6 H2 and MSP Mediums on tenant/MSP | tenant-msp running |
| 3 | 2 | Image/OCI signer gating on the real attestor; sign the images | oci-signing running |
| 4 | 2 | Least-privilege accounts, sudoers, unit hardening; owner script | privsep running |
| 5 | 2 | Separate bootstrap listener; DB-backed rate limits | hardening running |
| 6 | 2 | Merge integration-7 → gate → deploy; then merge 1–5 → gate → **review 8 (independent)** → SECURITY-REMEDIATION.md | lead |
| 7 | 2 | Two-controller partition test: only one controller executes | after #1 |
| 8 | 3 | Golden images: Debian 12 + Ubuntu 24.04, reproducible, independent boot attestation, sealed bootstrap | golden-prod running |
| 9 | 3 | **Owner prerequisite:** pve06 `import` content + OUImport ACLs (`docs/status/golden-image-results.md` §5) | **waiting on owner** |
| 10 | 3 | Real acceptance on pve06: no-SSH VM, signed component, health, restart, update, rollback, destroy-only-own | after 8, 9 |
| 11 | 3 | Wizards: connect (incl. SSH onboarding, owner request), deployment, change, rollback; console for releases and standby | ssh-onboard and console-new running |
| 12 | 4 | Full-stack BOM: every component real (no placeholders); capacity against pve06 | fullstack-plan running |
| 13 | 4 | Component fixes found by real clients (Gromox SMTP/587/special-use/send-as); editor kit spawning | gw-fixes and docs-reliability running |
| 14 | 4 | ICS as a signed package with controlled upgrade and rollback | ics-pkg running |
| 15 | 4 | Deploy the full profile through ICS on pve06; repeatable; failure recovery | after 10, 12 |
| 16 | 5 | **Owner prerequisite:** PVE SDN zone, VNets, firewall per customer (`docs/admin/proxmox-sdn-isolation.md`, being written) | waiting on fullstack-plan, then owner |
| 17 | 5 | Two full customer deployments; isolation positive and negative across every service, network and backups | after 15, 16 |
| 18 | 6 | Alerts (email/SMS/webhook/in-product, escalation, per-customer routing, delivery tracking); MSP workflows end to end | after 17 |
| 19 | 7 | Internal alpha acceptance with real clients (GUI desktop sync, Thunderbird, Evolution, softphones; Outlook/mobile need owner devices) | after 18 |
| 20 | 8 | MSP pilot readiness report | last |

## Owner actions known now

1. **Remove `administrator` NOPASSWD: ALL.** The agent-prepared script `ics/deploy/privsep/apply-privsep.sh` (dry-run by default) is coming on branch privsep.
2. **pve06 golden-image import prerequisite.** Exact commands are in `docs/status/golden-image-results.md` §5.
3. **pve06 SDN/VLAN isolation.** Exact commands will be in `docs/admin/proxmox-sdn-isolation.md`.
4. **External mail delivery test.** Needs a real domain with MX/SPF/DKIM DNS you control and outbound TCP 25 from the lab network.
5. **Outlook and mobile clients.** Licences and devices (issue #1).
6. Rotate the Proxmox token; copy the release revocation certificate offline; invite approvers.

## Decisions recorded
- 2026-11-16, network isolation (owner accepted the recommendation): use **option A** (a per-customer SDN VNet plus the Proxmox firewall, with datacenter policies left at ACCEPT) **if** the pre-flight shows no node-level firewall rules on pve01–05. Otherwise use **option B** (VNets with no host gateway plus an ICS-deployed router/firewall VM per customer). The pre-flight comes from the SSH onboarding read-only discovery.
- 2026-11-16, CPU: the owner says pve06 CPU is sufficient. Plan the full two-customer layout.
- 2026-11-16, thin-pool totals: gathered by SSH onboarding discovery once the owner connects pve06.
- 2026-11-16, **P9 (PDF reader/editor) is DEFERRED** and is the final development priority. No agents or worktrees until stages 1–8 are complete and verified. Requirements: `docs/requirements/P9-pdf-reader-editor.md`.
- 2026-11-16, **P10 Post-Core Expansion** (10 modules) added to the roadmap as planned future capabilities after P9. Planning only; no change to current priorities. Plan: `docs/roadmap/post-core-expansion.md`. Foundations to keep in mind during core work: customer_id on every new model (already enforced), and signed events from new features where cheap.
