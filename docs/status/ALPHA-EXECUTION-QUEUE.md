# Office Unbound: beta execution queue and scorecard

This is the one authoritative queue. Owner directive 2026-11-16: **invite-only beta by 2026-12-31**.

How it is run:
- A single controller does the work. No agents unless the owner approves one.
- Feature freeze: P9 PDF Studio and P10 Post-Core stay deferred.
- Evidence levels: Unit · Integration · Lab · Real infrastructure · Production.
- Every evidence row records the commit it was produced on.

## Beta scorecard (evidence-based, weighted)

Readiness is the weighted share of each area's beta requirements that are **tested on the relevant level**. Implementation without tests counts zero. Data comes from this file and `docs/progress.json`.

| Area | Weight | Status (2026-11-16) | Evidence-based score |
|---|---|---|---|
| Security (no Critical/High; review 8; least privilege applied; signing verified) | 20 | 0 Critical. Independent review 8 done and fixed (1 High, 4 Medium, 2 Low; 1 Low open by design). 6 Highs Partial until owner privsep apply, helper re-install, signed registry | 60% |
| Installation and full-stack deploy through ICS (fresh, repeated) | 20 | Single VM and container on real PVE (A1). Full stack not yet deployed. Golden images and artifacts are on branches | 15% |
| Data integrity and recovery (backup and restore of tenant and ICS; upgrade and rollback; failover) | 15 | Lab-verified: restores, ICS controller tier, editor and groupware rollback, HA partition proof | 55% |
| Tenant isolation (identity, mail, files, docs, chat, meetings, admin, API, backups, network) | 15 | App and backup isolation lab-verified (209/0). Network (SDN) not yet applied | 45% |
| Core services working together (identity, mail incl. external, calendar and contacts, files and sync, docs, chat, meetings, telephony) | 15 | Lab-integrated. External mail, GUI desktop sync and Outlook not yet tested | 40% |
| MSP and Org admin (control center, Org Admin, provisioning API, quotas, audit) | 8 | Built and lab-tested on branches, merged in 5504775 | 50% |
| Operations (monitoring, alerts incl. email/SMS/webhook, updates, capacity) | 7 | Monitoring and incidents exist. Alert channels beyond webhook/email are partial | 35% |
| **Overall** | **100** | | **≈ 42%** |

| Tracker | Value (commit) |
|---|---|
| Security findings open | Critical 0 · High 6 Partial · Medium/Low: see `SECURITY-REMEDIATION.md` (140 rows) |
| Backend / frontend / e2e | Gate on 5504775 running. Last green: 9715881 (885 / 127 / 418+12) |
| Full-stack deploy success | 0 of 0 attempts |
| Tenant isolation | 209 pass / 0 fail (lab, branch evidence); network isolation pending |
| External mail | Not tested; needs owner domain/DNS |
| Backup and recovery | Lab restores verified (RTO 29–127 s); ICS tier verified |
| **Critical blockers** | Owner prerequisites for pve06 (connect via SSH onboarding, image import, SDN); external mail domain; privsep apply |
| **Estimated beta date** | 2026-12-31. On track only if the pve06 onboarding and the external-mail domain arrive in Stage 1–2 |

## Stages (owner schedule)

| Stage | Dates | Scope | State |
|---|---|---|---|
| 1 | Nov 16–22 | Security and repo stabilization: integrate remediation branches, review 8, gitleaks full history, signing/attestation verified, fencing, least privilege, SSH onboarding restrictions, no exposed secrets | **in progress** |
| 2 | Nov 23–29 | ICS complete: connection wizard, credentials, golden-image deploy, signed artifacts, profiles, VM and container deploy, change/rollback wizards, health verification, capacity. **Full-stack deploy demonstrated** | queued |
| 3 | Nov 30–Dec 6 | Integrated stack incl. email: external in/out, SMTP auth, IMAP, MAPI/HTTP, EWS, EAS, autodiscover, CalDAV/CardDAV, SPF/DKIM/DMARC, TLS, rspamd, ClamAV, queues, mailbox backup/restore, real Outlook where available | queued |
| 4 | Dec 7–13 | MSP and multi-tenant: two real customers, SDN/firewall applied, cross-tenant tests across every service | queued |
| 5 | Dec 14–20 | Alerts (email/SMS/webhook/in-product, escalation, routing, delivery status), backup and recovery RPO/RTO, updates and rollback, client compatibility, migration (mail first), onboarding | queued |
| 6 | Dec 21–27 | Clean-room beta candidate (24-step flow), guides, known limitations, release notes, freeze | queued |
| 7 | Dec 28–31 | Invite-only launch: 1–2 MSP partners, two isolated customers, ~20–30 users | queued |

## Stage 1 queue (next actions in order)

1. Gate 5504775 (integration-8 merged) → backup → deploy.
2. Integrate, with targeted tests then a full gate:
   - `ssh-onboard`: run its unrun tests first.
   - `oci-signing`, then `golden-prod`, then `artifacts-core`, then `artifact-dist`.
   - `gw-fixes`: `ou-gromox` ou3 still has to go through the signed pipeline.
   - `docs-reliability`.
   - `ha-proof`.
3. Fix gitleaks full-history scanning in CI.
4. Prepare the batched owner-action sheet (`docs/admin/OWNER-ACTIONS.md`).
5. ~~Independent security review 8~~ **done 2026-11-16** (one reviewer agent, owner-approved): `docs/status/security-review-8-2026-11-16.md`; fixes on `image-import` (fdd5aaa).
6. ~~Refresh `SECURITY-REMEDIATION.md`~~ done (R8 rows). Stage 1 exit still needs: owner privsep apply (OA-1) and the smoke-test helper re-install (R8-H-1).
7. Follow-ups:
   - ~~R1~~ done (81a7d44): promotion fails in-flight replica jobs as `uncertain_after_promotion`.
   - ~~`wal_receiver_timeout` 5 s~~ done (81a7d44).
   - Triage OSV findings so artifacts can be promoted to staging/stable.

**Stage 2 must-do (found during integration-9) — DONE 2026-11-16 (0956d33, 0df8ae4: action + console Images page):** `image.import` was not wired to any approved action or executor step. The verb, verification (`golden.verify_for_import`) and DB floors exist and are tested, but nothing calls them. Add an `image.import` typed action (high risk; Settings trust; DB floor; `FloorStore.record` after success) and a deployment step that imports when the template is missing.

**Frozen work:** PIM migration (`worktree-agent-a1c66e0c…`, WIP 247f94d; verification failed). It is preserved and re-enters in Stage 5 (migration) only after it verifies.

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
- 2026-11-16, HA proof complete (branch ha-proof, `docs/status/ha-partition-results.md`): split-brain execution prevented with the lease. Follow-up queued: **R1** (mark jobs queued/running in the replica as `uncertain` at promotion; operator resolves them before re-run) and set `wal_receiver_timeout` to ~5 s on standbys (the 60 s default delays promotion).
