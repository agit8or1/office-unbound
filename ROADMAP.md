# Office Unbound roadmap & progress

> Generated from [`docs/progress.json`](docs/progress.json) by `scripts/render_roadmap.py` — edit the JSON, not this file. Last updated **2026-11-16** · stage: **pre-alpha (lab)** · current version: **0.2.0-dev.2**.

Core platform components are integrated and tested in an isolated lab: own source build of Exchange-compatible groupware with single sign-on webmail, Keycloak SSO, file sync and browser document editing, backup/restore drills, chat and video meetings, and an infrastructure control server with monitoring, self-healing and a real Proxmox integration (VM lifecycle verified on a live cluster). Guided deployment wizards, provisioning automation and the credential vault are being integrated.

**Principles**

- Zero mandatory third-party licensing cost; no artificial user, mailbox or connection limits (ADR-0007)
- Own source builds where vendor packages are restricted (ADR-0008)
- A feature is working only when demonstrated by executed tests

**Status legend:** ⚪ Planned · 🔎 Researching · 🛠️ Implementing · 🧪 Integrated in lab · ✅ Tested · 🅰️ Alpha · 🅱️ Beta · 🚀 Production supported · ⛔ Blocked ·  Deferred

## P0 — Discovery and architecture  (✅ Tested)

| | Item | Status | Evidence |
|---|---|---|---|
| P0.1 | Architecture decision records and zero-cost component strategy | ✅ Tested | [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), [`docs/adr/`](docs/adr/) |
| P0.2 | Source-level licensing evaluation of groupware and document engine | ✅ Tested | [`docs/status/groupware-source-eval.md`](docs/status/groupware-source-eval.md), [`docs/status/docengine-source-eval.md`](docs/status/docengine-source-eval.md) |
| P0.3 | Third-party software inventory | 🛠️ Implementing | [`docs/status/third-party-inventory.md`](docs/status/third-party-inventory.md) |

## P1 — Control server foundation and core platform proof  (🛠️ Implementing)

| | Item | Status | Evidence |
|---|---|---|---|
| P1.1 | ICS: operator auth with MFA, encrypted vault, tamper-evident audit, approvals, durable jobs | ✅ Tested | [`docs/status/security-review-ics-2026-11-15.md`](docs/status/security-review-ics-2026-11-15.md) |
| P1.2 | ICS: service-level monitoring, incidents, alerts, signed node agents, bounded auto-remediation | 🧪 Integrated in lab | [`docs/status/ics-monitoring-results.md`](docs/status/ics-monitoring-results.md), [`docs/status/security-review-ics-monitoring-2026-11-15.md`](docs/status/security-review-ics-monitoring-2026-11-15.md) |
| P1.3 | Groupware: own source build of Gromox stack (MAPI/HTTP, EWS, ActiveSync, Autodiscover, IMAP/SMTP, CalDAV/CardDAV, webmail), no user cap | 🧪 Integrated in lab | [`docs/status/groupware-lab-results.md`](docs/status/groupware-lab-results.md) |
| P1.4 | Single user directory: OpenLDAP authoritative for Keycloak SSO, files and groupware | 🧪 Integrated in lab | [`docs/status/identity-files-lab-results.md`](docs/status/identity-files-lab-results.md), [`docs/status/groupware-ldap-results.md`](docs/status/groupware-ldap-results.md) |
| P1.5 | Files: OpenCloud with WebDAV, versions, desktop sync engine (offline, conflicts) | 🧪 Integrated in lab | [`docs/status/identity-files-lab-results.md`](docs/status/identity-files-lab-results.md) |
| P1.6 | Documents: browser editing via WOPI with verified save/reopen and restart persistence <br><sub>Lab uses vendor CODE packages for functional tests only</sub> | 🧪 Integrated in lab | [`docs/status/identity-files-lab-results.md`](docs/status/identity-files-lab-results.md) |
| P1.7 | Documents: own unlimited, rebranded Collabora Online source build <br><sub>Own source build, rebranded, no connection/document caps: 30 concurrent documents and 60 sessions verified; edit/save via WOPI verified. ou3 (dev channel): kit pre-spawn 16 + readiness-gated start + real-conversion health check (kit-ready) after the t08 'No child available' defect; help URL configurable; install-smoke attested</sub> | 🧪 Integrated in lab | [`docs/status/docengine-build-results.md`](docs/status/docengine-build-results.md), [`docs/status/docs-reliability-results.md`](docs/status/docs-reliability-results.md) |
| P1.8 | User lifecycle: provision and deprovision across all services with measured revocation <br><sub>Open gaps: OpenCloud app-token revocation, ActiveSync remote wipe, per-user IMAP session termination</sub> | 🧪 Integrated in lab | [`docs/status/user-lifecycle-results.md`](docs/status/user-lifecycle-results.md) |
| P1.9 | Backup and restore drills to separate machines (files, identity, ICS controller) | 🧪 Integrated in lab | [`docs/status/restore-drill-results.md`](docs/status/restore-drill-results.md), [`docs/runbooks/ics-recovery.md`](docs/runbooks/ics-recovery.md) |
| P1.10 | Groupware restore to a separate machine and clean-room rebuild <br><sub>Online logical backup; point-in-time consistency across mailboxes needs snapshots</sub> | 🧪 Integrated in lab | [`docs/status/restore-drill-results.md`](docs/status/restore-drill-results.md) |
| P1.11 | Real Outlook, Thunderbird and mobile client compatibility matrix <br><sub>Thunderbird 24/25 and Evolution calendar/contacts tested in lab (client-compat-results.md); groupware fixes from these tests in progress; Outlook/mobile need owner devices</sub> | 🛠️ Implementing | [`docs/status/client-compat-results.md`](docs/status/client-compat-results.md) |
| P1.12 | Versioning, changelog, release notes and release tracking (VERSION, build info, /api/v1/version, console System page) <br><sub>0.1.0 "Anchor" released (tag v0.1.0, GitHub pre-release); main is 0.2.0-dev "Beacon"; release names per minor line (ADR-0011 amendment)</sub> | ✅ Tested | [`docs/adr/0011-versioning-and-releases.md`](docs/adr/0011-versioning-and-releases.md), [`CHANGELOG.md`](CHANGELOG.md), [`VERSIONS.json`](VERSIONS.json) |
| P1.13 | Alpha security remediation (reviews 1-7): signing, attestation, cross-tenant scoping, fencing, admin takeover <br><sub>140 findings tracked with verified evidence. Independent review 8 (2026-11-16): 0 Critical, 1 High, 4 Medium, 3 Low; all fixed in code except R8-L-2 (open by design until the ICS source address seen by pve06 is known). 5 Highs Partial: R4-H2, R5-H2, R7-H3, R7-H5 need the owner privsep apply / lab drills, R6-H1 the signed registry (R8-H-1 closed: helper re-installed 2026-11-16); smoke-test helper on the ICS host</sub> | 🛠️ Implementing | [`docs/status/SECURITY-REMEDIATION.md`](docs/status/SECURITY-REMEDIATION.md), [`docs/status/ALPHA-EXECUTION-QUEUE.md`](docs/status/ALPHA-EXECUTION-QUEUE.md), [`scripts/security_remediation_check.py`](scripts/security_remediation_check.py), [`docs/status/security-review-8-2026-11-16.md`](docs/status/security-review-8-2026-11-16.md) |
| P1.14 | Least-privilege host accounts, sudoers, unit hardening <br><sub>Scripts, sudoers/polkit/unit drop-ins and docs are on main (lab-tested); NOT applied to any host: removal of administrator NOPASSWD:ALL is an owner action (apply pending)</sub> | 🛠️ Implementing | [`docs/status/security-review-7-2026-11-16.md`](docs/status/security-review-7-2026-11-16.md), [`docs/status/privilege-audit.md`](docs/status/privilege-audit.md), [`ics/deploy/privsep/apply-privsep.sh`](ics/deploy/privsep/apply-privsep.sh), [`ics/deploy/privsep/revert-privsep.sh`](ics/deploy/privsep/revert-privsep.sh) |
| P1.15 | ICS warm standby with fenced failover (epoch + lease/witness) <br><sub>Two-controller partition proof (lab): with lease fencing S1-S8b pass, zero side effects from the old primary after promotion, no job ran twice; residual R1 queued</sub> | 🧪 Integrated in lab | [`docs/status/ha-partition-results.md`](docs/status/ha-partition-results.md), [`docs/status/ics-standby-results.md`](docs/status/ics-standby-results.md) |

## P2 — Infrastructure orchestration and repeatable deployment  (🛠️ Implementing)

| | Item | Status | Evidence |
|---|---|---|---|
| P2.1 | Provider adapter with Proxmox VE as first provider (discovery, metrics, scoped VM lifecycle) <br><sub>Real PVE 9.2 cluster: scope refusals, clone, tag, configure, resize, start, snapshot, stop, destroy verified</sub> | 🧪 Integrated in lab | [`docs/status/provider-proxmox-real.md`](docs/status/provider-proxmox-real.md), [`docs/status/provider-proxmox.md`](docs/status/provider-proxmox.md) |
| P2.2 | Deployment engine: profiles, sizing, dependency graph, plans, desired vs actual state, drift <br><sub>Engine and plans work; full-stack bill of materials shows missing/unsigned artifacts (Keycloak, OpenCloud, MAS, Jitsi) being produced on branches artifacts-core / oci-signing</sub> | 🛠️ Implementing | [`docs/status/deployment-engine.md`](docs/status/deployment-engine.md) |
| P2.3 | Guest bootstrap: cloud-init, rootless Podman, signed digest-pinned images, agent enrollment <br><sub>Golden images Debian 12 + Ubuntu 24.04 built reproducibly from signed archives, independent boot suite 97/97 each, manifest v2 + DB version and date floor. image.import is an approved high-risk action (trust from Settings, floor from the DB, previewed sha256 bound into the plan) with a console Images page; not yet run against pve06</sub> | 🧪 Integrated in lab | [`docs/status/golden-image-prod-results.md`](docs/status/golden-image-prod-results.md), [`docs/status/bootstrap-v2.md`](docs/status/bootstrap-v2.md) |
| P2.4 | Setup, deployment and change wizards backed by approval-gated plans <br><sub>Setup/deployment/change wizards deployed as the default first-run path; end-to-end deployment run in progress</sub> | 🧪 Integrated in lab | — |
| P2.5 | Build and release pipeline for own distributions (signed packages/images, SBOM, staged channels) <br><sub>Signed apt pipeline with dev/staging/stable on main; hardened signer, per-channel keys, ICS-approved promotion and independent test attestation (the test runner runs the tests) on main; production keys need an owner key ceremony</sub> | 🛠️ Implementing | [`docs/status/package-pipeline-results.md`](docs/status/package-pipeline-results.md), [`docs/RELEASING.md`](docs/RELEASING.md), [`docs/adr/0008-build-release-pipeline.md`](docs/adr/0008-build-release-pipeline.md) |
| P2.6 | Continuous integration (tests, secret scanning, license checks) | 🛠️ Implementing | [`.github/workflows/`](.github/workflows/) |
| P2.7 | Connect with SSH: discover cluster, choose scope and rights, ICS creates its own Proxmox user/token and restricted SSH account <br><sub>Connect with SSH: own officeunbound@pve user/role/ACL/token + restricted ou-ics account and helper, host-key and API-certificate trust, normal risk per owner. Review 8 fixes: never adopts or deletes a pre-existing node account, offboarding bound to the onboarded host and key, cluster-wide helper reads need an approver. Owner test against pve06 pending</sub> | 🛠️ Implementing | [`docs/status/ssh-onboard-results.md`](docs/status/ssh-onboard-results.md), [`docs/adr/0014-ssh-onboarding.md`](docs/adr/0014-ssh-onboarding.md) |
| P2.8 | Signed artifact distribution to guests (apt repo + OCI registry, per-channel key pins) <br><sub>Signed apt repo + OCI registry for guests on the ICS host (port 8446), per-channel key pins in bootstrap metadata; lab proof incl. tamper/unsigned/wrong-key refusals</sub> | 🧪 Integrated in lab | [`docs/status/artifact-dist-results.md`](docs/status/artifact-dist-results.md) |
| P2.9 | ICS shipped as signed ou-ics package with automatic pre-upgrade backup and rollback <br><sub>Install, upgrade with migration and rollback proven in the lab on Ubuntu 24.04 and Debian 12 (12/12 checks each); not yet installed on the production ICS</sub> | 🧪 Integrated in lab | [`docs/status/ics-package-results.md`](docs/status/ics-package-results.md), [`docs/runbooks/ics-upgrade-rollback.md`](docs/runbooks/ics-upgrade-rollback.md), [`ics/deploy/pkg/ou-ics-setup`](ics/deploy/pkg/ou-ics-setup) |
| P2.10 | Per-customer network isolation (Proxmox SDN VNet per customer, default deny) <br><sub>Per-customer VNet network model and plan errors are in the ICS; SDN is not applied on the cluster yet and isolation is untested; owner decision: option A (VNet + PVE firewall) if no node rules on pve01-05, else option B</sub> | 🛠️ Implementing | [`ics/ics/deploy/netmodel.py`](ics/ics/deploy/netmodel.py), [`docs/admin/proxmox-sdn-isolation.md`](docs/admin/proxmox-sdn-isolation.md), [`docs/status/network-isolation-test-plan.md`](docs/status/network-isolation-test-plan.md) |
| P2.11 | Proxmox connection and access management wizard: sign in (password + TOTP/recovery), discover, select guests and deployment targets, automatic restricted credentials, reusable Manage access <br><sub>Branch pve-wizard (2026-11-16). Simulator-tested: ticket-only sign-in sessions with TFA, per-VMID operations preset + guest.power, inventory ledger (new/missing/moved/renamed/VMID reuse), incremental scope changes (guests, pools, networks, level), excess-privilege stop. Console: new Connect/Manage access wizard. Real-cluster evidence pending pve06.</sub> | 🛠️ Implementing | [`docs/adr/0016-proxmox-connection-wizard.md`](docs/adr/0016-proxmox-connection-wizard.md), [`ics/tests/test_admin_session.py`](ics/tests/test_admin_session.py), [`ics/tests/test_operate.py`](ics/tests/test_operate.py), [`ics/tests/test_inventory_ledger.py`](ics/tests/test_inventory_ledger.py), [`ics/tests/test_manage_access.py`](ics/tests/test_manage_access.py) |

## P3 — First working user experience  (🛠️ Implementing)

| | Item | Status | Evidence |
|---|---|---|---|
| P3.1 | Redesigned infrastructure console (dashboard, infrastructure views, operations, monitoring) <br><sub>Redesigned console; console v3 (releases/promotion, controller role banner, scope approvers, guest start-up panel) is on main, deployment of the new build pending</sub> | 🧪 Integrated in lab | [`docs/screenshots/`](docs/screenshots/), [`docs/status/console-v3-results.md`](docs/status/console-v3-results.md) |
| P3.2 | Unified user portal (mail, calendar, contacts, files, documents) with SSO <br><sub>SSO launcher, recent files, new documents; webmail single sign-on proven on a lab node</sub> | 🧪 Integrated in lab | [`docs/status/portal-results.md`](docs/status/portal-results.md) |
| P3.3 | Guided desktop and mobile onboarding | ⚪ Planned | — |

## P4 — MSP and organization administration  (⚪ Planned)

| | Item | Status | Evidence |
|---|---|---|---|
| P4.1 | Two isolated customer stacks with cross-customer access-denial tests <br><sub>Two independent lab customers: 153/155 isolation checks, and with per-customer encrypted backups 209 pass / 0 fail (backup-isolation-results.md); network isolation pending SDN (P2.10)</sub> | 🧪 Integrated in lab | [`docs/status/tenant-isolation-results.md`](docs/status/tenant-isolation-results.md), [`docs/status/backup-isolation-results.md`](docs/status/backup-isolation-results.md) |
| P4.2 | Organization admin and MSP Control Center <br><sub>Organization Admin in the portal (separate tenant API, customer-bound) + aliases/shared mailboxes/quotas tested in lab; MSP Control Center not started; send-as pending groupware fix</sub> | 🧪 Integrated in lab | [`docs/status/org-admin-results.md`](docs/status/org-admin-results.md), [`ics/ics/mailadmin.py`](ics/ics/mailadmin.py) |
| P4.3 | Versioned MSP provisioning API <br><sub>/api/msp/v1 with HMAC signing, idempotency, permission sets, signed webhooks, OpenAPI 3.1, reference client</sub> | 🧪 Integrated in lab | [`docs/adr/0013-msp-provisioning-api.md`](docs/adr/0013-msp-provisioning-api.md), [`docs/status/msp-api-results.md`](docs/status/msp-api-results.md), [`ics/ics/msp`](ics/ics/msp) |

## P5 — Operational maturity  (⚪ Planned)

| | Item | Status | Evidence |
|---|---|---|---|
| P5.1 | Patch rings, controlled upgrades and rollback <br><sub>Signed pinned-package upgrade + rollback drills: groupware (A21) and document engine (ou1<->ou2, ~30 s downtime, data intact)</sub> | 🛠️ Implementing | [`docs/status/docs-upgrade-drill-results.md`](docs/status/docs-upgrade-drill-results.md), [`docs/status/upgrade-drill-results.md`](docs/status/upgrade-drill-results.md) |
| P5.2 | Capacity analytics and scaling plans <br><sub>Capacity planning per full stack computed against pve06 (branch fullstack-plan); analytics/forecasting not built</sub> | ⚪ Planned | — |
| P5.3 | Encrypted off-host backups with measured RPO/RTO <br><sub>Encrypted append-only backups as ICS jobs with verified restores (RTO 29-127 s in lab)</sub> | 🧪 Integrated in lab | [`docs/status/backup-product-results.md`](docs/status/backup-product-results.md) |

## P6 — Chat, meetings and telephony  (🛠️ Implementing)

| | Item | Status | Evidence |
|---|---|---|---|
| P6.1 | Zero-cost collaboration stack evaluation (Matrix, Jitsi/LiveKit, Asterisk) | ✅ Tested | [`docs/status/collaboration-eval.md`](docs/status/collaboration-eval.md) |
| P6.2 | Chat (Synapse + MAS + Element) and meetings (Jitsi with SSO-issued tokens) | 🧪 Integrated in lab | [`docs/status/collaboration-lab-results.md`](docs/status/collaboration-lab-results.md) |
| P6.3 | Business telephony (Asterisk + browser softphone) <br><sub>WebRTC + native SIP calls, voicemail to email, LDAP extensions, deprovisioning 0.6 s; no PSTN/E911 yet</sub> | 🧪 Integrated in lab | [`docs/status/telephony-lab-results.md`](docs/status/telephony-lab-results.md) |

## P7 — Migration Center (Microsoft 365, Google Workspace)  (🛠️ Implementing)

| | Item | Status | Evidence |
|---|---|---|---|
| P7.1 | Read-only migration readiness assessment <br><sub>Implemented and tested against API-shaped fixtures; awaiting a real tenant</sub> | 🛠️ Implementing | [`docs/status/migration-assessment.md`](docs/status/migration-assessment.md) |
| P7.2 | Mail, calendar, contacts and file migration engine <br><sub>IMAP to groupware mail migration verified in lab; calendar/contacts/tasks migration frozen as WIP (verification did not pass) until after the alpha</sub> | 🧪 Integrated in lab | — |

## P8 — MSP pilot and production hardening  (⚪ Planned)

| | Item | Status | Evidence |
|---|---|---|---|
| P8.1 | Deliverability, performance, security testing and support documentation | ⚪ Planned | — |

## P9 — Office Unbound PDF Studio: full PDF reader, editor, forms and document management (DEFERRED — absolute last priority)  ( Deferred)

| | Item | Status | Evidence |
|---|---|---|---|
| P9.0 | Engine research, licence audit and feature/dependency matrix (PDF.js, Nib, Stirling PDF as reference only, others) <br><sub>Deferred: starts only after every other planned core feature and integration is complete and stable (owner, 2026-11-16)</sub> |  Deferred | [`docs/requirements/P9-pdf-reader-editor.md`](docs/requirements/P9-pdf-reader-editor.md) |
| P9.1 | PDF reader (tabs, presentation mode, protected documents, attachments) |  Deferred | — |
| P9.2 | Full editing of existing PDFs: text, images/objects, pages |  Deferred | — |
| P9.3 | Annotations and multi-reviewer review |  Deferred | — |
| P9.4 | Forms: filling and creation (AcroForm; XFA limits documented) |  Deferred | — |
| P9.5 | Electronic signatures and signing workflows |  Deferred | — |
| P9.6 | Cryptographic digital signatures (PKCS#12/X.509, PAdES, RFC 3161 timestamps, OCSP/CRL) |  Deferred | — |
| P9.7 | Secure redaction (verified non-recoverable) |  Deferred | — |
| P9.8 | OCR and scanned documents |  Deferred | — |
| P9.9 | Document conversion, merge/split, PDF/A |  Deferred | — |
| P9.10 | Document security, untrusted-input sandboxing |  Deferred | — |
| P9.11 | Advanced tools: compare, Bates, headers/footers, PDF/UA validation, reading-order editing, batch |  Deferred | — |
| P9.12 | Office Unbound Files integration, versioning, APIs |  Deferred | — |
| P9.13 | UX concept designs and review |  Deferred | — |
| P9.14 | Test suite and final acceptance |  Deferred | — |

## P10 — Post-Core Expansion: planned future capabilities (not available; starts after the core product and P9)  ( Deferred)

| | Item | Status | Evidence |
|---|---|---|---|
| P10.0 | Foundations design (F2 authorisation API, F4 search, F5 legal-hold hooks) and full licence audit of candidates [complexity XL] <br><sub>Planned future capability, not available. Planning only (owner, 2026-11-16).</sub> |  Deferred | [`docs/roadmap/post-core-expansion.md`](docs/roadmap/post-core-expansion.md) |
| P10.1 | Business applications and workflow automation (Power Apps/Automate/Forms/Lists/Planner equivalent) [complexity XL] <br><sub>Planned future capability, not available. Planning only (owner, 2026-11-16).</sub> |  Deferred | [`docs/roadmap/post-core-expansion.md`](docs/roadmap/post-core-expansion.md) |
| P10.2 | Company intranet and knowledge center (SharePoint equivalent) [complexity L] <br><sub>Planned future capability, not available. Planning only (owner, 2026-11-16).</sub> |  Deferred | [`docs/roadmap/post-core-expansion.md`](docs/roadmap/post-core-expansion.md) |
| P10.3 | Optional AI workspace: local or bring-your-own models, permission-checked, can be disabled [complexity L] <br><sub>Planned future capability, not available. Planning only (owner, 2026-11-16).</sub> |  Deferred | [`docs/roadmap/post-core-expansion.md`](docs/roadmap/post-core-expansion.md) |
| P10.4 | Advanced security operations (Defender equivalent): Wazuh, ExploitHound, MailThreatZero, rem0te [complexity XL] <br><sub>Planned future capability, not available. Planning only (owner, 2026-11-16).</sub> |  Deferred | [`docs/roadmap/post-core-expansion.md`](docs/roadmap/post-core-expansion.md) |
| P10.5 | Compliance and data governance (Purview equivalent): DLP, retention, legal hold, eDiscovery [complexity XL] <br><sub>Planned future capability, not available. Planning only (owner, 2026-11-16).</sub> |  Deferred | [`docs/roadmap/post-core-expansion.md`](docs/roadmap/post-core-expansion.md) |
| P10.6 | Endpoint and device management (Intune equivalent), rem0te-based; separate from ICS [complexity XL] <br><sub>Planned future capability, not available. Planning only (owner, 2026-11-16).</sub> |  Deferred | [`docs/roadmap/post-core-expansion.md`](docs/roadmap/post-core-expansion.md) |
| P10.7 | Advanced meetings: recording, transcripts, webinars, whiteboards, PSTN [complexity L] <br><sub>Planned future capability, not available. Planning only (owner, 2026-11-16).</sub> |  Deferred | [`docs/roadmap/post-core-expansion.md`](docs/roadmap/post-core-expansion.md) |
| P10.8 | Advanced office documents: fidelity, templates, automation, replaceable engine [complexity XL] <br><sub>Planned future capability, not available. Planning only (owner, 2026-11-16).</sub> |  Deferred | [`docs/roadmap/post-core-expansion.md`](docs/roadmap/post-core-expansion.md) |
| P10.9 | Business intelligence and analytics (Power BI equivalent) [complexity L] <br><sub>Planned future capability, not available. Planning only (owner, 2026-11-16).</sub> |  Deferred | [`docs/roadmap/post-core-expansion.md`](docs/roadmap/post-core-expansion.md) |
| P10.10 | Advanced identity and enterprise integrations (Entra ID/Graph equivalent) [complexity XL] <br><sub>Planned future capability, not available. Planning only (owner, 2026-11-16).</sub> |  Deferred | [`docs/roadmap/post-core-expansion.md`](docs/roadmap/post-core-expansion.md) |

## First functional demo — acceptance tests (22/24 demonstrated in lab)

| | Test | Status | Note |
|---|---|---|---|
| A1 | ICS deploys the required components into approved lab infrastructure | 🧪 Integrated in lab | ICS deployed a VM + signed container on real Proxmox end to end (lab-only bootstrap; production no-SSH bootstrap pending owner storage prerequisite) |
| A2 | Services reachable through correctly configured TLS endpoints | 🧪 Integrated in lab | Lab CA |
| A3 | Keycloak login and user provisioning | 🧪 Integrated in lab |  |
| A4 | User can enter the Office Unbound portal | 🧪 Integrated in lab | Portal with Keycloak SSO in lab |
| A5 | User can access mail | 🧪 Integrated in lab |  |
| A6 | Send and receive real test messages | 🧪 Integrated in lab | Within the lab; external deliverability not yet tested |
| A7 | Calendar events created and synchronized | 🧪 Integrated in lab |  |
| A8 | Contacts created and synchronized | 🧪 Integrated in lab |  |
| A9 | Create a document | 🧪 Integrated in lab |  |
| A10 | Edit and save a document | 🧪 Integrated in lab |  |
| A11 | Content correct after close and reopen | 🧪 Integrated in lab |  |
| A12 | Content survives service restart | 🧪 Integrated in lab |  |
| A13 | Desktop sync upload/download and offline work | 🧪 Integrated in lab | Sync engine tested headless; GUI client not yet |
| A14 | Groupware protocol tests report actual client compatibility | 🛠️ Implementing | Protocol level done; real clients pending |
| A15 | ICS detects a simulated service failure | 🧪 Integrated in lab |  |
| A16 | Approved recovery action succeeds | 🧪 Integrated in lab |  |
| A17 | Backup restored to a separate test machine | 🧪 Integrated in lab | Files, identity, groupware and ICS controller tiers restored to separate machines |
| A18 | Tests identify unsupported functionality instead of concealing it | 🧪 Integrated in lab |  |
| A19 | User deprovisioning removes effective access | 🧪 Integrated in lab | App tokens, IMAP sessions, ActiveSync wipe, Matrix and phone access all revoked in lab |
| A20 | Two isolated customer deployments pass access-denial tests | 🧪 Integrated in lab | Two independent customer stacks: 153/155 isolation checks; per-customer network isolation needs VLAN/SDN in production; backup key boundary being re-tested |
| A21 | Pinned upgrades and recovery demonstrated | 🧪 Integrated in lab | Pinned signed-package upgrade and rollback demonstrated (merge pending) |
| A22 | Installer can repeat the installation | 🧪 Integrated in lab | All lab tiers install in one pass on fresh machines and re-run idempotently; ICS installer on Ubuntu 24.04 and Debian 12 |
| A23 | Monitoring and audit history survive restarts | 🧪 Integrated in lab | Audit chain verified after controller restore |
| A24 | Administrator documentation describes real procedures | 🛠️ Implementing |  |

## Releases

| Version | Date | Status | Highlights |
|---|---|---|---|
| [0.2.0-dev.2](https://github.com/agit8or1/office-unbound/blob/main/CHANGELOG.md) | 2026-11-16 | prepared | Development build 2 of 0.2.0 "Beacon": first production golden image (Debian 12, signed, boot-tested), wizard protections shown as always on |
| [0.1.0](https://github.com/agit8or1/office-unbound/releases/tag/v0.1.0) | 2026-11-16 | released | Installable ICS with console, typed actions, approvals and hash-chained audit<br>Groupware, identity, files and browser document editing integrated and tested in an isolated lab<br>Proxmox provider verified on a live cluster; deployment engine, wizards, credential vault<br>Office Unbound Docs own source build, user portal, SSO, chat/meetings and telephony lab prototypes<br>Lab pre-alpha only: not production supported; security reviews 5-7 High findings open (fixes target 0.2.0) |

Full history: [`CHANGELOG.md`](CHANGELOG.md). Process: [`docs/RELEASING.md`](docs/RELEASING.md).

## Known limitations

- New Outlook for Windows and Outlook mobile cannot use MAPI/EWS against non-Microsoft servers (Microsoft limitation); IMAP/SMTP only
- Lab currently runs in isolated containers on a single host; production topology is full VMs on Proxmox
- Release 0.1.0 is a lab pre-alpha, unsigned; no production-supported release exists yet
