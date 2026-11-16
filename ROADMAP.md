# Office Unbound roadmap & progress

> Generated from [`docs/progress.json`](docs/progress.json) by `scripts/render_roadmap.py` — edit the JSON, not this file. Last updated **2026-11-15** · stage: **pre-alpha (lab)** · current version: **0.2.0-dev**.

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
| P1.7 | Documents: own unlimited, rebranded Collabora Online source build <br><sub>Own source build, rebranded, no connection/document caps: 30 concurrent documents and 60 sessions verified; edit/save via WOPI verified</sub> | 🧪 Integrated in lab | [`docs/status/docengine-build-results.md`](docs/status/docengine-build-results.md) |
| P1.8 | User lifecycle: provision and deprovision across all services with measured revocation <br><sub>Open gaps: OpenCloud app-token revocation, ActiveSync remote wipe, per-user IMAP session termination</sub> | 🧪 Integrated in lab | [`docs/status/user-lifecycle-results.md`](docs/status/user-lifecycle-results.md) |
| P1.9 | Backup and restore drills to separate machines (files, identity, ICS controller) | 🧪 Integrated in lab | [`docs/status/restore-drill-results.md`](docs/status/restore-drill-results.md), [`docs/runbooks/ics-recovery.md`](docs/runbooks/ics-recovery.md) |
| P1.10 | Groupware restore to a separate machine and clean-room rebuild <br><sub>Online logical backup; point-in-time consistency across mailboxes needs snapshots</sub> | 🧪 Integrated in lab | [`docs/status/restore-drill-results.md`](docs/status/restore-drill-results.md) |
| P1.11 | Real Outlook, Thunderbird and mobile client compatibility matrix <br><sub>Thunderbird 24/25 and Evolution calendar/contacts tested in lab (client-compat-results.md); groupware fixes from these tests in progress; Outlook/mobile need owner devices</sub> | 🛠️ Implementing | [`docs/status/client-compat-results.md`](docs/status/client-compat-results.md) |
| P1.12 | Versioning, changelog, release notes and release tracking (VERSION, build info, /api/v1/version, console System page) <br><sub>0.1.0 "Anchor" released (tag v0.1.0, GitHub pre-release); main is 0.2.0-dev "Beacon"; release names per minor line (ADR-0011 amendment)</sub> | ✅ Tested | [`docs/adr/0011-versioning-and-releases.md`](docs/adr/0011-versioning-and-releases.md), [`CHANGELOG.md`](CHANGELOG.md), [`VERSIONS.json`](VERSIONS.json) |
| P1.13 | Alpha security remediation (reviews 1-7): signing, attestation, cross-tenant scoping, fencing, admin takeover <br><sub>132 findings tracked with verified evidence; tenant-msp (review 6), hardening and privsep fixes landed on main via integration-8; fixes-r7 and oci-signing still pending merge; independent review 8 follows</sub> | 🛠️ Implementing | [`docs/status/SECURITY-REMEDIATION.md`](docs/status/SECURITY-REMEDIATION.md), [`docs/status/ALPHA-EXECUTION-QUEUE.md`](docs/status/ALPHA-EXECUTION-QUEUE.md), [`scripts/security_remediation_check.py`](scripts/security_remediation_check.py) |
| P1.14 | Least-privilege host accounts, sudoers, unit hardening <br><sub>Scripts, sudoers/polkit/unit drop-ins and docs are on main (lab-tested); NOT applied to any host: removal of administrator NOPASSWD:ALL is an owner action (apply pending)</sub> | 🛠️ Implementing | [`docs/status/security-review-7-2026-11-16.md`](docs/status/security-review-7-2026-11-16.md), [`docs/status/privilege-audit.md`](docs/status/privilege-audit.md), [`ics/deploy/privsep/apply-privsep.sh`](ics/deploy/privsep/apply-privsep.sh), [`ics/deploy/privsep/revert-privsep.sh`](ics/deploy/privsep/revert-privsep.sh) |
| P1.15 | ICS warm standby with fenced failover (epoch + lease/witness) <br><sub>Streaming standby, operator-triggered fenced promotion with controller epoch (3.1 s in lab) and old-agent fallback; lease-based self-fencing, witness mode and a two-controller partition test are not done (branches fixes-r7, ha-proof; pending merge)</sub> | 🧪 Integrated in lab | [`docs/runbooks/ics-recovery.md`](docs/runbooks/ics-recovery.md), [`docs/adr/0012-ics-warm-standby.md`](docs/adr/0012-ics-warm-standby.md), [`docs/status/ics-standby-results.md`](docs/status/ics-standby-results.md) |

## P2 — Infrastructure orchestration and repeatable deployment  (🛠️ Implementing)

| | Item | Status | Evidence |
|---|---|---|---|
| P2.1 | Provider adapter with Proxmox VE as first provider (discovery, metrics, scoped VM lifecycle) <br><sub>Real PVE 9.2 cluster: scope refusals, clone, tag, configure, resize, start, snapshot, stop, destroy verified</sub> | 🧪 Integrated in lab | [`docs/status/provider-proxmox-real.md`](docs/status/provider-proxmox-real.md), [`docs/status/provider-proxmox.md`](docs/status/provider-proxmox.md) |
| P2.2 | Deployment engine: profiles, sizing, dependency graph, plans, desired vs actual state, drift <br><sub>Engine and plans work; full-stack bill of materials shows missing/unsigned artifacts (Keycloak, OpenCloud, MAS, Jitsi) being produced on branches artifacts-core / oci-signing</sub> | 🛠️ Implementing | [`docs/status/deployment-engine.md`](docs/status/deployment-engine.md) |
| P2.3 | Guest bootstrap: cloud-init, rootless Podman, signed digest-pinned images, agent enrollment <br><sub>Bootstrap v2 (no-SSH HMAC callback) on main; golden images Debian 12 + Ubuntu 24.04 with independent boot attestation on branch golden-prod (pending merge); real VM run on pve06 after owner onboarding</sub> | 🧪 Integrated in lab | [`docs/status/bootstrap-v2.md`](docs/status/bootstrap-v2.md), [`docs/status/guest-bootstrap-results.md`](docs/status/guest-bootstrap-results.md) |
| P2.4 | Setup, deployment and change wizards backed by approval-gated plans <br><sub>Setup/deployment/change wizards deployed as the default first-run path; end-to-end deployment run in progress</sub> | 🧪 Integrated in lab | — |
| P2.5 | Build and release pipeline for own distributions (signed packages/images, SBOM, staged channels) <br><sub>Signed apt pipeline with dev/staging/stable on main; hardened signer, per-channel keys, ICS-approved promotion and independent test attestation on branch fixes-r7 (pending merge); production keys need an owner key ceremony</sub> | 🛠️ Implementing | [`docs/status/package-pipeline-results.md`](docs/status/package-pipeline-results.md), [`docs/RELEASING.md`](docs/RELEASING.md), [`docs/adr/0008-build-release-pipeline.md`](docs/adr/0008-build-release-pipeline.md) |
| P2.6 | Continuous integration (tests, secret scanning, license checks) | 🛠️ Implementing | [`.github/workflows/`](.github/workflows/) |
| P2.7 | Connect with SSH: discover cluster, choose scope and rights, ICS creates its own Proxmox user/token and restricted SSH account <br><sub>Owner request 2026-11-16; owner will test against pve06 via pve.agit8or.net (branch ssh-onboard)</sub> | 🛠️ Implementing | — |
| P2.8 | Signed artifact distribution to guests (apt repo + OCI registry, per-channel key pins) <br><sub>Branch artifact-dist</sub> | 🛠️ Implementing | — |
| P2.9 | ICS shipped as signed ou-ics package with automatic pre-upgrade backup and rollback <br><sub>Branch ics-pkg; install/upgrade/rollback drill on Ubuntu 24.04 and Debian 12 in progress</sub> | 🛠️ Implementing | — |
| P2.10 | Per-customer network isolation (Proxmox SDN VNet per customer, default deny) <br><sub>Per-customer VNet network model and plan errors are in the ICS; SDN is not applied on the cluster yet and isolation is untested; owner decision: option A (VNet + PVE firewall) if no node rules on pve01-05, else option B</sub> | 🛠️ Implementing | [`ics/ics/deploy/netmodel.py`](ics/ics/deploy/netmodel.py), [`docs/admin/proxmox-sdn-isolation.md`](docs/admin/proxmox-sdn-isolation.md), [`docs/status/network-isolation-test-plan.md`](docs/status/network-isolation-test-plan.md) |

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

## P9 — Full PDF Reader, Editor and Document Management (DEFERRED — final development priority)  ( Deferred)

| | Item | Status | Evidence |
|---|---|---|---|
| P9.0 | Technology and licensing evaluation (first step when P9 starts) <br><sub>Deferred until alpha readiness and MSP pilot objectives are complete (owner, 2026-11-16)</sub> |  Deferred | [`docs/requirements/P9-pdf-reader-editor.md`](docs/requirements/P9-pdf-reader-editor.md) |
| P9.1 | PDF reader |  Deferred | — |
| P9.2 | Full editing of existing PDFs: text, images/objects, pages |  Deferred | — |
| P9.3 | Annotations and multi-reviewer review |  Deferred | — |
| P9.4 | Forms: filling and creation (AcroForm; XFA limits documented) |  Deferred | — |
| P9.5 | Electronic signatures and signing workflows |  Deferred | — |
| P9.6 | Cryptographic digital signatures (PKCS#12/X.509, PAdES, OCSP/CRL) |  Deferred | — |
| P9.7 | Secure redaction (verified non-recoverable) |  Deferred | — |
| P9.8 | OCR and scanned documents |  Deferred | — |
| P9.9 | Document conversion, merge/split, PDF/A |  Deferred | — |
| P9.10 | Document security, untrusted-input sandboxing |  Deferred | — |
| P9.11 | Advanced tools: compare, Bates, accessibility, batch |  Deferred | — |
| P9.12 | Office Unbound Files integration, versioning, APIs |  Deferred | — |
| P9.13 | UX concept designs and review |  Deferred | — |
| P9.14 | Test suite and final acceptance |  Deferred | — |

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
| [0.2.0-dev](https://github.com/agit8or1/office-unbound/blob/main/CHANGELOG.md) | 2026-11-16 | prepared | In development: alpha readiness (security reviews 5-7 remediation, production no-SSH Proxmox deployment, full service profile, two-customer isolation) |
| [0.1.0](https://github.com/agit8or1/office-unbound/releases/tag/v0.1.0) | 2026-11-16 | released | Installable ICS with console, typed actions, approvals and hash-chained audit<br>Groupware, identity, files and browser document editing integrated and tested in an isolated lab<br>Proxmox provider verified on a live cluster; deployment engine, wizards, credential vault<br>Office Unbound Docs own source build, user portal, SSO, chat/meetings and telephony lab prototypes<br>Lab pre-alpha only: not production supported; security reviews 5-7 High findings open (fixes target 0.2.0) |

Full history: [`CHANGELOG.md`](CHANGELOG.md). Process: [`docs/RELEASING.md`](docs/RELEASING.md).

## Known limitations

- New Outlook for Windows and Outlook mobile cannot use MAPI/EWS against non-Microsoft servers (Microsoft limitation); IMAP/SMTP only
- Lab currently runs in isolated containers on a single host; production topology is full VMs on Proxmox
- Release 0.1.0 is a lab pre-alpha, unsigned; no production-supported release exists yet
