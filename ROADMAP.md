# Office Unbound roadmap & progress

> Generated from [`docs/progress.json`](docs/progress.json) by `scripts/render_roadmap.py` — edit the JSON, not this file. Last updated **2026-11-15** · stage: **pre-alpha (lab)**.

Core platform components are integrated and tested in an isolated lab: own source build of Exchange-compatible groupware with single sign-on webmail, Keycloak SSO, file sync and browser document editing, backup/restore drills, chat and video meetings, and an infrastructure control server with monitoring, self-healing and a real Proxmox integration (VM lifecycle verified on a live cluster). Guided deployment wizards, provisioning automation and the credential vault are being integrated.

**Principles**

- Zero mandatory third-party licensing cost; no artificial user, mailbox or connection limits (ADR-0007)
- Own source builds where vendor packages are restricted (ADR-0008)
- A feature is working only when demonstrated by executed tests

**Status legend:** ⚪ Planned · 🔎 Researching · 🛠️ Implementing · 🧪 Integrated in lab · ✅ Tested · 🅰️ Alpha · 🅱️ Beta · 🚀 Production supported · ⛔ Blocked

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
| P1.11 | Real Outlook, Thunderbird and mobile client compatibility matrix | ⚪ Planned | [`blueprints/lab/tests/MANUAL-CHECKLIST.md`](blueprints/lab/tests/MANUAL-CHECKLIST.md) |

## P2 — Infrastructure orchestration and repeatable deployment  (🛠️ Implementing)

| | Item | Status | Evidence |
|---|---|---|---|
| P2.1 | Provider adapter with Proxmox VE as first provider (discovery, metrics, scoped VM lifecycle) <br><sub>Real PVE 9.2 cluster: scope refusals, clone, tag, configure, resize, start, snapshot, stop, destroy verified</sub> | 🧪 Integrated in lab | [`docs/status/provider-proxmox-real.md`](docs/status/provider-proxmox-real.md), [`docs/status/provider-proxmox.md`](docs/status/provider-proxmox.md) |
| P2.2 | Deployment engine: profiles, sizing, dependency graph, plans, desired vs actual state, drift | 🛠️ Implementing | [`docs/status/deployment-engine.md`](docs/status/deployment-engine.md) |
| P2.3 | Guest bootstrap: cloud-init, rootless Podman, signed digest-pinned images, agent enrollment <br><sub>Tested in lab containers; real VM boot pending</sub> | 🧪 Integrated in lab | [`docs/status/guest-bootstrap-results.md`](docs/status/guest-bootstrap-results.md) |
| P2.4 | Setup, deployment and change wizards backed by approval-gated plans <br><sub>Setup/deployment/change wizards deployed as the default first-run path; end-to-end deployment run in progress</sub> | 🧪 Integrated in lab | — |
| P2.5 | Build and release pipeline for own distributions (signed packages/images, SBOM, staged channels) | ⚪ Planned | [`docs/adr/0008-build-release-pipeline.md`](docs/adr/0008-build-release-pipeline.md) |
| P2.6 | Continuous integration (tests, secret scanning, license checks) | 🛠️ Implementing | [`.github/workflows/`](.github/workflows/) |

## P3 — First working user experience  (🛠️ Implementing)

| | Item | Status | Evidence |
|---|---|---|---|
| P3.1 | Redesigned infrastructure console (dashboard, infrastructure views, operations, monitoring) <br><sub>Redesigned console deployed; infrastructure views await Proxmox provider integration</sub> | 🧪 Integrated in lab | [`docs/screenshots/`](docs/screenshots/) |
| P3.2 | Unified user portal (mail, calendar, contacts, files, documents) with SSO <br><sub>SSO launcher, recent files, new documents; webmail single sign-on proven on a lab node</sub> | 🧪 Integrated in lab | [`docs/status/portal-results.md`](docs/status/portal-results.md) |
| P3.3 | Guided desktop and mobile onboarding | ⚪ Planned | — |

## P4 — MSP and organization administration  (⚪ Planned)

| | Item | Status | Evidence |
|---|---|---|---|
| P4.1 | Two isolated customer stacks with cross-customer access-denial tests | ⚪ Planned | — |
| P4.2 | Organization admin and MSP Control Center | ⚪ Planned | — |
| P4.3 | Versioned MSP provisioning API | ⚪ Planned | — |

## P5 — Operational maturity  (⚪ Planned)

| | Item | Status | Evidence |
|---|---|---|---|
| P5.1 | Patch rings, controlled upgrades and rollback | ⚪ Planned | — |
| P5.2 | Capacity analytics and scaling plans | ⚪ Planned | — |
| P5.3 | Encrypted off-host backups with measured RPO/RTO | ⚪ Planned | — |

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
| P7.2 | Mail, calendar, contacts and file migration engine <br><sub>IMAP to groupware mail migration verified in lab (incremental, resumable); merge pending</sub> | 🧪 Integrated in lab | — |

## P8 — MSP pilot and production hardening  (⚪ Planned)

| | Item | Status | Evidence |
|---|---|---|---|
| P8.1 | Deliverability, performance, security testing and support documentation | ⚪ Planned | — |

## First functional demo — acceptance tests (19/24 demonstrated in lab)

| | Test | Status | Note |
|---|---|---|---|
| A1 | ICS deploys the required components into approved lab infrastructure | 🛠️ Implementing | Real VM lifecycle on Proxmox verified; full ICS-driven component deployment in progress |
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
| A19 | User deprovisioning removes effective access | 🧪 Integrated in lab | Known gaps listed in P1.8 |
| A20 | Two isolated customer deployments pass access-denial tests | ⚪ Planned |  |
| A21 | Pinned upgrades and recovery demonstrated | ⚪ Planned |  |
| A22 | Installer can repeat the installation | 🧪 Integrated in lab | Groupware rebuilt from source on a fresh machine; ICS one-command installer proven on two fresh machines (install, idempotent re-run, upgrade, restore) |
| A23 | Monitoring and audit history survive restarts | 🧪 Integrated in lab | Audit chain verified after controller restore |
| A24 | Administrator documentation describes real procedures | 🛠️ Implementing |  |

## Known limitations

- New Outlook for Windows and Outlook mobile cannot use MAPI/EWS against non-Microsoft servers (Microsoft limitation); IMAP/SMTP only
- Lab currently runs in isolated containers on a single host; production topology is full VMs on Proxmox
- No production releases exist yet
