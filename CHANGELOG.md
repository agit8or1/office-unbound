# Changelog

All notable changes to Office Unbound are recorded here. The format follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/);
versioning follows [Semantic Versioning](https://semver.org/) as defined in [ADR-0011](docs/adr/0011-versioning-and-releases.md).
While the major version is 0 the project is pre-alpha: MINOR releases may contain breaking changes.

Every entry links to the document that holds its evidence (executed tests, lab results, review reports). An entry without
evidence is a plan, not a change (ADR-0000). Release 0.1.0 is a **lab pre-alpha**: everything below was demonstrated in an
isolated lab; nothing is production supported ([ROADMAP.md](ROADMAP.md)).

## [Unreleased]

Work that exists on branches but is **not yet on `main`** (reviewed and merged by the lead before it is listed under a release).

### Added
- Release engineering branch (`release-ag`): Gromox `ou2` package carrying both patches, libexmdbpp / admin-web / Collabora components, hardened package pipeline, upgrade-drill scripts. See [security review 4](docs/status/security-review-4-2026-11-15.md) for the pipeline findings it targets.

### Security
- Security review 4 findings H1, H2, M3, M7, M8, M9 are addressed on the release-engineering branch; the rest of the review 4 findings (M1, M2, M4, M5, M6, M10, M11, L1-L9) are open. See [security review 4](docs/status/security-review-4-2026-11-15.md).

## [0.1.0] - 2026-11-15

First tagged state of the project: a lab-integrated pre-alpha. Installable ICS, console, groupware, identity, files, document
editing, chat/meetings, telephony prototype, migration tooling and package pipeline, all verified only in an isolated lab.

### Added
- **Versioning and releases** (this release): `VERSION`, `VERSIONS.json`, build info written at install time, `GET /api/v1/version`, `GET /api/v1/system`, console footer and Administration → System page, portal `/about`, changelog and release tooling. [ADR-0011](docs/adr/0011-versioning-and-releases.md)
- **Architecture and decisions**: ADR set 0000-0009 including the zero-cost / no-artificial-limits requirement (ADR-0007), own source builds where vendor packages are restricted (ADR-0008) and the infrastructure orchestration contract (ADR-0009). [ARCHITECTURE](docs/ARCHITECTURE.md), [docs/adr/](docs/adr/)
- **Infrastructure Control Server (ICS) foundation**: operator authentication with TOTP, encrypted vault, hash-chained audit log, typed actions with approvals and durable jobs, read-only Proxmox client, plan preview. [security review 1](docs/status/security-review-ics-2026-11-15.md)
- **ICS operator console** (Vue 3) served under a strict CSP, later redesigned with an app shell, design system, dashboard, infrastructure views and integrations. [ui-verification-main](docs/status/ui-verification-main.md)
- **Groupware** built from public source in an isolated lab: MAPI/HTTP, EWS, ActiveSync, Autodiscover, IMAP/SMTP, CalDAV/CardDAV, shared mailboxes, restart persistence, backup/restore (57 checks). Single user store through OpenLDAP. [groupware-lab-results](docs/status/groupware-lab-results.md), [groupware-ldap-results](docs/status/groupware-ldap-results.md)
- **Identity, files and documents lab**: OpenLDAP, Keycloak, OpenCloud, OIDC, WebDAV, browser document edit/save with versions, and the desktop sync engine (upload, download, offline, conflict, delete). [identity-files-lab-results](docs/status/identity-files-lab-results.md)
- **Restore drills**: identity tier, files tier, groupware tier (23 mailboxes restored to a clean-room rebuild) and the ICS controller itself (passive restore to a fresh machine). [restore-drill-results](docs/status/restore-drill-results.md), [ICS recovery runbook](docs/runbooks/ics-recovery.md)
- **Monitoring, alerting and remediation**: health checks, incidents, maintenance windows, signed node agent, approved auto-restart with verified recovery (failure detected in 21 s in the lab). [ics-monitoring-results](docs/status/ics-monitoring-results.md)
- **Identity lifecycle across OpenLDAP, Keycloak, Gromox and OpenCloud**: create, update groups, disable with verification, enable, delete, reconcile; later Matrix. [user-lifecycle-results](docs/status/user-lifecycle-results.md)
- **Operator user management**: directory, invitations, access policy view and a guided privileged-access workflow; audited break-glass `disable-user` CLI. [users-and-access](docs/admin/users-and-access.md)
- **Proxmox provider and real-cluster integration**: provider interface, simulator, inventory and metrics, endpoint settings, node allowlist, VM lifecycle verified on a live cluster. [provider-proxmox-real](docs/status/provider-proxmox-real.md), [provider-proxmox](docs/status/provider-proxmox.md)
- **Deployment engine**: component and profile catalog, plan generation, drift/diff, step executor, `deployment.*` actions. [deployment-engine](docs/status/deployment-engine.md), [catalog schema](blueprints/catalog/README.md)
- **Guest bootstrap**: cloud-init renderer, typed rootless Podman/Quadlet and package runbooks, pinned image-signature policy, proven on a lab guest. [guest-bootstrap-results](docs/status/guest-bootstrap-results.md)
- **Wizards**: first-run setup, connection edit, new deployment and change wizards as the default path. [provider-stack-integration](docs/status/provider-stack-integration.md)
- **Provisioning modes A/B, credential vault, customers and approval links**: permission model, drift detection, customer policy and scoping, external customer approval, master-key re-wrap. [provider-provisioning](docs/status/provider-provisioning.md), [credential-vault](docs/status/credential-vault.md)
- **Providers UI**: Proxmox connection wizard, cluster dashboard, permissions, credentials, customers, read-only discovery. [providers-ui](docs/status/providers-ui.md)
- **Office Unbound Docs**: own source build of Collabora Online (`cp-26.04.6-1`, revision `ou1`), rebranded, unlimited connections and documents, with recipe, patches, tests and SBOM; convert 9/9 and WOPI edit/save verified. [docengine-build-results](docs/status/docengine-build-results.md), [recipe](blueprints/build/collabora)
- **User portal**: Keycloak OIDC backend-for-frontend, launcher, recent files, account, device onboarding (Apple profile, Thunderbird autoconfig); lab end-to-end 39/0. [portal-results](docs/status/portal-results.md)
- **Single sign-on**: webmail SSO into the groupware web client through Keycloak, calendar/contacts deep links, Gromox bearer-claim validation patch, key follower with rotation. [webmail-sso-results](docs/status/webmail-sso-results.md), [sso-rollout-results](docs/status/sso-rollout-results.md)
- **Chat and meetings lab**: Synapse with MAS and Keycloak, Element Web, Jitsi with an Office Unbound JWT. [collaboration-lab-results](docs/status/collaboration-lab-results.md)
- **Telephony lab prototype**: Asterisk PJSIP over WSS and TLS/SRTP, LDAP-provisioned extensions, browser softphone behind Keycloak, voicemail to email (65/0). No outside line and no emergency calling. [telephony-lab-results](docs/status/telephony-lab-results.md)
- **Migration tooling**: read-only Microsoft 365 / Google Workspace readiness assessment (52 fixture-based tests) and an IMAP-to-Gromox mail mover (read-only source, incremental, resumable, verified). [migration-assessment](docs/status/migration-assessment.md), [migration-engine-results](docs/status/migration-engine-results.md)
- **ICS installer**: single-command idempotent `bootstrap.sh` for a fresh Ubuntu 24.04 host (install, upgrade, uninstall), proven on two fresh machines. [ics-installer-results](docs/status/ics-installer-results.md), [installing-the-ics](docs/admin/installing-the-ics.md)
- **Administrator guide** built from executed procedures. [docs/admin](docs/admin/index.md)
- **Public roadmap feed** `docs/progress.json` with generated `ROADMAP.md` and a CI freshness check. [progress-schema](docs/progress-schema.md)
- **CI**: backend, frontend, security and lint workflows with actions pinned by commit SHA, checksum-verified tools and a license allowlist. [.github/workflows](.github/workflows)
- **Playwright UI verification harness** and baseline of UI defects. [ui-verification-baseline](docs/status/ui-verification-baseline.md)
- **Third-party inventory and license review** for every shipped component. [third-party-inventory](docs/status/third-party-inventory.md)

### Changed
- Console login lands on the dashboard; the setup wizard is offered there instead of opening automatically (owner decision). [ui-verification-main](docs/status/ui-verification-main.md)
- Production ICS demo data purged at the owner's request. [host-changes](docs/status/host-changes.md)
- Groupware authenticates from OpenLDAP (single user store) with measured deprovisioning. [groupware-ldap-results](docs/status/groupware-ldap-results.md)
- ICS console is reachable over TLS (nginx, private name-constrained CA, LAN and VPN only) with a loopback-only trusted proxy for real client IPs. [host-changes](docs/status/host-changes.md)
- Migrations linearized (monitoring hardening before the deployment engine, then node scope, security-review-3 fixes, provisioning, vault and provider stack). [ics/migrations](ics/migrations/versions)
- Test databases are per agent (`ics_test_<slot>`) so development can run in parallel. [ics/README](ics/README.md)

### Fixed
- Proxmox: gzip-encoded responses from the real API; clone UPID handling and missing node allowlist found in a real-cluster mutation test; destroy precondition uses live status (cluster resources lag after stop on PVE 9.2). [provider-proxmox-real](docs/status/provider-proxmox-real.md)
- Restore drills found and fixed gaps: plaintext-LDAP regression, UID shift, missing inotify tools, CA trust, split-brain-safe cut-over. [restore-drill-results](docs/status/restore-drill-results.md)
- Document open failure in the ~5 s window after an OpenCloud restart diagnosed; tests wait for editor re-registration (KI-1). [identity-files-lab-results](docs/status/identity-files-lab-results.md)
- Installer: accepts a passive (restored) controller as ready, tolerates `--skip-tls` hosts during backup. [ics-installer-results](docs/status/ics-installer-results.md)
- Production `/catalog` returned 500 because the catalog was not installed to `/opt`; `install.sh` now ships it and ICS backup includes it. Retention no longer fails to run for ten minutes after host boot (monotonic-clock sentinel; found by CI).
- Demo approver credentials moved out of `/tmp`. [security review 1](docs/status/security-review-ics-2026-11-15.md)
- gitleaks allowlist narrowed to test fixtures; E2E harness adapted to the redesigned console.

### Security
- **Review 1** (3 High, 8 Medium) remediated: dedicated `ics` service user, split migration credentials, invite-based accounts, plan-hash-bound approvals, audit HMAC; agent TLS handshake with deadline and connection cap (H1). [report](docs/status/security-review-ics-2026-11-15.md)
- **Review 2** (monitoring and agent) remediated: restart budget, check deadlines, stale plans, silencing approval, approval mode never auto-executes, agent hardening. [report](docs/status/security-review-ics-monitoring-2026-11-15.md)
- **Review 3** (1 High, 5 Medium, 8 Low) remediated, including node-scope fencing and removal actions. [report](docs/status/security-review-3-2026-11-15.md)
- **Review 4** (2 High, 11 Medium, 9 Low; gromox patches, lifecycle, SSO, telephony, migration engine, package pipeline, Collabora) reported. Findings are **open** on `main`; see Unreleased. [report](docs/status/security-review-4-2026-11-15.md)
- `SECURITY.md` (private reporting) and `CONTRIBUTING.md` (DCO sign-off) added; AGPL-3.0 license. [SECURITY](SECURITY.md)

[Unreleased]: https://github.com/agit8or1/office-unbound/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/agit8or1/office-unbound/releases/tag/v0.1.0
