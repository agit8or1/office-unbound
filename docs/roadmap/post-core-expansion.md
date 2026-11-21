# Post-Core Expansion (P10): planned future capabilities

**Status: planning only. None of this is available or under implementation.** Owner directive, 2026-11-16.

P10 starts only after:
1. the current core product, stages 1–8 of the alpha-readiness queue (`docs/status/ALPHA-EXECUTION-QUEUE.md`), and
2. P9 PDF Studio (`docs/requirements/P9-pdf-reader-editor.md`)

are complete and verified. The ten modules are then evaluated and prioritised; they are not built all at once. This document does not change any current priority.

**Licensing notes in this document reflect what we knew at planning time.** Every one of them is re-verified in **P10.0** before a component is adopted. P10.0 covers:
- licence text
- commercial-use rights
- user and connection limits
- feature-gated "enterprise" editions
- mandatory external services
- redistribution and modification obligations
- operating cost and resources
- security history

A project whose source code is public is not assumed to be open source. Components marked *(verify)* are ones whose licence or limits we are less certain of, or which are known to have changed.

Complexity: **S** (weeks), **M** (1–2 months), **L** (a quarter), **XL** (several quarters), for one coordinated team at current velocity. These are relative estimates, not commitments.

## Shared architecture rules for every module

These come from the owner directive and extend ADR-0002, 0006, 0007 and 0009.

1. **Identity:** one SSO (Keycloak/OIDC). No second identity system.
2. **Tenancy:** strict isolation, with `customer_id` on every record. Cross-tenant tests are a gate.
3. **Permissions:** granular RBAC, enforced server-side by the owning service, never only in the UI.
4. **APIs:** consistent and versioned, following the MSP API conventions (ADR-0013). Signed webhooks.
5. **Audit:** centralised logging. ICS-style hash-chained audit for administrative actions; per-application audit for user data.
6. **Operations:** visible to the ICS (inventory, health, alerts), deployable as VMs or containers through the catalog, Proxmox-compatible, automated install and configuration, health checks and recovery, backup and restore, upgrade and rollback.
7. **Quality:** documentation and automated tests.
8. **Modularity:** any component can be replaced without rebuilding its module.
9. **Licensing:** zero mandatory licensing cost and no artificial limits (ADR-0007). If a component brings mandatory cost or limits, we choose another or build it natively.

## Foundations the core should provide (identified now; do not expand current scope)

If these are missing, several modules would need expensive rework. Most already exist or are in the current plan; the gaps are noted.

| Foundation | Needed by | Current state |
|---|---|---|
| F1. Per-customer tenancy key on all data, with a server-side customer resolver | all | **In place** (review 7 H-4: plan customer derived from referenced resources). Keep it mandatory for new models. |
| F2. Service-to-service authorisation API ("can user U do action A on object O"), callable by other services | AI (permission-checked retrieval), intranet, compliance, BI | **Gap.** Permissions live inside each application (Gromox, OpenCloud, portal). Design the interface before P10; no build needed now. |
| F3. Event bus / signed webhooks for domain events (user, file, mail, meeting) | workflows, compliance, SecOps, BI | **Partial.** MSP API signed webhooks exist for plan/job/incident events, not for user-data events. |
| F4. Unified search index service (tenant-partitioned, permission-trimmed) | intranet, AI, eDiscovery, compliance | **Gap.** Gromox has its own index; OpenCloud has its own search. Planned as a P10 shared service. |
| F5. Retention and legal-hold hooks in storage tiers: block or record deletes, immutable copies | compliance, eDiscovery | **Gap.** Gromox and OpenCloud have no legal-hold integration. Highest rework risk; P10.5 investigates it first. |
| F6. Device identity and posture signals in Keycloak (for conditional access) | identity, endpoint, SecOps | **Gap.** Depends on P10.6 endpoint management. |
| F7. Tenant-scoped data export and ingestion API | BI, AI, migration | **Partial** (migration toolkit, backups). |
| F8. Keep the ICS node agent separate from any employee-device agent | endpoint, SecOps | **Rule.** The ICS agent (ADR-0002, polkit-restricted runbooks) manages infrastructure only and is never installed on employee devices. |

**Adjustment to current work: none required.** F1 is already enforced. F2–F5 are design items for the P10.0 phase. Recommendation: keep the existing "customer_id on every new model" rule, and keep emitting signed events from new features where it is cheap.

## Conflicts with the current architecture

- **ONLYOFFICE.**
  - The directive mentions "Collabora/ONLYOFFICE".
  - ADR-0007 and docs/status/docengine-* chose our own Collabora Online build, which is MPL-2.0 with no limits.
  - ONLYOFFICE Docs Community is AGPL-3.0 with Section 7 additional terms covering branding and legal constraints. It remains the documented fallback engine.
  - It is not added as a second production engine. A replaceable engine interface (WOPI) is kept instead (P10.8).
- **ICS vs endpoint management.** These are separate products with separate agents, permissions and trust roots (F8). Endpoint management never gains infrastructure rights.
- **AI.** It must not become a dependency. All AI calls go through F2 permission checks, and tenant data never crosses customers. External providers are opt-in per tenant.
- **Compliance claims.** Configurable policies only. No certification (GDPR, HIPAA, SOC 2 and so on) is claimed without independent assessment.

---

## P10.1 Business Applications and Workflow Automation (Power Apps / Automate / Forms / Lists / Planner) — XL

**Capabilities:**
- **Builders:** visual workflow designer; app builder; custom data models; forms and questionnaires.
- **Logic and automation:** approvals; automated tasks; schedules and triggers; email and notification triggers; conditional branching; API and webhook integrations; custom processes.
- **Work management:** projects and tasks; reusable templates.
- **Access:** role-based permissions.

**Candidates:**
- **Workflow engines:**
  - **Node-RED** (Apache-2.0)
  - **Flowable** (Apache-2.0, BPMN)
  - Camunda 7 CE (Apache-2.0, but end of life; Camunda 8 is not OSI for production, *verify*)
  - Windmill (AGPL core with enterprise features, *verify*)
  - Activepieces (MIT core with paid editions, *verify*)
  - **n8n is excluded:** its Sustainable Use License is not open source and restricts commercial hosting.
- **Data and apps:**
  - Baserow (MIT core plus premium, *verify*)
  - NocoDB (*verify*: licence changed)
  - Appsmith (Apache-2.0 core plus EE, *verify*)
  - Budibase (GPL-3.0 with self-host limits, *verify*)
- **Tasks:** Vikunja (AGPL-3.0), Taiga (MPL-2.0), Planka (*verify*: licence changed).

**Native vs integrated:** integrate one proven workflow engine (Node-RED or Flowable, chosen in P10.0) behind a native Office Unbound designer and UI. Data models and forms are native, on the tenant database, using F1 and F2. Tasks start from an integrated engine and are restyled.

**Depends on:** F2, F3, notifications (ICS alert channels exist), identity.

**Integration:** the MSP API (ADR-0013) for MSP-side automation; clientst0r (MIT, ours) for service-desk workflows.

**Acceptance:**
- A non-developer builds a form, then an approval workflow, then a task in a project, entirely in the UI.
- Flows run under tenant isolation and the user's permissions, with every run audited.
- Templates export and import.
- The engine is swappable without breaking stored definitions (versioned definition format).

## P10.2 Company Intranet and Knowledge Center (SharePoint) — L

**Capabilities:**
- **Sites and pages:** homepage; department portals; drag-and-drop page builder.
- **Content:** news and announcements; employee directory (from LDAP); knowledge base.
- **Documents:** publishing; department libraries on OpenCloud spaces; metadata and content types; approval processes; version history.
- **Search and access:** search across published content; granular permissions.
- **Collaboration spaces.**

**Candidates:**
- **BookStack** (MIT)
- XWiki (LGPL-2.1)
- Wiki.js (AGPL-3.0)
- **Outline is excluded:** BSL 1.1, not open source.
- Page builder: GrapesJS (BSD-3) as a component.

**Native vs integrated:** a native intranet shell and page builder, with files and libraries reused from OpenCloud (no second document store) and the knowledge base integrated (BookStack or XWiki) behind SSO, or native if theming and permissions don't fit.

**Depends on:** F2, F4, OpenCloud spaces API, identity groups.

**Acceptance:**
- A department publishes a page with a document library.
- Approval comes before publishing.
- A restricted page is invisible to unauthorised users, both in search and over the API.
- Version history and restore work.
- Directory data comes from the one directory.

## P10.3 Optional AI Workspace (Copilot) — L

**Capabilities:**
- **Mail and documents:** summaries; suggested replies; generation assistance.
- **Spreadsheets and meetings:** spreadsheet analysis; meeting transcription and summaries.
- **Search and knowledge:** natural-language and cross-application search; AI knowledge base.
- **Operations:** workflow and admin assistance; ticket and task analysis.
- **Rule for all of the above:** context is retrieved only after permission checks.

**Architecture:**
- Provider abstraction:
  - local: **Ollama** (MIT), **vLLM** (Apache-2.0)
  - user-supplied API keys for external providers
  - multiple providers
- Per-tenant configuration and a global and per-tenant kill switch.
- Retrieval goes through F2/F4: permission-trimmed, tenant-partitioned vector store. Candidates are pgvector (PostgreSQL licence) and Qdrant (Apache-2.0).
- Transcription: **whisper.cpp** (MIT).
- No mandatory subscription and no mandatory external dependency.
- Prompts and outputs are audited without storing content beyond the tenant's retention policy.

**Native vs integrated:** a native orchestration layer and UI, with integrated model runtimes.

**Depends on:** F2 and F4 (hard), F7, meetings recording (P10.7).

**Acceptance:**
- With AI disabled, every feature still works.
- A user cannot get AI output based on documents they can't open (red-team tests).
- Two tenants' data never mix (isolation tests).
- Runs fully on a local model with no internet access.

## P10.4 Advanced Security Operations (Defender) — XL

**Capabilities:**
- **Detection:**
  - endpoint detection and response
  - vulnerabilities, threat intelligence and correlation
  - malware and suspicious activity
  - email threats and phishing analysis
- **Response:** automated response; endpoint isolation; investigation.
- **Oversight:** dashboard, reports and escalation.
- **Every capability:** tenant isolation and granular permissions.

**Reuse first:**
- **Wazuh** (GPL-2.0): SIEM, EDR and vulnerability detection.
- Our own projects:
  - **ExploitHound**
  - **MailThreatZero**: email threats; complements rspamd in the groupware tier.
  - **rem0te** (MIT, remote assistance and isolation actions)
- ExploitHound and MailThreatZero are not in `reference/` yet. Their licences and APIs are read in P10.0.
- Threat intelligence: MISP (AGPL-3.0) or OpenCTI (Apache-2.0, *verify*).

**Native vs integrated:** integrated engines with a native unified SOC console. Alerts flow into the ICS incident model for MSP operators, with per-customer routing. Functionality that already exists in our projects is not duplicated.

**Depends on:** P10.6 endpoint agent decision, F3, F6, the ICS alerting stack (exists).

**Acceptance:**
- A simulated phishing mail is detected, quarantined and turned into an incident.
- A test endpoint is isolated after an approved response and later restored.
- Each customer sees only its own events.
- Correlation is shown on real lab telemetry.

## P10.5 Compliance and Data Governance (Purview) — XL

**Capabilities:**
- **Classification:** DLP; sensitive-data and PII discovery; document classification.
- **Retention and legal:** retention policies; legal holds; eDiscovery.
- **Policy:** information protection; policy-based restrictions.
- **Monitoring:** data-access tracking; insider-risk signals; audit and compliance reporting.
- **No certification claims.**

**Candidates:**
- **Microsoft Presidio** (MIT) for PII detection
- Apache Tika (Apache-2.0) for content extraction
- eDiscovery export via standard formats: EML/MBOX, ICS/VCF, files plus manifests

**Native vs integrated:** a native policy engine and console, with integrated detectors.

**Depends on:**
- **F5 (hard, and the largest architecture risk):** legal hold and retention need hooks in Gromox (store-level delete prevention or journal copies) and OpenCloud (versions or trash retention), designed with upstream-friendly patches.
- F4 for eDiscovery search.
- F3 for access tracking.

**Acceptance:**
- A legal hold prevents permanent deletion of held mail and files, proven by deletion attempts.
- An eDiscovery search exports a complete, hash-manifested set.
- A DLP rule blocks or flags sending a test credit-card number.
- Retention deletes on schedule, with an audit record.

## P10.6 Endpoint and Device Management (Intune) — XL

**Capabilities:**
- **Coverage:** Windows enrollment; Linux; macOS; mobile where feasible.
- **Inventory and software:** hardware and software inventory; software deployment; OS patching; application management.
- **Policy and compliance:** configuration policies; compliance reports.
- **Support and remediation:** remote assistance; isolation and remediation.
- **Lifecycle and reporting:** device lifecycle; central reporting.

**Candidates:**
- **rem0te** (MIT, ours; RustDesk-based remote support): the **primary integration foundation** for the device portal and remote assistance, per the owner directive.
- **osquery** (Apache-2.0/GPL-2.0) for inventory and compliance queries.
- **Fleet** (MIT core with paid premium features, *verify*)
- **MeshCentral** (Apache-2.0)
- Windows patching via native WSUS-like logic or winget
- **Mobile:** Headwind MDM (*verify*), Android Management API (not self-hosted, so not acceptable as mandatory), Apple MDM (requires an Apple Push certificate from Apple, which is free but an external dependency, so documented).

**Native vs integrated:** integrate rem0te with osquery or Fleet behind a native device console. The **device agent is separate from the ICS node agent (F8).**

Desktop sign-in and device enrollment with the organisational identity are planned as [P10.12 Office Unbound Connect](#p1012-office-unbound-connect-desktop-sign-in-and-device-enrollment--xl), which uses this module's device console and agent.

**Depends on:** F6 for conditional access, identity, F3.

**Acceptance:**
- Enroll Windows, Linux and macOS test devices.
- Inventory is accurate.
- Deploy a package and apply a patch.
- A configuration-policy drift is reported.
- Remote assistance works only with user consent or approved policy.
- A device in tenant A is invisible to tenant B.

## P10.7 Advanced Meetings and Collaboration (Teams advanced) — L

**Capabilities:**
- **Recording and transcripts:** recording; transcription; summaries; recording library; searchable transcripts.
- **Large events:** webinars; town halls and broadcasts; large presentations.
- **In-meeting tools:** whiteboards; screen sharing; scheduling; permissions; guest access.
- **Telephony:** PSTN through configurable SIP trunks (optional, user-supplied).
- **Emergency calling:** must be documented per jurisdiction. No promise of compliant emergency calling without a certified trunk provider.

**Candidates:**
- **Jibri** (Apache-2.0) for recording and streaming
- **whisper.cpp** (MIT)
- **Excalidraw** (MIT)
- LiveKit (Apache-2.0) as an alternative SFU for very large events
- an RTMP/HLS relay: nginx-rtmp (BSD-2) or SRS (MIT)

**Native vs integrated:** extend the existing Matrix + Element + Jitsi + Asterisk stack. Each component stays replaceable.

**Depends on:** storage (OpenCloud for recordings), F4, optional P10.3.

**Acceptance:**
- A recorded meeting lands in the user's library with a transcript that can be found by search.
- A webinar with N viewers is measured.
- A guest joins with an expiring link.
- A whiteboard is saved.
- A PSTN call runs over a lab SIP trunk.

## P10.8 Advanced Office Document Functionality (Word / Excel / PowerPoint) — XL, continuous

**Capabilities:**
- **Spreadsheets:** advanced spreadsheets; Excel compatibility; complex workbooks.
- **Templates:** document, spreadsheet and presentation templates.
- **Fidelity and charts:** charting; file-format fidelity.
- **Automation:** document automation; macros where technically and legally feasible.
- **Integration:** desktop applications; collaboration; PDF integration with P9.

**Approach:**
- Continue our own Collabora Online build.
- Upstream fidelity fixes where possible.
- A **replaceable engine through WOPI**, with ONLYOFFICE Docs Community as the documented alternative under its AGPL Section 7 constraints.
- Desktop integration through LibreOffice (MPL-2.0) and WebDAV/WOPI.
- A fidelity test corpus with measured scores.
- **We never claim full Microsoft Office compatibility without tests.**

**Depends on:** P9, the template store (OpenCloud).

**Acceptance:**
- Published fidelity metrics on a corpus of real-world DOCX, XLSX and PPTX files, improving release over release.
- Templates are managed per tenant.
- A defined set of automations works.

## P10.9 Business Intelligence and Analytics (Power BI) — L

**Capabilities:**
- **Dashboards and visuals:** dashboards; visualisations; business performance dashboards.
- **Reports:** reports; scheduled reports; SQL reporting; export.
- **Data:** connectors; custom datasets; API ingestion.
- **Access:** role-based access; tenant-specific reports.
- ICS analytics stay separate and can feed authorised datasets.

**Candidates:**
- **Apache Superset** (Apache-2.0)
- Metabase (AGPL-3.0 core with paid features, *verify*)
- Grafana (AGPL-3.0) for operational dashboards
- Apache ECharts (Apache-2.0) for native charts

**Native vs integrated:** integrate Superset with SSO, row-level security per tenant and an embedded UI. Datasets come through F7.

**Depends on:** F2, F7, identity.

**Acceptance:**
- A tenant builds a dashboard on its own data only (row-level-security test).
- A scheduled PDF or CSV report is delivered.
- An ICS capacity dataset is shared only to authorised MSP roles.

## P10.10 Advanced Identity and Enterprise Integrations (Entra ID advanced / Graph) — XL

**Capabilities:**
- **Access policies:** conditional and device-based access; advanced MFA policies.
- **Privileged access:** privileged access management; elevation with approval.
- **Governance:** access reviews; entitlement management.
- **Directory sync:** hybrid Active Directory and other directories.
- **Developer platform:** service accounts; application registration; developer API management; webhooks; SDKs.
- **Ecosystem:** integration marketplace; third-party connectors.

**Approach:**
- Extend Keycloak (Apache-2.0) and the OpenLDAP directory: Keycloak authentication flows and policies for conditional access, and step-up authentication.
- Hybrid AD via Keycloak user federation and LDAP sync, with Samba AD (GPL-3.0) for AD-compatible domains where needed.
- PAM elevation reuses the ICS approval engine pattern.
- API management through the existing versioned API conventions, plus an OpenAPI catalog. Gateway candidates: APISIX (Apache-2.0) or Kong OSS (Apache-2.0, *verify* feature split).
- **No second identity system.**

**Depends on:** F6 (device posture), P10.6, F3.

**Acceptance:**
- A policy blocks sign-in from a non-compliant device.
- Admin elevation needs approval and expires.
- An access review removes stale group membership.
- AD users sync both ways in a lab domain.
- A third-party application is registered with scoped consent.

## P10.12 Office Unbound Connect: desktop sign-in and device enrollment — XL

**PLANNED / NOT IMPLEMENTED.** Owner, 2026-11-21: documentation only, not authorized for development; after the current priorities.
Entra ID–style experience (not Entra-compatible): enrol Windows, macOS and Linux computers with the organisation address and the
person's account, sign in to the computer with the same identity, SSO to the apps, central device revocation and policies.
Requirements, platform options, licensing review and decisions: [office-unbound-connect.md](../requirements/office-unbound-connect.md).

**Builds on, does not duplicate:** OpenLDAP and Keycloak (identity, no second user database), P10.6 (device console and agent,
F8), P10.10 (conditional access on device signals, Samba AD option), F1 tenancy, F6 device posture.

**Phases (provisional):** C1 architecture, licensing and security design; C2 Windows sign-in and enrollment proof of concept;
C3 Windows device administration and recovery; C4 Linux; C5 macOS Platform SSO and MDM; C6 device dashboard and MSP
administration; C7 passwordless, device trust, conditional access; C8 hardening and validation.

---

## Proposed order (owner directive: proposed, not permission to start)

1. Business Applications and Workflow (P10.1)
2. Intranet and Knowledge (P10.2)
3. Optional AI (P10.3)
4. Security Operations (P10.4)
5. Compliance (P10.5)
6. Endpoint management (P10.6)
7. Advanced Meetings (P10.7)
8. Advanced Office (P10.8)
9. BI (P10.9)
10. Advanced Identity (P10.10)
11. Office Unbound Connect (P10.12), after P10.6 and P10.10 (owner, 2026-11-21: planning only)

**Note for the future planner:** P10.4 SecOps and P10.10 conditional access both depend on the P10.6 device agent. P10.3 AI and P10.5 eDiscovery both depend on F2 and F4. Building F2, F4 and the P10.6 agent decision early inside P10 avoids rework, even though the module order above stays as the owner proposed.

## Native vs integrated summary

| Module | Native | Integrated |
|---|---|---|
| P10.1 Workflow | designer UI, data models, forms | workflow engine (Node-RED or Flowable) |
| P10.2 Intranet | shell, page builder, publishing | knowledge base (BookStack or XWiki); OpenCloud libraries |
| P10.3 AI | orchestration, retrieval, policy, UI | Ollama, vLLM, whisper.cpp, vector store |
| P10.4 SecOps | SOC console, routing into ICS incidents | Wazuh, ExploitHound, MailThreatZero, rem0te, threat intelligence |
| P10.5 Compliance | policy engine, holds, eDiscovery | Presidio, Tika |
| P10.6 Endpoint | device console, policy model | rem0te, osquery or Fleet, MeshCentral, MDM |
| P10.7 Meetings | library, scheduling, permissions | Jibri, whisper.cpp, Excalidraw, LiveKit |
| P10.8 Office | templates, automation, fidelity tests | Collabora (our build), LibreOffice desktop |
| P10.9 BI | embedding, datasets | Superset, ECharts |
| P10.10 Identity | PAM, reviews, app registry UI | Keycloak, OpenLDAP, Samba AD, API gateway |
| P10.12 Connect | enrollment app, device identity, admin wizard | Keycloak, OpenLDAP, SSSD/PAM, Samba AD (option), Apple Platform SSO, NanoMDM, P10.6 agent |
