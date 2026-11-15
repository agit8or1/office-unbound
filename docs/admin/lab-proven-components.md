# Lab-proven components

Everything on this page ran **only in the isolated lab** (nspawn machines on the ICS host, lab CA, `ou-lab.internal` names). None of it is deployed or managed by the ICS yet, none is a supported production procedure, and the ICS has no actions for it. Read each evidence document before relying on any statement. Pre-alpha.

## Webmail single sign-on (Keycloak to grommunio-web)
Evidence: [webmail-sso-results.md](../status/webmail-sso-results.md). **Lab-proven on one fresh source-built node** (Chromium, one user, empty mailbox; the production-like lab node `ou-gw1` was not switched).
- Pure configuration of the pinned grommunio-web 5.2 / Gromox 3.13: a confidential Keycloak client `ou-webmail` (code flow, **no PKCE**, audience mapper required, exact redirect URI), `/etc/gromox/keycloak.json`, `/etc/gromox/bearer_pubkey`, and the CA in the node's trust store. Reproduction script: `blueprints/lab/spike-groupware/lab-sso.sh`.
- Calendar and Contacts deep links need the patch `blueprints/build/grommunio-web/patches/0001-context-deep-link.patch`.
- Behaviour: one password entry at Keycloak; sign-out at Keycloak ends webmail within about 5 minutes, not instantly (one measurement; no back-channel logout). IMAP, EWS, ActiveSync and DAV still use the LDAP password.
- **Key follower: Planned.** Gromox reads exactly one realm public key from `bearer_pubkey`. If the Keycloak realm key rotates, every SSO login fails ("Token did not validate") until that file is refreshed. The ICS action `groupware.sync_bearer_key` (fetch the realm key, compare, write) and its health check **do not exist**; until then refresh the file by hand after any realm key change and monitor the login page.
- Hardening still required before any production use: restrict users from editing their own email in the realm user profile (identity is the `email` claim), per-customer client and secret, back-channel logout. Break-glass if the login page loops: `DISABLE_KEYCLOAK` in grommunio-web `config.php`, or remove `keycloak.json`.

## Chat and meetings (Matrix, Jitsi)
Evidence: [collaboration-lab-results.md](../status/collaboration-lab-results.md). **Lab-proven prototype** (scripts `blueprints/lab/spike-collab/`): Synapse with Matrix Authentication Service and Element Web signing in through Keycloak (23/0 checks), Jitsi with tokens issued only to signed-in users (18/0), deprovisioning and Keycloak back-channel logout (6/0; one deprovisioning check failed as a test-design artefact).
Not proven: mobile apps, end-to-end-encryption key recovery, federation, TURN/NAT for outside users, backup/restore, HA. Vendor packages in the lab; production would use own builds. The meeting token service is a spike (in-memory sessions, shared secret).

## Telephony (Asterisk and browser softphone)
Evidence: [telephony-lab-results.md](../status/telephony-lab-results.md). **Lab-proven prototype** (`blueprints/lab/spike-pbx/`): two-party WebRTC calls (13/0), native SIP over TLS/SRTP, LDAP-driven extensions, voicemail to email, disabled users locked out within seconds (0.6 to 8.1 s measured).
**Emergency calling is not available**: there is no outside line, the dialplan only refuses 112/911/999 and similar, and legal review is pending. PSTN trunking, desk phones, mobile push, NAT/WAN exposure and ICS integration (enrolment, monitoring, backup) are **Planned**. Do not describe this as a phone-system replacement.

## Own document editor build, "Office Unbound Docs"
Evidence: [docengine-build-results.md](../status/docengine-build-results.md). Built from Collabora Online source tag `cp-26.04.6-1` (recipe `blueprints/build/collabora/recipe.sh`, SBOM for the online part) and run in a lab machine. Observed: reports product "Office Unbound Docs", connection and document limits of 100000, no nag/support-key strings in logs or config, 9/9 format conversion round trips, one real edit saved through WOPI, 30 documents / 60 connections without failure.
Not proven: building from an empty machine in one pass, browser rendering, jails and the reverse proxy, co-editing, XLSX/PPTX editing, OpenCloud integration, higher concurrency, an engine SBOM. Some engine strings still carry the upstream product name. The other labs used the vendor CODE image, which has its own limits and is not for production. **Status: Implementing.**

## Mail migration
- **Assessment** (read-only readiness report for Microsoft 365 or Google): code exists and 52 fixture tests pass; **never run against a real tenant** ([migration-assessment.md](../status/migration-assessment.md)). Command: `cd migration && python -m ou_migration assess --provider m365 --out DIR` (credentials only from environment or `*_FILE` secret files, mode 0600; `--deep`, `--bandwidth-mbps`, `--checkpoint` optional). Reports `assessment.json` and a self-contained `assessment.html`.
- **ICS integration of the assessment**: design only, **Planned** ([migration-ics-contract.md](../status/migration-ics-contract.md)).
- **Migration engine** (IMAP to groupware mail, incremental and resumable): the roadmap lists it as verified in the lab with the merge pending ([progress.json](../progress.json), item P7.2). Its results document is not in the repository yet, so this guide cannot describe procedures for it. **Planned for this guide** until it is merged.
