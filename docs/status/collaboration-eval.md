# Collaboration evaluation (chat, meetings, telephony) — Phase 6

Date: 2026-11-15. Status: **Researching** (desk evaluation only; nothing installed, nothing executed, no lab evidence).
Gate: ADR-0007 (zero mandatory licensing cost, no artificial user/room/participant limits, build from source where permitted).
Method: GitHub API/raw LICENSE files and README text fetched 2026-11-15, vendor docs via page fetch, plus web search. Anything not
confirmed from a primary source is marked **UNVERIFIED**. Release dates below come from the GitHub "latest release" API.
Nothing here is legal advice; license and regulatory notes are flags for review.

## 0. Summary

| Need | Recommended (zero-cost) | Why | Main risk |
|---|---|---|---|
| Chat | **Matrix Synapse + Element Web** (own build), SSO via **MAS -> Keycloak**; Element X mobile | AGPL source, no seat cap in source, mature | Element's paid tier (ESS Pro) holds LDAP/SCIM, S3, HA; need substitutes |
| Meetings | **Element Call + LiveKit** (MatrixRTC) as primary; **Jitsi Meet** as independent fallback / guest-link option | Both Apache/AGPL, self-hostable, no caps | Outlook-invite integration needs original work; recording is weak on LiveKit path |
| Telephony | **Asterisk** (+ PJSIP, WebRTC) with **JsSIP** softphone; Baresip/Linphone as optional native clients | GPL/MIT/BSD, no per-seat | Provisioning, presence bridge and emergency-calling UX are ours to build |
| Rejected | Mattermost, Rocket.Chat | Fail ADR-0007 gate (section 1.6, 1.7) | n/a |

## 1. Chat

### 1.1 Matrix Synapse
- License: dual-licensed by Element. Free under **AGPL-3.0-or-later**, or a paid Element Commercial License (README at github.com/element-hq/synapse; GitHub license field AGPL-3.0). Relicensing from Apache-2.0 to AGPL happened 2023 (background knowledge; the README confirms the current state).
- Latest: v1.165.0 (2026-11-10). Cadence: roughly every two weeks, with security fixes in point releases.
- Limits: none in source; no seat counting (no licence-key check found in README/docs read; **UNVERIFIED** by full code audit).
- AGPL implication: network-service modifications must be offered to users of that service; fine for us (we publish source). Trademark: "Element"/"Synapse" naming needs checking before rebranding (**UNVERIFIED**).
- Sliding sync: now native to Synapse (MSC4186 support in config docs; I did not confirm the exact release it landed in, **UNVERIFIED** version); the old separate proxy is not needed. Element X requires it.
- Identity: native OIDC client (Keycloak guide exists in docs/openid.md incl. back-channel logout). LDAP via module `matrix-synapse-ldap3` (Apache-2.0 LICENSE confirmed; repo under matrix-org; maintenance state **UNVERIFIED**).
- Footprint (**UNVERIFIED**, from general experience, not measured): 25-250 users fits in 2-4 vCPU / 4-8 GB RAM with PostgreSQL; media store grows with use. Needs PostgreSQL (we already run PG for ICS, but per-customer stack needs its own).
- Multi-tenant fit: one homeserver = one `server_name`; per-customer isolated stack (ADR-0006) fits naturally, one Synapse+PG per customer. Multi-tenancy inside one Synapse is an ESS Pro feature, so we would not use it.

### 1.2 Element clients
| Client | License (primary) | Latest | Note |
|---|---|---|---|
| Element Web | AGPL-3.0 (repo also contains LICENSE-GPL-3.0 and LICENSE-COMMERCIAL: dual AGPL/GPL-3.0 or commercial) | v1.12.35 (2026-11-12) | Build from source; branding/config via config.json |
| Element Desktop | AGPL-3.0; **old repo archived 2026-03-24**, merged into element-web `apps/desktop` | v1.12.13 (last standalone) | Build from the element-web monorepo going forward |
| Element X Android | AGPL-3.0 | v26.11.0 (2026-11-06) | Needs sliding sync and, for full features, MAS-based auth (**UNVERIFIED** whether legacy password login still works on all versions) |
| Element X iOS | AGPL-3.0 | 26.11.0 (2026-11-05) | App Store distribution under our own Apple account is an operational cost, not a license cost; self-built iOS apps need Apple developer program (**fee, flag**) |
Note: Element Web/X trademark and push gateway (sygnal + FCM/APNs keys) are separate considerations. Push for our own apps requires our own Firebase/APNs credentials; free but external services (opt-in? this is a mandatory dependency for mobile push, **flag against ADR-0007 "no mandatory external API"**; UnifiedPush is a possible alternative, **UNVERIFIED**).

### 1.3 Element Server Suite (ESS) — paid vs free
Source: github.com/element-hq/ess-helm README/FAQ.
- **ESS Community** (AGPL-3.0, helm): Synapse, MAS, Matrix RTC backend, Element Web, Element Admin, Hookshot, optional PostgreSQL, HAProxy. **No enforced user cap**; "up to 100 users" is guidance for "non-commercial community use", and Element "does not recommend it for typical commercial environments". It is a helm chart for Kubernetes; we would not use it directly (our stacks are VM/LXC based, to be confirmed with ADR-0006).
- **ESS Pro only**: Synapse Pro (multi-tenancy, autoscaling, in-cluster HA), Secure Border Gateway, **Advanced IAM (LDAP/SCIM lifecycle and group access control)**, Content Scanner, AuditBot/AdminBot, **LDAP user authentication, S3 media storage**, LTS and L3 support.
- Do we need them? Impact on Office Unbound:
  - LDAP login: not needed if Keycloak federates OpenLDAP and Synapse/MAS authenticate via OIDC (our existing architecture). LDAP group sync into Matrix rooms/spaces would be original work (small, via Synapse admin API driven by ICS).
  - SCIM/lifecycle: provisioning/deprovision is already an ICS action; add a Synapse admin API call (deactivate user, erase) to the lifecycle workflow (user-lifecycle-results.md).
  - S3: use local filesystem or MinIO-like alternatives only if required; not needed at 25-250 users.
  - HA/autoscaling: not needed at SMB scale; backup/restore is the real requirement.
  - Admin console: Element Admin is in Community (AGPL); Synapse-Admin (community) is an alternative (**UNVERIFIED** license).
  - Presence at scale: Synapse presence is off or limited in default config for large servers; SMB scale is fine (**UNVERIFIED**, no benchmark).
- Conclusion: none of the Pro features is mandatory for our target size; do not use ESS Pro artifacts, which are not redistributable.

### 1.4 matrix-authentication-service (MAS) + Keycloak
- License: dual AGPL-3.0 / commercial, README confirms. Latest v1.29.0 (2026-11-10). Part of ESS Community.
- Role: next-generation auth (MSC3861) in front of Synapse; Element X and Element Call/MatrixRTC increasingly assume it. It supports upstream OIDC providers (generic OIDC such as Keycloak: official docs page for upstream providers could not be fetched, **UNVERIFIED** exact Keycloak config page; widely documented). LDAP: **UNVERIFIED** (I could not confirm any native LDAP in MAS; assume none, route through Keycloak).
- Plan: Keycloak (already integrated in lab) is the single IdP; MAS delegates to Keycloak upstream; Synapse delegates to MAS. Extra component to run per customer (Rust binary + its own PG database).
- Alternative: Synapse native OIDC to Keycloak without MAS (simpler, fully documented), but loses some Element X / Element Call features (**UNVERIFIED** which ones); decide in lab.

### 1.5 Alternative Matrix homeservers
- **Tuwunel** (matrix-construct/tuwunel): Apache-2.0, Rust, "official successor to conduwuit", sponsored by Swiss government per README; pushed 2026-11-15; v2.0.0 assets 2026-11-10. README lists Synapse migration as "Not yet". Lighter (**UNVERIFIED** footprint); LDAP/OIDC support not stated on README page (**UNVERIFIED**). Candidate if Synapse footprint is a problem; fewer admin tools and shorter track record.
- **Dendrite**: matrix-org repo archived (Nov 2024, Apache-2.0); element-hq/dendrite AGPL-3.0, v0.15.2 (2025-08-15), pushed 2026-09; feature-incomplete / maintenance mode. Not recommended.
- Conduit/Conduwuit: conduwuit superseded by Tuwunel.

### 1.6 Mattermost — **REJECTED (gate)**
- LICENSE.txt (read): compiled binaries from Mattermost Inc. are MIT; source otherwise AGPL-3.0 or commercial; trademark approval required. So building from source is possible under AGPL.
- But v11 introduced the "Entry" free tier (commercial-license Enterprise binary) with limits (10,000-message history, 10,000 push/month) per mattermost.com blog and forum threads; Team Edition is "under 250 users, no SSO" per docs (docs.mattermost.com editions-and-offerings; **UNVERIFIED** details, secondary sources). SSO/LDAP are enterprise-gated. Keycloak/OIDC SSO would require patching enterprise code we may not relicense (enterprise dir terms **UNVERIFIED**). Fails "no artificial limits" for the vendor build, and the SSO gate for source builds.

### 1.7 Rocket.Chat — **REJECTED (gate)**
- LICENSE (read): MIT outside `ee/` dirs; ee directories under a separate (proprietary) license. Repo license field NOASSERTION.
- Plans page (via search): workspaces on 6.5+ are provisioned as **Starter (up to 50 users, self-hosted)**; Community described as the MIT edition with fewer features; push notifications via Rocket.Chat Cloud limited to 1,000/month and workspace registration reportedly required for read/write (**UNVERIFIED**: sources conflict, no 2026 official change found). Registration dependency and gated features fail ADR-0007; OIDC/LDAP availability in CE is **UNVERIFIED**.

### 1.8 Zulip
- Apache-2.0 (GitHub license field). Latest 13.2 (2026-11-13). No user cap in source. Topic-threaded model suits async teams, not a Teams-like experience. Has LDAP sync and OIDC (SAML/OIDC support exists in Zulip docs; **UNVERIFIED** here as I did not fetch the docs). No built-in voice/video beyond external provider integration (Jitsi default, configurable). Strong fallback if Matrix proves too heavy; mobile apps are open source. Multi-tenant via "realms" in one server (**UNVERIFIED** practicality), per-customer stack also fine.

## 2. Meetings

### 2.1 Element Call / MatrixRTC + LiveKit
- Element Call: dual AGPL-3.0 / commercial; v0.28.2 (2026-11-05). Pre-1.0 versioning, active development.
- LiveKit server: **Apache-2.0**, v1.13.11 (2026-10-25); egress (recording/streaming) Apache-2.0 v1.15.0; livekit/sip Apache-2.0 (SIP gateway). lk-jwt-service (MatrixRTC authorization service): AGPL-3.0, v0.10.0.
- Self-hosting per docs/self_hosting.md (read): requires dedicated LiveKit SFU, lk-jwt-service, Synapse experimental flags (msc3266, msc4143, msc4222), `max_event_delay_duration: 24h`, `matrix_rtc` transport config, TLS reverse proxy, UDP/TCP media ports (exact list **UNVERIFIED** here). The page does not mention MAS, recording, or SIP.
- Features: E2EE listed as a key feature (details **UNVERIFIED**); screen share and group calls supported (**UNVERIFIED** in this fetch); breakout rooms: **not supported** to my knowledge (**UNVERIFIED**); recording: via LiveKit egress is technically possible but Element Call has no recording UI (**UNVERIFIED**) -> original work; SIP dial-in: LiveKit SIP is a separate service bridging to a SIP trunk/PBX (could connect to Asterisk), but mapping Matrix rooms to dial-in numbers is original work.
- Scale: SFU practical limits are bandwidth/CPU bound; no software cap. Typical SFU rule of thumb: tens of participants per room with simulcast on a few cores (**UNVERIFIED**, benchmark in lab).
- Browser: modern Chromium/Firefox/Safari (**UNVERIFIED** matrix of E2EE support on Safari/Firefox).
- Identity: through Matrix account (Keycloak via MAS/Synapse). Guest access possible in standalone mode with open registration on a separate homeserver (docs say new homeserver recommended). External guest-link UX is weaker than Jitsi.
- Footprint: LiveKit single binary + Redis optional (**UNVERIFIED**); 25-250 users: 2-4 vCPU and ~1 Gbit NIC adequate for a handful of simultaneous calls (**UNVERIFIED**).
- Per-customer fit: one SFU per customer (docs say dedicated per site); needs a public UDP range/IP per customer or TURN/TCP fallback; coordinate with network design.

### 2.2 Jitsi Meet
- Apache-2.0 (jitsi-meet repo; jibri Apache-2.0; videobridge Apache-2.0 per GitHub fields I could confirm for meet and jibri only). Release stable/jitsi-meet_11248 (2026-09-14). Mature, frequent stable builds.
- Auth (docs read): internal, LDAP (`AUTH_TYPE=ldap`), JWT, Matrix, and external token auth URL. OIDC via third-party adapter (e.g. jitsi-keycloak adapter, **UNVERIFIED** license/status) or by minting JWTs from our own app after Keycloak login (Office Unbound control: simple, preferred).
- Recording: Jibri (Chrome-in-container, 2 GB shm, one recording per Jibri instance, heavy). Live streaming supported. SIP: Jigasi (audio-only SIP gateway; works with Asterisk). Dial-in numbers: Jigasi + SIP trunk (customer-paid minutes, not a license).
- Screen share, breakout rooms (supported in recent releases, **UNVERIFIED** in this fetch), lobby, E2EE (insertable streams, Chromium/Firefox, **UNVERIFIED** current browser matrix), mobile apps open source (Android/iOS, **UNVERIFIED** current license state; Jitsi SDK builds are common).
- Limits: none artificial; practical ~100+ per JVB-supported room with last-N; with 2 vCPU JVB, tens of participants (**UNVERIFIED**).
- Footprint: prosody, jicofo, JVB, nginx; 4 vCPU/8 GB for 25-250 SMB (**UNVERIFIED**). Maintenance: moderate; 8x8 sponsors upstream.
- Per-customer: easy (docker or deb), one JVB per customer with UDP 10000. Multi-tenant possible via domains but we prefer isolated.

### 2.3 BigBlueButton
- LGPL-3.0 (GitHub field), v4.0.2 (2026-11-06). Education-oriented: slides, whiteboard, breakouts, polls, recordings built in.
- Requirements (docs read): Ubuntu 24.04 only for 4.0; production minimum **16 GB RAM, 8 cores, 500 GB (50 GB w/o recording), 250 Mbit/s symmetric**; dedicated server; in-place upgrade from 3.0 not supported. Heavy for 25-user SMB per-customer stacks; Greenlight OIDC/LDAP not stated in the page (**UNVERIFIED**; Greenlight v3 is known to support OIDC but unconfirmed).
- Verdict: capable (best recording/breakouts) but resource-heavy and customer-isolation costly. Optional add-on only.

### 2.4 Calendar integration (Outlook/EWS via Gromox) — feasibility only
Options, none implemented or tested:
1. **Outlook web/desktop add-in (Office.js)**: a "Add meeting link" button inserts an Office Unbound/Jitsi/Element Call join URL into the appointment body/location. Office.js add-ins are served from our own HTTPS site via a manifest; whether Gromox's OWA/EAS/MAPI stack supports add-in sideloading for desktop Outlook on a non-Exchange server is **UNVERIFIED** (add-in manifest deployment typically requires Exchange/M365 admin center; desktop Outlook can sideload manually per user). Grommunio-web (our webmail) is a separate plugin API (PHP/JS), so a webmail plugin is the realistic first deliverable.
2. **Server-side**: a hook on Gromox calendar objects (EWS/CalDAV via grommunio-dav) that auto-appends a meeting URL to events flagged "online meeting" (poll or event listener); needs a bridge service. Gromox has no public event-hook API known to me (**UNVERIFIED**).
3. **Static personal meeting rooms**: each user gets a stable URL (e.g. meet.customer/room/user) shown in the signature/contact; zero integration, delivers 80% value. Recommended MVP.
Note: Outlook "Teams meeting" button is Microsoft-proprietary; nothing to reuse.

## 3. Telephony

### 3.1 PBX engines
| | Asterisk | FreeSWITCH |
|---|---|---|
| License | **GPL-2.0** (COPYING) + dual alt. licensing via Sangoma; doc states GPL applies to all loadable modules used | **MPL-1.1** (debian/copyright LICENSE file read) |
| Latest | 24.0.0 (2026-11-05) | v1.11.3 (2026-08-28) |
| Maintainer | Sangoma, long LTS cadence | SignalWire; binary packages historically need a SignalWire token (**UNVERIFIED** current state) -> build from source (planned anyway) |
| WebRTC | Built-in PJSIP WebRTC (WSS, DTLS-SRTP, ICE) | Built-in (also mod_verto, legacy) |
| Provisioning | ARI/AMI APIs, realtime DB (PJSIP in PostgreSQL/LDAP-backed config) | XML-curl, mod_xml_ldap, ESL |
| Fit | Larger SMB ecosystem, LDAP realtime (**UNVERIFIED** completeness), stable docs | High-performance, but harder ops |
- Neither has per-seat licensing in source. Recommend **Asterisk** (common skills, ARI for ICS-driven provisioning). Commercial GUIs like FreePBX/Sangoma are separate and licensed differently; do not adopt without inventory review (FreePBX GPL, modules mixed; **UNVERIFIED**).
- Identity: Asterisk SIP credentials are separate secrets; we would generate per-user SIP credentials via ICS and store in realtime DB, not reuse LDAP passwords. Optional: Keycloak-gated provisioning page that displays QR/auto-provision config. LDAP direct bind for SIP digest is not possible (digest needs plaintext/HA1).
- Footprint: 25-250 users fits in 2 vCPU/2-4 GB (**UNVERIFIED**, depends on transcoding). Per-customer isolation: one container/VM per customer; or one multi-tenant PBX contexts (not preferred).

### 3.2 Softphone options
| Option | License | Status | Note |
|---|---|---|---|
| JsSIP | MIT | v3.13.9 on npm (registry modified 2026-10-20) | Active; WebRTC softphone in browser |
| SIP.js | MIT | v0.21.2, npm last modified **2022-10** | Effectively unmaintained; avoid for new work |
| Baresip | **BSD-3-Clause** | Baresip Foundation, active (LICENSE 2020-2026) | Linux/Android/macOS/iOS/Windows (README); CLI-oriented, UI work needed |
| Linphone desktop/Android/iOS | **GPL-3.0 or paid proprietary** (README: "dual licensed ... under GPLv3 for free ... or proprietary, for a fee, for closed-source applications"); liblinphone core AGPL-3.0 per GitHub field | Active | Free for us under GPL; must publish source of any modifications/derived apps; avoid linking into closed code. Branding rules apply (**UNVERIFIED**) |
- Recommendation: browser softphone built on JsSIP embedded in our web portal (original UI); Linphone (GPL, unmodified) as supported desktop/mobile clients; Baresip for headless/desk-phone scenarios.
- Hardware desk phones: auto-provisioning templates (Yealink, etc.) = original work; no license issue.

### 3.3 PSTN and emergency calling (flag only)
- PSTN via customer-chosen SIP trunk; paid usage, not a software license; keep optional/default off per ADR-0007.
- US: Kari's Law (direct 911 dialing, no prefix, notification on multiline systems) and RAY BAUM'S Act (dispatchable location) may apply to multi-line phone systems deployed in the US. Other regions (EU 112 / E.164 location rules, UK, etc.) have comparable duties. We should **flag these in product docs and make the PBX configuration support direct-dial emergency routing, location data and on-premises notification**; legal review required before offering telephony as a supported service. No legal conclusion drawn.

## 4. Cross-cutting matrix

| Component | Keycloak OIDC | LDAP direct | Per-customer fit | Footprint (25-250 users) | Cadence |
|---|---|---|---|---|---|
| Synapse | Yes (native, documented) | Via module (Apache-2.0) | Good (1 per customer) | 2-4 vCPU, 4-8 GB (UNVERIFIED) | ~2 weeks |
| MAS | Upstream OIDC (UNVERIFIED docs) | No (UNVERIFIED) | Good | small | ~weeks |
| Element Web | via Synapse/MAS | n/a | Static files | negligible | ~2 weeks |
| LiveKit + lk-jwt | via Matrix account | n/a | 1 SFU per customer | 2-4 vCPU, NIC bound | 1-2 months |
| Jitsi | JWT minted by us / adapter | Yes (prosody) | Good | 4 vCPU/8 GB | few months |
| BBB | Greenlight OIDC (UNVERIFIED) | UNVERIFIED | Poor (16 GB/8 core min) | heavy | ~months |
| Asterisk | no (SIP creds minted by ICS) | no | Good | 2 vCPU/2-4 GB | LTS yearly+ |
| Zulip | OIDC/SAML+LDAP (UNVERIFIED) | Yes | Good | 4 GB+ | ~2 months |

## 5. Recommended zero-cost stack for Phase 6
1. **Chat**: Synapse (own AGPL source build, pinned) + PostgreSQL; MAS delegating to Keycloak; Element Web (own build, rebranded) and Element X mobile (own build; push gateway decision needed). Element Desktop from element-web monorepo `apps/desktop`.
2. **Meetings**: Phase 6a Jitsi Meet (JWT minted by Office Unbound after Keycloak login; guests via signed links; Jigasi to Asterisk for dial-in; Jibri optional) because it is mature, supports guests and recording. Phase 6b Element Call + LiveKit for in-chat calls. Do not run BBB by default.
3. **Telephony**: Asterisk with PJSIP, WebRTC (WSS) enabled; JsSIP browser softphone; Linphone/Baresip as optional native clients; trunks optional.
4. Keep Mattermost/Rocket.Chat out. Zulip is the documented fallback if Matrix operations prove too heavy.
5. All builds go through the ADR-0008 pipeline; every dependency into third-party-inventory.md first (not yet done for any of the above).

## 6. Original development needed
- ICS actions: provision/deprovision users across Synapse (admin API), MAS, Jitsi (JWT claims), Asterisk (PJSIP endpoints in realtime DB), plus group-to-room sync (replaces ESS Pro "Advanced IAM").
- **Office Unbound presence bridge**: unify presence (Matrix presence, SIP/Asterisk device state, Gromox calendar busy/OOF) into one status; requires a service reading Asterisk ARI/AMI events and Gromox free/busy and writing Matrix presence/custom status. Non-trivial; no off-the-shelf equivalent known (**UNVERIFIED** search of bridges).
- Meeting-link generation: webmail plugin and/or Outlook Office.js add-in, with static personal rooms as MVP (section 2.4).
- Jitsi/Element Call-in-Matrix widget wiring and guest-link service; recording workflow (Jibri or LiveKit egress) with retention.
- Softphone web UI around JsSIP, desk-phone provisioning templates, emergency-call configuration profile.
- Own packaging/signing for Synapse, MAS (Rust), Element builds, LiveKit, Jitsi components, Asterisk; push gateway choice.
- Backup/restore for Synapse (PG + media + signing keys), MAS DB, Asterisk DB; fits existing drill model.

## 7. Risks
1. **Element dual-licensing / commercial pressure**: ESS Community text discourages commercial use ("not recommended for typical commercial environments"); AGPL terms themselves allow it. Monitor license changes; pin versions. Source obligations apply to our modified builds.
2. Element Desktop repo archived and merged; Element Call is pre-1.0 (v0.28), with experimental Synapse flags (`msc*`) that may break between releases.
3. Element X/Element Call coupling to MAS may force MAS even if we prefer simpler Synapse OIDC.
4. Mobile push (FCM/APNs) and Apple developer fee are external dependencies that conflict with a strict reading of ADR-0007; needs an owner decision (UnifiedPush or opt-in).
5. Recording and breakout rooms are weak on the Matrix path; Jitsi carries those needs.
6. Many facts here are **UNVERIFIED** (marked); a lab phase must verify: MAS+Keycloak flow, Synapse footprint at 250 users, LiveKit/Jitsi load, Gromox add-in feasibility.
7. Emergency-calling legal duties could make a turnkey telephony offering a liability; consider shipping telephony as "advanced/optional".
8. Mattermost and Rocket.Chat license/limit facts rely partly on secondary sources; re-verify if either is reconsidered.
9. Trademarks: Element/Synapse/Jitsi/Mattermost names and logos need removal or permission in rebranded builds.
10. Operational load: five extra services per customer (Synapse, MAS, LiveKit/Jitsi, Asterisk, PG) raise the ICS monitoring and patch workload.

## 8. Next steps
Add components to third-party-inventory.md; lab: Synapse+MAS+Keycloak SSO test, Element Call/LiveKit call test, Jitsi JWT test, Asterisk PJSIP+WebRTC test; record executed evidence before changing any status to Integrated/Tested.
