# Office Unbound — architecture (revised for ADR-0007, 2026-11-15)

**Foundational constraint (ADR-0007):** $0 mandatory third-party licensing/subscription/API/LLM cost; no per-user, per-mailbox, per-document or per-connection charges; no artificial limits. Where a vendor's *package* is restricted but the *source license* permits, Office Unbound builds, patches and ships its own distribution (ADR-0008). Statuses below use ADR-0000 values and link to evidence.

## 1. Per-customer stack (one isolated stack per customer — ADR-0006)

```
                 Office Unbound provisioning (ICS typed actions / MSP API)
                                      │
                         OpenLDAP (authoritative directory, entryUUID = immutable id)
                 ┌────────────────────┼─────────────────────────┐
        Keycloak (OIDC, MFA,     Gromox (ldap_adaptor,       OpenCloud (same LDAP,
        read-only LDAP fed.)     own source build)           read-only; OIDC via Keycloak)
                 │                    │                            │  WOPI
          web SSO / tokens   MAPI/HTTP · EWS · EAS · IMAP ·    Collabora Online (own build,
                             SMTP · CalDAV/CardDAV · webmail    unlimited, rebranded)
```

| Layer | Component (license) | Distribution strategy | Status / evidence |
|---|---|---|---|
| Directory | OpenLDAP 2.6 (OLDAP-2.8) | distro package | Integrated in lab — identity-files-lab-results.md; restore drill passed |
| Identity/SSO | Keycloak 26.8.2 (Apache-2.0) | pinned upstream tarball (SHA-1 only — supply-chain item) | Integrated in lab; restore drill passed |
| Groupware | gromox 3.13 + grommunio-sync 2.7 / -dav 1.9 / -web 5.2 (AGPL-3.0-or-later; some GPL-2.0-only files), libHX 4.28, wmime 1.2.0 | **own source build** (vendor "5 users" exists only in admin-api, which we don't ship unpatched) | Integrated in lab — 57 protocol checks; LDAP single user store (groupware-ldap-results.md) |
| Anti-spam | rspamd + ClamAV (Apache-2.0 / GPL-2.0) | distro packages | Planned |
| Files | OpenCloud 9.1.0 (Apache-2.0) | pinned upstream binary (SHA-256) | Integrated in lab; desktop sync engine T07 11/0; restore drill passed |
| Documents | Collabora Online cp-26.04 (MPL-2.0 + LGPL-3.0 core) | **own source build**: no welcome-URL/home-mode, no support key, max connections/documents raised, Collabora marks removed | Lab functional tests on vendor CODE (lab-only); own build Implementing (docengine-build-results.md pending) |
| Fallbacks | mailcow/SOGo (GPL), Seafile CE (AGPL), ONLYOFFICE open-source build (AGPL + §7 attribution) | only if a primary fails a mandatory requirement | Researching |

Rejected for mandatory functionality: grommunio subscriptions/repos, Collabora subscriptions, CODE images in production, ONLYOFFICE commercial editions, any paid SMS/PSTN/AI dependency.

## 2. Control plane — ICS (this host)
FastAPI + PostgreSQL + Vue console (https://192.168.22.167, LAN/VPN only). Deterministic, no LLM dependency. Operator auth argon2id + TOTP; typed action catalog → plan (hash-bound) → approvals (2 for high risk, provenance rules) → single-use job → HMAC'd hash-chained audit. Read-only Proxmox client (TLS pinning) — **not yet used against real Proxmox (owner deferred)**. Monitoring: service-level checks → incidents → alerts (email, signed webhook; Pushover/SMS interface only, disabled) → bounded remediation through **managed node agents** (Ed25519-signed single-use requests, replay journal, polkit-restricted fixed runbooks). Status: Tested (151 tests) + lab demo; second security review open findings (H1 agent idle-connection DoS, H2 approval mode) — see security-review-ics-monitoring-2026-11-15.md.
Controller resilience: customer stacks don't depend on the ICS at runtime; ICS state = Postgres + /etc/office-unbound keys (backup/restore procedure for the ICS itself: Planned).

## 3. Functionality that requires original development (no upstream we can use as-is)
1. **Packaging + apt repo + signing** for the gromox stack (~10 packages; no public Debian packaging) and the Collabora engine — ADR-0008 pipeline.
2. **Mailbox provisioning** without vendor admin tooling: `gw-ldap-sync.py` prototype → ICS action (or admin-api built from source with the cap patch — evaluated, not chosen yet).
3. **Mail archiving/journaling** — not present in public gromox source.
4. **Backup orchestration** — upstream offers CLI tools only (gromox export/import/mbop); files/identity drill scripts exist; product-grade scheduling, encryption, off-host copies, retention, RPO measurement remain.
5. **User lifecycle across all credential types** (Keycloak sessions/offline tokens, OpenCloud app tokens, gromox auth cache + open IMAP sessions, ActiveSync device wipe without admin-api) — in progress (user-lifecycle-results.md pending).
6. **Rebranding patch queues** (grommunio-web theme plugin, Collabora branding) and trademark-safe naming.
7. **Unified portal, Org Admin, MSP Control Center, Migration Center** — Planned (ICS console patterns reusable).
8. **Chat/meetings/telephony** — to evaluate: Matrix Synapse (AGPL) + Element (AGPL/Apache), LiveKit (Apache-2.0) or Jitsi (Apache-2.0), Asterisk (GPL) — all unrestricted; Phase 6.

## 4. Known product limitations we will not hide
- New Outlook for Windows and Outlook iOS/Android cannot use MAPI/EWS against a non-Microsoft server (Microsoft-documented); expected: IMAP/SMTP only. Classic Outlook (MAPI/HTTP) and Outlook for Mac (EWS) are the native targets — **real-client tests not yet run** (MANUAL-CHECKLIST.md).
- Collabora jails unavailable in unprivileged nspawn (lab only); production VMs must run with jails.
- Lab runs on systemd-nspawn on the ICS host (no nested virt, Proxmox deferred) — not the intended production topology.

## 5. Legal review items (not blocking engineering; consolidated in third-party-inventory.md)
GPL-2.0-only files in gromox and combination with AGPL; Ext JS (GPL-3.0-only) in grommunio-web; grommunio/gromox/Collabora trademarks; AGPL §13 source offer for our hosted services; ONLYOFFICE §7 terms (fallback only); font licenses in the document engine.

## Future modules
The Post-Core Expansion plan (`docs/roadmap/post-core-expansion.md`) lists the shared architecture rules for the ten planned modules and the foundations they depend on: F1 tenancy key, F2 service authorisation API, F3 event bus, F4 search index, F5 legal-hold hooks, F6 device posture, F7 export and ingestion, F8 separate device and ICS agents. It also holds P10.12 Office Unbound Connect (desktop sign-in and device enrollment, [requirements](requirements/office-unbound-connect.md)). Nothing in it is built yet.
